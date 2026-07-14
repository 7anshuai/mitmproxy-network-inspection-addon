"""mitmproxy addon that exposes captured HTTP flows as a Chrome DevTools target.

Run:
    mitmdump -s network_inspection_addon.py

Then add 127.0.0.1:9229 in chrome://inspect/#devices.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from typing import Any

from aiohttp import web, WSMsgType
from mitmproxy import ctx, http


CDP_HOST = "127.0.0.1"
CDP_PORT = 9229
BODY_LIMIT = 5_000_000
CACHE_BYPASS_HEADERS = (
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
)
OFFLINE_ERROR_TEXT = "net::ERR_INTERNET_DISCONNECTED"


class NetworkConditions:
    def __init__(
        self,
        offline: bool = False,
        latency: float = 0.0,
        download_throughput: float = 0.0,
        upload_throughput: float = 0.0,
        connection_type: str = "none",
    ) -> None:
        self.offline = offline
        self.latency = latency
        self.download_throughput = download_throughput
        self.upload_throughput = upload_throughput
        self.connection_type = connection_type

    @classmethod
    def from_cdp_params(cls, params: dict[str, Any]) -> "NetworkConditions":
        return cls(
            offline=bool(params.get("offline", False)),
            latency=max(float(params.get("latency") or 0), 0.0),
            download_throughput=float(params.get("downloadThroughput") or 0),
            upload_throughput=float(params.get("uploadThroughput") or 0),
            connection_type=str(params.get("connectionType") or "none"),
        )

    def delay_for_request(self, byte_count: int) -> float:
        return self.latency / 1000 + self.delay_for_body(
            byte_count,
            self.upload_throughput,
        )

    def delay_for_download(self, byte_count: int) -> float:
        return self.delay_for_body(byte_count, self.download_throughput)

    def delay_for_body(self, byte_count: int, throughput: float) -> float:
        if throughput > 0 and byte_count > 0:
            return byte_count / throughput
        return 0.0


class CDPBridge:
    def __init__(self) -> None:
        self.target_id = str(uuid.uuid4())
        self.clients: set[web.WebSocketResponse] = set()
        self.response_bodies: dict[str, bytes] = {}
        self.request_seq = 0
        self.runner: web.AppRunner | None = None
        self.cache_disabled = False
        self.network_conditions = NetworkConditions()
        self.network_state = NetworkConditions()
        self.network_rule_seq = 0

        self.app = web.Application()
        self.app.router.add_get("/json/version", self.json_version)
        self.app.router.add_get("/json", self.json_list)
        self.app.router.add_get("/json/list", self.json_list)
        self.app.router.add_get(f"/{self.target_id}", self.websocket)

    def running(self) -> None:
        asyncio.get_running_loop().create_task(self.start_server())

    def done(self) -> None:
        if self.runner:
            asyncio.get_running_loop().create_task(self.runner.cleanup())

    async def start_server(self) -> None:
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, CDP_HOST, CDP_PORT)
        await site.start()
        ctx.log.info(f"CDP discovery endpoint: http://{CDP_HOST}:{CDP_PORT}/json/list")

    async def json_version(self, request: web.Request) -> web.Response:
        return web.json_response({
            "Browser": "",
            "Protocol-Version": "1.1",
        })

    async def json_list(self, request: web.Request) -> web.Response:
        ws_url = f"{CDP_HOST}:{CDP_PORT}/{self.target_id}"
        return web.json_response([{
            "description": "mitmproxy addon that exposes captured HTTP flows as a Chrome DevTools target.",
            "devtoolsFrontendUrl": f"devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws={ws_url}",
            "devtoolsFrontendUrlCompat": f"devtools://devtools/bundled/inspector.html?experiments=true&v8only=true&ws={ws_url}",
            "id": self.target_id,
            "title": "mitmproxy-network-inspection-addon",
            "type": "node",
            "url": "file://",
            "webSocketDebuggerUrl": f"ws://{ws_url}",
        }])

    async def websocket(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.clients.add(ws)
        ctx.log.info(f"DevTools frontend attached ({len(self.clients)} total)")

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    await self.handle_cdp_command(ws, json.loads(msg.data))
                elif msg.type == WSMsgType.ERROR:
                    ctx.log.warn(f"CDP WebSocket error: {ws.exception()}")
        finally:
            self.clients.discard(ws)
            ctx.log.info(f"DevTools frontend detached ({len(self.clients)} remaining)")

        return ws

    async def handle_cdp_command(self, ws: web.WebSocketResponse, msg: dict[str, Any]) -> None:
        msg_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        if method == "Network.setCacheDisabled":
            self.cache_disabled = bool(params.get("cacheDisabled", False))
            await self.send_result(ws, msg_id)
            return

        if method == "Network.emulateNetworkConditions":
            self.network_conditions = NetworkConditions.from_cdp_params(params)
            await self.send_result(ws, msg_id)
            return

        if method == "Network.emulateNetworkConditionsByRule":
            rule_ids = self.handle_network_conditions_by_rule(params)
            await self.send_result(ws, msg_id, {"ruleIds": rule_ids})
            return

        if method == "Network.overrideNetworkState":
            self.network_state = NetworkConditions.from_cdp_params(params)
            await self.send_result(ws, msg_id)
            return

        if method == "Network.getResponseBody":
            request_id = params.get("requestId", "")
            body = self.response_bodies.get(request_id, b"")
            await ws.send_json({
                "id": msg_id,
                "result": {
                    "body": base64.b64encode(body).decode("ascii"),
                    "base64Encoded": True,
                },
            })
            return

        if method == "Page.getResourceTree":
            await ws.send_json({
                "id": msg_id,
                "result": {
                    "frameTree": {
                        "frame": {
                            "id": "mitmproxy-frame",
                            "loaderId": "mitmproxy-loader",
                            "url": "about:blank",
                            "securityOrigin": "about:blank",
                            "mimeType": "text/plain",
                        },
                        "resources": [],
                    }
                },
            })
            return

        if msg_id is not None:
            await self.send_result(ws, msg_id)

    async def send_result(
        self,
        ws: web.WebSocketResponse,
        msg_id: Any,
        result: dict[str, Any] | None = None,
    ) -> None:
        if msg_id is not None:
            await ws.send_json({"id": msg_id, "result": result or {}})

    def handle_network_conditions_by_rule(self, params: dict[str, Any]) -> list[str]:
        conditions = params.get("matchedNetworkConditions") or []
        rule_ids = []

        for condition in conditions:
            self.network_rule_seq += 1
            rule_id = f"network-rule-{self.network_rule_seq}"
            rule_ids.append(rule_id)

            if self.condition_matches_all_urls(condition):
                self.network_conditions = NetworkConditions.from_cdp_params(condition)
                self.network_conditions.offline = bool(params.get("offline", False))

        if not conditions:
            self.network_conditions = NetworkConditions(offline=bool(params.get("offline", False)))

        return rule_ids

    @staticmethod
    def condition_matches_all_urls(condition: dict[str, Any]) -> bool:
        url_pattern = condition.get("urlPattern")
        return url_pattern in (None, "", "*")

    def emit(self, method: str, params: dict[str, Any]) -> None:
        if not self.clients:
            return
        event = {"method": method, "params": params}
        for ws in list(self.clients):
            asyncio.get_running_loop().create_task(ws.send_json(event))

    def next_request_id(self) -> str:
        self.request_seq += 1
        return f"req-{self.request_seq}"

    async def request(self, flow: http.HTTPFlow) -> None:
        request_id = self.next_request_id()
        flow.metadata["cdp_request_id"] = request_id

        if self.cache_disabled:
            self.disable_request_cache(flow)

        body = flow.request.raw_content or b""
        self.emit("Network.requestWillBeSent", {
            "requestId": request_id,
            "loaderId": "mitmproxy-loader",
            "documentURL": flow.request.pretty_url,
            "request": {
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "headers": dict(flow.request.headers),
                "postData": flow.request.get_text(strict=False) if body and len(body) < 50_000 else None,
                "hasPostData": bool(body),
            },
            "timestamp": time.monotonic(),
            "wallTime": time.time(),
            "initiator": {"type": "other"},
            "type": self.resource_type(flow.request.headers, None),
            "frameId": "mitmproxy-frame",
        })
        self.emit("Network.requestWillBeSentExtraInfo", {
            "requestId": request_id,
            "associatedCookies": [],
            "headers": dict(flow.request.headers),
            "connectTiming": {
                "requestTime": time.monotonic(),
            },
        })

        if self.network_conditions.offline:
            flow.metadata["cdp_offline_failed"] = True
            flow.response = http.Response.make(
                503,
                b"Network offline by DevTools emulation.",
                {
                    "content-type": "text/plain; charset=utf-8",
                    "cache-control": "no-store",
                },
            )
            self.emit_loading_failed(flow, OFFLINE_ERROR_TEXT)
            return

        await self.sleep_for(self.network_conditions.delay_for_request(len(body)))

    async def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("cdp_offline_failed"):
            return

        request_id = flow.metadata.get("cdp_request_id")
        if not request_id or not flow.response:
            return

        body = flow.response.raw_content or b""
        await self.sleep_for(self.network_conditions.delay_for_download(len(body)))

        decoded_body = flow.response.content or body
        if len(decoded_body) < BODY_LIMIT:
            self.response_bodies[request_id] = decoded_body

        content_type = flow.response.headers.get("content-type", "")
        self.emit("Network.responseReceivedExtraInfo", {
            "requestId": request_id,
            "blockedCookies": [],
            "headers": dict(flow.response.headers),
            "resourceIPAddressSpace": "Unknown",
            "statusCode": flow.response.status_code,
        })
        self.emit("Network.responseReceived", {
            "requestId": request_id,
            "loaderId": "mitmproxy-loader",
            "timestamp": time.monotonic(),
            "type": self.resource_type(flow.request.headers, content_type),
            "hasExtraInfo": True,
            "response": {
                "url": flow.request.pretty_url,
                "status": flow.response.status_code,
                "statusText": flow.response.reason,
                "headers": dict(flow.response.headers),
                "mimeType": content_type.split(";")[0] or "application/octet-stream",
                "connectionReused": False,
                "connectionId": 0,
                "remoteIPAddress": flow.server_conn.ip_address[0] if flow.server_conn.ip_address else "",
                "remotePort": flow.server_conn.ip_address[1] if flow.server_conn.ip_address else 0,
                "fromDiskCache": False,
                "fromServiceWorker": False,
                "encodedDataLength": len(body),
                "protocol": flow.request.http_version,
                "securityState": "secure" if flow.request.scheme == "https" else "neutral",
            },
            "frameId": "mitmproxy-frame",
        })

        self.emit("Network.loadingFinished", {
            "requestId": request_id,
            "timestamp": time.monotonic(),
            "encodedDataLength": len(body),
        })

    def error(self, flow: http.HTTPFlow) -> None:
        request_id = flow.metadata.get("cdp_request_id")
        if not request_id:
            return
        self.emit("Network.loadingFailed", {
            "requestId": request_id,
            "timestamp": time.monotonic(),
            "type": "Fetch",
            "errorText": str(flow.error) if flow.error else "net::ERR_FAILED",
        })

    @staticmethod
    async def sleep_for(delay: float) -> None:
        if delay > 0:
            await asyncio.sleep(delay)

    @staticmethod
    def disable_request_cache(flow: http.HTTPFlow) -> None:
        for header in CACHE_BYPASS_HEADERS:
            try:
                del flow.request.headers[header]
            except KeyError:
                pass

        flow.request.headers["cache-control"] = "no-cache"
        flow.request.headers["pragma"] = "no-cache"

    def emit_loading_failed(self, flow: http.HTTPFlow, error_text: str) -> None:
        request_id = flow.metadata.get("cdp_request_id")
        if not request_id:
            return

        self.emit("Network.loadingFailed", {
            "requestId": request_id,
            "timestamp": time.monotonic(),
            "type": self.resource_type(flow.request.headers, None),
            "errorText": error_text,
        })

    @staticmethod
    def resource_type(headers: http.Headers, content_type: str | None) -> str:
        accept = headers.get("accept", "").lower()
        ct = (content_type or "").lower()
        if "json" in ct or "json" in accept:
            return "XHR"
        if "javascript" in ct:
            return "Script"
        if "css" in ct:
            return "Stylesheet"
        if "html" in ct:
            return "Document"
        if ct.startswith("image/"):
            return "Image"
        return "Fetch"


addons = [CDPBridge()]
