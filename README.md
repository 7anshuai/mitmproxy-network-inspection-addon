# mitmproxy Network Inspection Addon

This addon exposes mitmproxy-captured HTTP and HTTPS flows as a Chrome DevTools Protocol target so Chrome's built-in Network panel can display proxy traffic.

## Setup

```bash
$ git clone https://github.com/7anshuai/mitmproxy-network-inspection-addon.git
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
```

## Run

```bash
mitmdump -s network_inspection_addon.py
```

The addon starts a CDP discovery server at:

```text
http://127.0.0.1:9229/json/list
```

Add this target in Chrome:

```text
chrome://inspect/#devices
Configure...
127.0.0.1:9229
```

Configure your browser, phone, or app to use mitmproxy as its HTTP proxy. For HTTPS traffic, install mitmproxy's CA certificate on the client device.

## Notes

- This creates a separate DevTools target for mitmproxy traffic. It does not inject requests into an existing page's Network panel.
- Response bodies are cached up to 5 MB and returned through `Network.getResponseBody`.
- mitmproxy usually exposes decoded response content through `flow.response.content`, so compressed HTML should display correctly in DevTools.
- DevTools Network controls for disabling cache and applying network presets are mapped onto proxied flows. Throttling is a simple per-flow approximation, not shared aggregate bandwidth.
