# Repository Guidelines

## Project Structure & Module Organization

This repository contains a single mitmproxy addon:

- `network_inspection_addon.py`: addon implementation. It starts an `aiohttp` Chrome DevTools Protocol discovery and WebSocket server, then maps mitmproxy HTTP flows into DevTools Network events.
- `requirements.txt`: runtime dependencies (`mitmproxy` and `aiohttp`).
- `README.md`: setup and manual usage instructions.

There is currently no dedicated `tests/` directory, packaging metadata, or static asset folder. Keep new modules small and colocated until the addon grows enough to justify a package layout.

## Build, Test, and Development Commands

Create and activate a local environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the addon locally:

```bash
mitmdump -s network_inspection_addon.py
```

Then inspect the CDP discovery endpoint at `http://127.0.0.1:9229/json/list` and add `127.0.0.1:9229` in `chrome://inspect/#devices`.

Optional syntax check before submitting changes:

```bash
python3 -m py_compile network_inspection_addon.py
```

## Coding Style & Naming Conventions

Use Python 3 style with 4-space indentation, type hints for public methods and shared state, and explicit imports from the standard library before third-party imports. Prefer descriptive method names that match mitmproxy lifecycle hooks or CDP concepts, such as `request`, `response`, `json_list`, and `handle_cdp_command`. Constants should remain uppercase (`CDP_HOST`, `BODY_LIMIT`).

Keep asynchronous code readable: create tasks only for fire-and-forget WebSocket/server operations, and use `await` where ordering or error visibility matters.

## Testing Guidelines

No automated test suite is currently defined. For behavior changes, at minimum run `python3 -m py_compile network_inspection_addon.py`, start `mitmdump -s network_inspection_addon.py`, connect Chrome DevTools, and verify request, response, error, and `Network.getResponseBody` behavior with representative HTTP and HTTPS traffic.

If tests are added, place them under `tests/` and name files `test_*.py`.

## Commit & Pull Request Guidelines

This checkout does not include local Git history, so no project-specific commit convention can be inferred. Use concise, imperative commit messages, for example `Add response body size guard` or `Fix CDP WebSocket cleanup`.

Pull requests should describe the traffic scenario tested, include any manual verification steps, and call out changes to ports, body limits, CDP payload shapes, or dependency versions.
