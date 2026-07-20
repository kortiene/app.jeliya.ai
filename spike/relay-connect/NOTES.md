# Spike run log — browser→native Iroh through authenticated relay (#23)

This file is appended to by `run-spike.mjs`. The newest run is at the bottom.
Each run records the verdict, the exact revisions, the wasm-bindgen wrapper
shape, the relay deployment, and per-engine results.

A FAIL verdict blocks any Phase 1 or Phase 2 engineering commitment; the
resulting architecture change is raised as its own decision record rather
than settled inside this spike.

## Run log

### 2026-07-20T20:33:36.497Z — verdict: **PASS**

Engines: chromium, firefox, webkit
Iroh revision: iroh 1.0.1 (crates.io), pinned `a5d98b70…` via iroh-rooms workspace dep
Wrapper shape: wasm-bindgen `--target web`, default-features=off, tls-ring, ring compiled with clang for wasm32-unknown-unknown
Relay deployment: dedicated local iroh-relay 1.0.1 (`spike-relay-server`) on 127.0.0.1:3340 (plain HTTP dev mode), `AccessControl` validates relay-auth tokens
Relay-auth: local HTTP service on 127.0.0.1:7780, Ed25519 PoP + 60s endpoint-bound token, signing key generated in-process (verifying_key=a20e616c…, NOT present in any served asset: true)
Native endpoint: local iroh Endpoint (ALPN `jeliya/spike/echo/1`) behind the dedicated relay, endpoint_id=a2678f91…

| Engine | Verdict | Echoed | Expected | Token (len) | Token TTL (ms) | Round-trip (ms) |
|---|---|---|---|---|---|---|
| Chromium | PASS | PING FROM THE BROWSER | PING FROM THE BROWSER | 323 | 59730 | 37 |
| Firefox | PASS | PING FROM THE BROWSER | PING FROM THE BROWSER | 323 | 59762 | 24 |
| WebKit | PASS | PING FROM THE BROWSER | PING FROM THE BROWSER | 323 | 59779 | 11 |

#### Static-asset secret scan

Served files scanned: index.html, spike.mjs, pkg/spike_browser_client.js, pkg/spike_browser_client_bg.wasm
Patterns checked: 32-byte hex (signing-key-shaped); 44-char base64 (key-shaped)
Findings: 12 candidate string(s); relay-auth signing key present in assets: **no**


#### Amendment A4 note (WebKit storage boundary)

WebKit's seven-day eviction of script-writable storage is a property of installed-PWA browser-peer mode (Phase 4), not of this Phase 0 transport spike: this spike stores nothing in IndexedDB, Cache Storage, or a service worker. The WebKit run above proves the transport path; A4's storage constraint applies to the first browser-peer build, not here.

---
