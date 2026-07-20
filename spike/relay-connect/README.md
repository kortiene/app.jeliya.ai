# Spike: browser-to-native Iroh connectivity through an authenticated relay

> **THROWAWAY.** This whole directory is throwaway spike code for GitHub issue
> [#23](https://github.com/kortiene/app.jeliya.ai/issues/23) — the Phase 0
> go/no-go gate item "a browser reaches a native test endpoint through an
> authenticated relay" and the plan's top two highest-risk unknowns.
>
> It is **not** a member of the Jeliya Cargo workspace
> (`/home/sekou/AGI/app.jeliya.ai/Cargo.toml`). It has its own
> `Cargo.toml`/`Cargo.lock` so its dependency tree (iroh-relay server, wasm-bindgen,
> tokio-with-tls, ...) never enters the shipped Jeliya lockfile or any release
> artifact. Nothing under `spike/` is built by `cargo build --workspace`, by
> `release.yml`, or by any required CI gate. To ship any of this code it must
> survive its own review and land under a real crate directory; see
> `docs/production-deployment.md` (Repository change map) and the issue's
> acceptance criterion 7.

## What this proves (or fails to prove)

The Phase 0 question is whether a **browser** can reach a **native** Iroh
endpoint through a **dedicated, authenticated relay**, using a **short-lived
endpoint-bound credential** obtained after proof of possession, with **no
project API secret** in any served static asset. Every later phase of the
production deployment plan assumes this works. If it does not, the
companion-backed first slice has no transport and the phase plan behind it is
void.

The full acceptance criteria are on the issue. The condensed pass condition is:

1. A browser reaches a native test endpoint through an authenticated relay.
2. The browser obtains a short-lived, endpoint-bound relay credential from the
   relay-auth endpoint after proof of possession, and no project API secret
   appears in any served static asset, bundle, manifest, or public config.
3. The connection is end-to-end encrypted and completes a round-trip payload
   in both directions.
4. The run is repeated on Chromium, Firefox, and WebKit; the WebKit run is
   recorded separately (amendment A4's storage boundary).
5. The exact Iroh revision, the wasm-bindgen wrapper shape, the browser
   builds, and the relay deployment are recorded with the result.

## Architecture

```
            (1) POST /token  {endpoint_id, challenge, signature}   proof of possession
 browser ───────────────────────────────────────►  relay-auth (HTTP, :7780)
 (wasm)                                            signs a short-lived token with the
   │                                               relay-auth signing key (TTL 60s)
   │                  (2) token {endpoint_id,exp,nonce} signed by relay-auth
   ◄─────────────────────────────────────────────
   │
   │  (3) connect to dedicated relay, present token in the auth header
   ▼
 relay-server (iroh-relay --dev :3340)            AccessControl validates the
   │                                               relay-auth signature + TTL + endpoint binding
   │  (4) iroh QUIC-over-WebSocket, end-to-end encrypted (Ed25519 TLS)
   ▼
 native-endpoint (iroh Endpoint, ALPN jeliya/spike/echo/1)
   │  echoes every received frame back uppercase, so the round trip is verifiable
```

## Components

| Directory | What | Status |
|---|---|---|
| `native-endpoint/` | Rust binary. An iroh `Endpoint` that joins the local relay and accepts a custom echo ALPN. | see NOTES.md |
| `relay-auth/` | Rust binary. A small HTTP service that verifies an Ed25519 challenge signature and issues a short-lived signed token bound to the endpoint id. | see NOTES.md |
| `relay-server/` | Wrapper around `iroh-relay`'s server with a custom `AccessControl` that admits only a valid relay-auth token. | see NOTES.md |
| `browser-client/` | Rust cdylib → `wasm32-unknown-unknown` via wasm-bindgen. An iroh `Endpoint` with default features disabled, wrapped for JS. | see NOTES.md |
| `web/` | Static page: WebCrypto Ed25519 keypair, fetch token, run round trip. | see NOTES.md |
| `e2e/` | Playwright spec running on Chromium, Firefox, and WebKit. | see NOTES.md |

## How to run

See `NOTES.md` for the recorded result and the exact commands. The short
version, from this directory:

```bash
# 1. Build the four Rust pieces (native, relay-auth, relay-server, wasm pkg).
./build.sh

# 2. Orchestrate a run: relay, native endpoint, relay-auth, static server, Playwright.
./run-spike.mjs
```

## Recording a result

Every run appends to `NOTES.md` with the verdict (PASS or FAIL), the exact
`iroh` / `iroh-relay` / `iroh-rooms` revisions, the wasm-bindgen wrapper shape,
the browser build versions, and the relay deployment. A FAIL verdict is
recorded as such and blocks any Phase 1 or Phase 2 engineering commitment; the
resulting architecture change is raised as its own decision record rather than
settled inside this spike.
