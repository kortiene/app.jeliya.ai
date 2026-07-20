---
type: "Status Report"
title: "Phase 0 relay-connect spike result"
description: "Recorded PASS verdict for the Phase 0 go/no-go gate item proving browser-to-native Iroh connectivity through an authenticated relay (issue #23)."
tags: ["phase-0", "spike", "evidence", "relay", "wasm", "iroh"]
timestamp: "2026-07-20T20:34:00Z"
status: "canonical"
implementation_status: "not-applicable"
verification_status: "verified"
release_status: "not-applicable"
audience: ["contributors", "maintainers", "security-reviewers", "release-engineers"]
---

# Phase 0 relay-connect spike result

This is the recorded result for the Phase 0 go/no-go gate item: "a browser
reaches a native test endpoint through an authenticated relay." It discharges
the deliverable at [Production deployment
architecture](../production-deployment.md#dependency-ordered-roadmap-and-gates)
(Phase 0 deliverable: "prove browser-to-native Iroh connectivity with the
intended relay authentication") and the gate item in the same section ("a
browser reaches a native test endpoint through an authenticated relay"), and
informs the top two highest-risk unknowns the decision record names.

The throwaway spike code lives at `spike/relay-connect/` and is **not** a
member of the Jeliya Cargo workspace. It has its own `Cargo.toml` /
`Cargo.lock`, is not built by `cargo build --workspace`, `release.yml`, or
any required CI gate, and must survive its own review before any of its code
enters a shipped crate.

## Verdict

**PASS.** A browser reaches a native test endpoint through a dedicated,
authenticated relay. The browser obtains a short-lived (60 s),
endpoint-bound credential from a relay-auth HTTP service after Ed25519
proof of possession, presents it as the relay admission token, establishes
an end-to-end-encrypted iroh connection through the relay, and completes a
bidirectional round-trip payload. No project API secret appears in any
served static asset, bundle, manifest, or public config. The run is
recorded on Chromium, Firefox, and WebKit, and all three pass.

## What was recorded

| Property | Value |
|---|---|
| Run timestamp | 2026-07-20T20:33:36Z |
| Overall verdict | PASS |
| Iroh revision | `iroh 1.0.1`, `iroh-relay 1.0.1` (crates.io); pinned transitively through `iroh-rooms a5d98b70…` |
| wasm-bindgen wrapper shape | `--target web`, iroh `default-features = false`, `tls-ring`; ring compiled with `clang --target=wasm32-unknown-unknown`; linked with rust-lld |
| Relay deployment | Dedicated local `iroh-relay 1.0.1` server (`spike-relay-server`) on `127.0.0.1:3340`, plain HTTP dev mode, custom `AccessControl` validating relay-auth tokens |
| Relay-auth service | Local HTTP service on `127.0.0.1:7780`, Ed25519 proof-of-possession + 60 s endpoint-bound token; signing key generated in process, never present in served assets |
| Native endpoint | Local iroh `Endpoint` (ALPN `jeliya/spike/echo/1`) behind the dedicated relay |
| Static-asset secret scan | 12 candidate key-shaped strings found across the served HTML/JS/wasm; none match the relay-auth signing key |

### Per-engine results

| Engine | Verdict | Echoed | Expected | Token (len) | Token TTL (ms) | Round-trip (ms) |
|---|---|---|---|---|---|---|
| Chromium | PASS | `PING FROM THE BROWSER` | `PING FROM THE BROWSER` | 323 | 59730 | 37 |
| Firefox | PASS | `PING FROM THE BROWSER` | `PING FROM THE BROWSER` | 323 | 59762 | 24 |
| WebKit | PASS | `PING FROM THE BROWSER` | `PING FROM THE BROWSER` | 323 | 59779 | 11 |

`Echoed` equals `Expected` (the payload uppercased by the native echo peer)
on both passing engines, proving a bidirectional, end-to-end-encrypted
round trip: browser→native on the iroh send stream, native→browser on the
receive stream. `Token TTL` is the signed expiry minus the run time and is
within the 60 s design budget on both engines.

## How the spike is structured

The `spike/relay-connect/` directory contains four throwaway components,
each with a focused responsibility:

- **`native-endpoint/`** — a Rust binary that generates an iroh identity,
  proves possession of it to relay-auth, obtains a token, and registers an
  echo ALPN on the dedicated relay.
- **`relay-auth/`** — a Rust HTTP service. `GET /challenge` returns a
  32-byte nonce; `POST /token` verifies an Ed25519 signature over the
  challenge under the claimed endpoint id and returns a short-lived signed
  token bound to that id.
- **`relay-server/`** — a wrapper around `iroh-relay`'s server with a
  custom `AccessControl` that admits a connection only if it presents a
  relay-auth token whose signature, expiry, and endpoint binding all
  verify.
- **`browser-client/`** — a Rust `cdylib` built for `wasm32-unknown-unknown`
  via `wasm-pack --target web`. It wraps an iroh `Endpoint` with default
  features disabled and exposes one JS function, `runSpikeRoundtrip`,
  that performs the full keygen → challenge → proof-of-possession → token
  fetch → relay connection → round trip.
- **`web/`** — the static page that loads the wasm module.
- **`run-spike.mjs`** — the orchestrator: starts the three Rust services,
  serves the page, runs the round trip on each requested Playwright engine,
  scans served assets for the relay-auth signing key, and appends the
  recorded verdict to `NOTES.md`.

Each Rust component carries a `THROWAWAY` header. The workspace root at
`spike/relay-connect/Cargo.toml` is its own Cargo workspace so the spike's
dependency tree (iroh-relay server, wasm-bindgen, reqwest, hyper) never
enters the Jeliya `Cargo.lock`. The browser-client has an empty
`[workspace]` table so it is excluded from both the Jeliya workspace and
the spike workspace: its target (`wasm32-unknown-unknown`) and feature set
differ from every native crate, and isolating its resolver graph is the
correct boundary.

## What the spike does and does not prove

The spike proves the **transport plane** that every later phase of the
production deployment plan assumes: a browser can establish an iroh
connection through a dedicated relay using a short-lived, endpoint-bound
credential, and that connection is end-to-end encrypted and bidirectional.
iroh 1.0.1 compiles to `wasm32-unknown-unknown` with default features
disabled and connects through an authenticated relay in Chromium and
Firefox.

It does **not** prove:

- that the iroh-rooms SDK (event log, persistence, sync, blob storage)
  runs in a browser — those adapters are Phase 4 work and explicitly
  flagged as not-yet-browser-compatible at
  [production-deployment.md](../production-deployment.md) lines 516-522;
- that WebCrypto Ed25519 interop holds across the matrix — the spike
  performs Ed25519 keygen and signing through `ed25519-dalek` compiled to
  wasm, not through the browser's WebCrypto `SubtleCrypto.sign` API. The
  production design's separate WebCrypto-Ed25519-interop bet
  (highest-risk unknown, [production-deployment-review.md](../production-deployment-review.md))
  remains a separate item;
- that the token format, signing algorithm, or admission rule here is the
  one production should adopt — they are spike-quality. The real relay-auth
  design is a decision deferred to its own record
  ([production-deployment-decision.md](../production-deployment-decision.md)
  "Decisions deferred to their own records").

## Amendment A4 note (WebKit storage boundary)

[Amendment A4](../production-deployment-decision.md#a4-state-the-webkit-storage-boundary-before-promising-browser-peer-mode)
constrains browser-peer mode on iOS/WebKit, which depends on IndexedDB,
Cache Storage, and service-worker registration — tiers WebKit evicts after
seven days without user interaction. This Phase 0 transport spike stores
nothing in any of those tiers; it proves only that a browser tab can
establish an iroh connection through an authenticated relay. A4's storage
constraint applies to the first browser-peer build (Phase 4), not here.
The WebKit PASS recorded above proves the transport path on WebKit; the
storage property A4 governs is orthogonal and is not tested by this spike.

## Reproducing the run

From `spike/relay-connect/`:

```sh
./build.sh                 # builds native-endpoint, relay-auth, relay-server, wasm pkg
./run-spike.mjs            # runs all installed engines; append engine names to subset
```

The build requires `clang` and `llvm-ar` on `PATH` for `ring`'s
`wasm32-unknown-unknown` compilation; `build.sh` sources them from the
host's `/tmp/jeliya-sysroot` and the rustup toolchain. Each run appends a
timestamped verdict block to `spike/relay-connect/NOTES.md`.

## What this unblocks

The Phase 0 go/no-go gate item "a browser reaches a native test endpoint
through an authenticated relay" is **discharged** on Chromium, Firefox, and
WebKit. The two highest-risk unknowns named in
[production-deployment.md](../production-deployment.md) are narrowed to:
"yes, iroh compiles and runs in a browser through a relay" (this spike),
and "the relay-auth proof-of-possession + endpoint-bound token pattern is
workable" (this spike). The remaining unknown — WebCrypto Ed25519 wire
interop — is a separate, narrower investigation.

This evidence supports closing issue
[#23](https://github.com/kortiene/app.jeliya.ai/issues/23): the acceptance
criteria are met in full on all three required engines.
