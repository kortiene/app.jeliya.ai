---
type: "Reference"
title: "Companion control wire protocol v1 (D5b/D6) — specification"
description: "The versioned control-wire format ADR #2 decision 10 defers to D5: the /jeliya/control/1 ALPN, the plaintext version negotiation (D6) bound into the Noise XX prologue, the Noise_XX_25519_AESGCM_SHA256 handshake, the transcript-derived SAS, the encrypted capability exchange, the scoped-RPC framing with per-session nonce replay windows, pairing enrollment, rate limits, revocation teardown, and the persistence records — the byte-level artifact the D5b/D6 independent review gate approves."
tags: ["protocol", "pairing", "companion", "security", "wire-format", "phase-2", "d5b", "d6"]
timestamp: "2026-07-23T00:00:00Z"
status: "draft"
implementation_status: "partial"
verification_status: "not-applicable"
release_status: "unreleased"
audience: ["contributors", "maintainers", "security-reviewers"]
---

# Companion control wire protocol v1 (D5b/D6) — specification

**Status: DRAFT — subject to the D5b/D6 independent review gate.** This
document is the wire-format specification that
[ADR #2](companion-control-protocol-decision.md) decision 10 defers to D5
("D5 picks the versioned framing bytes and registers the ALPN, subject to the
independent security review"). It is the byte-level artifact the
[D5b/D6 review gate](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate)
approves; nothing here is a reviewed security boundary until that gate closes.
It folds in deliverable D6 (protocol version and capability negotiation,
[phase-1-plan.md](phase-1-plan.md)) because the negotiation frames the
handshake and the handshake authenticates the negotiation.

This specification deliberately lives outside `docs/PROTOCOL.md`: the daemon
loopback protocol and the control wire are different surfaces with different
trust models, and `PROTOCOL.md` is in the Phase 1 review pin's reopen set.
Where this document and ADR #2 disagree, ADR #2 governs.

## Roles and layering

- **Companion** — the native service holding the root identity (the change map
  reserves `crates/jeliya-companion/`). It is the Noise **responder** and the
  only party that authorizes anything.
- **Browser controller** — a web origin holding a per-pairing, WebCrypto
  non-extractable X25519 **control key**. It is the Noise **initiator**. Under
  [amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name)'s
  threat model the hostile party is the browser origin itself.

Layering, bottom to top:

1. **Iroh QUIC connection** on the dedicated ALPN (below). The iroh layer is
   carrier only: the browser's iroh endpoint key lives in script-reachable
   memory and proves nothing. No authorization decision may depend on the
   iroh-level `remote_id()`; it is used only for pre-handshake rate limiting.
2. **One bidirectional QUIC stream** per control session, opened by the
   initiator. v1 uses exactly one stream; a second stream on the same
   connection is a protocol error (close the connection).
3. **Framing** (length-prefixed frames, below), carrying: plaintext hellos
   (D6), the three Noise XX handshake messages, then AEAD transport frames.
4. **Scoped RPCs** inside transport frames, each crossing the
   `jeliya-control` gateway: identity → revocation → expiry → scope (with
   per-room binding) → rate limit → replay, in that order, fail closed.

## ALPN

```
/jeliya/control/1
```

The trailing `1` is the ALPN generation, not the negotiated protocol version;
it changes only if the pre-handshake framing itself becomes incompatible.
Version negotiation happens inside generation 1 via the hello exchange.

## Framing

All integers are **big-endian**. All strings are UTF-8, length-prefixed with
`u16`, and MUST be valid UTF-8 (invalid UTF-8 is a protocol error).

Every frame on the stream is:

```
u32  length      // length of body in bytes; MUST be ≤ 65_536
u8   frame_type
[u8] body        // length bytes
```

Receiving a frame with `length > 65_536`, an unknown `frame_type` for the
current state, or any trailing/missing bytes after parsing the body is a
**protocol error**: the receiver closes the connection immediately. There are
no compatibility skips in v1 — unknown means hostile or broken, and both fail
closed.

Frame types:

| `frame_type` | Name | Direction | Phase |
|---|---|---|---|
| `0x01` | `ClientHello` | browser → companion | plaintext |
| `0x02` | `ServerHello` | companion → browser | plaintext |
| `0x03` | `Handshake1` (Noise `e`) | browser → companion | handshake |
| `0x04` | `Handshake2` (Noise `e, ee, s, es`) | companion → browser | handshake |
| `0x05` | `Handshake3` (Noise `s, se`) | browser → companion | handshake |
| `0x10` | `Transport` | both | encrypted |

Exactly one frame of each handshake type, in order. Any deviation is a
protocol error.

## D6 — version and capability negotiation

### Plaintext hellos

`ClientHello` body:

```
[u8; 4]  magic            // b"JCTL"
u8       version_count    // MUST be ≥ 1 and ≤ 8
[u16]    versions         // supported protocol versions, descending preference
u8       session_kind     // 1 = pairing, 2 = control
[u8; 16] pairing_nonce    // the rendezvous nonce from the QR/link for
                          // session_kind 1; MUST be all-zero for kind 2
```

`ServerHello` body:

```
[u8; 4]  magic            // b"JCTL"
u16      version          // the version the companion chose
u16      min_version      // the companion-enforced minimum-safe floor
```

Rules:

- The companion picks the highest client-offered version it supports that is
  `≥ min_version`; if none exists it sends `ServerHello` with `version = 0`
  and closes after flushing (so the browser can render an upgrade prompt —
  [amendment A3](production-deployment-decision.md#a3-specify-the-companion-update-path-and-measure-version-skew)'s
  in-browser prompt keys off this). `version = 0` is never a valid protocol
  version.
- v1 is the only version this specification defines. `min_version` default
  is 1.
- For `session_kind = 1` the companion MUST have a pairing offer outstanding
  whose nonce equals `pairing_nonce`; otherwise it closes before Noise.
  Each pairing nonce is single-use: it is consumed by the first `ClientHello`
  that presents it, successful or not.
- For `session_kind = 2` a non-zero `pairing_nonce` is a protocol error.

### Downgrade detection

The **exact bytes** of the `ClientHello` and `ServerHello` frames (header and
body, in that order: `client_hello_frame || server_hello_frame`) form the
Noise **prologue**. Noise mixes the prologue into the handshake hash before
any DH output, so a middle party that alters either hello — stripping a
version, forging the floor, changing the session kind or nonce — causes both
sides to compute different handshake hashes and the handshake fails at the
first authenticated payload (`Handshake2` cannot decrypt). Downgrade
detection is therefore not a comparison after the fact; tampering is
unrepresentable in a completed handshake.

### Encrypted capability exchange

Capabilities are **not** in the plaintext hellos (they would fingerprint the
companion to any prober). The first `Transport` frame after the handshake is
the companion's `SessionAccept` (below), which carries the method registry it
serves. A peer MUST NOT send a scoped RPC for a method the companion did not
advertise; the companion rejects unknown methods regardless.

## The handshake

**Noise protocol name:** `Noise_XX_25519_AESGCM_SHA256`
(Noise Protocol Framework rev 34 semantics).

- **DH:** X25519 (curve25519 Montgomery ladder, clamped scalars). The
  implementation MUST reject an all-zero DH output (non-contributory peer
  key) and abort the handshake.
- **AEAD:** AES-256-GCM with the Noise nonce construction (4 zero bytes ‖
  64-bit big-endian counter).
- **Hash:** SHA-256; HKDF as defined by Noise (HMAC-SHA-256 chains).
- **Prologue:** the hello bytes, as above.

Message pattern (XX):

```
→ e
← e, ee, s, es      // companion's static, encrypted
→ s, se             // browser's static (the control key), encrypted
```

Handshake payloads are empty in v1 (zero-length plaintexts, still
authenticated). Reserved for future use; a non-empty payload is a protocol
error in v1.

Properties this instantiation is chosen for:

- **Mutual static authentication with initiator identity hiding** (ADR #2
  decision 2): the browser's control key is revealed only in message 3,
  encrypted to a companion that already proved possession of its static key.
- **Browser implementability without extractable keys** (A1): every browser
  primitive is WebCrypto-native — X25519 `deriveBits` against a
  `{extractable: false}` static key, AES-GCM, HMAC/HKDF-SHA-256. The browser
  never implements a cryptographic primitive in script and never holds its
  static private key in script-readable memory. Ephemeral keys are generated
  per-handshake and are also non-extractable.
- **Companion-side reuse of reviewed primitives:** the Rust side reuses
  `aes-gcm 0.10.3` (the exact crate and version the Phase-1-reviewed recovery
  envelope uses) and the `curve25519-dalek` build already load-bearing for
  every iroh `EndpointId` in the transport layer — no second curve
  implementation enters the runtime graph.

### Companion static key pinning

The companion's static key is its long-lived pairing identity (ADR #2
decision 2). The pairing QR / custom-protocol link carries
`fp = SHA-256(companion_static_public)[0..8]` (8 bytes). During a pairing
handshake the browser MUST verify the static key received in `Handshake2`
against `fp` and abort on mismatch, **before** SAS display. During a control
(already-paired) session the browser MUST verify the full 32-byte static key
against the value it stored at pairing. The SAS ceremony — not the 64-bit
fingerprint — is the pairing-time MITM authority; the fingerprint is an
early-abort optimization and a hard pin thereafter.

### SAS derivation (pairing sessions)

After the handshake completes, both sides hold the Noise handshake hash `h`
(which covers the prologue, both static keys, both ephemerals, and every
handshake ciphertext). The short authentication string is:

```
sas_bytes = HMAC-SHA-256(key = h, msg = "jeliya/control/sas/v1")[0..4]
group1    = u16 from sas_bytes[0..2]   // big-endian
group2    = u16 from sas_bytes[2..4]
display   = "%05d-%05d"                 // e.g. "04821-60110"
```

Two five-digit groups, 32 bits total, matching ADR #2 decision 4's format.
The SAS is transcript-derived: a middle party cannot present the same SAS on
both sides without breaking the DH. This replaces the Phase-1 scaffolding's
BLAKE3-over-two-keys construction (scope doc: "the D5b gate reviews the
transcript-derived SAS, not this simple construction"). The derivation is
domain-separated by the fixed message string, closing the Phase-1
"SAS has no domain-separation tag" note.

The SAS MUST be confirmed by the user **on both sides** before the companion
records the control key. The companion-side confirmation happens on a surface
the browser origin cannot render or forge (ADR #2 adoption resolution;
presentation details land under amendment A5's accessibility gate). No scoped
RPC is accepted on a pairing session, before or after confirmation — a
pairing session exists only to enroll a key and is closed after `PairResult`.

## Transport phase

After `Handshake3`, both sides move to Noise transport mode: two
unidirectional AEAD cipherstates (initiator→responder and
responder→initiator), each with its own strictly-incrementing 64-bit counter
nonce. A frame that fails AEAD decryption is a protocol error (close). The
Noise layer therefore already rejects cross-frame replay, reordering, and
truncation within a session; the application nonce below is an independent,
ADR-mandated second layer whose window semantics survive future multi-stream
transports. Rekey is out of scope for v1: sessions are bounded (below) far
under the AES-GCM nonce budget.

`Transport` frame body = one AEAD ciphertext. Its plaintext is:

```
u8    msg_type
[u8]  msg_body
```

Message types:

| `msg_type` | Name | Direction |
|---|---|---|
| `0x01` | `SessionAccept` | companion → browser |
| `0x02` | `SessionReject` | companion → browser |
| `0x03` | `PairConfirm` | browser → companion |
| `0x04` | `PairResult` | companion → browser |
| `0x10` | `Request` | browser → companion |
| `0x11` | `Response` | companion → browser |

### Session admission (control sessions)

On a `session_kind = 2` session, after the handshake the companion checks the
browser static key from message 3 against its installed control-key records —
the full gateway order: known → not revoked → not expired. On success it
sends `SessionAccept`; on failure `SessionReject { reason }` and closes. The
check result is confidential (inside the encrypted channel): an unpaired
prober that completes a handshake learns only "rejected", not which reason,
unless it holds the key in question.

`SessionAccept` body:

```
u16      method_count
[u16]    methods          // the method-registry ids this companion serves
u64      expires_at_ms    // this key's expiry, for browser display
```

`SessionReject` body:

```
u16      reason           // 1 = unknown key, 2 = revoked, 3 = expired,
                          // 4 = busy (rate/limit), 5 = incompatible
```

### Pairing enrollment (pairing sessions)

Enrollment is **not an RPC** and is not reachable from any granted scope
(threat model: "control-key enrollment is itself unenumerated" — here it is
enumerated as its own session kind, gated by possession of a fresh
rendezvous nonce plus the SAS ceremony plus companion-local human action).

Sequence after the handshake:

1. Both sides display the SAS. The browser user confirms on the browser; the
   browser then sends `PairConfirm {}` (empty body).
2. The companion user confirms **on the companion's trusted surface**,
   selecting (or accepting) the granted scopes, the granted rooms, and the
   key lifetime. The companion MUST NOT install before **both** its local
   confirmation and `PairConfirm` have arrived. Order between them is
   irrelevant.
3. The companion installs the control-key record and replies `PairResult`:

```
u8       installed        // 1 = installed, 0 = aborted
u16      scope_count      // present iff installed
[u16]    scopes           // scope registry ids
u16      room_count
[string] rooms            // granted room ids
u64      expires_at_ms
```

4. The pairing session closes. Scoped RPCs require a fresh control session.

A wrong SAS on either side aborts: the companion side aborts locally (no
install — the gate's "wrong-SAS fail closed" row); the browser side simply
never sends `PairConfirm` and closes. A pairing session that has not
completed installation within **120 seconds** of the handshake is aborted and
its rendezvous nonce is already spent. At most **one** pairing session may be
outstanding per companion at a time; a second concurrent attempt is rejected
at the hello (busy), preventing interleaved-ceremony SAS confusion.

### Scoped RPCs

`Request` body:

```
u64      nonce            // per-session, starts at 1; 0 is invalid
u16      method           // method registry id
[u8]     params           // method-specific, defined below
```

`Response` body:

```
u64      nonce            // echoes the request
u8       ok               // 1 ok, 0 error
[u8]     body             // result on ok; else: u16 error code + string message
```

v1 is **single-in-flight**: the companion processes one request at a time and
produces its `Response` before accepting the next, so responses are always in
request order. A request that arrives while the previous one's response has not
been produced is a protocol error (close). Pipelining is reserved for a later
version. The application nonce is per-session (fresh session keys make
cross-session replay cryptographically impossible; persisting per-key nonce
state would add a rollback-on-crash acceptance window, so v1 deliberately
scopes the window to the session). The companion tracks the highest nonce
plus a sliding window of 64 (out-of-order acceptance within the window,
exact replays and below-floor nonces rejected) — the same tested window
semantics as the Phase-1 state machine, now keyed by session.

**Rate limiting precedes validation.** The per-key RPC and byte limits are
charged on *every* request from an admitted key, before method and parameter
validation, so a compromised origin cannot spend unbounded
decrypt/parse/encrypt work by sending well-keyed but malformed requests (an
unknown method or invalid params) without hitting the limits. The
strike-to-teardown counter that drops a session on sustained violation is
**per session**, so one abusive session cannot tear down a sibling session
sharing the same control key.

**Method registry v1** — the complete list; anything else fails closed with
`method_unknown` before any scope evaluation:

| id | Method | Scope required | params | result |
|---|---|---|---|---|
| `0x0001` | `room.timeline` | `room.read` in the named room | `string room_id, u8 has_limit, u32 limit?, u8 has_after, string after?` | the daemon `room.timeline` result JSON, UTF-8 |
| `0x0002` | `room.members` | `room.read` in the named room | `string room_id` | the daemon `room.members` result JSON, UTF-8 |
| `0x0003` | `message.send` | `message.send` in the named room | `string room_id, string body, string client_msg_id` | the daemon `message.send` result JSON, UTF-8 |

**Scope registry v1:** `0x0001` = `room.read`, `0x0002` = `message.send`.
Everything ADR #2 decision 6 lists as separately-approved (`invite.*`,
`file.*`, `pipe.*`, `identity.*`, `agent.*`, `room.leave`, `room.join`) has
**no method id in v1** — a controller cannot name what the wire cannot
express. In particular:

- `room.join` redemption (the A1 confused deputy) is absent from v1; when a
  later version adds it, its method definition MUST carry the
  companion-surface human confirmation of the ticket-resolved room identity,
  per adopted ADR #2.
- `daemon.status` is absent: it returns the endpoint id, dialable socket
  addresses, and the relay URL, which the threat model directs the scope
  model to keep out of the browser's reach.
- `room.open` / `room.close` / `room.leave` are absent: the readable set is
  exactly "the rooms the user explicitly opened through the companion", and
  the browser cannot grow, shrink, or hint it. Browser-supplied dial hints
  (threat model TB3) are unrepresentable: no v1 params field carries an
  address, hint, or peer list.
- `client_msg_id` is **required** on `message.send` (D2 idempotency is the
  duplication bound the rate limiter leans on).
- `room.timeline`'s `limit` is **capped at 500** (`MAX_TIMELINE_LIMIT`): a
  tiny request must not be able to force an unbounded timeline read or
  materialization, which the request-byte limiter does not bound. An explicit
  larger limit is clamped; an absent limit leaves the daemon's own small
  default in force.

The companion constructs the daemon dispatch params **itself** from the
parsed, validated wire fields — browser bytes are never forwarded as JSON to
the engine, so a field the wire does not define cannot reach `dispatch`.
Room ids in params MUST match the granted-rooms set on the key record
(the "selected-room" binding of ADR #2 decision 6, checked in the gateway,
not in the transport).

**Error codes** (`Response.body` on `ok = 0`):

| code | name |
|---|---|
| `0x0001` | `denied_unknown_key` |
| `0x0002` | `denied_revoked` |
| `0x0003` | `denied_expired` |
| `0x0004` | `denied_scope` |
| `0x0005` | `denied_room` |
| `0x0006` | `denied_replay` |
| `0x0007` | `denied_rate_limited` |
| `0x0008` | `method_unknown` |
| `0x0009` | `params_invalid` |
| `0x000A` | `engine_error` (daemon error kind + message passed through) |

Denials are precise on an authenticated session (the key holder may know why
it was denied); they advance no granting state.

## Control-key records and lifetime

The companion records, per control key (ADR #2 decision 5): the 32-byte
X25519 public key, the granted scope set, the granted room set, creation
time, expiry (`created_at + lifetime`), last-use time, and the revoked flag.

- **Lifetime default: 30 days** (fixed by ADR #2 adoption). **Hard maximum:
  90 days. Hard minimum: 5 minutes.** The record constructor clamps; there is
  no API path to an unbounded key. (The 90-day maximum is an implementation
  parameter for the D5b/D6 gate to confirm, like the replay window.)
- The gateway owns the clock. Callers cannot supply time (closing the
  Phase-1 finding F3 caller-supplied-`now_ms` gap); tests inject a fake
  clock through a constructor seam.
- The **only** path to an installed record is a completed pairing ceremony
  (SAS-verified transcript + both confirmations) or a load from the
  companion's own persisted store. The Phase-1 public
  `install`/`ControlKeyRecord::new` bypass surface is removed.

### Persistence

Records persist across companion restarts (a restart is not a mass
revocation) in `control_keys.json` under the companion data dir, following
the `localstate.rs` discipline exactly: versioned JSON (`version: 1`),
atomic write (staged temp file + fsync file and directory + rename), `0600`
on Unix, and a process-global write lock. Replay windows are **not**
persisted (they are per-session); `last_used_ms` is persisted lazily (on
install, revoke, expiry-eviction, and at most once per minute otherwise) so
a crash can lose only last-use freshness, never an authorization fact.
Revoked records are retained until expiry so a restart cannot resurrect a
revoked key, then evicted.

## Rate limiting (ADR #2 decision 8)

Fail-closed limits, enforced by the companion; sustained violation drops the
session, not just the frame:

| Surface | Limit (v1 parameters) |
|---|---|
| Handshakes, per remote iroh EndpointId | 6 per minute (burst 6) |
| Handshakes, global | 30 per minute (burst 30) |
| Pairing sessions | 1 outstanding; offers expire with their nonce (120 s) |
| RPCs, per control key | sustained 10/s, burst 40 |
| Request bytes, per control key | sustained 256 KiB/s, burst 1 MiB |
| Violations, per session | 3 rate denials in 60 s → session teardown |

Token-bucket semantics; parameters are v1 implementation values for the
D5b/D6 gate to confirm. The per-EndpointId handshake limit is the only
control that keys off the (unauthenticated) iroh identity, and it can only
deny service to that identity, never grant.

Enforcement split: the per-key RPC and byte limits live in the gateway
(`jeliya-control`, checked on every scoped RPC, all-or-nothing across the two
buckets). The handshake-tier limits (per-EndpointId and global) live in
`jeliya-control`'s `HandshakeLimiter`, which the transport adapter drives —
the sans-I/O session core never sees the iroh `EndpointId`. Likewise, the
single-use rendezvous nonce, the one-outstanding-pairing rule, and the 120 s
pairing deadline are enforced by the companion's offer registry in the
transport adapter (they need cross-connection state and a wall clock the
session core does not hold); the session core enforces that a pairing
`ClientHello` presents the live offer's nonce.

## Revocation (ADR #2 decision 9)

`revoke` marks the record revoked immediately and returns the set of live
session ids bound to that key; the companion closes each underlying QUIC
connection at once. Future handshake admissions and in-flight RPCs under the
key fail closed (`denied_revoked`). Revocation is local: it cannot recall
actions already authorized (TB4), and the signed room log keeps whatever a
revoked controller already sent. There is no offline send queue in v1:
authorization is checked at execution time on a live session, never deferred
past revocation (closing the threat model's deferred-signing row for this
surface).

## Session bounds

A control session is torn down on: QUIC connection loss, key revocation, key
expiry (the next RPC fails closed and the session closes), 3 rate-limit
strikes, any protocol error, or **24 hours** of session age, whichever comes
first. Re-establishing costs one handshake. The browser controller treats
teardown as a normal reconnect, not an error surface.

## What this wire deliberately cannot say (review checklist)

- No frame carries a daemon bearer token, and no companion response contains
  one. The daemon token and the control channel never meet (ADR #2 "It does
  not replace the daemon token").
- No v1 method reaches files, pipes, agents, identity operations, invites,
  join/leave/open/close, shutdown, or status (Phase 2 gate: "a malicious
  controller cannot invoke files, pipes, agents, or identity reset").
- No params field carries an address, relay URL, peer hint, or endpoint id in
  either direction (TB3 dial-hint injection; TB2 metadata hygiene).
- No plaintext byte after the hellos identifies the companion (capabilities
  are encrypted; the hellos contain versions and a nonce only).
- Enrollment cannot be reached from a control session, and control cannot be
  exercised from a pairing session.

## Conformance fixtures

`crates/jeliya-protocol` carries golden byte fixtures for every frame and
message type above (hex, committed) plus negative fixtures (oversized frame,
bad magic, zero nonce, unknown method, non-UTF-8 string, trailing bytes).
The Rust encoder/decoder and the browser TypeScript encoder/decoder are both
tested against the same fixture corpus (the D6 "conformance corpus of
fixtures that later phases reuse across native and browser clients").
Handshake correctness is additionally cross-validated against an independent
Noise implementation (`snow`, dev-dependency only) over randomized
handshakes, including transcript-hash agreement — the SAS input.

## Citations

- [ADR #2 — companion control protocol](companion-control-protocol-decision.md) — the adopted decisions this wire implements (transport, handshake, bootstrap, SAS, key bounds, scopes, replay, rate limiting, revocation; decision 10 defers the bytes to this document).
- [Phase 1 security review scope — the D5b/D6 gate](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate) — what the gate assesses; this document is its input.
- [Phase 1 plan — D5, D6](phase-1-plan.md) — the deliverable definitions folded together here.
- [Production deployment decision — amendments A1, A3](production-deployment-decision.md) — the authority bound and the version-skew obligations the hellos serve.
- [Security threat model — TB3](security-threat-model.md) — the per-row obligations the "cannot say" checklist answers.
- [Phase 0 relay spike](evidence/phase-0-relay-spike.md) — the browser-to-native iroh connectivity this rides on.
