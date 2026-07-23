---
type: "Architecture"
title: "Phase 1 implementation plan"
description: "Sequencing, dependency order, gate mapping, and per-deliverable tasks for the seven Phase 1 production-identity and protocol-primitive deliverables unlocked by the Phase 0 go/no-go gate."
tags: ["phase-1", "roadmap", "architecture", "identity", "protocol", "governance"]
timestamp: "2026-07-21T15:00:00Z"
status: "proposal"
implementation_status: "planned"
verification_status: "not-applicable"
release_status: "not-applicable"
audience: ["contributors", "maintainers", "security-reviewers", "release-engineers"]
---

# Phase 1 implementation plan

**This is a reviewable plan, not an authorization.** Phase 1 ("production
identity and protocol primitives") was unlocked by the
[Phase 0 go/no-go gate verdict](phase-0-gate-verdict.md) on 2026-07-21. This
page sequences the seven Phase 1 deliverables from
[Production deployment architecture](production-deployment.md) (Phase 1),
maps each to its go/no-go gate condition and the repository code it touches, and
records the dependency order that keeps the critical path on amendment A1. It
advances no implementation, verification, or release status; a deliverable's
status is carried by the code and evidence it produces, not by appearing here.

The 3-to-5-week figure in the
[phase heading](production-deployment.md) predates the decision record and omits
the work amendment A1 adds. It is re-baselined by this plan, not carried forward
as a release commitment.

## Source and scope

Phase 1 deliverables (from
[Production deployment architecture](production-deployment.md), Phase 1):

1. recovery bundle and OS-keystore abstraction;
2. `client_msg_id` idempotency;
3. incremental timeline cursor;
4. invite default expiry and cancellation;
5. companion pairing/control protocol;
6. protocol version and capability negotiation;
7. surface upstream's durable critical `store_degraded` decision and define the
   operator response to exhausted store retries or queue overflow.

Phase 1 go/no-go gate conditions (same source):

- recovery succeeds from a fresh install on every supported OS;
- native production mode no longer leaves the root secret plaintext;
- 10,000 injected lost-response retries produce no duplicate message;
- cursor resync matches full-log materialization;
- expired and cancelled tickets fail on every transport;
- replay, wrong-SAS, expired-key, and revoked-key pairing tests fail closed;
- independent security review approves the wire formats and key lifecycle.

[Amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name)
blocks the Phase 1 gate and is tracked alongside the seven deliverables because
it is a design prerequisite to specifying the pairing protocol (deliverable 5).

## Dependency order

```text
Tier 0 — foundational, no Phase-1-internal dependencies:
  D7  store_degraded surfacing + operator runbook
  D6  protocol version and capability negotiation
  D1  keystore abstraction + recovery bundle
      └── blocked on ADR #3 (recovery-bundle format and custody) before impl

Tier 1 — independent engine/supervisor primitives:
  D2  client_msg_id idempotency
  D3  incremental timeline cursor
  D4  invite default expiry + invite.cancel

Tier 2 — depends on Tier 0/1 and A1:
  A1  scope-model change (room.join redemption scope, non-extractable control
      key, bounded lifetime) — design prerequisite to D5
  D5  companion pairing/control protocol
      ├── consumes D2 (idempotent chat sends)
      ├── consumes D6 (version/capability framing)
      ├── consumes A1 (scope model)
      └── blocked on ADR #2 (control protocol and pairing transcript) before impl
```

The critical path is **A1 → D6 → D5**, with **D1** as the parallel long pole
(OS-specific keystore work, blocked on its ADR). D2, D3, and D4 are independent,
may land in any order, and unblock the Phase 2 vertical slice.

## Suggested sequencing

| Order | Item | Primary gate condition | Primary code surface | Blocked by |
|---|---|---|---|---|
| 1 | D7 — `store_degraded` surfacing | (operator runbook; no Phase 1 gate row) | `crates/jeliya-core/src/supervisor.rs`, `docs/runbooks/` | nothing |
| 2 | D4 — invite default expiry + `invite.cancel` | expired and cancelled tickets fail on every transport | `supervisor.rs` ([create_invite](../crates/jeliya-core/src/supervisor.rs):1281), [parse_expiry](../crates/jeliya-core/src/supervisor.rs):3202, `error.rs` ([TicketExpired](../crates/jeliya-core/src/error.rs):28) | nothing |
| 3 | D2 — `client_msg_id` idempotency | 10,000 injected lost-response retries produce no duplicate message | `supervisor.rs` ([send_message](../crates/jeliya-core/src/supervisor.rs):1641) | nothing |
| 4 | D3 — incremental timeline cursor | cursor resync matches full-log materialization | `supervisor.rs` (cursor at :2531) | nothing |
| 5 | D1 — keystore abstraction + recovery bundle | recovery succeeds from a fresh install on every supported OS; native production mode no longer leaves the root secret plaintext | `crates/jeliya-core/src/identity.rs` ([create](../crates/jeliya-core/src/identity.rs):108, [SecretKeys::load](../crates/jeliya-core/src/identity.rs):162) | ADR #3 |
| 6 | A1 — scope-model change (room.join redemption, non-extractable control key, bounded lifetime) | (amendment; enables the D5 gate row) | `engine.rs` ([requires_room_access_preflight](../crates/jeliya-core/src/engine.rs):47) | nothing |
| 7 | D6 — protocol version and capability negotiation | independent security review approves the wire formats | new `crates/jeliya-protocol/` | nothing |
| 8 | D5 — companion pairing/control protocol | replay, wrong-SAS, expired-key, and revoked-key pairing tests fail closed | new `crates/jeliya-control/` | A1, D2, D6, ADR #2 |

D7 is first because it is operator-facing, low-risk, and produces the runbook
the gate's `store_degraded` row references. D2/D3/D4 follow because they are
self-contained primitives that unblock Phase 2. D1 is the long pole and should
start as soon as its ADR lands, in parallel with D2–D4. A1 is a design change
that must land before D5 is specified; D6 frames D5's wire format.

## Deliverable detail

### D1 — recovery bundle and OS-keystore abstraction

**Current state.**
[`identity.rs`](../crates/jeliya-core/src/identity.rs) writes both seeds to a
plaintext `identity.secret` under owner-only `0600` permissions; the module
header states this directly: "Seeds are stored plaintext under owner-only
permissions (the SDK MVP threat model)" ([identity.rs:5](../crates/jeliya-core/src/identity.rs)).
[`create`](../crates/jeliya-core/src/identity.rs) generates both keys in-process
and [`SecretKeys::load`](../crates/jeliya-core/src/identity.rs) reads them back.
There is no export, recovery, rotation, or OS-keystore path.

**Work.**

- Introduce a `Keystore` trait in `jeliya-core` that loads and stores the two
  signing seeds, replacing the direct file reads in
  [`SecretKeys::load`](../crates/jeliya-core/src/identity.rs) and the write in
  [`secret_file_contents`](../crates/jeliya-core/src/identity.rs).
- Provide three production backends, gated by cargo features: macOS Keychain,
  Windows DPAPI/CNG, and Linux Secret Service.
- Provide an explicit encrypted-file fallback with versioned KDF/password
  parameters; the current plaintext fallback must not remain the production
  default.
- Define a versioned recovery-bundle format: an authenticated-encryption
  envelope containing the profile root, the room membership index, device
  authorization state, and relay config. The recovery key is a random 256-bit
  value (optionally rendered as a phrase); it is not derived from a low-entropy
  password.
- Require a successful test restore before identity setup is called complete.
- Do not derive the only recovery key from a user password, and do not let
  optional cloud storage hold anything but the opaque encrypted envelope.

**Gates.** "recovery succeeds from a fresh install on every supported OS";
"native production mode no longer leaves the root secret plaintext". The
supported OS set is fixed by the
[Supported platform matrix decision](platform-matrix-decision.md).

**Blocked by.** ADR #3 ("Recovery-bundle format, custody, and optional opaque
hosting"; decision deferred by the
[production deployment decision](production-deployment-decision.md#decisions-deferred-to-their-own-records)).

**Contributes to.** The "key lifecycle" half of the independent-security-review
gate row.

### D2 — `client_msg_id` idempotency

**Current state.**
[`send_message`](../crates/jeliya-core/src/supervisor.rs) builds and signs a
fresh event per call. There is no client-supplied idempotency key and no
deduplication index, so a lost response followed by a client retry produces a
duplicate room event.

**Work.**

- Add a stable `client_msg_id` to the send path (caller-supplied, validated for
  shape and uniqueness).
- Persist a seen-`client_msg_id` index alongside the room store; a repeat send
  with the same id returns the originally recorded event id instead of authoring
  a new one.
- Define the index lifetime and eviction rule so dedup survives a daemon
  restart.
- Add a regression that injects 10,000 lost-response retries for the same
  `client_msg_id` and asserts exactly one room event results.

**Gate.** "10,000 injected lost-response retries produce no duplicate message".

**Blocked by.** Nothing.

### D3 — incremental timeline cursor

**Current state.** A receiver cursor is maintained across pump iterations
([supervisor.rs:2531](../crates/jeliya-core/src/supervisor.rs)), but clients
materialize the full log to render a timeline. There is no durable incremental
cursor a client can resume from.

**Work.**

- Define a durable, resumable timeline cursor keyed by room and event lamport
  order.
- Serve an incremental timeline read that returns events newer than the cursor
  plus the new cursor value.
- Prove equivalence: an incremental read from cursor zero returns the same
  ordered event set as a full-log materialization, including after disconnect,
  resync, and concurrent interleaved authoring.

**Gate.** "cursor resync matches full-log materialization".

**Blocked by.** Nothing.

### D4 — invite default expiry and cancellation

**Current state.**
[`create_invite`](../crates/jeliya-core/src/supervisor.rs) accepts an optional
expiry; absence means no expiry. [`parse_expiry`](../crates/jeliya-core/src/supervisor.rs)
parses `<int>{s|m|h|d}`. There is no `invite.cancel` RPC and no provisional-join
window closure beyond the upstream `member.invited`/`member.joined` events. The
error kinds [`TicketExpired`](../crates/jeliya-core/src/error.rs) and `BadTicket`
exist but cancellation does not surface through them today.

**Work.**

- Apply a default expiry when the caller omits one: 30 minutes for live pairing
  and no more than 24 hours for asynchronous invites, per
  [Production deployment architecture — Secure invitation links](production-deployment.md#secure-invitation-links).
- Add an `invite.cancel` RPC (owner-only) that revokes a pending invite and
  closes the provisional join window immediately.
- Make redemption close the window too: a cancelled or already-redeemed ticket
  fails on every transport with `TicketExpired` or a new `TicketCancelled`.
- Cover the negative matrix in the loopback suite: expired, cancelled, and
  already-redeemed tickets each fail on every transport they can reach.

**Gate.** "expired and cancelled tickets fail on every transport".

**Blocked by.** Nothing. Note: the current upstream pin `a5d98b70...` is already
past the `58aca4ba...` boundary the plan makes a precondition.

### D5 — companion pairing/control protocol

**Current state.** Does not exist. The change map reserves
`crates/jeliya-control/` for the pairing transcript, scoped RPC, nonce/counter
replay protection, and revocation.

**Work.**

- Implement a Noise XX-equivalent authenticated pairing transcript over Iroh
  between the browser control key and the companion, with a displayed short
  authentication string and required user confirmation on both sides.
- Record the browser public key, granted scopes, expiry, creation time, and last
  use on the companion.
- Default scopes cover selected-room reads and idempotent chat sends only;
  invite creation, `room.join` redemption (with human confirmation of the room
  being joined on a surface the browser origin cannot forge, per amendment A1
  and adopted ADR #2), file access, pipes, identity operations, and agents
  require separate approval.
- Rate-limit, expire, and allow immediate revocation of control keys.
- Enforce nonce/counter replay protection on every scoped RPC.
- Add the negative suite: replay, wrong-SAS, expired-key, and revoked-key
  attempts each fail closed.

**Gate.** "replay, wrong-SAS, expired-key, and revoked-key pairing tests fail
closed". The "wire formats" half of the independent-security-review row also
falls here.

**Blocked by.** A1 (scope model), D2 (idempotent sends), D6 (version/capability
framing), and ADR #2 ("Companion control protocol and pairing transcript";
decision deferred by the
[production deployment decision](production-deployment-decision.md#decisions-deferred-to-their-own-records)).

### D6 — protocol version and capability negotiation

**Current state.**
[`dispatch`](../crates/jeliya-core/src/engine.rs) routes RPC methods by string
match against the v1 method set; there is no version or capability handshake.
The change map reserves `crates/jeliya-protocol/` for pure protocol-v2 types,
canonical encoding, signatures, and conformance fixtures.

**Work.**

- Stand up `crates/jeliya-protocol/` with versioned protocol-v2 types and a
  canonical encoding reused by every later wire surface (control protocol,
  browser peer).
- Define a version and capability negotiation handshake that a peer runs before
  any scoped RPC, including downgrade detection.
- Produce a conformance corpus of fixtures that later phases reuse across native
  and browser clients.

**Gate.** Contributes to "independent security review approves the wire formats".

**Blocked by.** Nothing. Lands before D5 so D5's wire format is framed by it.

### D7 — surface `store_degraded` and define the operator response

**Current state.** The upstream pin `a5d98b70...` raises a durable critical
`store_degraded` decision on store-retry exhaustion or queue overflow (per
[Production deployment architecture](production-deployment.md)). The daemon does
not yet surface this decision to the operator, and no runbook exists.

**Work.**

- Surface the upstream `store_degraded` decision through `jeliya-core` to a
  visible operator signal (a derived state the UI and logs both render).
- Author `docs/runbooks/store-degraded.md` defining the operator response to
  exhausted store retries and queue overflow, including the disk-failure case
  the upstream decision does not make impossible.

**Gate.** No dedicated Phase 1 gate row; this deliverable discharges the Phase 1
deliverable bullet and feeds the Phase 3 incident-runbook gate.

**Blocked by.** Nothing. Lowest-risk item; lands first.

## Amendment A1 — bound the companion's authority to what the browser may name

A1
([Production deployment decision](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name))
blocks the Phase 1 gate. It is a design change, not a documentation change, and
must land in the scope model before D5 is specified.

**Two paths grant the browser more authority than the scope list admits:**

- `room.join` is a confused deputy.
  [`requires_room_access_preflight`](../crates/jeliya-core/src/engine.rs) in
  [`engine.rs`](../crates/jeliya-core/src/engine.rs) deliberately exempts
  `room.join`; a compromised origin can mint an identity-bound ticket into a room
  it controls and have the paired companion redeem it with the root identity's
  authority.
- The browser control key's extractability is unspecified. The proposal
  mandates non-extractability for the browser identity key (which does not exist
  in the first slice) and says nothing about the control key, which is what
  actually authorizes the companion to act.

**Required work.**

- An explicit `room.join` redemption scope with human confirmation of the room
  being joined.
- A non-extractable browser control key.
- A bounded maximum control-key lifetime, expressed as a duration rather than
  "expire".

**Blocked by.** Nothing (it is a prerequisite, not a consumer).

## Gate-condition mapping

| Phase 1 gate condition | Deliverable(s) | Notes |
|---|---|---|
| recovery succeeds from a fresh install on every supported OS | D1 | supported OS set per [platform matrix decision](platform-matrix-decision.md) |
| native production mode no longer leaves the root secret plaintext | D1 | removes the plaintext default called out at [identity.rs:5](../crates/jeliya-core/src/identity.rs) |
| 10,000 injected lost-response retries produce no duplicate message | D2 | |
| cursor resync matches full-log materialization | D3 | |
| expired and cancelled tickets fail on every transport | D4 | |
| replay, wrong-SAS, expired-key, and revoked-key pairing tests fail closed | D5 + A1 | A1 supplies the scope model; D5 the protocol |
| independent security review approves the wire formats and key lifecycle | D1, D5, D6 | D1 owns key lifecycle; D5 and D6 own wire formats |

A1 does not map to a single gate row; it is an amendment that blocks the Phase 1
gate as a whole and is a prerequisite to the D5 row.

## Open decisions this plan depends on

Two ADRs deferred by the
[production deployment decision](production-deployment-decision.md#decisions-deferred-to-their-own-records)
gate Phase 1 implementation work:

- **ADR #2 — Companion control protocol and pairing transcript.** Blocks D5.
- **ADR #3 — Recovery-bundle format, custody, and optional opaque hosting.**
  Blocks D1.

Both should land before the deliverables they block consume engineering time.
This plan does not draft them; each requires its own record under the
[documentation profile](PROFILE.md).

## Out of scope

- Phase 2 deliverables (the companion-backed vertical slice, packaging,
  recovery/re-pair UI) — see
  [Production deployment architecture](production-deployment.md), Phase 2.
- Browser-peer storage, Wasm signing, and device authorization — Phase 4.
- Code-signing procurement and notarization — deferred to the
  [post-deploy signing gate](signing-deferral-decision.md); Phases 1–5 run with
  an unsigned companion.
- Publication of a `v0.6.0` artifact — a later release-promotion action under
  explicit release authority, not a Phase 1 deliverable.

## Citations

- [Production deployment architecture](production-deployment.md) — Phase 1 deliverables, gate conditions, and the dependency-ordered roadmap.
- [Production deployment decision](production-deployment-decision.md) — amendment A1 and the deferred ADRs this plan depends on.
- [Phase 0 go/no-go gate verdict](phase-0-gate-verdict.md) — 2026-07-21 GO verdict that unlocked Phase 1.
- [Supported platform matrix decision](platform-matrix-decision.md) — fixes the supported OS set the D1 gate runs against.
- [Code-signing deferral decision](signing-deferral-decision.md) — why Phases 1–5 run unsigned.
