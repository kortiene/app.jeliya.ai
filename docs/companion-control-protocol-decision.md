---
type: "Decision"
title: "Companion control protocol and pairing transcript — decision record"
description: "Proposes the mutually-authenticated, end-to-end-encrypted browser-to-companion control protocol (Noise XX-equivalent over the Iroh control ALPN), the SAS-confirmed pairing transcript, the non-extractable bounded-lifetime browser control key, the default-deny scope model, replay defense, and revocation, so Phase 1 deliverable D5 can be implemented under amendment A1."
tags: ["protocol", "pairing", "companion", "security", "decision", "phase-1", "amendment-a1"]
timestamp: "2026-07-21T17:00:00Z"
status: "proposal"
implementation_status: "planned"
verification_status: "not-applicable"
release_status: "unreleased"
audience: ["contributors", "maintainers", "security-reviewers"]
---

# Companion control protocol and pairing transcript — decision record

**Status: PROPOSED — not yet adopted.** This record is ADR #2 from the
[production deployment decision](production-deployment-decision.md#decisions-deferred-to-their-own-records),
settling the companion control protocol and pairing transcript so that Phase 1
deliverable D5 (see
[Phase 1 implementation plan — D5](phase-1-plan.md#d5--companion-pairingcontrol-protocol))
can be specified and implemented. It is shaped by
[Production deployment architecture — Browser-to-companion pairing](production-deployment.md#browser-to-companion-pairing)
and is bound by
[amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name),
which fixes the browser-control-key authority boundary this protocol must enforce.

Adoption advances D5 from "blocked on its ADR" to "implementable". The D5 gate
("replay, wrong-SAS, expired-key, and revoked-key pairing tests fail closed")
still requires the implementation and its tests, and the wire formats here are
subject to the Phase 1 independent security review.

## Decision

1. **Transport.** The control protocol runs over a dedicated Iroh ALPN on a
   mutually authenticated, end-to-end-encrypted connection. The companion
   listens loopback + an Iroh endpoint; the browser reaches it through an
   authenticated relay (proven by the
   [Phase 0 relay-connect spike](evidence/phase-0-relay-spike.md)). The companion
   never exposes a public HTTP/WS listener and never hands a browser the daemon
   token (see [Why the loopback daemon must not be public](production-deployment.md#why-the-loopback-daemon-must-not-be-public)).

2. **Handshake.** A Noise **XX**-equivalent handshake (3-flight, mutual static
   authentication, forward secrecy, identity hiding for the initiator) establishes
   a session. The companion's static key is its long-lived pairing identity; the
   browser's static key is the per-pairing **control key**. The handshake output
   is a session key + a transcript hash.

3. **Bootstrap is not a bearer.** The companion displays a QR / custom-protocol
   link carrying its ephemeral rendezvous — endpoint, a fresh nonce, and the
   companion static-key fingerprint — never a reusable secret. The browser
   connects, runs the handshake, and then both sides derive the SAS from the
   transcript hash.

4. **SAS confirmation is gating.** A ~30-bit short authentication string (two
   5-digit groups) is shown on both sides; the user must confirm on both before
   the companion records the control key. No scoped RPC is accepted until the SAS
   is confirmed. A wrong SAS aborts the pairing; the gate's "wrong-SAS … fail
   closed" row is this check.

5. **The control key is non-extractable and bounded (amendment A1).** The
   browser generates its static control key with WebCrypto `{extractable: false}`.
   The companion records, per control key: the public key, the granted scopes, a
   creation time, a **bounded maximum lifetime expressed as a duration** (default
   30 days, configurable), and a last-use time. An extractable control key would
   make a single origin compromise permanent and off-origin; the lifetime bound
   makes compromise recoverable by waiting, and revocation (below) makes it
   immediate.

6. **Default-deny scope model (amendment A1).** A control key grants nothing by
   default. The first slice defines exactly these scopes:
   - `room.read` — read the selected room's timeline/members (the rooms the user
     explicitly opened through the companion).
   - `message.send` — send chat in a selected room, **idempotent** through
     `client_msg_id` (Phase 1 D2).
   Everything else — `invite.*`, `file.*`, `pipe.*`, `identity.*`, `agent.*`,
   `room.leave`, and **`room.join`** — requires a separate, individually approved
   scope. `room.join` is the confused-deputy A1 calls out: redeeming a ticket
   with the root identity's authority requires **human confirmation of the room
   being joined**, not just a granted scope.

7. **Replay defense.** Every scoped RPC carries a client-chosen nonce and a
   session counter. The companion tracks the counter (monotonic) plus a bounded
   replay window for out-of-order delivery, and rejects any replay or regression.
   The "replay … fail closed" gate row is this check.

8. **Rate limiting.** The companion rate-limits handshakes, RPCs, and bytes per
   control key, and fails closed on sustained violation (drop the session, not
   just the frame).

9. **Revocation.** The companion can revoke a control key immediately; it leaves
   the active set, future RPCs under it fail closed, and any in-flight session is
   torn down. The "revoked-key … fail closed" gate row is this check. Revocation
   is local to the companion (it stops accepting the key); it cannot recall
   actions already authorized before revocation reached the session.

10. **Wire format is deferred to D5.** This ADR settles the security semantics
    (mutual auth, non-extractability, lifetime, scopes, replay, revocation, SAS).
    D5 picks the versioned framing bytes and registers the ALPN, subject to the
    independent security review.

## What this protocol does not do

- **It does not make a browser a room peer.** Companion mode keeps the room
  runtime native; the browser is a scoped controller. A browser-resident room
  peer is Phase 4, on its own gates.
- **It does not recall already-authorized work.** A revoked key stops future
  RPCs; messages already signed and published remain in the signed room log
  (trust boundary TB4).
- **It does not replace the daemon token.** The companion holds the root
  identity; the browser control key is a narrow, revocable grant over the
  companion's surface, never the daemon's loopback token.

## Open questions for adoption

- **Control-key lifetime default.** 30 days is proposed (recoverable by waiting,
  short enough to bound a stale key). A shorter default (e.g. 7 days) raises
  re-pair friction; a longer one weakens the bound. Left for the reviewer.
- **`room.join` confirmation surface.** Whether the human confirmation is a
  companion-side prompt (native dialog) or a browser-side confirmation that the
  companion double-checks. A1 requires the confirmation; this ADR leaves the UX
  surface to D5, subject to the accessibility gate (amendment A5, Phase 2).
- **Replay window size.** Bounded (e.g. 64 frames) for out-of-order delivery; the
  exact bound is an implementation parameter, not a security property, as long as
  it is bounded.

## Consequences

- D5 becomes implementable in `crates/jeliya-control/` (see the
  [repository change map](production-deployment.md#repository-change-map)) against
  this ADR and under A1. The crate owns the pairing transcript, scoped RPC,
  nonce/counter replay protection, and revocation.
- The Phase 1 D5 gate's four negative assertions (replay, wrong-SAS, expired-key,
  revoked-key) map directly to decisions 4, 5, 7, and 9 above.
- The default-deny scope model (decision 6) is a design change in the engine's
  scope surface, so A1's scope-model work lands alongside D5, not after it.
- This ADR adds no new trust boundary: it instantiates the companion authority
  boundary TB3 already stated in the
  [target system](production-deployment.md#target-system-and-trust-boundaries).

## Citations

- [Production deployment architecture — Browser-to-companion pairing](production-deployment.md#browser-to-companion-pairing) - the pairing design this ADR instantiates.
- [Production deployment decision — amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name) - the browser-authority boundary binding this protocol.
- [Production deployment decision — Decisions deferred](production-deployment-decision.md#decisions-deferred-to-their-own-records) - ADR #2 in the deferred-decisions list.
- [Phase 1 implementation plan — D5](phase-1-plan.md#d5--companion-pairingcontrol-protocol) - the deliverable this unblocks.
- [Phase 0 relay-connect spike result](evidence/phase-0-relay-spike.md) - the browser-to-native Iroh connectivity this protocol rides on.
