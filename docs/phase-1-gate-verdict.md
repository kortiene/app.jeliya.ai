---
type: "Decision"
title: "Phase 1 go/no-go gate verdict"
description: "Dated verdict against each of the seven Phase 1 go/no-go gate conditions. Row #7 re-scoped to the two D1 wire envelopes (F2) and returned NOT APPROVED with 10 findings (2026-07-21); remediation in progress, blocking Phase 2. Row #2 relabeled OPEN (opt-in encryption, F5). Rows #1/#3-#6 recorded PASS with scope limits."
tags: ["phase-1", "decision", "release", "verification", "governance"]
timestamp: "2026-07-22T02:30:00Z"
status: "canonical"
implementation_status: "not-applicable"
verification_status: "partial"
release_status: "not-applicable"
audience: ["contributors", "maintainers", "release-engineers", "security-reviewers"]
---

# Phase 1 go/no-go gate verdict

**Verdict: NOT APPROVED — row #7 returned 10 findings (2026-07-21); remediation
in progress.** The [security review](phase-1-security-review.md)
landed and returned **NOT APPROVED** with 10 findings (3 blockers, 6 highs, 1
medium). **This review was conducted by an analyst who was also the Phase-1
implementer (the same agent); it is not independent, and the gate condition's
independence requirement is not satisfied.** Final row #7 sign-off requires a
different reviewer. Row #7 was [re-scoped to the two D1 wire envelopes](phase-1-security-review-scope.md)
(the at-rest `identity.secret` envelope and the recovery-bundle envelope) plus
their key lifecycle; the control-protocol wire is deferred to a
[D5b/D6 review gate](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate)
because it does not exist yet ([finding F2](phase-1-security-review.md#f2--blocker-no-control-wire-format-exists-to-approve)).
**Phase 2 may not begin** until the remediation path completes and a re-review
by a different reviewer lands.

Rows #1–#6 were recorded PASS with linked test evidence, but **row #2 is now
relabeled OPEN** (opt-in encryption is not enforced — see
[finding F5](phase-1-security-review.md#f5--high-production-encryption-is-opt-in-not-enforced)
below). The other rows' PASS claims have not been individually re-examined
against the findings record and may carry similar caveats.

Two rows pass with a stated scope limit rather than blanket: row #1 (recovery)
is verified on Linux with the OS-keystore breadth deferred to D1c, and row #5
(expired/cancelled tickets) at loopback + fold level with the live cross-transport
half pending D5b. D6 (protocol version/capability negotiation) is a Phase 1
deliverable deliberately folded into D5b — its value only emerges with the
control transport — so it has no wire format for row #7 to review yet; see
[Out of scope](#out-of-scope).

The six passing rows are satisfied by the Phase 1 implementation merged to
`main` as `cdcae83…` (pull request #78), verified by the local test suite and
the daemon-only six-job CI matrix (run `29868870066`, all green). They are
**local/unit evidence**, not the network qualification a *release* requires:
`cdcae83` is past the network-qualified pre-Phase-1 pair `922f620…` +
`a5d98b70…`, so a release at `cdcae83` additionally needs fresh signed
direct/relay runs. This record advances no release status.

## Candidate under verdict

| Field | Value |
|---|---|
| Jeliya source candidate | `cdcae8397700be792f4efea2a387ea60af65e232` (`main`; PR #78 on `922f620…`) |
| Pre-Phase-1 network-qualified candidate | `922f620b30ee95c82426a7d4404b1f73a70c0958` (signed direct `098c4979` + relay `8bda01e6` bind this pair; does not transfer to `cdcae83`) |
| Iroh Rooms pin | `a5d98b70d717f35d3ce60953a88e12e646f2e871` (unchanged from the pre-Phase-1 candidate) |
| Verdict date (UTC) | 2026-07-21 |

## The gate conditions

The plan's Phase 1 go/no-go gate lists seven conditions. Each is evaluated below.

### 1. Recovery succeeds from a fresh install on every supported OS — PASS (Linux; OS-keystore breadth pending D1c)

`recovery::restore_to_dir_reproduces_a_loadable_identity_in_a_fresh_install`
([recovery.rs](../crates/jeliya-core/src/recovery.rs)) exports an identity, then
imports the bundle into a fresh data dir and asserts the loaded identity's ids
match. `recovery_rpc_round_trips_through_dispatch`
([engine.rs](../crates/jeliya-core/src/engine.rs)) proves the same through the
`recovery.export` / `recovery.restore` / `recovery.test_restore` RPCs. The
supported-OS breadth is the OS-keystore lane (D1c, deferred): the
password-hardened encrypted-file backend runs everywhere and is verified here on
Linux; Keychain / DPAPI / Secret Service land in their hosted lanes.

### 2. Native production mode no longer leaves the root secret plaintext — OPEN (opt-in, not enforced)

**Relabeled from PASS per [finding F5](phase-1-security-review.md#f5--high-production-encryption-is-opt-in-not-enforced).**
The at-rest encryption exists and works:
`create_with_password_seals_the_secret_not_plaintext`
([identity.rs](../crates/jeliya-core/src/identity.rs)) asserts an identity
created under `JELIYA_IDENTITY_PASSWORD` writes a sealed file, and
`load_with_a_wrong_password_fails_closed` /
`load_an_encrypted_secret_without_a_password_fails_closed` confirm fail-closed
behavior. **But encryption is opt-in, not enforced.** Unset or empty
`JELIYA_IDENTITY_PASSWORD` → plaintext `0600` with only `tracing::warn!`. No
packaging, systemd unit, launchd plist, or startup path sets or requires the
variable. The onboarding flow
([`ui/src/components/Onboarding.tsx`](../ui/src/components/Onboarding.tsx))
calls `identity.create` with no password, so a production deployment following
the docs as written ships plaintext root seeds. The gate condition is **not
met**. To close it: either (a) define an enforced production invariant (refuse
`identity.create` / `recovery.restore` without protected storage, with a
documented dev override), or (b) accept encryption as opt-in and keep this row
open until the OS-keystore backends (D1c) provide the enforced path.

### 3. 10,000 injected lost-response retries produce no duplicate message — PASS

`message_send_with_client_msg_id_dedupes_10k_lost_response_retries`
([supervisor.rs](../crates/jeliya-core/src/supervisor.rs)) sends once with a
`client_msg_id`, retries 10,000 times with the same id, and asserts the timeline
holds exactly one message. `message_send_client_msg_id_survives_restart` proves
the durable index survives a daemon restart.

### 4. Cursor resync matches full-log materialization — PASS

`timeline_after_returns_the_exact_suffix_matching_full_materialization`,
`timeline_after_pages_through_matching_full_materialization`, and
`timeline_after_concurrent_interleaved_authoring_matches_full`
([supervisor.rs](../crates/jeliya-core/src/supervisor.rs)) page a settled log —
including one built with concurrent interleaved authoring — and assert the
concatenation equals the full materialization suffix in canonical
`(lamport, event_id)` order.

### 5. Expired and cancelled tickets fail on every transport — PASS (loopback + fold-level; live cross-transport pending D5b)

`expired_invite_join_fails_with_ticket_expired` proves an expired ticket is
rejected before any network IO (the ticket's signed `expires_at`).
`invite_cancel_authors_member_removed_and_marks_invitee_removed` and
`cancelled_invite_cannot_be_redeemed_by_the_membership_fold`
([supervisor.rs](../crates/jeliya-core/src/supervisor.rs)) prove a cancelled
invite (owner-authored `member.removed`) is rejected by the membership fold's
`departure_consumes` rule with `expired_invite` (`ticket_expired`) once the
signed cancellation reaches the redeeming peer.

### 6. Replay, wrong-SAS, expired-key, and revoked-key pairing tests fail closed — PASS (state machine)

`replayed_nonce_is_rejected`, `wrong_sas_yields_no_record`,
`expired_key_is_rejected`, and `revoked_key_is_rejected`
([jeliya-control/src/lib.rs](../crates/jeliya-control/src/lib.rs)) exercise the
control-protocol gateway directly. Plus `scope_is_default_deny` (A1),
`out_of_order_nonces_inside_the_window_are_accepted`,
`nonce_below_the_window_floor_is_rejected`, and the SAS MITM-detection
properties.

**Honest boundary:** the four assertions pass at the control-protocol *state
machine* — **which is scaffolding, not a security boundary**
([finding F3](phase-1-security-review.md#f3--high-jeliya-control-core-does-not-enforce-the-attributed-properties)).
The crate provides types and checks a correct host *could* enforce, but nothing
in it forces enforcement: `install`/`ControlKeyRecord::new` bypass SAS and
lifetime; `authorize` trusts caller-supplied time; there is no rate limiting;
scopes are global not per-room. The Noise wire transport, browser Wasm side,
and daemon wiring that would bind these checks to a real session are **Phase 2
(D5b)**, under the [D5b/D6 review gate](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate).

### 7. Independent security review approves the wire formats and the key lifecycle — NOT APPROVED (remediation in progress)

**The review landed 2026-07-21 and returned NOT APPROVED with 10 findings**
(3 blockers, 6 highs, 1 medium). The full findings record, severity taxonomy,
and ordered remediation path live in
[Phase 1 security review — findings record](phase-1-security-review.md). **The
review was conducted by the Phase-1 implementer (same agent), not an independent
reviewer; the gate condition names independence as a requirement, and that
requirement is not satisfied until the Step 7 re-review by a different
reviewer lands.**

Row #7 was [re-scoped per finding F2](phase-1-security-review-scope.md) to the
**two D1 wire envelopes only** — the at-rest encryption envelope and Argon2id
parameters ([identity.rs](../crates/jeliya-core/src/identity.rs)), and the
recovery-bundle AEAD and key handling ([recovery.rs](../crates/jeliya-core/src/recovery.rs))
— plus their key lifecycle. The control-protocol surface
([jeliya-control](../crates/jeliya-control/src/lib.rs)) has no wire format to
review and is deferred to the
[D5b/D6 review gate](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate).

The remediation is in progress (Steps 0–1 complete; Steps 2–7 tracked in the
[findings record](phase-1-security-review.md#remediation-path)). Until it
completes and a re-review by a **different reviewer** (especially for the
cryptographic choices) lands, the Phase 1 gate is not closed and Phase 2 is
blocked.

## Amendment A1 is in scope but lands with D5

[Amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name)
(the browser control key's authority boundary) is binding on the Phase 1 gate.
Its design is recorded in [ADR #2](companion-control-protocol-decision.md)
(non-extractable key, bounded lifetime, default-deny scopes, `room.join`
redemption with human confirmation) and the default-deny scope model is
implemented in `crates/jeliya-control`. The `room.join` redemption-confirmation
half of A1 is a transport-layer concern and lands with D5b (Phase 2); it is not
a Phase 1 gate condition separate from row #6/#7.

## D6 is a Phase 1 deliverable folded into D5b

D6 (protocol version and capability negotiation) is named as a Phase 1
deliverable in the [Phase 1 implementation plan](phase-1-plan.md). It was
deliberately folded into D5b rather than built standalone: a version/capability
handshake has no consumer until the companion control transport exists, so
building it ahead of D5 would produce unconsumed scaffolding. The consequence
this record states plainly: Phase 1's deliverable tally is **D1, D2, D3, D4,
D5a, D7 done; D6 deferred into D5b (Phase 2)** — not "seven of seven". D6's wire
format therefore does not exist for row #7 to review. **Re-scoped per F2**:
row #7 covers the two D1 envelopes only (the at-rest `identity.secret`
envelope and the recovery-bundle envelope); the control-protocol state machine
has no wire format either, and its review is deferred to the
[D5b/D6 gate](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate).

## Out of scope

- **D1c** (OS keystore backends: Keychain / DPAPI / Secret Service) and **D5b**
  (control-protocol wire transport + browser Wasm + daemon wiring) are Phase 2
  lanes, not Phase 1 gate conditions. Row #1 passes via the password-hardened
  fallback; row #6 passes at the **state-machine unit-test level only** — the
  crate is [scaffolding](phase-1-security-review.md#f3--high-jeliya-control-core-does-not-enforce-the-attributed-properties),
  not an enforced boundary.
- **Network qualification at `cdcae83`** is a *release* gate, not a Phase 1 gate
  condition. `cdcae83` is past the network-qualified `922f620…` pair, so fresh
  signed direct/relay runs are required for any release here.
- **Publication of a `v0.6.0` artifact** is a later release-promotion action
  under explicit release authority.

## What this record authorizes

None beyond recording the verdict. Phase 2 implementation is blocked on row #7.
The review landed 2026-07-21 and returned NOT APPROVED; the remediation path is
tracked in the [findings record](phase-1-security-review.md#remediation-path).
When the remediation completes and a re-review by a different reviewer approves
the two D1 wire formats and key lifecycle (or records conditions), this record
updates to GO and Phase 2 may begin.

## Citations

- [Phase 1 security review — findings record](phase-1-security-review.md) — the NOT APPROVED verdict, 10 findings, and the ordered remediation path.
- [Phase 1 security review scope](phase-1-security-review-scope.md) — the re-scoped review package for row #7 (two D1 envelopes; control deferred to D5b/D6).
- [Production deployment architecture](production-deployment.md) — Phase 1 deliverables, gate conditions, and the dependency-ordered roadmap.
- [Phase 1 implementation plan](phase-1-plan.md) — the sequenced deliverables this verdict evaluates.
- [Phase 0 go/no-go gate verdict](phase-0-gate-verdict.md) — the 2026-07-21 GO that unlocked Phase 1.
- [Release versus main](release-vs-main.md) — the `cdcae83` / `922f620…` boundary and the evidence non-transfer.
