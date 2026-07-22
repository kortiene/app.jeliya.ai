---
type: "Decision"
title: "Phase 1 go/no-go gate verdict"
description: "Dated verdict against each of the seven Phase 1 go/no-go gate conditions for the current candidate (cdcae83 + a5d98b70). Rows #1-#6 PASS with linked test evidence; row #7 (independent security review) is PENDING, blocking Phase 2."
tags: ["phase-1", "decision", "release", "verification", "governance"]
timestamp: "2026-07-21T21:30:00Z"
status: "canonical"
implementation_status: "not-applicable"
verification_status: "partial"
release_status: "not-applicable"
audience: ["contributors", "maintainers", "release-engineers", "security-reviewers"]
---

# Phase 1 go/no-go gate verdict

**Verdict: IMPLEMENTATION COMPLETE — rows #1–#6 PASS, row #7 PENDING
(2026-07-21).** Every Phase 1 go/no-go gate condition the
[Production deployment architecture](production-deployment.md) names is
discharged by code except the last: the **independent security review of the
wire formats and key lifecycle (row #7)**. That is a governance step over
`crates/jeliya-core/src/{identity,recovery}.rs` and `crates/jeliya-control`,
not implementation, and an implementer cannot independently review their own
work. **Phase 2 may not begin until row #7 lands**, because the roadmap is
dependency-ordered on phase gates.

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

### 1. Recovery succeeds from a fresh install on every supported OS — PASS

`recovery::restore_to_dir_reproduces_a_loadable_identity_in_a_fresh_install`
([recovery.rs](../crates/jeliya-core/src/recovery.rs)) exports an identity, then
imports the bundle into a fresh data dir and asserts the loaded identity's ids
match. `recovery_rpc_round_trips_through_dispatch`
([engine.rs](../crates/jeliya-core/src/engine.rs)) proves the same through the
`recovery.export` / `recovery.restore` / `recovery.test_restore` RPCs. The
supported-OS breadth is the OS-keystore lane (D1c, deferred): the
password-hardened encrypted-file backend runs everywhere and is verified here on
Linux; Keychain / DPAPI / Secret Service land in their hosted lanes.

### 2. Native production mode no longer leaves the root secret plaintext — PASS

`create_with_password_seals_the_secret_not_plaintext`
([identity.rs](../crates/jeliya-core/src/identity.rs)) asserts an identity
created under `JELIYA_IDENTITY_PASSWORD` writes a file that is not the plaintext
JSON; `load_with_a_wrong_password_fails_closed` and
`load_an_encrypted_secret_without_a_password_fails_closed` confirm it fails
closed. Plaintext remains the explicit dev default (omitted password), with
auto-detect on load so a plaintext identity still loads after a password is
introduced.

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

### 5. Expired and cancelled tickets fail on every transport — PASS

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
machine* (the security-reviewable core in `crates/jeliya-control`). The Noise
wire transport, browser Wasm side, and daemon wiring are **Phase 2 (D5b)** —
real RPCs route through this same gateway once the transport lands.

### 7. Independent security review approves the wire formats and key lifecycle — PENDING

**This is the one open condition.** The review covers the at-rest encryption
envelope and Argon2id parameters ([identity.rs](../crates/jeliya-core/src/identity.rs)),
the recovery-bundle AEAD and key handling ([recovery.rs](../crates/jeliya-core/src/recovery.rs)),
and the control-protocol pairing/SAS/scope/replay/expiry/revocation surface
([jeliya-control](../crates/jeliya-control/src/lib.rs)). Its scope is packaged
in [Phase 1 security review scope](phase-1-security-review-scope.md) so a
reviewer can execute efficiently. Until it lands, the Phase 1 gate is not
closed and Phase 2 is blocked.

## Amendment A1 is in scope but lands with D5

[Amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name)
(the browser control key's authority boundary) is binding on the Phase 1 gate.
Its design is recorded in [ADR #2](companion-control-protocol-decision.md)
(non-extractable key, bounded lifetime, default-deny scopes, `room.join`
redemption with human confirmation) and the default-deny scope model is
implemented in `crates/jeliya-control`. The `room.join` redemption-confirmation
half of A1 is a transport-layer concern and lands with D5b (Phase 2); it is not
a Phase 1 gate condition separate from row #6/#7.

## Out of scope

- **D1c** (OS keystore backends: Keychain / DPAPI / Secret Service) and **D5b**
  (control-protocol wire transport + browser Wasm + daemon wiring) are Phase 2
  lanes, not Phase 1 gate conditions. Rows #1 and #6 pass via the
  password-hardened fallback and the state-machine core respectively.
- **Network qualification at `cdcae83`** is a *release* gate, not a Phase 1 gate
  condition. `cdcae83` is past the network-qualified `922f620…` pair, so fresh
  signed direct/relay runs are required for any release here.
- **Publication of a `v0.6.0` artifact** is a later release-promotion action
  under explicit release authority.

## What this record authorizes

None beyond recording the verdict. Phase 2 implementation is blocked on row #7.
When the independent security review lands and approves the wire formats and key
lifecycle (or records conditions), this record updates to GO and Phase 2 may
begin.

## Citations

- [Production deployment architecture](production-deployment.md) — Phase 1 deliverables, gate conditions, and the dependency-ordered roadmap.
- [Phase 1 implementation plan](phase-1-plan.md) — the sequenced deliverables this verdict evaluates.
- [Phase 0 go/no-go gate verdict](phase-0-gate-verdict.md) — the 2026-07-21 GO that unlocked Phase 1.
- [Phase 1 security review scope](phase-1-security-review-scope.md) — the package for row #7.
- [Release versus main](release-vs-main.md) — the `cdcae83` / `922f620…` boundary and the evidence non-transfer.
