---
type: "Decision"
title: "Phase 1 go/no-go gate verdict"
description: "Dated verdict against each of the seven Phase 1 go/no-go gate conditions. GO recorded 2026-07-22: the risk-owner-of-record countersigned the Step 7 APPROVE-WITH-CONDITIONS re-review against candidate df28f6a; Phase 2 may begin. Row #2 remains OPEN as an accepted risk (opt-in encryption, F5); verdict conditions tracked; no release status advanced."
tags: ["phase-1", "decision", "release", "verification", "governance"]
timestamp: "2026-07-22T17:06:00Z"
status: "canonical"
implementation_status: "not-applicable"
verification_status: "partial"
release_status: "not-applicable"
audience: ["contributors", "maintainers", "release-engineers", "security-reviewers"]
---

# Phase 1 go/no-go gate verdict

**Verdict: GO — recorded 2026-07-22 with the risk-owner's countersignature
(see [GO decision](#go-decision--risk-owner-countersignature-2026-07-22));
Phase 2 may begin.** The original
[security review](phase-1-security-review.md) (2026-07-21, by the implementer —
not independent) returned **NOT APPROVED** with 10 findings (3 blockers, 6
highs, 1 medium); the remediation path (Steps 0–6) completed, and the
**Step 7 independent re-review landed 2026-07-22 with
[APPROVE-WITH-CONDITIONS](phase-1-security-review.md#step-7-re-review-verdict-2026-07-22)**
against pin `df28f6a` (no blocker or high confirmed; 2 medium + 10 low/info
conditions tracked; independence caveat stated in the verdict). Row #7 remains
[re-scoped to the two D1 wire envelopes](phase-1-security-review-scope.md)
(the at-rest `identity.secret` envelope and the recovery-bundle envelope) plus
their key lifecycle; the control-protocol wire is deferred to a
[D5b/D6 review gate](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate)
because it does not exist yet ([finding F2](phase-1-security-review.md#f2--blocker-no-control-wire-format-exists-to-approve)).
**The risk-owner-of-record countersigned 2026-07-22 and Phase 2 may begin**
(row #2 remains OPEN as an accepted risk with an exit criterion; the verdict's
conditions stay tracked) — see the
[GO decision](#go-decision--risk-owner-countersignature-2026-07-22).

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
the daemon-only six-job CI matrix (run `29868870066` — a `pull_request` run at
the PR #78 branch head `e9f1ed5`, all green), and
re-verified at the row #7 re-review pin `df28f6a` (push run `29922951249`, all
green) and at the delta-reviewed conditions tree `d610076` (push run
`29951799090`, all green — see the candidate table below). They are **local/unit evidence**, not
the network qualification a *release* requires: these SHAs are past the
network-qualified pre-Phase-1 pair `922f620…` + `a5d98b70…`, so a release at
the current `dcd940e` candidate additionally needs fresh signed direct/relay
runs. This record advances no release status.

## Candidate under verdict

| Field | Value |
|---|---|
| Jeliya source candidate (rows #1–#6, original verdict) | `cdcae8397700be792f4efea2a387ea60af65e232` (`main`; PR #78 on `922f620…`) |
| Jeliya source candidate (row #7 re-review pin) | `df28f6a15c6c154c0759eea76b2c164c41c047bc` (`main`; PR #85 — the [review target pin](phase-1-security-review-scope.md#review-target-pin)) |
| Pre-Phase-1 network-qualified candidate | `922f620b30ee95c82426a7d4404b1f73a70c0958` (signed direct `098c4979` + relay `8bda01e6` bind this pair; does not transfer to later SHAs) |
| Iroh Rooms pin | `a5d98b70d717f35d3ce60953a88e12e646f2e871` (unchanged from the pre-Phase-1 candidate) |
| Conditions tree (delta-reviewed) | `d610076c05f0f29cb8f87c7dbe805a5f603ecc89` (`main`; PR #89 — the [Step 7 verdict conditions](phase-1-security-review.md#step-7-re-review-verdict-2026-07-22); the `df28f6a` approval [extends to it](phase-1-security-review.md#conditions-delta-review-2026-07-22)) |
| Final pin (micro-delta-reviewed) | `dcd940e65a74b3596a9d8defacfc4946aedabd7d` (`main`; PR #90 — the `from_phrase` fixed-buffer hardening; the approval [extends to it](phase-1-security-review.md#conditions-delta-review-2026-07-22)) |
| Verdict dates (UTC) | rows #1–#6: 2026-07-21 (at `cdcae83`; test evidence re-verified green at `df28f6a`, push run `29922951249`); row #7: 2026-07-22 (at `df28f6a`; extended to `d610076` by the conditions delta review the same day) |

**Single candidate for the GO decision: `df28f6a`.** The reviewed crypto
surfaces changed between `cdcae83` and `df28f6a` (remediation Steps 5–6
touched `identity.rs`/`recovery.rs` and `Cargo.lock`), so the rows #1–#6 test
evidence recorded at `cdcae83` is carried to `df28f6a` by the full six-job CI
matrix running green there (push run `29922951249`; also at the docs-only
`5fa0bae` HEAD, push run `29928189003`; run IDs corrected 2026-07-22 per the
[delta-review erratum](phase-1-security-review.md#conditions-delta-review-2026-07-22))
— the same suites, including every test the row verdicts cite. A risk-owner
countersigning this record countersigns `df28f6a`; the approval was
subsequently extended to the conditions tree `d610076` by the
[conditions delta review](phase-1-security-review.md#conditions-delta-review-2026-07-22)
(push run `29951799090` green there) and to the final pin `dcd940e` by the
PR #90 micro-delta review.

## GO decision — risk-owner countersignature (2026-07-22)

**Decision: GO. Phase 2 implementation may begin.**

| Field | Value |
|---|---|
| Decision | GO |
| Candidate countersigned | `df28f6a15c6c154c0759eea76b2c164c41c047bc` |
| Risk-owner-of-record | Sekou (the human decision-maker named by the [approval contract](phase-1-evidence-package.md#codified-approval-contract)) |
| Recorded | 2026-07-22, on the risk-owner's explicit directive ("record GO") in the Step 7 review session |

By countersigning, the risk-owner accepts:

- The [Step 7 re-review verdict](phase-1-security-review.md#step-7-re-review-verdict-2026-07-22)
  of APPROVE-WITH-CONDITIONS, **including its reviewer-independence caveat**
  (the re-reviewer was a different agent session than the implementer but the
  same model family).
- **Row #2 remaining OPEN** as an accepted risk (opt-in at-rest encryption,
  F5) with its exit criterion (enforced production invariant or D1c
  OS-keystore backends).
- The verdict's **seven conditions remaining open and tracked** (none
  blocking); landing conditions 1–6 (and 7's error-kind half) reopens the pin
  and requires a scoped delta review.
- The other accepted risks as recorded in the
  [accepted-risk register](phase-1-evidence-package.md#accepted-risks)
  (F3 scaffolding, F7 irrevocable old recovery material, F4 single-user
  assumption, env-var password).

The GO authorizes **Phase 2 implementation only**. It advances no release
status: a release still requires fresh network qualification (signed
direct/relay runs) past `df28f6a`, and the control-protocol wire remains
gated by the
[D5b/D6 review](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate).

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

### 7. Independent security review approves the wire formats and the key lifecycle — APPROVE-WITH-CONDITIONS (re-review landed 2026-07-22)

**The Step 7 re-review landed 2026-07-22 and returned APPROVE-WITH-CONDITIONS**
against pin `df28f6a` — see the
[Step 7 re-review verdict](phase-1-security-review.md#step-7-re-review-verdict-2026-07-22)
for the reviewer identity, the reproduced evidence (125/0/1 test gate, measured
Argon2id RSS 19.06 MiB / ~41 ms, zeroize features verified), the 12 confirmed
findings (no blocker, no high; 2 medium evidence-quality overclaims + 10
low/info), and the 7 tracked conditions. **Independence caveat:** the reviewer
was a different agent session than the implementer/analyst but the same model
family; a countersignature by the human risk-owner-of-record is recommended
before the gate-level GO decision.

The original review landed 2026-07-21 and returned NOT APPROVED with 10
findings (3 blockers, 6 highs, 1 medium); the full findings record, severity
taxonomy, and ordered remediation path live in
[Phase 1 security review — findings record](phase-1-security-review.md). That
review was conducted by the Phase-1 implementer (same agent) and did not
satisfy the independence requirement; the 2026-07-22 re-review above is the
independent pass.

Row #7 was [re-scoped per finding F2](phase-1-security-review-scope.md) to the
**two D1 wire envelopes only** — the at-rest encryption envelope and Argon2id
parameters ([identity.rs](../crates/jeliya-core/src/identity.rs)), and the
recovery-bundle AEAD and key handling ([recovery.rs](../crates/jeliya-core/src/recovery.rs))
— plus their key lifecycle. The control-protocol surface
([jeliya-control](../crates/jeliya-control/src/lib.rs)) has no wire format to
review and is deferred to the
[D5b/D6 review gate](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate).

The remediation path (Steps 0–7) is **complete**: the pin was finalized against
`df28f6a` and the re-review landed 2026-07-22 with the verdict above. Row #7's
independence requirement is satisfied subject to the stated caveat. The
gate-level GO decision was **recorded 2026-07-22 with the risk-owner's
countersignature** — see the
[GO decision](#go-decision--risk-owner-countersignature-2026-07-22).

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

**Phase 2 implementation.** The Step 7 re-review recorded
APPROVE-WITH-CONDITIONS for the two D1 wire formats and key lifecycle
(2026-07-22); the risk-owner-of-record countersigned the same day and the
[GO decision](#go-decision--risk-owner-countersignature-2026-07-22) is
recorded above. The verdict's conditions stay tracked in the
[verdict record](phase-1-security-review.md#step-7-re-review-verdict-2026-07-22).
Nothing else is authorized: no release status advances (fresh network
qualification is still required past `df28f6a`), and the control-protocol
wire remains gated by the D5b/D6 review.

## Citations

- [Phase 1 security review — findings record](phase-1-security-review.md) — the NOT APPROVED verdict, 10 findings, and the ordered remediation path.
- [Phase 1 security review scope](phase-1-security-review-scope.md) — the re-scoped review package for row #7 (two D1 envelopes; control deferred to D5b/D6).
- [Production deployment architecture](production-deployment.md) — Phase 1 deliverables, gate conditions, and the dependency-ordered roadmap.
- [Phase 1 implementation plan](phase-1-plan.md) — the sequenced deliverables this verdict evaluates.
- [Phase 0 go/no-go gate verdict](phase-0-gate-verdict.md) — the 2026-07-21 GO that unlocked Phase 1.
- [Release versus main](release-vs-main.md) — the `cdcae83` / `922f620…` boundary and the evidence non-transfer.
