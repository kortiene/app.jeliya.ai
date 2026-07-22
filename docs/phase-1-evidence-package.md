---
type: "Status Report"
title: "Phase 1 evidence package and approval contract"
description: "Reproducible evidence package for Phase 1 gate row #7 (exact commands, expected results, test-to-finding mapping, threat-model cross-reference) plus the codified security-review approval contract (reviewer independence, severity taxonomy, blocking threshold, risk-owner, required artifacts, re-review rules)."
tags: ["security", "review", "phase-1", "governance", "evidence", "verification"]
timestamp: "2026-07-22T04:00:00Z"
status: "canonical"
implementation_status: "not-applicable"
verification_status: "partial"
release_status: "unreleased"
audience: ["security-reviewers", "maintainers", "release-engineers"]
---

# Phase 1 evidence package and approval contract

This document pairs two artifacts the
[findings record](phase-1-security-review.md) ([F10](phase-1-security-review.md#f10--medium-evidence-package-needs-reproducible-adversarial-coverage),
[F9](phase-1-security-review.md#f9--blocker-approval-contract-and-normative-inputs-undefined))
require before the Phase 1 gate can close:

1. **The codified approval contract** — what counts as a review, who may
   perform it, what severity blocks, and what triggers re-review.
2. **The evidence package** — exact commands, expected results,
   test-to-finding mapping, and threat-model cross-reference, so a reviewer
   who was not the implementer can reproduce the evidence base.

The [review scope](phase-1-security-review-scope.md) defines *what* is under
review; the [pin](phase-1-security-review-scope.md#review-target-pin) defines
*which tree*; this document defines *how to approve* and *what evidence to
verify*.

## Codified approval contract

### Reviewer independence

- The reviewer **must not be** the implementer of the code under review.
  For cryptographic choices (KDF parameters, AEAD construction, nonce
  handling, SAS derivation), the reviewer must have **demonstrated
  cryptography expertise**.
- The Phase 1 review recorded in the
  [findings record](phase-1-security-review.md) was conducted by **the same
  agent that implemented the code** — it does **not** satisfy the independence
  requirement. The Step 7 re-review requires a **different reviewer**.
- An agent that both implements and reviews may record findings, propose
  remediation, and draft evidence, but **cannot self-certify** the final
  approval.

### Severity taxonomy

| Tier | Meaning | Blocking? |
|---|---|---|
| Blocker | Must be resolved before any approval can be recorded; an approval with this open is not reproducible or not meaningful. | Yes — blocks approval. |
| High | A real security claim is wrong, a required control is missing, or evidence overclaims a property. | Yes — must be resolved or accepted (see below). |
| Medium | Quality, completeness, or reproducibility gap. | No — must be tracked to closure. |
| Low (informational) | Minor observation; no security impact. | No. |

### Blocking threshold

The Phase 1 gate may close only when:

- **All blockers are resolved** (the fix is merged, the doc is corrected, or
  the finding is reframed with the risk-owner's acceptance).
- **All highs are resolved** or have a documented **accepted-risk** with:
  - a named **risk-owner** (the human decision-maker);
  - an **exit criterion** (what future work closes the risk);
  - a **threat-model mapping** (which trust boundary the risk lives at).
- **No unresolved contradiction** exists between the code and the normative
  spec (ADRs #2/#3).
- The [pin](phase-1-security-review-scope.md#review-target-pin) is recorded
  against an immutable source SHA.

### Risk-owner

The **risk-owner-of-record** is the human user who decides dispositions for
product/spec choices (e.g., base32 vs hex, param-set changes, scope widening).
The implementer produces the fix; the risk-owner approves the disposition; an
independent reviewer signs off on the result.

### Required artifacts

A reviewer executing the Step 7 re-review must have:

| Artifact | Location |
|---|---|
| The pinned source tree | [Pin values](phase-1-security-review-scope.md#review-target-pin) |
| The review scope | [Phase 1 security review scope](phase-1-security-review-scope.md) |
| The findings record | [Phase 1 security review — findings record](phase-1-security-review.md) |
| The normative ADRs | [ADR #3](recovery-bundle-decision.md) (`canonical`), [ADR #2](companion-control-protocol-decision.md) (`proposal`) |
| The gate verdict | [Phase 1 gate verdict](phase-1-gate-verdict.md) |
| This evidence package | (this document) |

### Re-review rules

Any change in the pin's
[reopen set](phase-1-security-review-scope.md#reopens-review) invalidates the
approval and requires a new review pass. The re-review itself requires a
**different reviewer** from the one who approved the prior pass.

## Evidence package

### Reproduce the review

```sh
# 1. Check out the pinned source SHA (from the pin section of the scope doc).
git checkout <PINNED_SHA>

# 2. Verify Cargo.lock matches the pin.
sha256sum Cargo.lock
# Expected: <PINNED_HASH> (from the pin table)

# 3. Verify the toolchain matches (CI/release).
rustc --version   # Expected: 1.91.0 (MSRV)
node --version    # Expected: v22.22.3

# 4. Run the full gate.
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
node scripts/check-docs.mjs
node scripts/check-ui-i18n.mjs

# 5. Expected results.
# cargo fmt: no output (clean).
# cargo clippy: no warnings.
# cargo test: 125 passed, 0 failed, 1 ignored.
# check-docs: OK.
# check-ui-i18n: OK.
```

### CI runs (the authoritative build path)

The CI workflows use Rust `1.91.0` (MSRV) and Node `22.22.3`, pinned in
`ci.yml` and `release.yml`. The six required jobs are:

| Job | Scope |
|---|---|
| Rust + smoke + E2E + protocol conformance | workspace build, loopback suite, installer smoke |
| docs + TypeScript + release contracts | `check-docs.mjs`, `tsc --noEmit`, release-receipt validation |
| UI browser regression (Playwright) | Playwright browser suite |
| dependency security (Cargo + npm) | `cargo audit`, `npm audit` |
| Windows installer integrity | checksum + tamper + reparse |
| MSRV 1.91.0 | workspace build on the MSRV toolchain |

CI artifact links for the remediation PRs (all six jobs green):

| PR | Run |
|---|---|
| [#80](https://github.com/kortiene/app.jeliya.ai/pull/80) (Steps 0–1) | run `29889552405` |
| [#81](https://github.com/kortiene/app.jeliya.ai/pull/81) (Step 2) | run `29911928786` |
| [#82](https://github.com/kortiene/app.jeliya.ai/pull/82) (Step 3) | run `29913916028` |
| [#83](https://github.com/kortiene/app.jeliya.ai/pull/83) (Step 4) | run `29915796041` |
| [#84](https://github.com/kortiene/app.jeliya.ai/pull/84) (Step 5) | run `29920201448` |

### Test-to-finding mapping

| Finding | Tests / evidence | What the evidence proves | What it does NOT prove |
|---|---|---|---|
| F1 (mutable target) | [Pin section](phase-1-security-review-scope.md#review-target-pin) | The target is pinned to an immutable SHA + Cargo.lock + toolchain | Reproducibility across machines (CI is the authoritative path) |
| F2 (no control wire) | [Scope doc re-scoping](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate) | Row #7 covers the two D1 envelopes only | N/A (scope decision) |
| F3 (control core) | 8 `jeliya-control` tests (replay, SAS, expiry, revocation, scope, nonce) | State-machine unit properties pass | Does NOT prove enforcement at runtime (crate is scaffolding) |
| F4 (authority path) | [Honest-boundary statement](phase-1-security-review-scope.md#honest-boundaries-the-review-should-confirm-are-communicated); `recovery_rpc_round_trips_through_dispatch` | The authority path is documented; engine.rs + serve.rs + PROTOCOL.md are in the reopen set | Does NOT prove a same-user socket boundary is enforced |
| F5 (opt-in encryption) | `create_with_password_seals_the_secret_not_plaintext`, `load_with_a_wrong_password_fails_closed`, `load_an_encrypted_secret_without_a_password_fails_closed` | Encryption works when a password is set; fails closed on wrong/missing password | Does NOT prove production enforces it (row #2 is OPEN) |
| F6 (KDF versioning) | `v1_kdf_params_are_pinned`, `v1_legacy_dispatch_opens_a_v1_envelope_regardless_of_sealing_version`, `unknown_envelope_version_is_rejected`, `kdf_derivation_is_memory_hard` | Params are immutable per version; v1 legacy dispatch works; latency is measurable | Memory/RSS verification (Step 7 evidence); no v2 migration yet |
| F7 (lifecycle) | [Lifecycle section](phase-1-security-review-scope.md#key-lifecycle-summary-surfaces-in-scope); ADR #3 "What the bundle restores" | Re-export does not rotate; old material irrevocable | N/A (doc fix) |
| F8 (zeroize) | [Zeroize audit](phase-1-security-review-scope.md#zeroization-recast-per-f8); `aes-gcm`/`argon2` `zeroize` features enabled; `derive_kek` returns `Zeroizing`; `from_phrase` wipes `stripped` | Dependency features enabled; KEK and phrase intermediates are `Zeroizing` | Does NOT include heap inspection or measured RSS evidence (Step 7) |
| F9 (approval contract) | (this document) | Contract codified: independence, taxonomy, threshold, risk-owner, artifacts, re-review | Must be exercised by a real independent reviewer at Step 7 |
| F10 (evidence package) | (this document) | Reproducible commands, expected results, test mapping, threat-model mapping | Fuzz/property tests, cross-platform permission checks, and concurrency tests are noted as gaps below |

### Known-answer and adversarial test coverage

| Category | Tests | Status |
|---|---|---|
| Envelope round-trip | `export_then_open_round_trips_the_identity`, `create_then_load_roundtrips` | Covered |
| Wrong recovery key | `open_rejects_a_wrong_recovery_key` | Covered |
| Tampered bundle | `open_rejects_a_tampered_bundle` (flip last ciphertext byte) | Covered |
| Unknown version | `open_rejects_an_unknown_version`, `unknown_envelope_version_is_rejected` | Covered |
| Truncated bundle | `decrypt_secret_bytes` header-length check | Covered (implicit in the parse) |
| Wrong password | `load_with_a_wrong_password_fails_closed` | Covered |
| Encrypted-without-password | `load_an_encrypted_secret_without_a_password_fails_closed` | Covered |
| Seed↔profile consistency | `load_with` cross-check in identity.rs; `open_bundle` id-match in recovery.rs | Covered |
| V1 legacy dispatch | `v1_legacy_dispatch_opens_a_v1_envelope_regardless_of_sealing_version` | Covered |
| KDF param immutability | `v1_kdf_params_are_pinned` | Covered |
| KDF latency | `kdf_derivation_is_memory_hard` | Covered |
| File permissions | `files_are_owner_only`, `encrypted_secret_stays_owner_only` | Covered (Unix only) |
| Replay defense | `replayed_nonce_is_rejected`, `out_of_order_nonces_inside_the_window_are_accepted`, `nonce_below_the_window_floor_is_rejected`, `nonce_zero_is_rejected` | Covered (state machine) |
| SAS MITM detection | `sas_changes_when_either_key_is_substituted`, `sas_is_role_symmetric` | Covered (state machine) |
| Scope default-deny | `scope_is_default_deny`, `unknown_key_is_denied` | Covered (state machine) |
| Expired key | `expired_key_is_rejected` | Covered (state machine) |
| Revoked key | `revoked_key_is_rejected` | Covered (state machine) |
| Restore clobber refusal | `restore_refuses_to_clobber_an_existing_identity` | Covered |
| Test restore | `test_restore_passes_on_a_live_identity` | Covered |

### Gaps (not yet covered)

The following adversarial coverage is **not yet** in the evidence package and
should be addressed before or during the Step 7 re-review:

| Gap | Description | Severity |
|---|---|---|
| Fuzz / property tests | No `proptest` or `cargo-fuzz` harness for envelope parsing, KDF edge cases, or replay-window state | Medium |
| Cross-platform permissions | File-permission tests are Unix-only (`#[cfg(unix)]`); Windows ACL behavior is not tested locally | Medium |
| Memory/RSS verification | `kdf_derivation_is_memory_hard` measures wall-clock time only; no RSS/heap inspection to prove the configured memory target is exercised | Medium |
| Control concurrency | No test for `ControlGateway` under concurrent access (the documented invariant requires external serialization) | Low (D5b/D6 scope) |
| Max-lifetime / clock-rollback | `expired_key_is_rejected` tests a single boundary; no clock-rollback or NTP-skew property test | Low (D5b/D6 scope) |

### Threat-model cross-reference

Each finding maps to the
[Security and threat model](security-threat-model.md):

| Finding | Trust boundary | Threat-model entry |
|---|---|---|
| F4 | TB3 (native authority) + loopback daemon | "Two high-authority surfaces over one identity"; the `/api/session` forgeability (lines 226–231); `PROTOCOL.md` single-user assumption |
| F5 | TB3 (native authority) | "Root and device seeds are plaintext at rest" — the at-rest encryption is opt-in |
| F6 | TB3 (native authority) | Same row — the encryption envelope and KDF are the partial control |
| F7 | TB4 (room peers) + ADR #3 | "Does not solve revocation"; "An authorized room member can copy data already shared" |
| F8 | TB3 (endpoint compromise) | "Endpoint compromise defeats application-level key protection while an identity is in use" |

### Accepted risks

Risks that are accepted (not fixed in Phase 1) with owner and exit criterion:

| Risk | Owner | Exit criterion |
|---|---|---|
| At-rest encryption is opt-in (F5) | Risk-owner-of-record | Row #2 closes when either an enforced production invariant lands or D1c OS-keystore backends provide the enforced path |
| `jeliya-control` is scaffolding (F3) | Risk-owner-of-record | D5b/D6 review gate approves the control wire |
| Old recovery material is irrevocable (F7) | Risk-owner-of-record | Phase 4 multi-device revocation enables root authority rotation |
| Single-user-machine assumption (F4) | Risk-owner-of-record | A same-user socket boundary is enforced, or the scope is widened to include the daemon auth path |
| KEK/phrase zeroize (F8) | Implementer | Step 7 re-review verifies heap inspection or equivalent |

## Citations

- [Phase 1 security review — findings record](phase-1-security-review.md) — the 10 findings and the ordered remediation path.
- [Phase 1 security review scope](phase-1-security-review-scope.md) — what is under review (re-scoped to the two D1 envelopes) and the pin.
- [Phase 1 gate verdict](phase-1-gate-verdict.md) — row #7 is the open condition.
- [Security and threat model](security-threat-model.md) — trust boundaries, assets, threats, controls, and residual risks.
