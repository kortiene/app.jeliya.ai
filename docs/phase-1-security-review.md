---
type: "Status Report"
title: "Phase 1 security review — findings record"
description: "Durable record of the Phase 1 security review: NOT APPROVED with 10 findings (3 blockers, 6 highs, 1 medium), the ordered remediation path (Steps 0–6 complete), and the Step 7 re-review verdict of 2026-07-22: APPROVE-WITH-CONDITIONS against pin df28f6a by an independent review session (no blocker/high; 2 medium + 10 low/info conditions tracked)."
tags: ["security", "review", "phase-1", "governance", "cryptography", "identity", "control-protocol"]
timestamp: "2026-07-22T15:07:00Z"
status: "canonical"
implementation_status: "not-applicable"
verification_status: "partial"
release_status: "unreleased"
audience: ["security-reviewers", "maintainers", "release-engineers", "contributors"]
---

# Phase 1 security review — findings record

**Verdict: NOT APPROVED — 2026-07-21.** A security review of Phase 1 returned
**10 findings: 3 blockers, 6 highs, 1 medium.** This record is the durable,
in-repo copy of those findings so they survive outside any chat transcript. It
is the **authoritative input** for the Phase 1 remediation; it supersedes the
prior implementer self-review, which had recommended APPROVE-WITH-CONDITIONS.

**This review is NOT independent.** The analyst who produced these findings was
also the Phase-1 implementer (the same agent that wrote the code under review).
The [Phase 1 gate](phase-1-gate-verdict.md) row #7 is named "independent
security review approves the wire formats and key lifecycle" — that is the
*target*, not a property of this artifact. Final row #7 sign-off requires a
**different reviewer**, especially for the cryptographic choices; do not treat
this record as satisfying the independence requirement. This page exists so the
findings are durable and reviewable, not so they self-certify.

This page records the findings and the remediation path. Each finding's
"Status" line tracks where the work sits. The re-review against the pinned,
settled target **landed 2026-07-22** with APPROVE-WITH-CONDITIONS — see the
[Step 7 re-review verdict](#step-7-re-review-verdict-2026-07-22); the
[Phase 1 gate verdict](phase-1-gate-verdict.md) row #7 reflects it, and the
risk-owner countersigned the
[gate-level GO](phase-1-gate-verdict.md#go-decision--risk-owner-countersignature-2026-07-22)
the same day.

## Candidate under review

| Field | Value |
|---|---|
| Jeliya source | `4a739221efa12545dd18d25c4f876a2405b96f1c` (`main`; PR #78 `cdcae83…` + PR #79 `4a73922…`) |
| Iroh Rooms pin | `a5d98b70d717f35d3ce60953a88e12e646f2e871` (unchanged) |
| Verdict date (UTC) | 2026-07-21 |
| Scope doc | [Phase 1 security review scope](phase-1-security-review-scope.md) |

**F1 (below) is itself a blocker against this candidate reference:** the scope
doc points reviewers at "the current `main` HEAD, not a frozen hash," so an
approval against this row cannot be reproduced if `main` moves. The
`4a73922…` SHA is recorded here for traceability; the immutable pin
(source SHA + `Cargo.lock` + toolchain + ADR revisions + clean-worktree
assertion) is part of the remediation in [Step 3](#remediation-path).

## Severity taxonomy in use

This review uses a four-tier severity scale. **The taxonomy itself, the
blocking threshold, and reviewer-independence rules are uncodified** — that is
finding **F9** (a blocker). The labels are applied here as a working
convention, not as a binding contract:

| Tier | Working meaning |
|---|---|
| Blocker | Must be resolved before any approval can be recorded; an approval recorded with this open is not reproducible or not meaningful. |
| High | A real security claim is wrong, a required control is missing, or evidence overclaims a property. Resolution changes the code, the spec, or the evidence before sign-off. |
| Medium | Quality, completeness, or reproducibility gap that does not by itself invalidate an approval but must be tracked to closure. |

## Finding index

| # | Severity | Title |
|---|---|---|
| F1 | Blocker | Mutable review target — scope points at "current main HEAD," not an immutable pin — **resolved 2026-07-22 (pin recorded; provisional pending Steps 4–6)** |
| F2 | Blocker | No control-protocol wire format exists to approve; row #7 is mis-scoped — **resolved 2026-07-22 (re-scoped to two D1 envelopes; control deferred to D5b/D6)** |
| F3 | High | `jeliya-control` core does not enforce the attributed security properties — **resolved (labeling) 2026-07-22 (relabel as scaffolding); enforcement gaps are D5b/D6 work** |
| F4 | High | Review scope omits the actual authority path (`engine.rs` + daemon `/api/session` + single-user assumption) — **resolved (doc) 2026-07-22 (honest boundary stated; engine.rs in pin)** |
| F5 | High | "Production encryption" is opt-in, not enforced — **resolved (doc) 2026-07-22 (row #2 relabeled OPEN)** |
| F6 | High | KDF versioning/attribution is inaccurate — **resolved 2026-07-22 (immutable per-version param-set + dispatch; OWASP attribution corrected; migration fixtures + latency test)** |
| F7 | High | "Rotate by re-exporting" is false — old recovery material is irrevocable — **resolved (doc) 2026-07-22 (lifecycle text corrected)** |
| F8 | High | Test evidence overclaims zeroization — **resolved (code+doc) 2026-07-22 (features enabled, KEK/phrase Zeroizing, audit complete; RSS evidence at Step 7)** |
| F9 | Blocker | Approval contract and normative inputs undefined; ADRs #2/#3 contradict the code — **ADR/code contradictions resolved 2026-07-21; approval contract codified 2026-07-22** |
| F10 | Medium | Evidence package lacks reproducible adversarial coverage — **resolved 2026-07-22 (evidence package built; gaps tracked for Step 7)** |

## The findings

### F1 — Blocker: mutable review target

**Claim.** [Phase 1 security review scope](phase-1-security-review-scope.md)
tells reviewers to read the code "at the revision current at review time
(`cdcae83…` from PR #78 plus the self-review hardening PR #79 — i.e. the
current `main` HEAD, not a frozen hash)." An approval recorded against that
reference cannot be reproduced if `main` moves.

**Evidence.** The instruction was observed in flight: `main` advanced while an
uncommitted KDF-parameter change sat in the working tree. The same review
package would have certified a different byte-for-byte target depending on when
the reviewer ran `git rev-parse HEAD`.

**Impact.** An approval is a statement about a *specific* input. A floating
reference makes the approval non-reproducible and silently re-binds it to
whatever `main` points at when someone later asks "what was approved?".

**Fix direction.** The review target must be pinned to an immutable set of
inputs and a clean-worktree assertion: full source SHA, `Cargo.lock` hash,
toolchain version, the ADR revisions that define the normative spec, and the
exact document revisions under review. The scope doc must also state which
later changes reopen review (any change to a reviewed surface; any change to
the normative ADRs) and which do not (whitespace, unrelated docs).

**Status.** Resolved 2026-07-22 — the review target is now pinned in the
[scope doc's Review target pin section](phase-1-security-review-scope.md#review-target-pin)
(source SHA `35b1c5e`, `Cargo.lock` hash, toolchain, ADR revisions, crypto
dependency versions, clean-worktree assertion, reopen rules). The pin is
**provisional**: Step 5 changes `identity.rs` (KDF param encoding) and will
require a re-pin before the Step 7 re-review.

### F2 — Blocker: no control wire format exists to approve

**Claim.** [Phase 1 gate verdict](phase-1-gate-verdict.md) row #7 is "wire
formats and key lifecycle." The `jeliya-control` crate has **no wire format**:
framing, serialization, handshake, proof-of-possession, request
authentication, method-to-scope mapping, and daemon integration are all
deferred to D5b/D6. There is nothing byte-level for a reviewer to approve on
the control side.

**Evidence.** [`crates/jeliya-control/src/lib.rs`](../crates/jeliya-control/src/lib.rs)
exposes a Rust API (`Pairing`, `ControlGateway`, `authorize`, `install`,
`revoke`) but no byte serialization, no transport, and no daemon binding. The
gate verdict and the scope doc both concede the transport is Phase 2 ("the
encrypted transport and the daemon's exposure of the gateway are Phase 2
(D5b)").

**Impact.** Reviewing row #7 as written would either certify scaffolding as if
it were a wire format, or rely on "confirm the upgrade path" — which is not an
approvable artifact. Either path leaves the actual control-protocol wire
unreviewed when it ships in D5b.

**Fix direction.** Re-scope row #7 to the two implemented D1 envelopes (the
at-rest `identity.secret` envelope and the recovery-bundle envelope) plus
their key lifecycle. Create a **separate D5b/D6 review gate** that owns the
control wire (framing, handshake, transcript, request auth, method-to-scope
mapping, daemon integration). The Phase 1 gate cannot close on a control wire
that does not exist.

**Status.** Resolved 2026-07-22 — row #7 re-scoped to the two D1 envelopes
([scope doc](phase-1-security-review-scope.md#surfaces-under-review));
control-protocol wire deferred to the
[D5b/D6 review gate](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate).

### F3 — High: jeliya-control core does not enforce the attributed properties

**Claim.** The state machine in
[`crates/jeliya-control/src/lib.rs`](../crates/jeliya-control/src/lib.rs) is
attributed security properties it does not actually enforce at the API
surface it exposes.

**Evidence.**

- **SAS binds only two sorted pubkeys.** [`Pairing::sas`](../crates/jeliya-control/src/lib.rs)
  hashes `companion_key || browser_key` in canonical order — no version,
  roles, scopes, lifetime, nonce, or transcript. A two-sided attacker can
  birthday-search the ~32-bit SAS space in roughly 2^16 pairings
  (SAS is two 16-bit groups → ~2^32 space).
- **SAS confirmation is bypassable via the public API.** `Pairing::confirm`
  is the gate, but `ControlGateway::install` accepts any `ControlKeyRecord`
  the caller constructs; the record's `new` constructor is public. A host
  that calls `install` directly bypasses SAS, lifetime, and pairing entirely.
- **"Bounded lifetime" accepts any `Duration`.** `ControlKeyRecord::new`
  takes a caller-supplied `lifetime: Duration`; a host can pass
  `Duration::MAX`. The bound is on the field, not enforced by the type.
- **Expiry trusts caller-supplied time.** `authorize` takes `now_ms` from the
  caller; there is no clock bound and no daemon-supplied monotonic time.
- **No selected-room binding.** `Scope::RoomRead` / `Scope::MessageSend` are
  global; a record with that scope can name any accepted room. ADR #2
  decision 6 names "selected-room"; the code does not.
- **No rate limiting.** ADR #2 decision 8 names per-key rate limiting; the
  crate has none.

**Impact.** The crate is presented as "the security-reviewable core" every
scoped RPC crosses. In fact it is a library of types and checks a *correct*
host could choose to enforce. Nothing in the crate forces a host to do so, and
the daemon wiring that would bind these checks to a real session does not
exist.

**Fix direction.** Treat `jeliya-control` as **scaffolding**, not an approved
boundary. Row #7 should not assert the control surface is conformant; the
gate verdict's row #6 PASS-at-the-state-machine framing should be relabeled
to make clear nothing transports or enforces these checks yet. The actual
enforcement review happens at the D5b/D6 gate.

**Status.** Resolved (labeling) 2026-07-22 — `jeliya-control` relabeled as
scaffolding in its [module doc](../crates/jeliya-control/src/lib.rs), the
[gate verdict](phase-1-gate-verdict.md) row #6, and the
[scope doc](phase-1-security-review-scope.md). The enforcement gaps themselves
(SAS bypass, unbounded lifetime, caller-supplied time, no rate limiting, global
scopes) are D5b/D6 work — the four F9 control-protocol divergences (#2/#3/#4/#6)
are all deferred.

### F4 — High: scope omits the actual authority path

**Claim.** The review scope covers `identity.rs`, `recovery.rs`, and
`jeliya-control/src/lib.rs`, but the **real** authority path to root is
[`crates/jeliya-core/src/engine.rs`](../crates/jeliya-core/src/engine.rs)
(the 24-method dispatch table with no per-method auth) plus the daemon's
[`/api/session`](../crates/jeliyad/src/serve.rs) handshake plus the
single-user-machine assumption in [`docs/PROTOCOL.md`](PROTOCOL.md).

**Evidence.** The threat model in
[Security and threat model](security-threat-model.md) admits (lines 226–231)
that the `Origin` and `Sec-Fetch-Site` checks on `/api/session` are
browser-shaped and forgeable by a non-browser local process, and that the
route performs no token comparison at all — so a different local OS user (or
same-user process) that forges those headers receives the daemon token and,
over `/ws`, the full root+device authority surface. At-rest encryption and
`0600` permissions do not affect this path; the bearer token is the authority,
not the file mode.

**Impact.** A review that scopes only the crypto envelopes and the control
gateway certifies the wrong surface. Root authority is reached through
`engine.rs` and the daemon handshake, and the binding assumption is
single-user, single-OS-account operation — which the threat model already
excludes hostile violation of.

**Fix direction.** Either (a) bring `engine.rs`, the daemon auth, protocol
serialization, UI custody, and the deployment constraints into the review
scope, or (b) enforce a same-user socket boundary (e.g. SCM-credentials-bound
loopback) and place the single-user assumption explicitly under "Honest
boundaries" so it cannot be silently inherited by a co-resident companion.
At minimum the single-user assumption must be stated as an honest boundary
even if the scope is not widened.

**Status.** Resolved (doc) 2026-07-22 — the daemon-auth/single-user boundary is
now stated as an honest boundary in the
[scope doc](phase-1-security-review-scope.md#honest-boundaries-the-review-should-confirm-are-communicated),
with `engine.rs`, `serve.rs`, and `docs/PROTOCOL.md` all in the pin's
[reopen set](phase-1-security-review-scope.md#review-target-pin). Full scope
widening or same-user socket enforcement is a later product decision.

### F5 — High: "production encryption" is opt-in, not enforced

**Claim.** The gate verdict's row #2 PASS asserts "native production mode no
longer leaves the root secret plaintext." In fact encryption is opt-in and
the production default is plaintext.

**Evidence.**

- [`identity.rs`](../crates/jeliya-core/src/identity.rs): `password_from_env`
  returns `None` when `JELIYA_IDENTITY_PASSWORD` is unset or empty; `create`
  /`write_existing` then write plaintext, emitting only `tracing::warn!`.
- No packaging, systemd unit, launchd plist, or startup path sets or requires
  the variable. The onboarding flow calls `identity.create` with no password
  ([`ui/src/components/Onboarding.tsx`](../ui/src/components/Onboarding.tsx)).
- The test `create_with_password_seals_the_secret_not_plaintext` proves only
  that *when a password is supplied* the file is sealed — it does not assert
  that production refuses to run without one.

**Impact.** The row #2 PASS is true only for an opt-in mode no production
path enables. A real production deployment, following the docs as written,
ships plaintext root seeds.

**Fix direction.** Pick one and implement it: either (a) define an enforced
production invariant — refuse `identity.create` / `recovery.restore` without
protected storage (password set, or an OS-keystore backend present), with a
documented dev override — or (b) relabel row #2 truthfully as opt-in and
**leave row #2 open** at the Phase 1 gate.

**Status.** Resolved (doc) 2026-07-22 — gate-verdict row #2 relabeled from PASS
to OPEN (opt-in, not enforced); summary line, frontmatter, and index.md
updated. Code-level enforcement (refuse create/restore without protected
storage) is a separate product decision not taken in this step.

### F6 — High: KDF versioning/attribution is inaccurate

**Claim.** The Argon2id parameters are described as versioned via the
envelope and as "RFC 9106 example-1 tier." Neither is accurate.

**Evidence.**

- [`identity.rs`](../crates/jeliya-core/src/identity.rs) lines 62–66:
  `ARGON_M_COST = 19_456`, `ARGON_T_COST = 2`, `ARGON_P_COST = 1` are
  compile-time constants. The on-disk envelope is
  `version(1) || salt(16) || nonce(12) || ct+tag` — **the parameters are not
  in the envelope**. Changing the constants recompiles the daemon, which then
  silently fails to read identities written by an older build (no legacy
  dispatch in `decrypt_secret_bytes`).
- 19 MiB / t=2 is the OWASP *minimum* for Argon2id, not an RFC 9106 profile.
  RFC 9106's profiles are 64 MiB / t=3 / p=4 (first profile) and
  2 GiB / t=1 / p=4 (second profile). The scope doc and the source comment
  both say "RFC 9106 example-1 tier," which is wrong.

**Impact.** A future parameter bump silently breaks existing identity files,
and the documented "versioned KDF" property is not actually present. The
wrong RFC citation understates the gap between current params and the RFC's
recommended tier.

**Fix direction.** Encode authenticated KDF parameters per envelope version
(either inline params authenticated by the AEAD tag, or an immutable
param-set identified by a version byte with legacy dispatch for v1). Add
migration fixtures (a v1 fixture that a v2 reader still opens) and measured
latency/memory targets for each supported param-set. Cite OWASP minimum
correctly.

**Status.** Resolved 2026-07-22 — KDF params are now an immutable per-version
param-set (`KdfParams` struct + `V1_KDF` const + `kdf_params_for_version`
dispatch in [`identity.rs`](../crates/jeliya-core/src/identity.rs)): changing
params requires a version bump, and the v1 reader stays as the legacy dispatch
so existing identity files keep loading. Attribution corrected (OWASP minimum,
not RFC 9106 example-1). Migration fixtures added: `v1_kdf_params_are_pinned`
(param immutability), `v1_identity_round_trips_through_version_dispatch`
(legacy read), `unknown_envelope_version_is_rejected` (future-version
rejection). Latency target measured by `kdf_derivation_is_memory_hard`.

### F7 — High: "rotate by re-exporting" is false

**Claim.** The scope doc's key-lifecycle table says of the recovery key:
"rotate by re-exporting under a fresh key."

**Evidence.** [`recovery.rs`](../crates/jeliya-core/src/recovery.rs):
`export_bundle` mints a fresh random `RecoveryKey` and a fresh valid bundle.
It does **not** revoke, invalidate, or in any way retire the prior key or
bundle. `open_bundle` accepts any valid bundle for the same identity; AEAD
cannot detect rollback of an older-but-valid bundle. There is no concept of
a bundle generation, no supersession list, no revocation.

**Impact.** Re-export creates an *additional* valid recovery path; every
prior recovery key and bundle remains valid indefinitely. The product copy
implies a rotation operation that does not exist. Old recovery material is
irrevocable until root authority itself rotates (Phase 4 multi-device
revocation), and a duplicated device seed or a lost-device authority is a
residual risk that must be named.

**Fix direction.** Correct the lifecycle text: re-export adds a backup, it
does not rotate. State plainly that old recovery material stays valid until
root authority rotation, which is Phase 4 work, and record the duplicated-seed
/ lost-device residual risk.

**Status.** Resolved (doc) 2026-07-22 — lifecycle text corrected in the
[scope doc](phase-1-security-review-scope.md#key-lifecycle-summary-surfaces-in-scope)
and [ADR #3](recovery-bundle-decision.md#what-the-bundle-restores-and-what-it-does-not):
re-export adds a backup, old material irrevocable until root authority rotates
(Phase 4); duplicated-seed / lost-device residual risks recorded.

### F8 — High: test evidence overclaims zeroization

**Claim.** The scope doc points to functional round-trip and tamper tests as
evidence that zeroization is covered; those tests do not assert zeroization.

**Evidence.**

- `open_rejects_a_tampered_bundle`, `open_rejects_a_wrong_recovery_key`, and
  the round-trip tests exercise correctness, not zeroization. They never read
  the process's former heap and assert a buffer was wiped.
- `wrong_password_does_not_leak_seed_bytes_in_the_error`
  ([`identity.rs`](../crates/jeliya-core/src/identity.rs)) asserts the error
  string does not contain the literal `"identity_secret"` and that the file
  does not start with `{`. It does not inspect seed bytes.
- Real un-zeroized copies exist in the current code: the KEK is returned by
  value out of `Zeroizing` (`derive_kek` returns `[u8; 32]` by value, so the
  caller's copy is plain); the password arrives as a plain `&str` borrowed
  from a `String` the caller owns; `aes-gcm` and `argon2` are pulled in
  without confirming their `zeroize` cargo features are enabled.

**Impact.** The zeroize claim reads stronger than what is tested. Real
plaintext copies of secret material outlive the calls that produced them,
which is exactly what zeroize is meant to prevent.

**Fix direction.** Recast the zeroize work as a **source/dependency audit**
(enabled features on `aes-gcm`, `argon2`, `hex`; KEK return-by-value; phrase
and password handling) plus a **secret-data-flow inventory** that lists each
secret, each buffer it touches, and how each is wiped. Drop the test-based
claim until the audit closes.

**Status.** Resolved (code+doc) 2026-07-22 — zeroize overclaim acknowledged
and recast as a source/dependency audit + secret-data-flow inventory in the
[scope doc](phase-1-security-review-scope.md#zeroization-recast-per-f8).
Step 6 fixes: `aes-gcm`/`argon2` `zeroize` cargo features **enabled**;
`derive_kek` returns `Zeroizing<[u8; 32]>`; `from_phrase` wraps `stripped` in
`Zeroizing<String>`. Measured evidence (RSS/heap inspection) remains for the
Step 7 re-review.

### F9 — Blocker: approval contract and normative inputs undefined

**Claim.** The review cannot approve conformance against a spec that is not
settled, and the approval contract itself is undefined.

**Evidence.**

- **No approval contract.** The repo defines no reviewer-independence rule,
  severity taxonomy, blocking threshold, risk-owner role, required artifact
  list, remediation owner, or re-review rule. (This page's taxonomy above is
  a working convention, not a binding contract.)
- **ADRs #2 and #3 are `proposal` / `not yet adopted`.**
  [`docs/companion-control-protocol-decision.md`](companion-control-protocol-decision.md)
  (ADR #2) and
  [`docs/recovery-bundle-decision.md`](recovery-bundle-decision.md) (ADR #3)
  both carry `status: "proposal"` and `implementation_status: "planned"`.
- **ADRs contradict the code** on at least six points:
  1. ADR #3 names a grouped-**base32** recovery phrase; the code emits
     grouped-**hex** ([`recovery.rs` `to_phrase`](../crates/jeliya-core/src/recovery.rs)).
  2. ADR #2 specifies a **Noise-XX transcript-derived SAS**; the code emits a
     simple BLAKE3 over two sorted pubkeys
     ([`jeliya-control/src/lib.rs` `Pairing::sas`](../crates/jeliya-control/src/lib.rs)).
  3. ADR #2 decision 8 specifies per-key **rate limiting**; the code has none.
  4. ADR #2 decision 5 specifies a default **30-day lifetime**; the code
     accepts any caller-supplied `Duration` and has no default.
  5. ADR #3 decision 3 specifies an optional Argon2id **password wrap of the
     recovery key**; the code has no such wrap (the bundle is sealed directly
     under the random recovery key).
  6. ADR #2 decision 6 specifies **per-room "selected-room"** scope binding;
     the code's `Scope::RoomRead` / `Scope::MessageSend` are global.

**Impact.** An approval against this state would certify code that does not
match its spec, against a spec that is not adopted, with no rule for what
counts as an approval.

**Fix direction.** Settle the normative spec **before** any conformance
approval: for each divergence decide, with the risk owner, whether to (a)
amend the ADR to match the code, or (b) change the code to match the ADR.
The likely honest outcome is to adopt the ADRs as the canonical **Phase-2
target** and mark the current Phase-1 code as a partial/scaffolding
implementation whose conformance is checked at the D5b/D6 review — **not** to
pretend Phase 1 conforms. Codify the approval contract (independence,
taxonomy, blocking threshold, risk-owner, required artifact, remediation
ownership, re-review rules).

#### Resolutions (2026-07-21)

The dispositions below were applied 2026-07-21 by **the user acting as
risk-owner-of-record** (the human decision-maker who answered the divergence
questions). The formal risk-owner role, attribution, and approval artifact are
themselves part of the **open** F9 approval contract and are codified at
[Step 6](#remediation-path); until then these dispositions are **provisional**
pending that contract, and an auditor should not read them as a closed
approval. The ADR/code contradictions the dispositions resolve are real and
durable; the contract under which they were authorized is not.

| Div | Subject | Disposition | Effect |
|---|---|---|---|
| #1 | Recovery phrase encoding (base32 vs hex) | **Amend ADR #3 to grouped-hex** ([Amendment A](recovery-bundle-decision.md#amendments-a-and-b-2026-07-21)) | Phase-1 bundle conforms to ADR #3 decision 2 (amended). No code change. |
| #2 | SAS derivation (transcript vs simple BLAKE3) | **Defer: ADR #2 is Phase-2 target** | Simple SAS is Phase-1 scaffolding; transcript SAS is checked at D5b/D6. No change to ADR #2 (stays `proposal`); [note added](companion-control-protocol-decision.md#relationship-to-the-phase-1-scaffolding-2026-07-21) recording the relationship. |
| #3 | Per-key rate limiting | **Defer: ADR #2 is Phase-2 target** | Rate limiting lands with the D5b transport. |
| #4 | Control-key lifetime default/max | **Defer: ADR #2 is Phase-2 target** | Lifetime enforcement lands with the D5b daemon wiring. |
| #5 | Recovery-key password wrap | **Amend ADR #3 to mark wrap as Phase-2 extension** ([Amendment B](recovery-bundle-decision.md#amendments-a-and-b-2026-07-21)) | Phase-1 bundle conforms (the "off" branch is the only one shipped). No code change. |
| #6 | Selected-room scope binding | **Defer: ADR #2 is Phase-2 target** | Per-room binding lands at the D5b transport seam. |

ADR #3 was promoted `proposal → canonical` with `implementation_status: partial`
(decision 3's optional-on wrap and decision 5's wider payload remain Phase 2).
ADR #2 remains `proposal`; its body now states plainly that the merged
`crates/jeliya-control` code is scaffolding toward this ADR and does not
conform to it. Neither ADR claims Phase-1 conformance where none exists.

**Status.** ADR/code contradictions **resolved** (dispositions above). The
approval-contract portion of F9 (independence, taxonomy, blocking threshold,
risk-owner, required artifact, remediation ownership, re-review rules) is
**codified** in the
[evidence package](phase-1-evidence-package.md#codified-approval-contract).
Exercised by a real independent reviewer at Step 7.

### F10 — Medium: evidence package needs reproducible adversarial coverage

**Claim.** The scope doc lists tests to read but does not provide a
reproducible evidence package.

**Evidence.** Missing or incomplete: exact commands and expected outputs;
toolchain/platform record; CI artifact links; known-answer envelope/KDF
fixtures; old-version migration fixtures; header/truncation tamper cases;
fuzz/property tests; cross-platform permission checks; max-lifetime and
clock-rollback cases; reinstall-after-revocation cases; control concurrency
and session-binding cases. Findings are not individually mapped to
[Security and threat model](security-threat-model.md); "accepted" residual
risks are not labelled with a risk owner and exit criterion.

**Impact.** A reviewer cannot reproduce the evidence base; a later change
cannot be checked against a fixed expected-outcome set.

**Fix direction.** Build the evidence package: commands, environments,
expected results, KDF/envelope known-answer fixtures, migration fixtures,
tamper matrix, fuzz/property harnesses, cross-platform permission checks,
lifetime/clock-rollback, reinstall-after-revocation, control concurrency.
Map every finding to the threat model. Label every "accepted" risk with an
owner and an exit criterion.

**Status.** Resolved 2026-07-22 — the evidence package is built in
[Phase 1 evidence package and approval contract](phase-1-evidence-package.md):
exact commands, expected results, CI artifact links, test-to-finding mapping,
threat-model cross-reference, gap list, and accepted-risk register. Remaining
gaps (fuzz/property tests, cross-platform permissions, RSS/heap verification)
are noted and tracked for the Step 7 re-review.

## Remediation path

The remediation is ordered. Do not skip ahead; later steps depend on earlier
ones.

| Step | Finding(s) | Outcome |
|---|---|---|
| 0 | (this page) | ✅ The findings are recorded in the repo as the durable independent-review record, linked from [the wiki index](index.md). |
| 1 | F9 | ✅ ADR/code contradictions resolved 2026-07-21 (see [F9 resolutions](#resolutions-2026-07-21)): ADR #3 promoted `proposal → canonical` / `partial` with [Amendments A and B](recovery-bundle-decision.md#amendments-a-and-b-2026-07-21); ADR #2 remains `proposal` with its [scaffolding relationship](companion-control-protocol-decision.md#relationship-to-the-phase-1-scaffolding-2026-07-21) documented. Approval-contract codification is still open and folds into Step 6 + Step 7. |
| 2 | F2, F3 | ✅ Row #7 re-scoped to the two D1 envelopes ([scope doc](phase-1-security-review-scope.md)); `jeliya-control` relabeled as scaffolding in its [module doc](../crates/jeliya-control/src/lib.rs) and the [gate verdict](phase-1-gate-verdict.md) row #6; D5b/D6 control-wire review gate defined in the [scope doc](phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate). |
| 3 | F1 | ✅ Review target pinned in the [scope doc](phase-1-security-review-scope.md#review-target-pin): source SHA `35b1c5e` + `Cargo.lock` hash + toolchain + ADR revisions + crypto dep versions + clean-worktree assertion + reopen rules. **Provisional** — Step 5 changes `identity.rs` and requires a re-pin before Step 7. |
| 4 | F5, F7, F4, F8 | ✅ Doc overclaims fixed: row #2 relabeled OPEN (F5, opt-in not enforced); lifecycle corrected — re-export adds a backup, old material irrevocable (F7); daemon-auth/single-user boundary stated as honest boundary, `engine.rs` in pin (F4); zeroize recast as source/dep audit + secret-data-flow inventory (F8, full audit is Step 6). |
| 5 | F6 | ✅ KDF params are now an immutable per-version param-set (`KdfParams` + `V1_KDF` + `kdf_params_for_version` dispatch); attribution corrected (OWASP minimum); migration fixtures + latency measurement added. `identity.rs` changed — pin needs re-record before Step 7. |
| 6 | F10 | ✅ Evidence package built ([new doc](phase-1-evidence-package.md)): exact commands, expected results, CI links, test-to-finding mapping, threat-model cross-reference, gap list, accepted-risk register. Approval contract codified (F9 remaining). Zeroize dependency features enabled + KEK/phrase Zeroizing fixes (F8 remaining). Pin re-recorded (Cargo.lock hash updated). |
| 7 | all | ✅ **Re-review landed 2026-07-22: APPROVE-WITH-CONDITIONS** against pin `df28f6a` by an independent review session (not the implementer). No blocker or high; 2 medium + 10 low/info conditions tracked. See [Step 7 re-review verdict](#step-7-re-review-verdict-2026-07-22). |

## This session's scope

This session has completed **Steps 0–6** of the remediation path and
**prepared Step 7** (re-review handoff below). The pin is finalized against
`df28f6a`. The re-review itself requires a **different reviewer** — the
implementer cannot self-certify.

## Step 7 — re-review handoff

> **The implementer cannot perform this step.** The prior implementer and the
> prior analyst were the same agent. The Step 7 re-review must be executed by
> a different reviewer, with demonstrated cryptography expertise for the
> cryptographic choices.

### What to check out

> **The code surfaces (`.rs` files) are identical at `df28f6a` and at the
> current `main` HEAD** — the Step 7 PR is docs-only. A reviewer may check out
> either; `main` HEAD includes both the code and the finalized review package.

```sh
# Option A: check out main HEAD (code + finalized docs together).
git checkout main && git pull
# Verify the code surfaces match the pin:
git log --oneline -1 -- crates/jeliya-core/src/identity.rs  # Expected: df28f6a

# Option B: check out the exact code pin (docs at this SHA are one step behind).
git checkout df28f6a15c6c154c0759eea76b2c164c41c047bc

# Either way, verify the lockfile:
sha256sum Cargo.lock   # Expected: dda192b5...
```

Verify the pin values in the
[scope doc's Review target pin](phase-1-security-review-scope.md#review-target-pin)
match the tree you checked out.

### What to read (in order)

1. **This document** — the 10 findings and how each was resolved.
2. [The scope doc](phase-1-security-review-scope.md) — what is under review
   (the two D1 envelopes), what is deferred (control wire → D5b/D6), and the
   honest boundaries.
3. [The evidence package](phase-1-evidence-package.md) — exact commands,
   expected results, test-to-finding mapping, threat-model cross-reference,
   and the codified approval contract.
4. [ADR #3](recovery-bundle-decision.md) — the normative recovery-bundle spec
   (`canonical` / `partial`).
5. [ADR #2](companion-control-protocol-decision.md) — the Phase-2 control
   target (`proposal`; not under Phase 1 review).
6. [The gate verdict](phase-1-gate-verdict.md) — the current verdict (row #2
   OPEN, row #7 NOT APPROVED → remediation complete, awaiting re-review).

### What to assess

The review covers **two surfaces only** (per F2):

- **At-rest identity envelope** (`identity.rs`): the AES-256-GCM envelope
  format, the Argon2id KDF (immutable per-version param-set, OWASP minimum),
  the opt-in encryption policy (F5 — row #2 OPEN), the version dispatch
  (`kdf_params_for_version`), and the zeroize coverage (features enabled, KEK
  returns `Zeroizing`).
- **Recovery bundle** (`recovery.rs`): the AEAD construction, the recovery key
  (random 256-bit, grouped-hex phrase), the lifecycle (re-export does not
  rotate — F7), the fail-closed paths, and the zeroize coverage (`stripped` is
  `Zeroizing<String>`).

### What is explicitly NOT in scope

- The control-protocol wire (D5b/D6 gate).
- Enforcement of opt-in encryption in production (F5 accepted risk).
- Runtime enforcement of the control core (F3 accepted risk).
- Root authority rotation / old-material revocation (F7 accepted risk, Phase 4).
- The single-user-machine assumption as an enforced boundary (F4 accepted risk).

### What the output should be

Per the [approval contract](phase-1-evidence-package.md#codified-approval-contract):
APPROVE, APPROVE-WITH-CONDITIONS, or REJECT — recorded against the pin, with
the reviewer's identity, date, and any conditions. The output updates the
[gate verdict](phase-1-gate-verdict.md) row #7.

The [Phase 1 gate verdict](phase-1-gate-verdict.md) is now consistent with this
record: row #2 is OPEN (F5), row #7 is APPROVE-WITH-CONDITIONS (see the
[Step 7 re-review verdict](#step-7-re-review-verdict-2026-07-22) below), and the
control surface is deferred to D5b/D6 (F2/F3).

## Step 7 re-review verdict (2026-07-22)

**Verdict: APPROVE-WITH-CONDITIONS** — recorded against pin
`df28f6a15c6c154c0759eea76b2c164c41c047bc` (`Cargo.lock`
`dda192b5…`, verified; worktree clean; all per-surface and ADR last-change SHAs
match the [pin table](phase-1-security-review-scope.md#review-target-pin)).

**Reviewer identity and independence.** The re-review was executed 2026-07-22
by an independent Claude review session (Fable 5) that did not author the code
under review or the prior findings record, running a multi-agent adversarial
review (six finder lenses, a 2–3-lens refutation panel per candidate finding,
an empirical measurement harness, and a completeness critic). **Independence
caveat, stated per the approval contract:** the reviewer is a different agent
session from the implementer/analyst but the same model family; organizational
independence is therefore limited, and a countersignature by the human
risk-owner-of-record is recommended before the gate-level GO decision.

**Evidence reproduced.** `cargo fmt` clean; `clippy` clean;
`cargo test --locked --workspace` = **125 passed, 0 failed, 1 ignored**
(matching the [evidence package](phase-1-evidence-package.md#reproduce-the-review));
`check-docs` OK; `check-ui-i18n` OK. Local toolchain rustc 1.97.1 (the pin's
transparency note; CI lanes 1.96.0 / 1.91.0 are the authoritative build path).

**Measured evidence (closes the Step 7 RSS/heap ask).** The probe harness is
committed at [`tools/step7-kdf-probe/`](../tools/step7-kdf-probe/README.md)
(standalone crate pinning the exact reviewed versions `argon2 =0.5.3`,
`aes-gcm =0.10.3`, `zeroize =1.9.0`; commands and the recorded transcript in
its README). Measured: Argon2id `V1_KDF` peak-RSS delta **≈ 18.95 MiB**
(≈ the configured m=19456 KiB — the memory parameter is real), derivation
latency **21–29 ms** on the recording machine (a review-time run on a loaded
machine measured ~41 ms; both dwarf the in-tree 1 ms floor — condition 2);
`cargo tree --locked -p jeliya-core -e features` on the pinned tree confirms
the `zeroize` feature resolves onto `argon2`, `aes-gcm`, and their cipher
internals. Volatile-read wipe probes (empirical, UB-caveated): the heap
probe's discriminating region (bytes 16..32, past glibc tcache metadata)
reads all-zero with `Zeroizing` vs `0xAA` residue in the no-`Zeroizing`
control; the stack probe reads fully zeroed after an inner-scope drop.

**Findings: no blocker, no high.** 22 candidate findings entered adversarial
verification; 10 were refuted (chiefly as restatements of already-disclosed
accepted risks — the package's honest boundaries held); 12 were confirmed:
2 medium, 6 low, 4 info. The two mediums are evidence-quality overclaims in
the F6/F8 closure story, not code-security defects. Under the
[codified blocking threshold](phase-1-evidence-package.md#codified-approval-contract),
none blocks approval; all become conditions.

**Conditions (tracked to closure; none blocking):**

1. **(medium, from F8's inventory-completeness claim)** `SigningKey::to_seed()`
   returns a plain `[u8; 32]` (verified in the pinned iroh-rooms source); the
   raw root/device seeds are bound to unwiped locals at four call sites
   (`recovery.rs` `export_bundle`, `identity.rs` `secret_file_contents`).
   Wrap the returns in `Zeroizing` and add a raw-seed row to the
   [scope doc's inventory](phase-1-security-review-scope.md#zeroization-recast-per-f8).
2. **(medium, from F6's closure evidence)** `kdf_derivation_is_memory_hard`
   asserts only ≥ 1 ms — ~40× below the measured latency and unable to detect
   a silently ineffective memory parameter. Raise the floor (≥ 5 ms) or add an
   RSS assertion, and reword the evidence row; the measured values above stand
   as the evidence for this pin.
3. **(low)** Zeroize hygiene: pre-size `from_phrase`'s `Zeroizing<String>`
   (realloc fragments); wrap `test_restore`'s ephemeral password in
   `Zeroizing`; make `PayloadV1`'s two secret fields wipe on the
   serde-error path of `export_bundle`.
4. **(low)** The identity envelope has no tamper/truncation test (the recovery
   bundle has both); the evidence row "Covered (implicit in the parse)" cites
   code, not a test. Add the two tests or relabel the row.
5. **(low)** Append the missing CI rows to the evidence-package table:
   PR #85 tree `df28f6a` → push run `29922951249`, PR #86 tree `5fa0bae` →
   push run `29928189003` (both verified green). *(Erratum, corrected
   2026-07-22: this condition originally dictated run IDs `29925118834` /
   `29932744561`, which do not exist — the
   [conditions delta review](#conditions-delta-review-2026-07-22) caught the
   error and independently verified the correct runs above; the underlying
   green-CI claim was always true.)*
6. **(low/info)** Amend two stale ADR #3 passages: the Consequences bullet
   claiming Argon2id parameters live in the on-disk format (they do not, in
   either envelope), and the "does not certify" text still calling F6/F7 open.
7. **(info, non-binding)** Unknown identity-envelope version maps to
   `ErrorKind::Internal` (recovery uses `InvalidParams`); and at the next
   envelope version bump, bind the header (version/salt/nonce) as AEAD
   associated data — self-authenticating today, cheap defense-in-depth for v2.

**Conditions status (2026-07-22, post-GO).** Conditions 1–6 and condition 7's
error-kind half were implemented the same day in the conditions PR:
`Zeroizing` wraps at the four `to_seed()` call sites + a raw-seed inventory
row with the residual stack-temporary limitation stated (1); the latency-test
floor raised to 5 ms with the committed probe harness
[`tools/step7-kdf-probe`](../tools/step7-kdf-probe/README.md) as the memory
evidence (2); `from_phrase` pre-sizing, `Zeroizing` ephemeral password, and
the export-side wipe-before-error fix (3); identity-envelope
truncation/tamper tests + corrected evidence rows (4); the PR #85/#86 CI rows
(5); the two stale ADR #3 passages amended (6); unknown-envelope-version now
`InvalidParams` (7 — its AAD half remains a v2 design note). The conditions
merged as `d610076` (PR #89). The re-pin and the scoped delta review are
**complete** — see [Conditions delta review](#conditions-delta-review-2026-07-22).

#### Conditions delta review (2026-07-22)

**Verdict: APPROVE-WITH-CONDITIONS — the `df28f6a` approval extends to the
conditions tree `d610076c05f0f29cb8f87c7dbe805a5f603ecc89`.** The scoped delta
review required by the reopen rules was executed by an **independent
delta-review session** (fresh agent contexts, Claude Fable 5, distinct from
the conditions implementer; the same model-family independence caveat as the
Step 7 verdict applies, and the risk-owner's merge of the recording PR serves
as countersignature). Two adversarial challengers (refutation lens on the
security-relevant claims; scope-creep lens on the full diff) upheld the
verdict with zero objections.

The delta reviewer's statement, verbatim:

> I independently verified the pin (Cargo.lock sha256 dda192b5…, per-surface
> last-change SHAs, toolchain and all five crypto dependency versions
> unchanged) and walked the entire df28f6a..d610076 diff: every code hunk maps
> to one of the seven Step 7 conditions, all seven are correctly and
> completely implemented in the post-state, nothing changed outside crates/,
> docs/, and tools/, and I reproduced the gates locally (fmt clean, clippy
> clean, 127 passed / 0 failed / 1 ignored including the new envelope tests
> and the 5 ms KDF floor). I found one evidence defect: the two CI run IDs
> condition 5 dictated (29925118834, 29932744561) do not exist on GitHub,
> though the underlying claim is true — I verified the actual green runs
> 29922951249 (df28f6a) and 29928189003 (5fa0bae) myself. The df28f6a
> approval therefore extends to d610076 with two conditions: a docs-only
> erratum correcting those run IDs wherever they appear, and confirmation
> that the in-progress d610076 push run 29951799090 concludes green.

**Disposition of the delta review's two conditions (2026-07-22):**

1. **Run-ID erratum — applied.** All eight occurrences across the evidence
   package, gate verdict, capability status, release-vs-main, and this
   record's condition 5 were corrected to the verified push runs
   (`29922951249` at `df28f6a`, `29928189003` at `5fa0bae`), each
   independently re-verified against the GitHub API before recording.
2. **`d610076` push run — confirmed.** Run `29951799090` completed with
   conclusion `success` (all six jobs) after the review; verified directly.

Carried notes (no action this gate): the two `to_seed()` call sites in
`supervisor.rs` outside row #7's surfaces (disclosed in the
[zeroize inventory](phase-1-security-review-scope.md#zeroization-recast-per-f8),
tracked for the next zeroize pass / D5b review); the env-var password
register row is governance recording of an already-countersigned risk, not
new scope. The pin is
[re-recorded at `d610076`](phase-1-security-review-scope.md#review-target-pin).

**Reopen note.** Landing ANY of the conditions touches the pin's
[reopen set](phase-1-security-review-scope.md#reopens-review): conditions
1–3 change the pinned code surfaces (`identity.rs` / `recovery.rs` or their
tests), condition 4 changes the reviewed tests and the evidence package,
condition 5 changes the evidence package's evidence list, condition 6 amends
ADR #3 (any ADR #3 change reopens), and condition 7's error-kind half changes
`identity.rs` (its AAD half is v2 design work). Condition work therefore
lands with a re-pin and a scoped delta review of those diffs — none of it is
"editorial" under the reopen rules' exception. This approval holds for the
pinned tree as reviewed, with the conditions tracked.

**Accepted risks reaffirmed** (unchanged owners and exit criteria, per the
[accepted-risk register](phase-1-evidence-package.md#accepted-risks)): opt-in
at-rest encryption (F5, row #2 stays OPEN), `jeliya-control` scaffolding (F3),
irrevocable old recovery material (F7), the single-user-machine assumption
(F4), and the env-var password.

**Effect.** Gate-verdict row #7 is updated to APPROVE-WITH-CONDITIONS. The
gate-level GO decision (given row #2 remains OPEN as an accepted risk) belongs
to the risk-owner-of-record per the approval contract, not to this review; the
risk-owner
[countersigned and recorded GO on 2026-07-22](phase-1-gate-verdict.md#go-decision--risk-owner-countersignature-2026-07-22).

## Operating rules

- **Verify, don't assume.** After any code change, run
  `cargo fmt --all -- --check`,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`,
  `cargo test --locked --workspace`,
  `node scripts/check-docs.mjs`, and `node scripts/check-ui-i18n.mjs`.
- **Keep the working tree clean** between steps (commit or revert; never
  leave floating changes — that was F1).
- **Do not commit, push, or open a PR unless the user explicitly says to.**
- **Independence caveat.** The prior implementer and the prior analyst were
  the same agent; final row #7 sign-off needs a different reviewer,
  especially for the cryptographic choices. Do not self-certify.

## Citations

- [Phase 1 security review scope](phase-1-security-review-scope.md) — the package this review was run against (itself revised by Step 3).
- [Phase 1 gate verdict](phase-1-gate-verdict.md) — row #7 is the open condition; its current "rows #1–#6 PASS" framing is corrected in Step 4.
- [Companion control protocol decision (ADR #2)](companion-control-protocol-decision.md) — `proposal` / `not yet adopted`; reconciled in Step 1.
- [Recovery bundle decision (ADR #3)](recovery-bundle-decision.md) — `canonical` / `implementation_status: partial` (promoted from `proposal` in Step 1); Phase-1 slices adopted, decision 8 (test_restore in setup) not yet wired, password wrap + wider payload are Phase 2.
- [Security and threat model](security-threat-model.md) — the daemon-auth/single-user assumption F4 references and the residual-risk list F10 maps to.
- [Production deployment decision — amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name) — the browser-authority boundary binding the control protocol.
