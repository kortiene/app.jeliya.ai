---
type: "Reference"
title: "Phase 1 security review scope"
description: "The review package for Phase 1 gate row #7: re-scoped (2026-07-22, finding F2) to the two D1 wire envelopes (at-rest identity encryption + recovery bundle) and their key lifecycle; the control-protocol wire is deferred to a separate D5b/D6 review gate."
tags: ["security", "review", "phase-1", "cryptography", "identity", "control-protocol"]
timestamp: "2026-07-22T01:30:00Z"
status: "canonical"
implementation_status: "implemented"
verification_status: "partial"
release_status: "unreleased"
audience: ["security-reviewers", "maintainers"]
---

# Phase 1 security review scope

This is the review package for [Phase 1 gate row #7](phase-1-gate-verdict.md#7-independent-security-review-approves-the-wire-formats-and-the-key-lifecycle--not-approved-remediation-in-progress):
the security review of the wire formats and key lifecycle introduced by Phase 1.
**Re-scoped 2026-07-22 per [finding F2](phase-1-security-review.md#f2--blocker-no-control-wire-format-exists-to-approve)**:
row #7 covers the **two D1 envelopes only** — the at-rest `identity.secret`
envelope and the recovery-bundle envelope — plus their key lifecycle. The
control-protocol wire does not exist yet (there is no framing, serialization,
handshake, or daemon binding), so there is nothing byte-level to review on the
control side. The control wire gets its own **D5b/D6 review gate** (see
[Deferred surface — the D5b/D6 control-wire review gate](#deferred-surface--the-d5bd6-control-wire-review-gate)).

The [independent review landed 2026-07-21](phase-1-security-review.md) and
returned **NOT APPROVED** with 10 findings; row #7 is not "PENDING" (waiting for
a review) but "NOT APPROVED — remediation in progress." This document is the
input package, not the verdict; the verdict lives in the
[findings record](phase-1-security-review.md).

## Surfaces under review

**Two modules carry the D1 wire formats and key-lifecycle logic under row #7.**
A third module — the control-protocol core — is **deferred to the D5b/D6 gate**
because it has no wire format to review (see
[Deferred surface](#deferred-surface--the-d5bd6-control-wire-review-gate)).

> **The review target is pinned** — see
> [Review target pin](#review-target-pin). A reviewer checks out the pinned
> SHA and verifies the `Cargo.lock` hash, toolchain, and ADR revisions match.
> The pin is **provisional**: Steps 4–6 of the
> [remediation path](phase-1-security-review.md#remediation-path) may modify
> reviewed surfaces (notably Step 5 changes `identity.rs` for KDF param
> encoding); the pin will be re-recorded before the Step 7 re-review.

### 1. At-rest identity encryption — `crates/jeliya-core/src/identity.rs`

The on-disk `identity.secret` is sealed when `JELIYA_IDENTITY_PASSWORD` is set
(gate row #2). Review the envelope, the KDF, and the fallback policy.

- **Envelope:** `version(1) || salt(16) || nonce(12) || ciphertext+tag`, AES-256-GCM
  over the legacy plaintext-JSON body. The first byte (`{` vs the version byte)
  lets `load` auto-detect the format without a sidecar.
  ([`encrypt_secret_bytes`](../crates/jeliya-core/src/identity.rs),
  [`decrypt_secret_bytes`](../crates/jeliya-core/src/identity.rs)).
- **KDF:** Argon2id, m=19456 KiB, t=2, p=1 (RFC 9106 example-1 tier), output
  32 bytes. Params are versioned via the envelope; strengthening before launch
  is a review item, not a silent change.
- **Policy:** password unset ⇒ plaintext `0600` (dev default, explicit);
  password set ⇒ sealed. A plaintext identity keeps loading after a password is
  introduced (auto-detect + warning); there is no force-migrate-on-read (it
  would race concurrent loads). Wrong password / encrypted-without-password
  fail closed with `invalid_params`.
- **Assess:** nonce freshness (CSPRNG per seal); the `0600`-plaintext fallback
  threat model; whether Argon2id params meet the launch bar; that no seed bytes
  surface in errors (asserted by `wrong_password_does_not_leak_seed_bytes_in_the_error`).

### 2. Recovery bundle — `crates/jeliya-core/src/recovery.rs` (ADR #3)

The backup/restore transport for an accountless identity (gate row #1). Review
the AEAD construction, the recovery key, and the import-time fail-closed paths.

- **Envelope:** `version(1) || nonce(12) || ciphertext+tag`, AES-256-GCM over a
  versioned JSON payload (profile fields + the two signing seeds as hex). AEAD
  gives integrity/authenticity; an unknown version, truncation, tamper, or wrong
  key fails closed.
- **Key:** a random 256-bit `RecoveryKey` the user holds, rendered as a
  grouped-hex phrase. The daemon does **not** persist it; it is shown once at
  `recovery.export`. An optional Argon2id password wrap is a forward extension
  (off by default in the first slice).
- **Payload scope:** the first slice restores identity *authority* only — the
  profile root + device seeds. Room provenance / device-auth state / relay
  config are Phase-2 slices (the versioned payload makes adding them a
  migration, not a break). See [ADR #3 decision 5](recovery-bundle-decision.md).
- **Assess:** the AEAD choice and nonce handling; zeroize coverage
  (`export_bundle` and `open_bundle` both zeroize the plaintext bytes — asserted
  by the round-trip and tamper tests); the `restore_to_dir` clobber refusal and
  the secret/public id consistency check on import.

## Deferred surface — the D5b/D6 control-wire review gate

The control-protocol core in `crates/jeliya-control/src/lib.rs` is **not under
Phase 1 row #7 review**. [Finding F2](phase-1-security-review.md#f2--blocker-no-control-wire-format-exists-to-approve)
established that the crate has no wire format — no framing, serialization,
handshake, proof-of-possession, request authentication, method-to-scope
mapping, or daemon binding — so there is nothing byte-level for a Phase 1
reviewer to approve. [Finding F3](phase-1-security-review.md#f3--high-jeliya-control-core-does-not-enforce-the-attributed-properties)
further established that the crate does not enforce its attributed properties
at the API surface it exposes (public `install`/`ControlKeyRecord::new` bypass
SAS and lifetime; `authorize` trusts caller-supplied time; no rate limiting;
global scopes). The crate's module doc now states plainly that it is
**scaffolding toward ADR #2**, not a security boundary.

The **D5b/D6 review gate** owns the control wire. It triggers when D5b (the
control-protocol transport + browser Wasm + daemon wiring) and D6 (version and
capability negotiation) land, and it covers:

- **Framing and serialization:** the versioned wire format for scoped RPCs,
  method-to-scope mapping, and the ALPN registration.
- **Handshake and proof-of-possession:** the Noise XX-equivalent transcript,
  SAS derivation from the transcript hash (not the simple BLAKE3-over-two-keys
  the Phase 1 scaffolding uses), and the ephemeral bootstrap.
- **Request authentication:** binding each scoped RPC to a confirmed control
  key, enforcing SAS-gated pairing, bounded lifetime (with a real default and
  max), default-deny scopes with per-room "selected-room" binding, nonce/counter
  replay defense, per-key rate limiting, and immediate revocation with
  session teardown.
- **Daemon integration:** the `ControlGateway` serialization invariant (the
  daemon must hold a mutex around every mutation), persistence of control-key
  records across daemon restarts, and the `room.join` redemption confirmation
  (A1 confused-deputy).
- **Independence:** this gate requires a reviewer who is not the implementer,
  especially for the cryptographic choices (SAS entropy, Noise transcript
  binding, nonce construction).

Until D5b/D6 review closes, the [Phase 1 gate verdict](phase-1-gate-verdict.md)
row #6 ("replay, wrong-SAS, expired-key, revoked-key pairing tests fail closed")
passes only at the **state-machine unit-test level** — not as a property of a
running, enforcing system.

### What the D5b/D6 gate will assess (design context from the scaffolding)

The Phase 1 scaffolding establishes the intended design; the D5b/D6 gate reviews
the implementation that actually enforces it:

- **Pairing + SAS:** `Pairing::sas` derives a ~32-bit short authentication
  string (BLAKE3 over both public keys, role-symmetric, two 5-digit groups). A
  MITM substituting either key changes the SAS; the user compares both displays.
  `Pairing::confirm` yields a `ControlKeyRecord` only on a matching SAS. **The
  D5b gate reviews the transcript-derived SAS, not this simple construction**
  (see [ADR #2](companion-control-protocol-decision.md) decision 4; F9
  divergence #2 deferred).
- **Control key (A1):** non-extractable public key (the private half never
  leaves the browser); a **bounded lifetime as a duration** (`expires_at_ms` =
  created + lifetime); default-deny scopes; immediate revocation. **The D5b
  gate reviews the enforced default and max** (F9 divergence #4 deferred).
- **Gateway:** `ControlGateway::authorize` is the single enforcement point,
  fixed order identity → revocation → expiry → scope → replay. A denial advances
  no granting state. **The D5b gate reviews the daemon's call site**, not just
  the library function.
- **Replay defense:** a sliding per-key window (`REPLAY_WINDOW = 64`); the
  highest nonce seen plus a bounded `seen` set; out-of-order gaps in-window
  accepted, exact replays and below-floor nonces rejected. Nonce 0 rejected;
  clients start at 1.
- **Rate limiting:** ADR #2 decision 8 names per-key rate limiting; the crate
  has none. **The D5b gate reviews the implementation** (F9 divergence #3
  deferred).
- **Per-room scope binding:** ADR #2 decision 6 names "selected-room"; the
  crate's scopes are global. **The D5b gate reviews the binding** (F9 divergence
  #6 deferred; the transport seam is where a room id is available on an RPC).

## Key lifecycle summary (surfaces in scope)

| Secret | Where it lives | Protection | Rotation / revocation |
|---|---|---|---|
| Identity + device seeds (root authority) | `identity.secret` on the daemon's data dir | `0600` plaintext (dev) or AES-256-GCM under `JELIYA_IDENTITY_PASSWORD` (prod) | not yet (Phase 4 multi-device revocation); `recovery.export` is the only backup |
| Recovery key (256-bit random) | user-held (phrase); never persisted by the daemon | out of band | re-export adds a backup; old material is irrevocable until root authority rotates (Phase 4) — see [F7](phase-1-security-review.md#f7--high-rotate-by-re-exporting-is-false), corrected in Step 4 |
| Browser control key (per pairing) | browser WebCrypto non-extractable; public half on the companion | non-extractable + bounded lifetime + default-deny scopes | immediate revocation via `ControlGateway::revoke` — **D5b/D6 scope, not Phase 1 row #7** |

> The recovery-key rotation text previously said "rotate by re-exporting under
> a fresh key," which [finding F7](phase-1-security-review.md#f7--high-rotate-by-re-exporting-is-false)
> records as false. The corrected lifecycle is shown above; the full narrative
> fix is [Step 4](phase-1-security-review.md#remediation-path).

## Test evidence to rely on

The reviewer should read the tests that back each gate row (cited in the
[Phase 1 verdict](phase-1-gate-verdict.md)) and confirm they actually prove the
security property (not just the happy path).

**In scope (D1 envelopes, row #7):**

- `crates/jeliya-core/src/recovery.rs`: `open_rejects_a_wrong_recovery_key`,
  `open_rejects_a_tampered_bundle`, `open_rejects_an_unknown_version`,
  `restore_to_dir_reproduces_a_loadable_identity_in_a_fresh_install`.
- `crates/jeliya-core/src/identity.rs`: `create_with_password_seals_the_secret_not_plaintext`,
  `load_with_a_wrong_password_fails_closed`,
  `load_an_encrypted_secret_without_a_password_fails_closed`.

**Deferred (control state machine, D5b/D6 gate):**

- `crates/jeliya-control/src/lib.rs`: the four fail-closed assertions
  (`replayed_nonce_is_rejected`, `wrong_sas_yields_no_record`,
  `expired_key_is_rejected`, `revoked_key_is_rejected`) plus
  `scope_is_default_deny`, `out_of_order_nonces_inside_the_window_are_accepted`,
  `nonce_below_the_window_floor_is_rejected`, `sas_changes_when_either_key_is_substituted`.
  These prove state-machine unit properties only; they do not prove the
  properties hold in a running system (see [F3](phase-1-security-review.md#f3--high-jeliya-control-core-does-not-enforce-the-attributed-properties),
  [F8](phase-1-security-review.md#f8--high-test-evidence-overclaims-zeroization)).

## Honest boundaries the review should confirm are communicated

- Recovery restores identity *authority*, not unreplicated events/blobs (a
  missing event with no peer holding it is gone — TB4).
- Cancellation is eventual (signed-log); a redeeming peer that committed before
  the cancellation reached it is not recalled.
- The control-protocol core is **scaffolding, not a reviewed boundary**: it has
  no wire format, and its enforcement gaps are recorded as
  [F2](phase-1-security-review.md#f2--blocker-no-control-wire-format-exists-to-approve)
  and [F3](phase-1-security-review.md#f3--high-jeliya-control-core-does-not-enforce-the-attributed-properties).
  The encrypted transport and the daemon's exposure of the gateway are Phase 2
  (D5b), under the [D5b/D6 review gate](#deferred-surface--the-d5bd6-control-wire-review-gate).
- At-rest encryption's password fallback is explicit, not the OS keystore
  (D1c lanes pending). Encryption is **opt-in, not enforced** — see
  [F5](phase-1-security-review.md#f5--high-production-encryption-is-opt-in-not-enforced),
  corrected in [Step 4](phase-1-security-review.md#remediation-path).

## Self-review findings (2026-07-21) — superseded

> **Superseded 2026-07-21 by the [Phase 1 security review — findings record](phase-1-security-review.md).**
> The self-review below recommended APPROVE-WITH-CONDITIONS; the independent
> review rejected that and returned NOT APPROVED with 10 findings. This section
> is retained for historical context (the specific fixes and carry-overs are
> real), but its severity assessments and its "design is sound" conclusion are
> **not authoritative**. In particular: the Argon2id attribution "RFC 9106
> example-1 tier" is wrong (F6 — it is the OWASP minimum); the zeroize claims
> are overclaimed (F8); "no P1/critical" is superseded by the 3 blockers the
> independent review found. Read this section against the findings record, not
> as a stand-alone assessment.

An implementer self-review (this is **not** the review row #7 requires — that
needs a different reviewer; this section exists so the reviewer starts from a
finding list rather than re-discovering it). The self-review found **no
P1/critical** issue; the design is sound. Findings and dispositions:

### Fixed in tree (this pass)

- **`recovery.rs` — parsed payload seeds not zeroized.** `open_bundle` zeroized
  the decrypted `plaintext` Vec but not the `PayloadV1.identity_secret`/
  `device_secret` Strings (the actual seed hex). Now zeroized right after the
  `SigningKey`s are constructed.
- **`jeliya-control` — no internal synchronization (invariant documented).**
  `ControlGateway::authorize`/`install`/`revoke` are `&mut self`; the replay
  window is only correct under external serialization. Documented as a
  security-critical invariant on the struct — the D5b daemon wiring must hold a
  mutex around every mutation.
- **`identity.rs` — silent plaintext create.** `create`/`write_existing` with no
  password now `tracing::warn!` (the load-time warning already existed), so an
  accidental plaintext store is visible in the daemon log.
- **`recovery.rs` — `test_restore` second-copy risk.** `test_restore` now writes
  the throwaway restored copy ENCRYPTED under a fresh ephemeral password, so a
  cleanup failure cannot leave a second *plaintext* root identity under the
  data dir.
- **`identity.rs` — version-byte collision guard.** Added
  `const _: () = assert!(ENCRYPTED_VERSION != b'{');` so a future envelope
  version bump cannot collide with the plaintext JSON marker that load uses to
  auto-detect format.

### Carry-overs for D5b (Phase 2 — out of the Phase-1 state-machine scope)

- **Per-room scope binding.** A `RoomRead`/`MessageSend` grant is global; ADR #2
  decision 6 names "selected-room." `authorize` gains a room id and the record
  carries an allowed-rooms set at the D5b transport seam.
- **Persistence and session teardown.** A daemon restart drops control-key
  records (re-pair required); revocation must tear down an in-flight transport
  session (ADR #2 decision 9). Both are D5b daemon-wiring concerns.

### Accepted / deferred (P3, informational)

- **Argon2id params** (m=19 MiB, t=2, p=1) are the RFC 9106 example-1 tier —
  legitimate and versioned; recommend strengthening (m=46–64 MiB) in a
  pre-release hardening pass before the encrypted file is exposed broadly.
- **Env-var password is process-environment-readable** (`/proc/PID/environ`);
  acceptable for the loopback daemon; the durable fix is the OS keystore (D1c).
- **SAS has no domain-separation tag** and is ~32 bits — acceptable for
  human-in-the-loop; Phase 2's Noise transcript binding strengthens it.
- **Bundle `profile_version` is not validated** against a known value (the
  on-disk `SecretFile.version` is checked on load). Minor.

### Confirmed sound (no finding)

Nonce freshness (CSPRNG per seal) in both AEAD uses; AES-256-GCM choice;
replay-window correctness (in-window / out-of-order / below-floor / exact-replay
/ nonce-0, all tested); scope default-deny and `room.join` not being a silent
scope (A1); the load-time seed↔profile consistency check that mitigates an
encrypted→plaintext downgrade; restore clobber refusal; bundle
tamper/version/wrong-key fail-closed.

## Review target pin

> **Finding F1** ([mutable review target](phase-1-security-review.md#f1--blocker-mutable-review-target))
> required an immutable pin. This section records it. A reviewer reproduces the
> review by checking out the source SHA and verifying every field below matches;
> a later change to any field in the "reopens review" set requires a re-review
> before the Phase 1 gate can close.

### Pin values (recorded 2026-07-22 against `35b1c5e`)

| Field | Value |
|---|---|
| Source SHA | `35b1c5e60b79a94934c2e3263b60401e76071fc9` (`main`; PR #81) |
| `Cargo.lock` SHA-256 | `f0baf2f1aa821ff2014a9cc4d391867630045e993a30f9332e7c940e8423c516` |
| Rust toolchain (build) | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Rust MSRV (`Cargo.toml`) | `1.91` |
| Node | `v24.18.0` |
| Worktree at pin time | clean (`git status --porcelain` empty) |
| Pin date (UTC) | 2026-07-22 |

### Reviewed surfaces (last-change SHA)

| Surface | File | Last changed |
|---|---|---|
| At-rest identity envelope | [`crates/jeliya-core/src/identity.rs`](../crates/jeliya-core/src/identity.rs) | `4a73922` (PR #79) |
| Recovery bundle | [`crates/jeliya-core/src/recovery.rs`](../crates/jeliya-core/src/recovery.rs) | `4a73922` (PR #79) |
| Authority path (F4) | [`crates/jeliya-core/src/engine.rs`](../crates/jeliya-core/src/engine.rs) | `cdcae83` (PR #78) |

### Normative ADR revisions

| ADR | Document | Last changed | Status |
|---|---|---|---|
| ADR #3 (recovery bundle) | [`docs/recovery-bundle-decision.md`](recovery-bundle-decision.md) | `ce49d73` (PR #80) | `canonical` / `partial` (Amendments A+B) |
| ADR #2 (control protocol) | [`docs/companion-control-protocol-decision.md`](companion-control-protocol-decision.md) | `ce49d73` (PR #80) | `proposal` (D5b/D6 target) |

### Crypto dependency versions (from `Cargo.lock`)

| Crate | Version |
|---|---|
| `aes-gcm` | `0.10.3` |
| `argon2` | `0.5.3` |
| `blake3` | `1.8.5` |
| `zeroize` | `1.9.0` |
| `getrandom` | `0.2.17` |
| `hex` | `0.4.3` |

### Reopens review

Any of the following after this pin invalidates the review and requires a
re-review (record a new pin before the Step 7 re-review):

- A change to `crates/jeliya-core/src/identity.rs` or its tests.
- A change to `crates/jeliya-core/src/recovery.rs` or its tests.
- A change to ADR #3 ([recovery-bundle-decision.md](recovery-bundle-decision.md))
  or ADR #2 ([companion-control-protocol-decision.md](companion-control-protocol-decision.md)).
- A version change in `Cargo.lock` to any crypto dependency listed above
  (`aes-gcm`, `argon2`, `blake3`, `zeroize`, `getrandom`, `hex`).
- A change to the KDF parameters (`ARGON_M_COST`, `ARGON_T_COST`,
  `ARGON_P_COST`) or the envelope format constants (`ENCRYPTED_VERSION`,
  `BUNDLE_VERSION`, `PAYLOAD_VERSION`, `ARGON_SALT_LEN`, `AEAD_NONCE_LEN`).
- A change to the Rust toolchain that affects codegen of the reviewed files
  (a rustc version bump; MSRV stays `1.91`).

### Does not reopen review

- Documentation-only changes to docs not listed as normative ADRs above.
- UI changes (`ui/`).
- Changes to other crates (`jeliyad`, `jeliya-control`, `jeliya-core/src/`
  files other than `identity.rs` / `recovery.rs` / their tests).
- CI/workflow changes that do not affect the build outputs of the reviewed
  files.
- The remediation steps themselves (Steps 3–6) update this pin before the
  Step 7 re-review; those updates are expected, not reopenings.

### Provisional status

This pin is **provisional**. The [remediation path](phase-1-security-review.md#remediation-path)
includes:
- **Step 4** (F5/F7/F4/F8) — may add the daemon-auth/single-user boundary to
  the reviewed-surface set (F4); does not change `identity.rs` or `recovery.rs`
  code but may change their docs.
- **Step 5** (F6) — **changes `identity.rs`** to encode authenticated KDF
  params per envelope version. This reopens the code surface; the pin will be
  re-recorded after Step 5 lands.

The **final pin** is recorded when Steps 3–6 are all complete, immediately
before the Step 7 re-review. A reviewer executing the Step 7 re-review should
verify the pin values against the tree they are reviewing, not against the
provisional values recorded here.

## Citations

- [Phase 1 security review — findings record](phase-1-security-review.md) — the NOT APPROVED verdict (10 findings) and the remediation path; authoritative input that supersedes the self-review below.
- [Phase 1 gate verdict](phase-1-gate-verdict.md) — row #7 re-scoped to the two D1 envelopes; status NOT APPROVED (remediation in progress).
- [Recovery bundle decision (ADR #3)](recovery-bundle-decision.md) — `canonical` / `partial`; the bundle format and custody, amended 2026-07-21 (grouped-hex phrase, password wrap = Phase 2).
- [Companion control protocol decision (ADR #2)](companion-control-protocol-decision.md) — `proposal`; the pairing transcript and scope model the D5b/D6 gate reviews against.
- [Production deployment decision — amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name) — the browser-authority boundary.
