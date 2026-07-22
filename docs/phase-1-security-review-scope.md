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

This is the review package for [Phase 1 gate row #7](phase-1-gate-verdict.md#7-independent-security-review-approves-the-wire-formats-and-the-key-lifecycle--approve-with-conditions-re-review-landed-2026-07-22):
the security review of the wire formats and key lifecycle introduced by Phase 1.
**Re-scoped 2026-07-22 per [finding F2](phase-1-security-review.md#f2--blocker-no-control-wire-format-exists-to-approve)**:
row #7 covers the **two D1 envelopes only** — the at-rest `identity.secret`
envelope and the recovery-bundle envelope — plus their key lifecycle. The
control-protocol wire does not exist yet (there is no framing, serialization,
handshake, or daemon binding), so there is nothing byte-level to review on the
control side. The control wire gets its own **D5b/D6 review gate** (see
[Deferred surface — the D5b/D6 control-wire review gate](#deferred-surface--the-d5bd6-control-wire-review-gate)).

The [original review landed 2026-07-21](phase-1-security-review.md) and
returned **NOT APPROVED** with 10 findings; the remediation path (Steps 0–6)
completed, and the **Step 7 independent re-review landed 2026-07-22 with
[APPROVE-WITH-CONDITIONS](phase-1-security-review.md#step-7-re-review-verdict-2026-07-22)**
against the pin below (no blocker or high; conditions tracked). This document
is the input package, not the verdict; the verdict lives in the
[findings record](phase-1-security-review.md).

## Surfaces under review

**Two modules carry the D1 wire formats and key-lifecycle logic under row #7.**
A third module — the control-protocol core — is **deferred to the D5b/D6 gate**
because it has no wire format to review (see
[Deferred surface](#deferred-surface--the-d5bd6-control-wire-review-gate)).

> **The review target is pinned and finalized** — see
> [Review target pin](#review-target-pin). A reviewer checks out `df28f6a`
> and verifies the `Cargo.lock` hash, toolchain, and ADR revisions match.
> Steps 0–6 of the
> [remediation path](phase-1-security-review.md#remediation-path) are complete;
> the pin is ready for the Step 7 re-review.

### 1. At-rest identity encryption — `crates/jeliya-core/src/identity.rs`

The on-disk `identity.secret` is sealed when `JELIYA_IDENTITY_PASSWORD` is set
(gate row #2). Review the envelope, the KDF, and the fallback policy.

- **Envelope:** `version(1) || salt(16) || nonce(12) || ciphertext+tag`, AES-256-GCM
  over the legacy plaintext-JSON body. The first byte (`{` vs the version byte)
  lets `load` auto-detect the format without a sidecar.
  ([`encrypt_secret_bytes`](../crates/jeliya-core/src/identity.rs),
  [`decrypt_secret_bytes`](../crates/jeliya-core/src/identity.rs)).
- **KDF:** Argon2id, m=19456 KiB, t=2, p=1 (the **OWASP minimum** for
  Argon2id, not an RFC 9106 profile — corrected per [F6](phase-1-security-review.md#f6--high-kdf-versioningattribution-is-inaccurate)),
  output 32 bytes. Params are an **immutable per-version set**: v1 maps to
  `V1_KDF` via `kdf_params_for_version`; changing params requires a version
  bump, and the v1 reader stays as the legacy dispatch. The **latency** target
  is measured by `kdf_derivation_is_memory_hard` (wall-clock; memory/RSS
  verification is Step 6 evidence work).
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
- **Assess:** the AEAD choice and nonce handling; the `restore_to_dir` clobber
  refusal and the secret/public id consistency check on import. **Zeroize
  claims are recast** — see [Zeroization (recast per F8)](#zeroization-recast-per-f8).

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
| Recovery key (256-bit random) | user-held (phrase); never persisted by the daemon | out of band | re-export adds a backup; old material is irrevocable until root authority rotates (Phase 4) — see [F7](phase-1-security-review.md#f7--high-rotate-by-re-exporting-is-false) |
| Browser control key (per pairing) | browser WebCrypto non-extractable; public half on the companion | non-extractable + bounded lifetime + default-deny scopes | immediate revocation via `ControlGateway::revoke` — **D5b/D6 scope, not Phase 1 row #7** |

> **Recovery-key lifecycle (corrected per [F7](phase-1-security-review.md#f7--high-rotate-by-re-exporting-is-false)).**
> The previous text said "rotate by re-exporting under a fresh key," which is
> false. `recovery::export_bundle` mints a fresh random `RecoveryKey` and a
> fresh valid bundle; it does not revoke, invalidate, or retire any prior key
> or bundle. `open_bundle` accepts any valid bundle for the same identity; AEAD
> cannot detect rollback of an older-but-valid bundle. There is no bundle
> generation, supersession list, or revocation concept. **Every prior recovery
> key and bundle remains valid indefinitely** until root authority itself
> rotates (Phase 4 multi-device revocation). Residual risks: (a) a duplicated
> device seed exported in a prior bundle stays valid; (b) a lost device whose
> authority was backed up retains authority until root rotation; (c) an
> attacker who obtained an old bundle+key has permanent identity authority
> that cannot be revoked short of Phase 4 root rotation.

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

## Zeroization (recast per F8)

> **[Finding F8](phase-1-security-review.md#f8--high-test-evidence-overclaims-zeroization)**:
> the prior test evidence overclaimed zeroization. Functional round-trip and
> tamper tests exercise correctness, not zeroization — they never inspect the
> process's former heap. `wrong_password_does_not_leak_seed_bytes_in_the_error`
> checks a field-name literal and the `{` marker, not seed bytes. This section
> recasts the claim as a source/dependency audit + a secret-data-flow inventory.
> The full audit (with measured evidence) is [Step 6](phase-1-security-review.md#remediation-path)
> work; this section records what is known now.

### Known zeroize gaps (source audit — Step 6 fixes applied)

| Secret | Where it lives in memory | Current handling | Gap |
|---|---|---|---|
| KEK (Argon2id output, identity.rs) | `derive_kek` returns `Zeroizing<[u8; 32]>` (Step 6 fix) | Wiped on drop at every call site | **Resolved (Step 6)** — return type is `Zeroizing`; callers receive a wiping wrapper |
| Recovery key (`RecoveryKey`) | `RecoveryKey([u8; 32])` with `Drop` impl that calls `zeroize()` | Wiped on drop | Appears correct; verify no intermediate copies |
| Raw seeds from `to_seed()` (identity.rs `secret_file_contents`, recovery.rs `export_bundle`) | iroh-rooms `SigningKey::to_seed()` returns a plain `[u8; 32]` by value | Wrapped in `Zeroizing` at all four call sites in the pinned surfaces (Step 7 verdict condition 1) | **Residual**: the by-value return can leave transient stack temporaries (full fix is an upstream self-wiping return type). Two further call sites in `supervisor.rs` (lines ~854/~1607, device-key handoff to the session layer) are outside row #7's pinned surfaces — noted by the conditions delta review for the next zeroize pass |
| Password (identity.rs) | `password: &str` borrowed from a `String` the caller owns | The env-var `String` is plain; no wipe | Accepted: the env var outlives the process anyway (in the [accepted-risk register](phase-1-evidence-package.md#accepted-risks)) |
| Ephemeral test-restore password (recovery.rs `test_restore`) | `Zeroizing<String>` (Step 7 verdict condition 3) | Wiped on drop | — |
| Recovery phrase (recovery.rs) | `RecoveryKey::from_phrase` builds `stripped` as `Zeroizing<String>` (Step 6 fix) | Wiped on drop; pre-sized with `with_capacity` so growth cannot leave unwiped realloc copies (Step 7 verdict condition 3) | **Resolved (Step 6 + Step 7 condition 3)** |
| Seed hex intermediates | `PayloadV1.identity_secret` / `device_secret` as `String` in `open_bundle` and `export_bundle` | Import side: moved to `Zeroizing<String>` after parse. Export side: wiped before a serialization error can propagate (Step 7 verdict condition 3) | Correct |
| Plaintext JSON bytes | `plaintext: Vec<u8>` in `encrypt_secret_bytes` / `open_bundle` / `load_with` | Zeroized after use | Correct |

### Dependency feature audit (Step 6)

| Crate | Version | `zeroize` feature | Status |
|---|---|---|---|
| `aes-gcm` | `0.10.3` | `features = ["zeroize"]` in `Cargo.toml` | **Enabled (Step 6)** — AES round keys wiped on drop |
| `argon2` | `0.5.3` | `features = ["zeroize"]` in `Cargo.toml` | **Enabled (Step 6)** — internal Argon2 state wiped on drop |

A reviewer should still verify at Step 7 that the enabled features produce
measurable heap-wiping (RSS/heap inspection), not just that the cargo features
are declared.

## Honest boundaries the review should confirm are communicated

- **The actual root-authority path is the daemon token, not the file mode
  ([finding F4](phase-1-security-review.md#f4--high-scope-omits-the-actual-authority-path)).**
  Root authority is reached through [`engine.rs`](../crates/jeliya-core/src/engine.rs)
  (the 24-method dispatch table with no per-method auth) via a WebSocket
  authenticated by the per-start daemon bearer token. The token is handed out by
  [`/api/session`](../crates/jeliyad/src/serve.rs) whose `Origin` /
  `Sec-Fetch-Site` checks are browser-shaped — forgeable by any non-browser
  local process (e.g. `curl` can set any header). The route performs no token
  comparison; the constant-time bearer comparison guards only `/ws` and
  `/api/files/*`. The [threat model](security-threat-model.md) admits this
  (lines 226–231): a hostile same-user local process can forge the session
  header, get the daemon token, and reach the full root+device authority
  surface over WS. **At-rest encryption and `0600` do not help** — the token is
  the authority, not the file mode. The binding assumption is single-user,
  single-OS-account operation, documented in
  [`docs/PROTOCOL.md`](PROTOCOL.md) ("The trust boundary is a single-user
  machine"). A co-resident companion inherits this exclusion; the weaker of the
  two surfaces bounds the pair. This surface is in the review pin's
  [reopen set](#review-target-pin) (`engine.rs` is a reviewed surface) but its
  full inclusion depends on whether the user chooses to enforce a same-user
  socket boundary or widen the scope at a later step.
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
- At-rest encryption is **opt-in, not enforced** — see
  [F5](phase-1-security-review.md#f5--high-production-encryption-is-opt-in-not-enforced).
  The gate-verdict row #2 is relabeled OPEN; encryption works when a password
  is set but no production path sets or requires one.

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

- **Argon2id params** (m=19 MiB, t=2, p=1) are the **OWASP minimum** for
  Argon2id (corrected per F6; the prior "RFC 9106 example-1 tier" attribution
  was wrong). Now pinned as an immutable per-version param-set via
  `kdf_params_for_version`; strengthening requires a version bump to v2.
  hardening pass before the encrypted file is exposed broadly (RFC 9106 §7.4
  recommends m=2 GiB/t=1/p=4 or m=64 MiB/t=3/p=4).
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

### Pin values (re-recorded 2026-07-22 after the conditions merge)

> Pin history: `35b1c5e` (Step 3) → `df28f6a` (Step 6; the Step 7 verdict and
> GO were recorded against it) → `d610076` (verdict conditions, PR #89; the
> approval [extends to it](phase-1-security-review.md#conditions-delta-review-2026-07-22)).

| Field | Value |
|---|---|
| Source SHA | `d610076c05f0f29cb8f87c7dbe805a5f603ecc89` (`main`; PR #89, verdict-conditions merge) |
| `Cargo.lock` SHA-256 | `dda192b513195ca512587d01609aeb5d89447001fc04549aca538a3d0c31b223` |
| Rust toolchain (CI full gate) | `1.96.0` (stable; `dtolnay/rust-toolchain` in `ci.yml` with `toolchain: 1.96.0`) |
| Rust MSRV (CI MSRV lane) | `1.91.0` (`dtolnay/rust-toolchain` `1.91.0` in `ci.yml` and `release.yml`) |
| Node (CI + release) | `22.22.3` (pinned in `ci.yml` and `release.yml` `node-version`) |
| Local builder (this pin was recorded with) | `rustc 1.97.1`, Node `v24.18.0` — not the release toolchain; recorded for transparency only |
| Worktree at pin time | clean (`git status --porcelain` empty) |
| Pin date (UTC) | 2026-07-22 |

### Reviewed surfaces (last-change SHA)

| Surface | File | Last changed |
|---|---|---|
| At-rest identity envelope | [`crates/jeliya-core/src/identity.rs`](../crates/jeliya-core/src/identity.rs) | `d610076` (PR #89, verdict conditions) |
| Recovery bundle | [`crates/jeliya-core/src/recovery.rs`](../crates/jeliya-core/src/recovery.rs) | `d610076` (PR #89, verdict conditions) |
| Authority path (F4) | [`crates/jeliya-core/src/engine.rs`](../crates/jeliya-core/src/engine.rs) | `cdcae83` (PR #78) |
| Daemon auth (F4) | [`crates/jeliyad/src/serve.rs`](../crates/jeliyad/src/serve.rs) | `922f620` (PR #58; created the file, unchanged since) |

### Normative ADR revisions

| ADR | Document | Last changed | Status |
|---|---|---|---|
| ADR #3 (recovery bundle) | [`docs/recovery-bundle-decision.md`](recovery-bundle-decision.md) | `d610076` (PR #89; condition-6 corrections, delta-reviewed) | `canonical` / `partial` (Amendments A+B; F7 lifecycle fix; condition-6 corrections) |
| ADR #2 (control protocol) | [`docs/companion-control-protocol-decision.md`](companion-control-protocol-decision.md) | `ce49d73` (PR #80) | `proposal` (D5b/D6 target) |

### Crypto dependency versions (from `Cargo.lock`)

Direct dependencies of `crates/jeliya-core` (the reviewed surfaces):

| Crate | Direct dep (`Cargo.toml`) | Resolved (`Cargo.lock`) |
|---|---|---|
| `aes-gcm` | `"0.10"` | `0.10.3` |
| `argon2` | `"0.5"` | `0.5.3` |
| `zeroize` | `"1"` | `1.9.0` |
| `getrandom` | `"0.4"` | `0.4.3` |
| `hex` | `"0.4"` | `0.4.3` |

> **`getrandom` disambiguation.** `Cargo.lock` contains three `getrandom`
> entries: `0.2.17` (transitive, from `ring`/other), `0.3.4` (transitive), and
> `0.4.3` (the direct dependency `crates/jeliya-core` uses for CSPRNG fills in
> `identity.rs` and `recovery.rs`). A reviewer validating the RNG should check
> `0.4.3`, not the transitive copies.

Used by `crates/jeliya-control` (deferred to D5b/D6, not Phase 1 row #7):

| Crate | Resolved (`Cargo.lock`) | Used for |
|---|---|---|
| `blake3` | `1.8.5` | SAS derivation in `jeliya-control` (scaffolding; D5b/D6 scope) |

### Reopens review

Any of the following after this pin invalidates the review and requires a
re-review (record a new pin before the Step 7 re-review):

- A change to `crates/jeliya-core/src/identity.rs` or its tests.
- A change to `crates/jeliya-core/src/recovery.rs` or its tests.
- A change to `crates/jeliya-core/src/engine.rs` (the authority path; recorded
  as a reviewed surface for [F4](phase-1-security-review.md#f4--high-scope-omits-the-actual-authority-path)).
  Whether `engine.rs` is fully in scope depends on Step 4; until then a change
  to it reopens review conservatively.
- A change to `crates/jeliyad/src/serve.rs` (the daemon `/api/session` token
  handout and the `/ws` bearer gate — the actual root-authority path per F4).
- A change to [`docs/PROTOCOL.md`](PROTOCOL.md) (the single-user-machine
  assumption that bounds the daemon's trust model).
- A change to ADR #3 ([recovery-bundle-decision.md](recovery-bundle-decision.md))
  or ADR #2 ([companion-control-protocol-decision.md](companion-control-protocol-decision.md)).
- A change to a **review-package document** — this scope doc
  ([phase-1-security-review-scope.md](phase-1-security-review-scope.md)), the
  findings record ([phase-1-security-review.md](phase-1-security-review.md)),
  the gate verdict ([phase-1-gate-verdict.md](phase-1-gate-verdict.md)), or the
  evidence package + approval contract
  ([phase-1-evidence-package.md](phase-1-evidence-package.md))
  — that changes the surfaces under review, the evidence list, the reopen
  rules, the approval contract, or the pin itself. (Editorial fixes that do
  not change meaning — typos, link repairs — do not reopen.)
- A version change in `Cargo.lock` to any crypto dependency listed above
  (`aes-gcm`, `argon2`, `zeroize`, `getrandom`, `hex`; and `blake3` for the
  D5b/D6 gate).
- A change to the KDF parameter set (`V1_KDF`, the `KdfParams` struct,
  `kdf_params_for_version`) or the envelope format constants
  (`ENCRYPTED_VERSION`, `ARGON_SALT_LEN`, `AEAD_NONCE_LEN`). Adding a future
  `V2_KDF` or a new dispatch arm also reopens.
- A change to the Rust toolchain that affects codegen of the reviewed files
  (a rustc version bump in `ci.yml`/`release.yml`; MSRV stays `1.91`).

### Does not reopen review

- Documentation-only changes to docs **not** listed above (i.e., not the
  normative ADRs and not the review-package documents).
- UI changes (`ui/`).
- Changes to other crates (`jeliyad` source files **other than `serve.rs`**,
  `jeliya-control`, `jeliya-core/src/` files other than `identity.rs`,
  `recovery.rs`, `engine.rs`, or their tests).
- CI/workflow changes that do not affect the toolchain versions or build
  outputs of the reviewed files.
- The remediation steps themselves (Steps 3–6) update this pin before the
  Step 7 re-review; those updates are expected, not reopenings.

### Pin status: re-recorded at `d610076` (conditions delta review complete)

The Step 7 re-review approved `df28f6a` (2026-07-22, APPROVE-WITH-CONDITIONS,
GO countersigned); the verdict conditions then merged as `d610076` and the
required **scoped delta review** was executed by an independent delta-review
session, extending the approval to `d610076` — see the
[delta-review record](phase-1-security-review.md#conditions-delta-review-2026-07-22)
for the verdict, the reviewer's statement, and the run-ID erratum it caught.
A reviewer reproducing the current pin should:

1. `git checkout d610076`
2. Verify `sha256sum Cargo.lock` matches `dda192b5…` (unchanged across all
   three pins)
3. Verify the toolchain matches (CI full-gate Rust `1.96.0`, or MSRV `1.91.0`;
   Node `22.22.3`)
4. Run the commands in the [evidence package](phase-1-evidence-package.md#reproduce-the-review)
   (expected: 127 passed / 0 failed / 1 ignored)
5. Verify the pin values above against the tree they checked out

If any value does not match, the pin is stale and the review cannot proceed
until a new pin is recorded. Any future change in the
[reopen set](#reopens-review) requires the same re-pin + delta-review cycle.

## Citations

- [Phase 1 security review — findings record](phase-1-security-review.md) — the NOT APPROVED verdict (10 findings) and the remediation path; authoritative input that supersedes the self-review below.
- [Phase 1 gate verdict](phase-1-gate-verdict.md) — row #7 re-scoped to the two D1 envelopes; status NOT APPROVED (remediation in progress).
- [Recovery bundle decision (ADR #3)](recovery-bundle-decision.md) — `canonical` / `partial`; the bundle format and custody, amended 2026-07-21 (grouped-hex phrase, password wrap = Phase 2).
- [Companion control protocol decision (ADR #2)](companion-control-protocol-decision.md) — `proposal`; the pairing transcript and scope model the D5b/D6 gate reviews against.
- [Production deployment decision — amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name) — the browser-authority boundary.
