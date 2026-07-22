---
type: "Reference"
title: "Phase 1 security review scope"
description: "The review package for Phase 1 gate row #7: the wire formats, key lifecycle, and enforcement surfaces an independent reviewer must approve, with the exact files, tests, and design rationale behind each."
tags: ["security", "review", "phase-1", "cryptography", "identity", "control-protocol"]
timestamp: "2026-07-21T21:30:00Z"
status: "canonical"
implementation_status: "implemented"
verification_status: "partial"
release_status: "unreleased"
audience: ["security-reviewers", "maintainers"]
---

# Phase 1 security review scope

This is the review package for [Phase 1 gate row #7](phase-1-gate-verdict.md#7-independent-security-review-approves-the-wire-formats-and-key-lifecycle--pending):
the independent security review of the wire formats and key lifecycle introduced
by Phase 1. It scopes what to review, where the code and tests are, and the
design rationale behind each choice, so a reviewer who was not the implementer
can reach an approval (or record conditions) efficiently. The review's outcome
updates the [Phase 1 verdict](phase-1-gate-verdict.md) row #7 from PENDING.

The implementer cannot self-satisfy row #7; this document is the input, not the
verdict.

## Surfaces under review

Three modules carry the new cryptography and key-lifecycle logic. All merged to
`main` as `cdcae83…` (PR #78).

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

### 3. Control-protocol core — `crates/jeliya-control/src/lib.rs` (ADR #2, amendment A1)

The host-independent gateway every scoped companion RPC will cross (gate row #6).
Review the pairing/SAS, the scope model, and the replay/expiry/revocation
enforcement.

- **Pairing + SAS:** `Pairing::sas` derives a ~32-bit short authentication
  string (BLAKE3 over both public keys, role-symmetric, two 5-digit groups). A
  MITM substituting either key changes the SAS; the user compares both displays.
  `Pairing::confirm` yields a `ControlKeyRecord` only on a matching SAS.
- **Control key (A1):** non-extractable public key (the private half never
  leaves the browser); a **bounded lifetime as a duration** (`expires_at_ms` =
  created + lifetime); default-deny scopes; immediate revocation.
- **Gateway:** `ControlGateway::authorize` is the single enforcement point,
  fixed order identity → revocation → expiry → scope → replay. A denial advances
  no granting state.
- **Replay defense:** a sliding per-key window (`REPLAY_WINDOW = 64`); the
  highest nonce seen plus a bounded `seen` set; out-of-order gaps in-window
  accepted, exact replays and below-floor nonces rejected. Nonce 0 rejected;
  clients start at 1.
- **Assess:** SAS entropy and the comparison model (Phase 1 binds identities;
  Phase 2's Noise handshake binds the DH transcript — confirm the upgrade path);
  replay-window correctness under concurrency; that scope is default-deny and
  `room.join` is NOT a silent scope (A1 confused-deputy — confirmation lands at
  the D5b transport seam); the per-room scope binding (deferred to D5b, named in
  ADR #2 decision 6).

## Key lifecycle summary

| Secret | Where it lives | Protection | Rotation / revocation |
|---|---|---|---|
| Identity + device seeds (root authority) | `identity.secret` on the daemon's data dir | `0600` plaintext (dev) or AES-256-GCM under `JELIYA_IDENTITY_PASSWORD` (prod) | not yet (Phase 4 multi-device revocation); `recovery.export` is the only backup |
| Recovery key (256-bit random) | user-held (phrase); never persisted by the daemon | out of band | rotate by re-exporting under a fresh key |
| Browser control key (per pairing) | browser WebCrypto non-extractable; public half on the companion | non-extractable + bounded lifetime + default-deny scopes | immediate revocation via `ControlGateway::revoke` |

## Test evidence to rely on

The reviewer should read the tests that back each gate row (cited in the
[Phase 1 verdict](phase-1-gate-verdict.md)) and confirm they actually prove the
security property (not just the happy path). Of particular interest:

- `crates/jeliya-core/src/recovery.rs`: `open_rejects_a_wrong_recovery_key`,
  `open_rejects_a_tampered_bundle`, `open_rejects_an_unknown_version`,
  `restore_to_dir_reproduces_a_loadable_identity_in_a_fresh_install`.
- `crates/jeliya-core/src/identity.rs`: `create_with_password_seals_the_secret_not_plaintext`,
  `load_with_a_wrong_password_fails_closed`,
  `load_an_encrypted_secret_without_a_password_fails_closed`.
- `crates/jeliya-control/src/lib.rs`: the four fail-closed assertions plus
  `scope_is_default_deny`, `out_of_order_nonces_inside_the_window_are_accepted`,
  `nonce_below_the_window_floor_is_rejected`, `sas_changes_when_either_key_is_substituted`.

## Honest boundaries the review should confirm are communicated

- Recovery restores identity *authority*, not unreplicated events/blobs (a
  missing event with no peer holding it is gone — TB4).
- Cancellation is eventual (signed-log); a redeeming peer that committed before
  the cancellation reached it is not recalled.
- The control-protocol core is the state machine; the encrypted transport and
  the daemon's exposure of the gateway are Phase 2 (D5b).
- At-rest encryption's password fallback is explicit, not the OS keystore
  (D1c lanes pending).

## Self-review findings (2026-07-21)

An implementer self-review (this is **not** the independent review row #7
requires — that needs a different reviewer; this section exists so the
independent reviewer starts from a finding list rather than re-discovering it).
The self-review found **no P1/critical** issue; the design is sound. Findings
and dispositions:

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

## Citations

- [Phase 1 gate verdict](phase-1-gate-verdict.md) — row #7 is the open condition this package discharges.
- [Recovery bundle decision (ADR #3)](recovery-bundle-decision.md) — the bundle format and custody.
- [Companion control protocol decision (ADR #2)](companion-control-protocol-decision.md) — the pairing transcript and scope model.
- [Production deployment decision — amendment A1](production-deployment-decision.md#a1-bound-the-companions-authority-to-what-the-browser-may-name) — the browser-authority boundary.
