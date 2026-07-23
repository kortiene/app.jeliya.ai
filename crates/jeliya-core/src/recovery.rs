//! Phase 1 D1 recovery bundle (ADR #3): a versioned authenticated-encryption
//! envelope keyed by a random 256-bit recovery key, so an accountless Jeliya
//! identity can be backed up and restored to a fresh install.
//!
//! The bundle is the ONLY way to recover an identity whose device is lost — the
//! UI truthfully states the identity is unrecoverable without it. The on-disk
//! daemon secret ([`crate::identity`]) is the at-rest half (Phase 1 D1b, the
//! keystore abstraction); this module is the backup/restore transport: it seals
//! the identity's seeds into a bundle the user holds a recovery key for, and
//! restores them into a fresh data dir.
//!
//! Format (envelope version 1): `version(1) || nonce(12) || ciphertext+tag`,
//! where the ciphertext is AES-256-GCM over a versioned JSON payload (the
//! profile fields plus the two signing seeds as hex). AEAD gives integrity and
//! authenticity, so a tampered, truncated, or rolled-back bundle fails import;
//! the version byte rejects an unknown future format. The recovery key is a
//! random 256-bit value the user holds as a grouped-hex phrase; an optional
//! Argon2id password wrap (ADR #3) is a forward extension, not the first slice.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use iroh_rooms::identity::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CoreError, CoreResult, ErrorKind};
use crate::identity::{self, Profile, SecretKeys};

/// Envelope version (the first byte of every emitted bundle). Bumped only on a
/// breaking change to the outer framing; the sealed payload has its own
/// [`PAYLOAD_VERSION`].
const BUNDLE_VERSION: u8 = 1;
/// AES-256-GCM nonce length (96 bits, the GCM standard).
const NONCE_LEN: usize = 12;
/// Recovery key length (256 bits — the AEAD root).
const KEY_LEN: usize = 32;
/// Sealed payload schema version (migrates independently of the envelope).
const PAYLOAD_VERSION: u32 = 1;
/// Ed25519 seed length (mirrors `identity::SEED_LEN`).
const SEED_LEN: usize = 32;

/// A random 256-bit recovery key the user holds; the AEAD root that seals a
/// recovery bundle. Kept zeroized in memory; the user sees it only as a phrase
/// via [`RecoveryKey::to_phrase`] at export time and must save it out of band.
pub struct RecoveryKey([u8; KEY_LEN]);

impl RecoveryKey {
    /// Generate a fresh random recovery key.
    pub fn generate() -> CoreResult<Self> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(key.as_mut_slice())
            .map_err(|e| CoreError::internal(format!("OS CSPRNG unavailable: {e}")))?;
        Ok(Self(*key))
    }

    /// Render the key as a grouped lowercase-hex phrase (4-char groups joined
    /// by `-`) a user can transcribe. ADR #3 names grouped-base32 as a future
    /// UX refinement; hex needs no new dependency and is unambiguous.
    #[must_use]
    pub fn to_phrase(&self) -> String {
        let hex = hex::encode(self.0);
        let mut out = String::with_capacity(hex.len() + hex.len() / 4);
        for (i, chunk) in hex.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                out.push('-');
            }
            // hex::encode is ASCII, so from_utf8 is infallible.
            out.push_str(std::str::from_utf8(chunk).expect("hex is ascii"));
        }
        out
    }

    /// Parse a grouped-hex phrase (case-insensitive; spaces/dashes/colons/underscores
    /// optional) back into a recovery key.
    pub fn from_phrase(phrase: &str) -> CoreResult<Self> {
        // Parse into a fixed self-wiping buffer instead of a growable String:
        // nothing input-proportional is allocated, so no reallocation can
        // strand an unwiped copy of pasted phrase material, however long or
        // malformed the input (Step 7 verdict condition 3, hardened after the
        // conditions delta review).
        const HEX_LEN: usize = 2 * KEY_LEN;
        let mut hex_buf = Zeroizing::new([0u8; HEX_LEN]);
        let mut n = 0usize;
        for c in phrase.chars() {
            if matches!(c, ' ' | '-' | '_' | ':') {
                continue;
            }
            if n == HEX_LEN {
                return Err(CoreError::invalid(format!(
                    "recovery phrase must decode to exactly {KEY_LEN} bytes (too many characters)"
                )));
            }
            if !c.is_ascii() {
                return Err(CoreError::invalid("recovery phrase is not valid hex"));
            }
            hex_buf[n] = (c as u8).to_ascii_lowercase();
            n += 1;
        }
        if n != HEX_LEN {
            return Err(CoreError::invalid(format!(
                "recovery phrase must decode to exactly {KEY_LEN} bytes (got {n} hex characters)"
            )));
        }
        // decode_to_slice writes into our self-wiping buffer, so even a
        // partial decode of a non-hex input is wiped — hex::decode's error
        // path would drop a partially filled Vec unwiped inside the crate.
        let mut raw = Zeroizing::new([0u8; KEY_LEN]);
        hex::decode_to_slice(&hex_buf[..], raw.as_mut_slice())
            .map_err(|_| CoreError::invalid("recovery phrase is not valid hex"))?;
        Ok(Self(*raw))
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0))
    }
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The sealed payload (JSON; integrity comes from the AEAD tag, not canonical
/// encoding — we both produce and consume it). Carries the profile fields and
/// the two signing seeds as hex, exactly the on-disk `identity.secret` shape.
#[derive(Serialize, Deserialize)]
struct PayloadV1 {
    version: u32,
    profile_version: u32,
    name: String,
    identity_id: String,
    device_id: String,
    created_at_ms: u64,
    identity_secret: String,
    device_secret: String,
}

/// Build a fresh bundle for the identity in `data_dir`, plus the random
/// recovery key that seals it. The recovery key is NOT persisted — the caller
/// (the setup flow) shows it to the user once, who must save the phrase.
pub fn export_bundle_from_dir(data_dir: &Path) -> CoreResult<(Vec<u8>, RecoveryKey)> {
    let profile = identity::load_profile(data_dir)?.ok_or_else(|| {
        CoreError::new(
            ErrorKind::IdentityMissing,
            format!("no identity in {}", data_dir.display()),
        )
    })?;
    let keys = SecretKeys::load(data_dir)?;
    export_bundle(&profile, &keys)
}

/// Build a fresh bundle for a supplied identity.
pub fn export_bundle(profile: &Profile, keys: &SecretKeys) -> CoreResult<(Vec<u8>, RecoveryKey)> {
    let recovery_key = RecoveryKey::generate()?;
    // Extract the seeds as hex; zeroize every intermediate (mirrors
    // `identity::secret_file_contents`). to_seed() returns a plain [u8; 32]
    // by value; wrap immediately so the named copies are wiped (transient
    // stack temporaries from the by-value return remain an upstream
    // limitation).
    let identity_seed = Zeroizing::new(keys.identity.to_seed());
    let device_seed = Zeroizing::new(keys.device.to_seed());
    let mut identity_hex = Zeroizing::new(hex::encode(identity_seed.as_slice()));
    let mut device_hex = Zeroizing::new(hex::encode(device_seed.as_slice()));

    let mut payload = PayloadV1 {
        version: PAYLOAD_VERSION,
        profile_version: profile.version,
        name: profile.name.clone(),
        identity_id: profile.identity_id.clone(),
        device_id: profile.device_id.clone(),
        created_at_ms: profile.created_at_ms,
        identity_secret: identity_hex.as_str().to_owned(),
        device_secret: device_hex.as_str().to_owned(),
    };
    identity_hex.zeroize();
    device_hex.zeroize();

    // Wipe the payload's seed-hex copies BEFORE propagating a serialization
    // error, so the `?` cannot skip the wipe (Step 7 verdict condition 3).
    let encoded = serde_json::to_vec(&payload);
    payload.identity_secret.zeroize();
    payload.device_secret.zeroize();
    let mut plaintext = encoded
        .map_err(|e| CoreError::internal(format!("could not encode recovery payload: {e}")))?;
    let sealed = seal_bundle(&recovery_key, &plaintext);
    plaintext.zeroize();
    sealed.map(|bundle| (bundle, recovery_key))
}

/// Seal `plaintext` into `version || nonce || ciphertext+tag`.
fn seal_bundle(key: &RecoveryKey, plaintext: &[u8]) -> CoreResult<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| CoreError::internal(format!("OS CSPRNG unavailable: {e}")))?;
    let ciphertext = key
        .cipher()
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| CoreError::internal("could not seal the recovery bundle"))?;
    let mut bundle = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    bundle.push(BUNDLE_VERSION);
    bundle.extend_from_slice(&nonce_bytes);
    bundle.extend_from_slice(&ciphertext);
    Ok(bundle)
}

/// Open a sealed bundle and reconstruct the identity it carries. Fails closed
/// on truncation, an unknown version, any tamper (AEAD tag), a malformed
/// payload, or a secret/public id mismatch.
pub fn open_bundle(bundle: &[u8], key: &RecoveryKey) -> CoreResult<(Profile, SecretKeys)> {
    if bundle.len() < 1 + NONCE_LEN {
        return Err(CoreError::invalid("recovery bundle is truncated"));
    }
    let version = bundle[0];
    if version != BUNDLE_VERSION {
        return Err(CoreError::invalid(format!(
            "unsupported recovery bundle version {version} (expected {BUNDLE_VERSION})"
        )));
    }
    let nonce = Nonce::from_slice(&bundle[1..1 + NONCE_LEN]);
    let ciphertext = &bundle[1 + NONCE_LEN..];
    let mut plaintext = key.cipher().decrypt(nonce, ciphertext).map_err(|_| {
        CoreError::invalid(
            "the recovery bundle is corrupt, tampered, or sealed with a different key",
        )
        .with_hint("check the recovery phrase, or obtain a fresh bundle")
    })?;
    // Parse the payload, zeroizing the decrypted plaintext on every path — a
    // malformed payload's `?` would otherwise skip the wipe.
    let mut payload: PayloadV1 = match serde_json::from_slice(&plaintext) {
        Ok(p) => p,
        Err(_) => {
            plaintext.zeroize();
            return Err(CoreError::invalid("the recovery payload is malformed"));
        }
    };
    plaintext.zeroize();
    // Move the seed hex into Zeroizing locals immediately so every later exit
    // (version check, hex decode, consistency check) wipes them on drop — the
    // value of zeroize is on the error paths, not the happy path.
    let identity_hex = Zeroizing::new(std::mem::take(&mut payload.identity_secret));
    let device_hex = Zeroizing::new(std::mem::take(&mut payload.device_secret));
    if payload.version != PAYLOAD_VERSION {
        return Err(CoreError::invalid(format!(
            "unsupported recovery payload version {} (expected {PAYLOAD_VERSION})",
            payload.version
        )));
    }
    let identity_key = signing_key_from_seed_hex(identity_hex.as_str())?;
    let device_key = signing_key_from_seed_hex(device_hex.as_str())?;
    // The seeds must reproduce the bundle's public ids — a bundle whose halves
    // disagree is rejected whole, trusting neither side.
    if identity_key.identity_key().to_string() != payload.identity_id
        || device_key.device_key().to_string() != payload.device_id
    {
        return Err(CoreError::invalid(
            "the recovery bundle's secret keys do not match its profile ids",
        ));
    }
    let profile = Profile {
        version: payload.profile_version,
        name: payload.name,
        identity_id: payload.identity_id,
        device_id: payload.device_id,
        created_at_ms: payload.created_at_ms,
    };
    Ok((
        profile,
        SecretKeys {
            identity: identity_key,
            device: device_key,
        },
    ))
}

/// Restore a bundle into a fresh `target_dir`, writing the identity files the
/// daemon loads on its next start. Refuses to clobber an existing identity
/// (the caller points it at an empty data dir).
pub fn restore_to_dir(target_dir: &Path, bundle: &[u8], key: &RecoveryKey) -> CoreResult<Profile> {
    let (profile, keys) = open_bundle(bundle, key)?;
    identity::write_existing(target_dir, &profile, &keys)?;
    Ok(profile)
}

/// Export the identity in `data_dir` and re-import it into a throwaway sibling
/// dir, asserting the restored identity matches the source — the ADR #3
/// "successful test restore completes setup" gate. The test dir is removed on
/// return (including the error path).
pub fn test_restore(data_dir: &Path) -> CoreResult<()> {
    let (bundle, key) = export_bundle_from_dir(data_dir)?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|e| CoreError::internal(format!("OS CSPRNG unavailable: {e}")))?;
    let test_dir = data_dir.join(format!(".restore-test-{}", hex::encode(nonce)));
    let _cleanup = CleanUp(&test_dir);

    // Write the restored copy ENCRYPTED under a fresh ephemeral password, so
    // that a cleanup failure cannot leave a second *plaintext* copy of the
    // root identity under the data dir. The password is random and discarded.
    let mut pw_bytes = [0u8; 32];
    getrandom::fill(&mut pw_bytes)
        .map_err(|e| CoreError::internal(format!("OS CSPRNG unavailable: {e}")))?;
    // KEK-equivalent for the test-restore copy; wiped on drop (Step 7
    // verdict condition 3).
    let ephemeral_pw = Zeroizing::new(hex::encode(pw_bytes));
    pw_bytes.zeroize();
    let (profile, keys) = open_bundle(&bundle, &key)?;
    identity::write_existing_with(&test_dir, &profile, &keys, Some(ephemeral_pw.as_str()))?;

    let src = identity::load_profile(data_dir)?.ok_or_else(|| {
        CoreError::internal("no source identity after export (data dir changed mid-test?)")
    })?;
    let restored = identity::load_profile(&test_dir)?
        .ok_or_else(|| CoreError::internal("restore wrote no identity into the test dir"))?;
    if restored.identity_id != src.identity_id || restored.device_id != src.device_id {
        return Err(CoreError::internal(
            "test restore: restored profile ids do not match the source",
        ));
    }
    let restored_keys = SecretKeys::load_with(&test_dir, Some(ephemeral_pw.as_str()))?;
    if restored_keys.identity.identity_key().to_string() != src.identity_id
        || restored_keys.device.device_key().to_string() != src.device_id
    {
        return Err(CoreError::internal(
            "test restore: restored secret keys do not match the source profile",
        ));
    }
    Ok(())
}

/// Decode a 32-byte seed from hex; intermediates are zeroized.
fn signing_key_from_seed_hex(seed_hex: &str) -> CoreResult<SigningKey> {
    let mut raw =
        hex::decode(seed_hex).map_err(|_| CoreError::invalid("secret seed is not valid hex"))?;
    let key = if let Ok(seed) = <[u8; SEED_LEN]>::try_from(raw.as_slice()) {
        let seed = Zeroizing::new(seed);
        SigningKey::from_seed(&seed)
    } else {
        raw.zeroize();
        return Err(CoreError::invalid("secret seed has the wrong length"));
    };
    raw.zeroize();
    Ok(key)
}

/// RAII removal of the test-restore dir (best-effort; errors are ignored — the
/// dir lives under the owner-only data dir and is harmless if it lingers).
struct CleanUp<'a>(&'a Path);

impl Drop for CleanUp<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use tempfile::tempdir;

    fn seeded_dir() -> (tempfile::TempDir, Profile) {
        let dir = tempdir().unwrap();
        let profile = identity::create(dir.path()).unwrap();
        (dir, profile)
    }

    #[test]
    fn recovery_key_phrase_round_trips() {
        for _ in 0..64 {
            let key = RecoveryKey::generate().unwrap();
            let phrase = key.to_phrase();
            let again = RecoveryKey::from_phrase(&phrase).unwrap();
            assert_eq!(again.0, key.0, "phrase must round-trip the key");
        }
    }

    #[test]
    fn recovery_key_phrase_is_case_and_separator_insensitive() {
        let key = RecoveryKey::generate().unwrap();
        let upper = key.to_phrase().to_uppercase().replace('-', " ");
        let again = RecoveryKey::from_phrase(&upper).unwrap();
        assert_eq!(again.0, key.0);
    }

    #[test]
    fn recovery_key_phrase_rejects_wrong_length_and_garbage() {
        assert!(RecoveryKey::from_phrase("nothex!!").is_err());
        assert!(RecoveryKey::from_phrase(&"ab".repeat(31)).is_err());
        assert!(RecoveryKey::from_phrase(&"ab".repeat(33)).is_err());
        assert!(RecoveryKey::from_phrase("é".repeat(32).as_str()).is_err());
    }

    #[test]
    fn recovery_key_phrase_rejects_an_overlong_paste() {
        // A paste that embeds a real key inside surrounding text must be
        // rejected; the fixed-buffer parser allocates nothing proportional to
        // the input, so no heap copy of the paste can be stranded unwiped.
        let key = RecoveryKey::generate().unwrap();
        let paste = format!(
            "my recovery key: {} {}",
            key.to_phrase(),
            "x".repeat(10_000)
        );
        assert!(RecoveryKey::from_phrase(&paste).is_err());
    }

    #[test]
    fn restored_identity_reproduces_room_device_keys() {
        // Issue #91: room-scoped device keys are DERIVED from the profile
        // device seed, so the recovery bundle covers every room device —
        // including rooms joined after the export — with no bundle change.
        // A restored identity must reproduce the exact per-room device key
        // its membership bindings carry, or restored users could read but
        // never author in their rooms.
        let (dir, _profile) = seeded_dir();
        let original = identity::SecretKeys::load(dir.path()).unwrap();
        let room_id = [0x5Au8; 32];

        let (bundle, key) = export_bundle_from_dir(dir.path()).unwrap();
        let (_p2, restored) = open_bundle(&bundle, &key).unwrap();
        assert_eq!(
            restored.room_device(&room_id).device_key(),
            original.room_device(&room_id).device_key(),
            "a restored identity must reproduce its room-scoped device keys"
        );
    }

    #[test]
    fn export_then_open_round_trips_the_identity() {
        let (dir, profile) = seeded_dir();
        let (bundle, key) = export_bundle_from_dir(dir.path()).unwrap();
        let (p2, keys2) = open_bundle(&bundle, &key).unwrap();
        assert_eq!(p2.identity_id, profile.identity_id);
        assert_eq!(p2.device_id, profile.device_id);
        // The restored keys reproduce the public ids.
        assert_eq!(
            keys2.identity.identity_key().to_string(),
            profile.identity_id
        );
        assert_eq!(keys2.device.device_key().to_string(), profile.device_id);
    }

    #[test]
    fn open_rejects_a_wrong_recovery_key() {
        let (dir, _profile) = seeded_dir();
        let (bundle, _) = export_bundle_from_dir(dir.path()).unwrap();
        let wrong = RecoveryKey::generate().unwrap();
        let err = match open_bundle(&bundle, &wrong) {
            Ok(_) => panic!("a wrong recovery key must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.kind == ErrorKind::InvalidParams,
            "wrong key must fail closed"
        );
    }

    #[test]
    fn open_rejects_a_tampered_bundle() {
        let (dir, _profile) = seeded_dir();
        let (mut bundle, key) = export_bundle_from_dir(dir.path()).unwrap();
        // Flip a ciphertext byte (past version + nonce). AEAD must catch it.
        let last = bundle.len() - 1;
        bundle[last] ^= 0x01;
        let err = match open_bundle(&bundle, &key) {
            Ok(_) => panic!("a tampered bundle must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.kind == ErrorKind::InvalidParams,
            "tamper must fail closed"
        );
    }

    #[test]
    fn open_rejects_an_unknown_version() {
        let (dir, _profile) = seeded_dir();
        let (mut bundle, key) = export_bundle_from_dir(dir.path()).unwrap();
        bundle[0] = 255;
        let err = match open_bundle(&bundle, &key) {
            Ok(_) => panic!("an unknown bundle version must fail closed"),
            Err(err) => err,
        };
        assert!(err.kind == ErrorKind::InvalidParams);
    }

    #[test]
    fn restore_to_dir_reproduces_a_loadable_identity_in_a_fresh_install() {
        // The Phase 1 D1 gate: recovery succeeds from a fresh install.
        let (dir, profile) = seeded_dir();
        let (bundle, key) = export_bundle_from_dir(dir.path()).unwrap();

        let fresh = tempdir().unwrap();
        let restored = restore_to_dir(fresh.path(), &bundle, &key).unwrap();
        assert_eq!(restored.identity_id, profile.identity_id);

        // The fresh install loads the identity and the keys reproduce the ids.
        let loaded = identity::load_profile(fresh.path()).unwrap().unwrap();
        assert_eq!(loaded.identity_id, profile.identity_id);
        assert_eq!(loaded.device_id, profile.device_id);
        let keys = SecretKeys::load(fresh.path()).unwrap();
        assert_eq!(
            keys.identity.identity_key().to_string(),
            profile.identity_id
        );
    }

    #[test]
    fn restore_refuses_to_clobber_an_existing_identity() {
        let (dir, _profile) = seeded_dir();
        let (bundle, key) = export_bundle_from_dir(dir.path()).unwrap();
        // Same data dir already has an identity → refuse, do not overwrite.
        let err = restore_to_dir(dir.path(), &bundle, &key).unwrap_err();
        assert_eq!(err.kind, ErrorKind::IdentityExists);
    }

    #[test]
    fn test_restore_passes_on_a_live_identity() {
        let (dir, _profile) = seeded_dir();
        test_restore(dir.path()).unwrap();
        // The test dir is cleaned up.
        assert!(!std::fs::read_dir(dir.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".restore-test-")));
    }

    #[test]
    fn export_fails_when_no_identity_exists() {
        let dir = tempdir().unwrap();
        let err = match export_bundle_from_dir(dir.path()) {
            Ok(_) => panic!("export must fail when no identity exists"),
            Err(err) => err,
        };
        assert_eq!(err.kind, ErrorKind::IdentityMissing);
    }
}
