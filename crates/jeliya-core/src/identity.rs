//! Device identity persistence under `--data-dir`, mirroring the iroh-rooms
//! CLI's on-disk layout (IR-0101): a public `identity.json` profile and a
//! secret-bearing `identity.secret`, both owner-only (`0600`, dir `0700`).
//!
//! **At-rest encryption (Phase 1 D1b, gate row #2).** When a password is
//! configured (the `JELIYA_IDENTITY_PASSWORD` env var, or the `_with` variants
//! in tests), `identity.secret` is sealed as a versioned AES-256-GCM envelope
//! keyed by Argon2id(password, salt) — the "explicit, password-hardened
//! fallback" of [Production deployment architecture](../../docs/production-deployment.md).
//! Without a password the seeds are stored plaintext under owner-only
//! permissions (the SDK MVP threat model) — the dev/test default. [`SecretKeys::load`]
//! auto-detects the format from the file's first byte (`{` ⇒ plaintext JSON;
//! the envelope version byte ⇒ encrypted), so an existing plaintext identity
//! keeps loading after a password is introduced (with a warning). OS-backed
//! keystores (Keychain / DPAPI / Secret Service) are a future backend.

use std::fs::OpenOptions;
use std::io::{ErrorKind as IoErrorKind, Write};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use iroh_rooms::identity::SigningKey;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CoreError, CoreResult, ErrorKind};

/// Public profile file name.
pub const IDENTITY_FILE: &str = "identity.json";
/// Secret seed file name (the ONLY file holding secrets).
pub const SECRET_FILE: &str = "identity.secret";
/// On-disk format version (mirrors the CLI's).
const PROFILE_VERSION: u32 = 1;
/// Ed25519 seed length.
const SEED_LEN: usize = 32;
/// Display name recorded in the profile — the daemon protocol has no name
/// parameter on `identity.create`, so a fixed local default is used.
const DEFAULT_NAME: &str = "jeliya";

/// The env var a daemon reads for the at-rest password (Phase 1 D1b). When set,
/// [`create`]/[`write_existing`] seal `identity.secret` and [`SecretKeys::load`]
/// decrypts it. When unset, the seeds are stored plaintext (the dev default).
pub const IDENTITY_PASSWORD_ENV: &str = "JELIYA_IDENTITY_PASSWORD";

/// First byte of an encrypted `identity.secret` (envelope version). A plaintext
/// file starts with `{` (`0x7B`), so the first byte distinguishes the formats
/// unambiguously and [`SecretKeys::load`] can auto-detect without a sidecar.
const ENCRYPTED_VERSION: u8 = 1;
// Guard against a future version bump colliding with the plaintext JSON marker
// `{` (0x7B), which would break load's auto-detection.
const _: () = assert!(ENCRYPTED_VERSION != b'{');
/// Argon2id salt length.
const ARGON_SALT_LEN: usize = 16;
/// AES-256-GCM nonce length (96 bits).
const AEAD_NONCE_LEN: usize = 12;
/// AEAD key length (256 bits).
const AEAD_KEY_LEN: usize = 32;
/// Argon2id memory cost (KiB). Versioned via the envelope; changing it is a
/// migration, not a silent break. Initial value is the RFC 9106 example-1 tier
/// — legitimate and fast; strengthening before launch is a security-review item.
const ARGON_M_COST: u32 = 19_456;
/// Argon2id time cost (iterations).
const ARGON_T_COST: u32 = 2;
/// Argon2id parallelism (lanes).
const ARGON_P_COST: u32 = 1;

/// Read the at-rest password from [`IDENTITY_PASSWORD_ENV`] (empty ⇒ `None`).
fn password_from_env() -> Option<String> {
    std::env::var(IDENTITY_PASSWORD_ENV)
        .ok()
        .filter(|s| !s.is_empty())
}

/// Derive a 256-bit AEAD key from `password` and `salt` via Argon2id.
fn derive_kek(password: &str, salt: &[u8]) -> CoreResult<[u8; AEAD_KEY_LEN]> {
    let params = Params::new(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, Some(AEAD_KEY_LEN))
        .map_err(|e| CoreError::internal(format!("invalid Argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| CoreError::internal(format!("Argon2 derivation failed: {e}")))?;
    Ok(*key)
}

/// Seal `plaintext` (the JSON secret body) into `version || salt || nonce || ct+tag`.
fn encrypt_secret_bytes(plaintext: &[u8], password: &str) -> CoreResult<Vec<u8>> {
    let mut salt = [0u8; ARGON_SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|e| CoreError::internal(format!("OS CSPRNG unavailable: {e}")))?;
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| CoreError::internal(format!("OS CSPRNG unavailable: {e}")))?;
    let key = derive_kek(password, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| CoreError::internal("could not encrypt identity.secret"))?;
    let mut out = Vec::with_capacity(1 + ARGON_SALT_LEN + AEAD_NONCE_LEN + ciphertext.len());
    out.push(ENCRYPTED_VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open an encrypted envelope back to the plaintext JSON body. Fails closed on
/// truncation, an unknown version, or a wrong password (AEAD tag mismatch).
fn decrypt_secret_bytes(blob: &[u8], password: &str) -> CoreResult<Vec<u8>> {
    let header = 1 + ARGON_SALT_LEN + AEAD_NONCE_LEN;
    if blob.len() < header {
        return Err(CoreError::internal(
            "encrypted identity.secret is truncated",
        ));
    }
    let version = blob[0];
    if version != ENCRYPTED_VERSION {
        return Err(CoreError::internal(format!(
            "unsupported encrypted identity.secret version {version}"
        )));
    }
    let salt = &blob[1..1 + ARGON_SALT_LEN];
    let nonce = Nonce::from_slice(&blob[1 + ARGON_SALT_LEN..1 + ARGON_SALT_LEN + AEAD_NONCE_LEN]);
    let ciphertext = &blob[header..];
    let key = derive_kek(password, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher.decrypt(nonce, ciphertext).map_err(|_| {
        CoreError::invalid(
            "could not decrypt identity.secret (wrong password, or the file is corrupt)",
        )
        .with_hint("set JELIYA_IDENTITY_PASSWORD to the identity's password")
    })
}

/// The public identity profile (no secret bytes; safe to serialize/log).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    /// On-disk format version.
    pub version: u32,
    /// Local display name.
    pub name: String,
    /// `sender_id` public key, lowercase hex (64 chars).
    pub identity_id: String,
    /// `device_id` public key, lowercase hex (64 chars).
    pub device_id: String,
    /// Creation time (ms since epoch).
    pub created_at_ms: u64,
}

/// The two secret signing keys backing the local identity. No
/// `Debug`/`Serialize`, so a stray format call cannot leak a seed.
pub struct SecretKeys {
    /// Signs the device binding (authorizes `device_id` under `sender_id`).
    pub identity: SigningKey,
    /// Signs events; signatures verify under `device_id`.
    pub device: SigningKey,
}

/// On-disk shape of `identity.secret`; zeroized after use.
#[derive(serde::Deserialize)]
struct SecretFile {
    version: u32,
    identity_secret: String,
    device_secret: String,
}

impl Zeroize for SecretFile {
    fn zeroize(&mut self) {
        self.identity_secret.zeroize();
        self.device_secret.zeroize();
    }
}

/// Create the data directory owner-only (`0700` on Unix).
pub fn ensure_dir(dir: &Path) -> CoreResult<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| CoreError::internal(format!("could not create {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            CoreError::internal(format!(
                "could not set permissions on {}: {e}",
                dir.display()
            ))
        })?;
    }
    Ok(())
}

/// Load the public profile, or `Ok(None)` if no identity exists yet.
pub fn load_profile(data_dir: &Path) -> CoreResult<Option<Profile>> {
    let path = data_dir.join(IDENTITY_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == IoErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(CoreError::internal(format!(
                "could not read {}: {err}",
                path.display()
            )))
        }
    };
    let profile = serde_json::from_slice(&bytes).map_err(|e| {
        CoreError::internal(format!("corrupt identity file {}: {e}", path.display()))
    })?;
    Ok(Some(profile))
}

/// Create a fresh identity (and device) keypair under `data_dir`, using the
/// at-rest password from [`IDENTITY_PASSWORD_ENV`] (encrypted when set,
/// plaintext when unset).
///
/// # Errors
/// [`ErrorKind::IdentityExists`] if either identity file already exists.
pub fn create(data_dir: &Path) -> CoreResult<Profile> {
    let pw = password_from_env();
    create_with(data_dir, pw.as_deref())
}

/// Like [`create`] but with an explicit at-rest password (`Some` ⇒ encrypted
/// `identity.secret`, `None` ⇒ plaintext). Tests use this to avoid touching the
/// process environment.
pub fn create_with(data_dir: &Path, password: Option<&str>) -> CoreResult<Profile> {
    ensure_dir(data_dir)?;
    let identity_path = data_dir.join(IDENTITY_FILE);
    let secret_path = data_dir.join(SECRET_FILE);
    if identity_path.exists() || secret_path.exists() {
        return Err(CoreError::new(
            ErrorKind::IdentityExists,
            format!("an identity already exists in {}", data_dir.display()),
        ));
    }

    let identity_key = SigningKey::generate();
    let device_key = SigningKey::generate();
    let profile = Profile {
        version: PROFILE_VERSION,
        name: DEFAULT_NAME.to_owned(),
        identity_id: identity_key.identity_key().to_string(),
        device_id: device_key.device_key().to_string(),
        created_at_ms: crate::now_ms(),
    };
    let profile_json = serde_json::to_vec(&profile)
        .map_err(|e| CoreError::internal(format!("could not encode identity.json: {e}")))?;

    write_secret_and_profile(
        &secret_path,
        &identity_path,
        &identity_key,
        &device_key,
        &profile_json,
        password,
        data_dir,
    )?;
    Ok(profile)
}

/// Write an already-existing identity (a caller-supplied profile + secret keys)
/// into a fresh `data_dir` — the restore side of Phase 1 D1 recovery — using the
/// at-rest password from [`IDENTITY_PASSWORD_ENV`]. Like [`create`], it refuses
/// to clobber an existing identity and writes both files owner-only; unlike
/// [`create`] it does not generate new keys. The supplied profile's public ids
/// must match the keys (a restored bundle whose halves disagree is rejected,
/// mirroring [`SecretKeys::load`]'s guard).
pub fn write_existing(data_dir: &Path, profile: &Profile, keys: &SecretKeys) -> CoreResult<()> {
    let pw = password_from_env();
    write_existing_with(data_dir, profile, keys, pw.as_deref())
}

/// Like [`write_existing`] but with an explicit at-rest password.
pub fn write_existing_with(
    data_dir: &Path,
    profile: &Profile,
    keys: &SecretKeys,
    password: Option<&str>,
) -> CoreResult<()> {
    ensure_dir(data_dir)?;
    let identity_path = data_dir.join(IDENTITY_FILE);
    let secret_path = data_dir.join(SECRET_FILE);
    if identity_path.exists() || secret_path.exists() {
        return Err(CoreError::new(
            ErrorKind::IdentityExists,
            format!("an identity already exists in {}", data_dir.display()),
        ));
    }
    if keys.identity.identity_key().to_string() != profile.identity_id
        || keys.device.device_key().to_string() != profile.device_id
    {
        return Err(CoreError::internal(
            "cannot write an identity whose secret keys do not match the profile",
        ));
    }
    let profile_json = serde_json::to_vec(profile)
        .map_err(|e| CoreError::internal(format!("could not encode identity.json: {e}")))?;
    write_secret_and_profile(
        &secret_path,
        &identity_path,
        &keys.identity,
        &keys.device,
        &profile_json,
        password,
        data_dir,
    )?;
    Ok(())
}

/// Write `identity.secret` (sealed with `password` when set; plaintext
/// otherwise) then `identity.json`, both owner-only and exclusive. The secret
/// JSON bytes are zeroized after use. Maps the TOCTOU `AlreadyExists` to
/// [`ErrorKind::IdentityExists`].
fn write_secret_and_profile(
    secret_path: &Path,
    identity_path: &Path,
    identity_key: &SigningKey,
    device_key: &SigningKey,
    profile_json: &[u8],
    password: Option<&str>,
    data_dir: &Path,
) -> CoreResult<()> {
    let map_io = |e: std::io::Error| -> CoreError {
        if e.kind() == IoErrorKind::AlreadyExists {
            CoreError::new(
                ErrorKind::IdentityExists,
                format!("an identity already exists in {}", data_dir.display()),
            )
        } else {
            CoreError::internal(format!(
                "could not write identity files to {}: {e}",
                data_dir.display()
            ))
        }
    };
    // The only secret-bearing buffer; zeroized after it is sealed or written.
    let mut plaintext = secret_file_contents(identity_key, device_key).into_bytes();
    let secret_write = match password {
        Some(pw) => {
            let sealed = encrypt_secret_bytes(&plaintext, pw)
                .map_err(|e| CoreError::internal(format!("could not seal identity.secret: {e}")));
            plaintext.zeroize();
            sealed.and_then(|enc| write_new_owner_only(secret_path, &enc).map_err(map_io))
        }
        None => {
            tracing::warn!(
                "identity.secret is being written PLAINTEXT (no password configured); \
                 set {} to seal it at rest",
                IDENTITY_PASSWORD_ENV,
            );
            let w = write_new_owner_only(secret_path, &plaintext);
            plaintext.zeroize();
            w.map_err(map_io)
        }
    };
    secret_write.and_then(|()| write_new_owner_only(identity_path, profile_json).map_err(map_io))
}

impl SecretKeys {
    /// Load and cross-check the secret keys against the public profile, using
    /// the at-rest password from [`IDENTITY_PASSWORD_ENV`]. Auto-detects whether
    /// `identity.secret` is plaintext or encrypted (Phase 1 D1b).
    ///
    /// # Errors
    /// [`ErrorKind::IdentityMissing`] if no identity exists; [`ErrorKind::InvalidParams`]
    /// if the file is encrypted but no password is set, or the password is
    /// wrong; internal errors on corruption or a secret/public mismatch. No
    /// seed bytes appear in errors.
    pub fn load(data_dir: &Path) -> CoreResult<Self> {
        let pw = password_from_env();
        Self::load_with(data_dir, pw.as_deref())
    }

    /// Like [`SecretKeys::load`] but with an explicit at-rest password. The
    /// format is auto-detected from the file's first byte, so a plaintext
    /// identity keeps loading after a password is introduced (with a warning):
    /// the gate is that a fresh identity created with a password is sealed, not
    /// that legacy plaintext files are force-migrated on read (which would race
    /// under concurrent loads).
    pub fn load_with(data_dir: &Path, password: Option<&str>) -> CoreResult<Self> {
        let path = data_dir.join(SECRET_FILE);
        let blob = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == IoErrorKind::NotFound => {
                return Err(CoreError::new(
                    ErrorKind::IdentityMissing,
                    format!("no identity in {}", data_dir.display()),
                ));
            }
            Err(err) => {
                return Err(CoreError::internal(format!(
                    "could not read {}: {err}",
                    path.display()
                )))
            }
        };
        // Auto-detect: a plaintext file begins with `{`; an encrypted envelope
        // begins with its version byte (which is never `{`).
        let mut plaintext_bytes = if blob.first() == Some(&b'{') {
            if password.is_some() {
                tracing::warn!(
                    "identity.secret is stored plaintext although a password is configured; \
                     re-create the identity (or recovery.restore) under the password to seal it at rest"
                );
            }
            blob
        } else {
            let pw = password.ok_or_else(|| {
                CoreError::invalid(
                    "identity.secret is encrypted; set JELIYA_IDENTITY_PASSWORD to unlock it",
                )
            })?;
            decrypt_secret_bytes(&blob, pw)?
        };
        let parsed: Result<SecretFile, _> = serde_json::from_slice(&plaintext_bytes);
        plaintext_bytes.zeroize();
        let mut parsed = parsed.map_err(|_| {
            CoreError::internal(format!("identity files are corrupt: {}", path.display()))
        })?;
        let keys = Self::from_secret_file(&parsed);
        parsed.zeroize();
        let keys = keys?;

        // Consistency guard: seeds must reproduce the public profile.
        let profile = load_profile(data_dir)?.ok_or_else(|| {
            CoreError::new(
                ErrorKind::IdentityMissing,
                format!("no identity in {}", data_dir.display()),
            )
        })?;
        if keys.identity.identity_key().to_string() != profile.identity_id
            || keys.device.device_key().to_string() != profile.device_id
        {
            return Err(CoreError::internal(format!(
                "identity files are inconsistent (secret keys do not match identity.json) in {}",
                data_dir.display()
            )));
        }
        Ok(keys)
    }

    fn from_secret_file(file: &SecretFile) -> CoreResult<Self> {
        if file.version != PROFILE_VERSION {
            return Err(CoreError::internal(format!(
                "unsupported identity.secret version {}",
                file.version
            )));
        }
        Ok(Self {
            identity: signing_key_from_seed_hex(&file.identity_secret)?,
            device: signing_key_from_seed_hex(&file.device_secret)?,
        })
    }
}

/// Decode a 32-byte seed from lowercase hex; intermediates are zeroized.
fn signing_key_from_seed_hex(seed_hex: &str) -> CoreResult<SigningKey> {
    let mut raw =
        hex::decode(seed_hex).map_err(|_| CoreError::internal("secret seed is not valid hex"))?;
    let key = if let Ok(seed) = <[u8; SEED_LEN]>::try_from(raw.as_slice()) {
        let seed = Zeroizing::new(seed);
        SigningKey::from_seed(&seed)
    } else {
        raw.zeroize();
        return Err(CoreError::internal("secret seed has the wrong length"));
    };
    raw.zeroize();
    Ok(key)
}

/// Build the `identity.secret` body; the caller must zeroize the result.
fn secret_file_contents(identity_key: &SigningKey, device_key: &SigningKey) -> String {
    let identity_seed = identity_key.to_seed();
    let device_seed = device_key.to_seed();
    let mut identity_hex = hex::encode(identity_seed.as_slice());
    let mut device_hex = hex::encode(device_seed.as_slice());
    let contents = format!(
        "{{\"version\":{PROFILE_VERSION},\"identity_secret\":\"{identity_hex}\",\
         \"device_secret\":\"{device_hex}\"}}\n"
    );
    identity_hex.zeroize();
    device_hex.zeroize();
    contents
}

/// Create `path` exclusively with owner-only permissions and write `bytes`.
fn write_new_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::{create, create_with, load_profile, SecretKeys, IDENTITY_FILE, SECRET_FILE};
    use crate::error::ErrorKind;
    use tempfile::tempdir;

    #[test]
    fn create_then_load_roundtrips() {
        let dir = tempdir().unwrap();
        let profile = create(dir.path()).unwrap();
        assert_eq!(profile.identity_id.len(), 64);
        assert_eq!(profile.device_id.len(), 64);
        assert_ne!(profile.identity_id, profile.device_id);
        let loaded = load_profile(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.identity_id, profile.identity_id);
        let keys = SecretKeys::load(dir.path()).unwrap();
        assert_eq!(
            keys.identity.identity_key().to_string(),
            profile.identity_id
        );
        assert_eq!(keys.device.device_key().to_string(), profile.device_id);
    }

    #[test]
    fn second_create_is_identity_exists() {
        let dir = tempdir().unwrap();
        create(dir.path()).unwrap();
        let err = create(dir.path()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::IdentityExists);
    }

    #[test]
    fn load_missing_secret_is_identity_missing() {
        let dir = tempdir().unwrap();
        // SecretKeys has no Debug (so a stray {:?} can never leak a seed);
        // unwrap the error side manually.
        let err = match SecretKeys::load(dir.path()) {
            Ok(_) => panic!("load must fail with no identity"),
            Err(err) => err,
        };
        assert_eq!(err.kind, ErrorKind::IdentityMissing);
    }

    #[test]
    fn load_profile_missing_is_none() {
        let dir = tempdir().unwrap();
        assert!(load_profile(dir.path()).unwrap().is_none());
    }

    #[test]
    fn secret_never_leaks_into_identity_json() {
        let dir = tempdir().unwrap();
        create(dir.path()).unwrap();
        let json = std::fs::read_to_string(dir.path().join(IDENTITY_FILE)).unwrap();
        assert!(!json.contains("identity_secret"));
        assert!(std::fs::read_to_string(dir.path().join(SECRET_FILE))
            .unwrap()
            .contains("identity_secret"));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempdir().unwrap();
        create(dir.path()).unwrap();
        for name in [IDENTITY_FILE, SECRET_FILE] {
            let mode = std::fs::metadata(dir.path().join(name)).unwrap().mode();
            assert_eq!(mode & 0o777, 0o600, "{name} must be 0600");
        }
    }

    // ------------------------------------------------------------------
    // Phase 1 D1b — at-rest encryption (gate row #2)
    // ------------------------------------------------------------------

    /// Read the first byte of `identity.secret` (0x7B `{` ⇒ plaintext JSON; the
    /// envelope version byte ⇒ encrypted).
    fn secret_first_byte(dir: &tempfile::TempDir) -> u8 {
        std::fs::read(dir.path().join(SECRET_FILE)).unwrap()[0]
    }

    #[test]
    fn create_with_password_seals_the_secret_not_plaintext() {
        // The Phase 1 D1b gate: in production mode (password set), the on-disk
        // secret is NOT the plaintext JSON.
        let dir = tempdir().unwrap();
        let profile = create_with(dir.path(), Some("correct horse battery staple")).unwrap();
        assert_ne!(
            secret_first_byte(&dir),
            b'{',
            "a password-created identity.secret must not be plaintext JSON"
        );
        // And it still loads + reproduces the public ids.
        let keys = SecretKeys::load_with(dir.path(), Some("correct horse battery staple")).unwrap();
        assert_eq!(
            keys.identity.identity_key().to_string(),
            profile.identity_id
        );
        assert_eq!(keys.device.device_key().to_string(), profile.device_id);
    }

    #[test]
    fn encrypted_secret_stays_owner_only() {
        let dir = tempdir().unwrap();
        create_with(dir.path(), Some("pw")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode = std::fs::metadata(dir.path().join(SECRET_FILE))
                .unwrap()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "encrypted identity.secret must be 0600"
            );
        }
    }

    #[test]
    fn load_with_a_wrong_password_fails_closed() {
        let dir = tempdir().unwrap();
        create_with(dir.path(), Some("right-pw")).unwrap();
        let err = match SecretKeys::load_with(dir.path(), Some("wrong-pw")) {
            Ok(_) => panic!("a wrong password must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, ErrorKind::InvalidParams);
    }

    #[test]
    fn load_an_encrypted_secret_without_a_password_fails_closed() {
        let dir = tempdir().unwrap();
        create_with(dir.path(), Some("right-pw")).unwrap();
        let err = match SecretKeys::load_with(dir.path(), None) {
            Ok(_) => panic!("an encrypted secret without a password must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, ErrorKind::InvalidParams);
    }

    #[test]
    fn plaintext_identity_still_loads_after_a_password_is_introduced() {
        // Backward compatibility: an identity created without a password stays
        // plaintext on disk, and a later load with a password set still reads it
        // (auto-detect), so introducing JELIYA_IDENTITY_PASSWORD does not lock
        // existing dev identities out.
        let dir = tempdir().unwrap();
        let profile = create_with(dir.path(), None).unwrap();
        assert_eq!(
            secret_first_byte(&dir),
            b'{',
            "no-password create is plaintext"
        );
        let keys = SecretKeys::load_with(dir.path(), Some("now-a-password")).unwrap();
        assert_eq!(
            keys.identity.identity_key().to_string(),
            profile.identity_id
        );
    }

    #[test]
    fn wrong_password_does_not_leak_seed_bytes_in_the_error() {
        let dir = tempdir().unwrap();
        create_with(dir.path(), Some("right-pw")).unwrap();
        let err = match SecretKeys::load_with(dir.path(), Some("wrong-pw")) {
            Ok(_) => panic!("a wrong password must fail closed"),
            Err(e) => e,
        };
        let msg = format!("{err:?}{err}");
        assert!(!msg.contains("identity_secret"), "no seed field name");
        // The encrypted bytes on disk do not start with the plaintext JSON marker.
        let on_disk = std::fs::read(dir.path().join(SECRET_FILE)).unwrap();
        assert!(!on_disk.starts_with(b"{"));
    }
}
