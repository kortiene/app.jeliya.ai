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

/// Argon2id KDF parameters for an encrypted-identity envelope version. Each
/// envelope version maps to exactly one immutable `KdfParams`; changing the
/// params requires a version bump, and the reader dispatches by version so
/// older envelopes always open with their original params.
struct KdfParams {
    /// Memory cost (KiB).
    m_cost: u32,
    /// Time cost (iterations).
    t_cost: u32,
    /// Parallelism (lanes).
    p_cost: u32,
}

/// Envelope version 1 KDF parameters. These are the **OWASP minimum** for
/// Argon2id (per the OWASP Password Storage Cheat Sheet), **not** an RFC 9106
/// profile — RFC 9106 section 7.4 recommends two Argon2id profiles:
/// m=2 GiB/t=1/p=4 (high-memory) and m=64 MiB/t=3/p=4 (memory-constrained).
/// The previous attribution ("RFC 9106 example-1 tier") was wrong; corrected
/// per finding F6. These values are **immutable**: changing them requires
/// bumping [`ENCRYPTED_VERSION`] to 2, and this const set stays as the v1
/// legacy reader so existing identity files keep loading.
const V1_KDF: KdfParams = KdfParams {
    m_cost: 19_456,
    t_cost: 2,
    p_cost: 1,
};

/// Return the immutable KDF parameters for `version`. This is the legacy
/// dispatch: v1 envelopes always derive with `V1_KDF`, regardless of what the
/// current sealing version is. A future v2 with stronger params would add a
/// `2 => &V2_KDF` arm here; v1 files keep loading unchanged.
fn kdf_params_for_version(version: u8) -> CoreResult<&'static KdfParams> {
    match version {
        1 => Ok(&V1_KDF),
        // An unknown version is malformed/future user data, not a program bug.
        _ => Err(CoreError::invalid(format!(
            "unsupported encrypted identity.secret version {version}"
        ))),
    }
}

/// Read the at-rest password from [`IDENTITY_PASSWORD_ENV`] (empty ⇒ `None`).
fn password_from_env() -> Option<String> {
    std::env::var(IDENTITY_PASSWORD_ENV)
        .ok()
        .filter(|s| !s.is_empty())
}

/// Derive a 256-bit AEAD key from `password` and `salt` via Argon2id under the
/// given immutable `params` (dispatched by envelope version). Returns a
/// `Zeroizing` wrapper so the key is wiped on drop at every call site.
fn derive_kek(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> CoreResult<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    let argon_params = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(AEAD_KEY_LEN),
    )
    .map_err(|e| CoreError::internal(format!("invalid Argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| CoreError::internal(format!("Argon2 derivation failed: {e}")))?;
    Ok(key)
}

/// Seal `plaintext` (the JSON secret body) into `version || salt || nonce || ct+tag`.
fn encrypt_secret_bytes(plaintext: &[u8], password: &str) -> CoreResult<Vec<u8>> {
    let mut salt = [0u8; ARGON_SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|e| CoreError::internal(format!("OS CSPRNG unavailable: {e}")))?;
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| CoreError::internal(format!("OS CSPRNG unavailable: {e}")))?;
    let key = {
        let params = kdf_params_for_version(ENCRYPTED_VERSION)?;
        derive_kek(password, &salt, params)?
    };
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
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
    let params = kdf_params_for_version(version)?;
    let salt = &blob[1..1 + ARGON_SALT_LEN];
    let nonce = Nonce::from_slice(&blob[1 + ARGON_SALT_LEN..1 + ARGON_SALT_LEN + AEAD_NONCE_LEN]);
    let ciphertext = &blob[header..];
    let key = derive_kek(password, salt, params)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
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
    // to_seed() returns a plain [u8; 32] by value; wrap immediately so the
    // named copies are wiped on every exit path (transient stack temporaries
    // from the by-value return remain an upstream limitation).
    let identity_seed = Zeroizing::new(identity_key.to_seed());
    let device_seed = Zeroizing::new(device_key.to_seed());
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
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
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

    // ------------------------------------------------------------------
    // Phase 1 remediation Step 5 — KDF param versioning (F6)
    // ------------------------------------------------------------------

    #[test]
    fn v1_kdf_params_are_pinned() {
        // Migration fixture (F6): if anyone changes V1_KDF, this test fails,
        // alerting them that identity files sealed under the old params would
        // break. Changing params requires bumping ENCRYPTED_VERSION to 2 and
        // keeping this const set as the immutable v1 legacy reader.
        assert_eq!(
            super::V1_KDF.m_cost,
            19_456,
            "v1 m_cost is the OWASP minimum"
        );
        assert_eq!(super::V1_KDF.t_cost, 2);
        assert_eq!(super::V1_KDF.p_cost, 1);
    }

    #[test]
    fn v1_identity_round_trips_through_version_dispatch() {
        // The version dispatch (kdf_params_for_version) must open v1
        // envelopes with the v1 param set, regardless of the current sealing
        // version. This is the legacy-read guarantee.
        let dir = tempdir().unwrap();
        let profile = create_with(dir.path(), Some("dispatch-test-pw")).unwrap();
        let keys = SecretKeys::load_with(dir.path(), Some("dispatch-test-pw")).unwrap();
        assert_eq!(
            keys.identity.identity_key().to_string(),
            profile.identity_id
        );
    }

    #[test]
    fn v1_legacy_dispatch_opens_a_v1_envelope_regardless_of_sealing_version() {
        // Migration fixture (F6): explicitly construct a version-1 envelope
        // and prove the reader opens it via the 1 => &V1_KDF dispatch arm,
        // independent of what ENCRYPTED_VERSION currently is. If a future v2
        // bump changes the sealing version, this test still exercises v1.
        let plaintext = br#"{"version":1,"identity_secret":"deadbeef","device_secret":"cafebabe"}"#;
        let password = "legacy-fixture-pw";
        // Seal under V1_KDF explicitly (not via encrypt_secret_bytes, which
        // uses whatever ENCRYPTED_VERSION currently is).
        let salt = [0xABu8; super::ARGON_SALT_LEN];
        let nonce = [0xCDu8; super::AEAD_NONCE_LEN];
        let key = super::derive_kek(password, &salt, &super::V1_KDF).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), &plaintext[..])
            .unwrap();
        // Build the v1 envelope: version(1) || salt || nonce || ct+tag.
        let mut blob = Vec::with_capacity(1 + salt.len() + nonce.len() + ciphertext.len());
        blob.push(1u8); // explicitly version 1
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        // The reader must open it.
        let opened = super::decrypt_secret_bytes(&blob, password).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn unknown_envelope_version_is_rejected() {
        let dir = tempdir().unwrap();
        create_with(dir.path(), Some("pw")).unwrap();
        let mut blob = std::fs::read(dir.path().join(SECRET_FILE)).unwrap();
        blob[0] = 255; // unknown future version
        let err = match super::decrypt_secret_bytes(&blob, "pw") {
            Ok(_) => panic!("unknown version must fail"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind,
            ErrorKind::InvalidParams,
            "an unknown version is malformed user data, not an internal error"
        );
        assert!(err.message.contains("version 255"));
    }

    #[test]
    fn truncated_encrypted_secret_fails_closed() {
        // Step 7 verdict condition 4: exercise the header-bounds branch the
        // evidence table previously claimed only implicitly.
        let dir = tempdir().unwrap();
        create_with(dir.path(), Some("pw")).unwrap();
        let blob = std::fs::read(dir.path().join(SECRET_FILE)).unwrap();
        // Shorter than version(1) || salt(16) || nonce(12).
        let err = match super::decrypt_secret_bytes(&blob[..10], "pw") {
            Ok(_) => panic!("a truncated envelope must fail closed"),
            Err(e) => e,
        };
        assert!(err.message.contains("truncated"));
    }

    #[test]
    fn tampered_encrypted_secret_fails_closed() {
        // Step 7 verdict condition 4: mirror recovery's
        // open_rejects_a_tampered_bundle on the identity envelope.
        let dir = tempdir().unwrap();
        create_with(dir.path(), Some("pw")).unwrap();
        let mut blob = std::fs::read(dir.path().join(SECRET_FILE)).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip a ciphertext/tag bit; the AEAD must catch it
        let err = match super::decrypt_secret_bytes(&blob, "pw") {
            Ok(_) => panic!("a tampered envelope must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.kind, ErrorKind::InvalidParams);
    }

    #[test]
    fn kdf_derivation_is_memory_hard() {
        // Measured target (F6; floor raised per Step 7 verdict condition 2):
        // a single Argon2id derivation under V1_KDF measures 21-41ms locally
        // and ~30-80ms on the CI runner; a 5ms floor is far below every
        // measured value yet above what a non-memory-hard KDF or a collapsed
        // m_cost would take. The memory target itself (VmHWM delta ~19 MiB)
        // is measured by the committed probe harness in tools/step7-kdf-probe
        // (process-wide RSS is not assertable reliably inside a threaded
        // test binary).
        let salt = [0u8; super::ARGON_SALT_LEN];
        let start = std::time::Instant::now();
        let _key = super::derive_kek("latency-test", &salt, &super::V1_KDF).unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() >= 5,
            "KDF derivation took {elapsed:?}; expected >= 5ms (memory-hardness not active?)"
        );
        // Record the measured value for documentation (visible with --nocapture).
        eprintln!(
            "V1_KDF derivation latency: {elapsed:?} (m={}, t={}, p={})",
            super::V1_KDF.m_cost,
            super::V1_KDF.t_cost,
            super::V1_KDF.p_cost
        );
    }
}
