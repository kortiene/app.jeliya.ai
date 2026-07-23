//! Persistence of control-key records across companion restarts. A restart is
//! not a mass revocation, so the granted keys survive it — serialized here as
//! versioned JSON. This module owns the *format* (so the reviewed crate pins
//! it); the host owns the *file I/O*, following the `localstate.rs` discipline
//! (atomic write, fsync, `0600`, a process-global write lock). Replay windows
//! are deliberately **not** persisted: they are per-session, and persisting
//! per-key nonce state would open a rollback-on-crash acceptance window.
//! Revoked records are retained (with `revoked: true`) until expiry so a
//! restart cannot resurrect a revoked key.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::gateway::{ControlKey, ControlKeyRecord, Scope, MAX_LIFETIME};

/// The on-disk store version.
pub const STORE_VERSION: u32 = 1;

/// A persistence error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The JSON did not parse or did not match the schema.
    Json(String),
    /// The store version was not recognized.
    BadVersion(u32),
    /// A key or scope field was malformed.
    Malformed(&'static str),
}

/// One persisted control-key record. The key is stored as lowercase hex so the
/// `0600` JSON file is human-inspectable; scopes are stored as their wire
/// registry ids so the format does not depend on this crate's enum layout.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedKey {
    key_hex: String,
    scopes: Vec<u16>,
    rooms: Vec<String>,
    created_at_ms: u64,
    expires_at_ms: u64,
    last_used_ms: u64,
    revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ControlKeyStore {
    version: u32,
    keys: Vec<PersistedKey>,
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_nibble(b: u8) -> Result<u8, RecordError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(RecordError::Malformed("key_hex digit")),
    }
}

fn from_hex_32(s: &str) -> Result<[u8; 32], RecordError> {
    // Operate on raw bytes, not `&str` slices: a 64-*byte* string can hold a
    // multi-byte UTF-8 char, and slicing it at fixed 2-byte offsets would panic
    // on a non-char-boundary — a bad record must fail closed, never panic.
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(RecordError::Malformed("key_hex length"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (hex_nibble(bytes[i * 2])? << 4) | hex_nibble(bytes[i * 2 + 1])?;
    }
    Ok(out)
}

/// Serialize the gateway's records to the on-disk JSON string. The host writes
/// this atomically to `control_keys.json`.
#[must_use]
pub fn dump_records<'a>(records: impl Iterator<Item = &'a ControlKeyRecord>) -> String {
    let keys = records
        .map(|r| PersistedKey {
            key_hex: to_hex(&r.key().0),
            scopes: r.scopes().map(Scope::registry_id).collect(),
            rooms: r.rooms().map(str::to_owned).collect(),
            created_at_ms: r.created_at_ms(),
            expires_at_ms: r.expires_at_ms(),
            last_used_ms: r.last_used_ms(),
            revoked: r.is_revoked(),
        })
        .collect();
    let store = ControlKeyStore {
        version: STORE_VERSION,
        keys,
    };
    // Pretty-printed to match localstate.rs; serialization of this fixed schema
    // is infallible.
    serde_json::to_string_pretty(&store).expect("control-key store serializes")
}

/// Parse the on-disk JSON string into records the gateway can install. Rejects
/// an unknown version and malformed keys/scopes fail-closed (a bad record is a
/// hard error, not a silently-dropped key — a persisted key silently vanishing
/// would revoke it without a revocation event).
pub fn load_records(json: &str) -> Result<Vec<ControlKeyRecord>, RecordError> {
    let store: ControlKeyStore =
        serde_json::from_str(json).map_err(|e| RecordError::Json(e.to_string()))?;
    if store.version != STORE_VERSION {
        return Err(RecordError::BadVersion(store.version));
    }
    let mut out = Vec::with_capacity(store.keys.len());
    for pk in store.keys {
        let key = ControlKey(from_hex_32(&pk.key_hex)?);
        let mut scopes = BTreeSet::new();
        for id in pk.scopes {
            scopes.insert(Scope::from_registry_id(id).ok_or(RecordError::Malformed("scope id"))?);
        }
        let rooms: BTreeSet<String> = pk.rooms.into_iter().collect();
        // Clamp the stored expiry so a corrupt/hand-edited store cannot mint an
        // unbounded key: no loaded key outlives `created_at + MAX_LIFETIME`. This
        // keeps the "no path to an unbounded key" invariant true on the load
        // path as well as the pairing path.
        let max_expiry = pk
            .created_at_ms
            .saturating_add(MAX_LIFETIME.as_millis() as u64);
        let expires_at_ms = pk.expires_at_ms.min(max_expiry);
        out.push(ControlKeyRecord::from_persisted(
            key,
            scopes,
            rooms,
            pk.created_at_ms,
            expires_at_ms,
            pk.last_used_ms,
            pk.revoked,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::ControlGateway;
    use std::time::Duration;

    #[test]
    fn round_trips_through_json() {
        let mut gw = ControlGateway::new();
        let rec = ControlKeyRecord::new(
            ControlKey([0xAB; 32]),
            [Scope::RoomRead, Scope::MessageSend].into_iter().collect(),
            ["room-1".to_string(), "room-2".to_string()]
                .into_iter()
                .collect(),
            1_000,
            Duration::from_secs(30 * 24 * 3600),
        );
        gw.install(rec);
        let json = dump_records(gw.records());
        let loaded = load_records(&json).unwrap();
        assert_eq!(loaded.len(), 1);
        let r = &loaded[0];
        assert_eq!(r.key().0, [0xAB; 32]);
        assert_eq!(r.rooms().collect::<Vec<_>>(), vec!["room-1", "room-2"]);
        assert!(r.scopes().count() == 2);
        assert!(!r.is_revoked());
    }

    #[test]
    fn revoked_flag_survives_persistence() {
        let rec = ControlKeyRecord::new(
            ControlKey([1; 32]),
            [Scope::RoomRead].into_iter().collect(),
            ["r".to_string()].into_iter().collect(),
            0,
            Duration::from_secs(600),
        );
        let mut gw = ControlGateway::new();
        gw.install(rec);
        let key = ControlKey([1; 32]);
        gw.revoke(&key);
        let json = dump_records(gw.records());
        let loaded = load_records(&json).unwrap();
        assert!(
            loaded[0].is_revoked(),
            "a revoked key must persist as revoked"
        );
    }

    #[test]
    fn unknown_version_is_rejected() {
        let json = r#"{"version":99,"keys":[]}"#;
        assert_eq!(load_records(json), Err(RecordError::BadVersion(99)));
    }

    #[test]
    fn malformed_key_hex_fails_closed() {
        let json = r#"{"version":1,"keys":[{"key_hex":"zz","scopes":[],"rooms":[],"created_at_ms":0,"expires_at_ms":1,"last_used_ms":0,"revoked":false}]}"#;
        assert!(matches!(load_records(json), Err(RecordError::Malformed(_))));
    }

    #[test]
    fn non_ascii_key_hex_fails_closed_without_panicking() {
        // A 64-*byte* key_hex holding a multi-byte char must fail closed, not
        // panic on a non-char-boundary slice.
        let json =
            "{\"version\":1,\"keys\":[{\"key_hex\":\"é111111111111111111111111111111111111111111111111111111111111111\",\"scopes\":[],\"rooms\":[],\"created_at_ms\":0,\"expires_at_ms\":1,\"last_used_ms\":0,\"revoked\":false}]}";
        assert!(matches!(load_records(json), Err(RecordError::Malformed(_))));
    }

    #[test]
    fn oversized_persisted_expiry_is_clamped_on_load() {
        use crate::gateway::MAX_LIFETIME;
        let key = to_hex(&[2u8; 32]);
        // A hand-edited store claims a near-infinite expiry.
        let json = format!(
            r#"{{"version":1,"keys":[{{"key_hex":"{key}","scopes":[1],"rooms":["r"],"created_at_ms":1000,"expires_at_ms":18446744073709551615,"last_used_ms":0,"revoked":false}}]}}"#
        );
        let loaded = load_records(&json).unwrap();
        let cap = 1000u64 + MAX_LIFETIME.as_millis() as u64;
        assert_eq!(
            loaded[0].expires_at_ms(),
            cap,
            "no loaded key may outlive created_at + MAX_LIFETIME"
        );
    }

    #[test]
    fn unknown_scope_id_fails_closed() {
        let key = to_hex(&[0u8; 32]);
        let json = format!(
            r#"{{"version":1,"keys":[{{"key_hex":"{key}","scopes":[999],"rooms":["r"],"created_at_ms":0,"expires_at_ms":1,"last_used_ms":0,"revoked":false}}]}}"#
        );
        assert!(matches!(
            load_records(&json),
            Err(RecordError::Malformed(_))
        ));
    }
}
