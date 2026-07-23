//! The single authorization point every scoped RPC crosses, and the key
//! lifecycle it enforces. This is the piece the D5b/D6 gate reviews as "the
//! implementation that actually enforces it", replacing the Phase-1 scaffolding
//! whose public API could bypass SAS, accept any lifetime, trust a
//! caller-supplied clock, had no rate limiting, and used global (not
//! per-room) scopes.
//!
//! The fixes, point for point against finding F3:
//! - **No bypass.** [`ControlKeyRecord`] has no public constructor; the only
//!   way to install one is a completed pairing ceremony (`crate::session`) or a
//!   load from the companion's own persisted store (`crate::records`), both
//!   crate-internal.
//! - **Gateway owns the clock.** [`ControlGateway`] holds a [`Clock`]; no
//!   `authorize` argument carries time.
//! - **Bounded lifetime.** The lifetime is clamped to
//!   `[MIN_LIFETIME, MAX_LIFETIME]` with a 30-day default; there is no path to
//!   an unbounded key.
//! - **Per-room binding.** A grant carries an explicit room set; an RPC naming
//!   a room outside it is denied.
//! - **Per-key rate limiting.** Token-bucket limits on RPC rate and request
//!   bytes, with session-teardown on sustained violation.
//! - **Per-session replay window.** The 64-nonce sliding window is keyed by
//!   session, so fresh session keys make cross-session replay impossible
//!   without persisting nonce state that a crash could roll back.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// A browser control key's public half — 32 opaque bytes (the X25519 static key
/// the browser generates non-extractable in WebCrypto). Carries no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ControlKey(pub [u8; 32]);

impl ControlKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The narrow scopes a control key may exercise (ADR #2 decision 6). Default-
/// deny: a key grants exactly the set it was paired with, bound to named rooms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// Read a selected room's timeline/members.
    RoomRead,
    /// Send chat in a selected room (idempotent via `client_msg_id`).
    MessageSend,
}

impl Scope {
    /// The wire scope-registry id.
    #[must_use]
    pub fn registry_id(self) -> u16 {
        match self {
            Scope::RoomRead => jeliya_protocol::scope::ROOM_READ,
            Scope::MessageSend => jeliya_protocol::scope::MESSAGE_SEND,
        }
    }

    /// Map a wire scope-registry id to a scope, or `None` for an unknown id.
    #[must_use]
    pub fn from_registry_id(id: u16) -> Option<Self> {
        match id {
            jeliya_protocol::scope::ROOM_READ => Some(Scope::RoomRead),
            jeliya_protocol::scope::MESSAGE_SEND => Some(Scope::MessageSend),
            _ => None,
        }
    }

    /// The scope a wire method id requires, or `None` for a method not in v1.
    #[must_use]
    pub fn for_method_id(method_id: u16) -> Option<Self> {
        jeliya_protocol::scope_for_method(method_id)
            .ok()
            .and_then(Self::from_registry_id)
    }
}

/// Why a scoped RPC was denied. Every variant is fail-closed: the gateway never
/// partially authorizes, and a denial advances no grant-relevant state
/// (nonce-seen, last-use).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// No installed record for this control key.
    UnknownKey,
    /// The key was revoked.
    Revoked,
    /// The key's bounded lifetime elapsed.
    Expired,
    /// The scope is not in the key's grant (default-deny).
    ScopeDenied,
    /// The named room is not in the key's granted room set.
    RoomDenied,
    /// A per-key rate or byte limit was exceeded.
    RateLimited,
    /// The nonce was replayed or fell below the session's window floor.
    Replay,
}

impl Denial {
    /// The wire error-registry code for this denial.
    #[must_use]
    pub fn registry_code(self) -> u16 {
        use jeliya_protocol::error;
        match self {
            Denial::UnknownKey => error::DENIED_UNKNOWN_KEY,
            Denial::Revoked => error::DENIED_REVOKED,
            Denial::Expired => error::DENIED_EXPIRED,
            Denial::ScopeDenied => error::DENIED_SCOPE,
            Denial::RoomDenied => error::DENIED_ROOM,
            Denial::RateLimited => error::DENIED_RATE_LIMITED,
            Denial::Replay => error::DENIED_REPLAY,
        }
    }
}

/// Why a control session's post-handshake admission was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    UnknownKey,
    Revoked,
    Expired,
}

impl RejectReason {
    #[must_use]
    pub fn registry_code(self) -> u16 {
        use jeliya_protocol::reject;
        match self {
            RejectReason::UnknownKey => reject::UNKNOWN_KEY,
            RejectReason::Revoked => reject::REVOKED,
            RejectReason::Expired => reject::EXPIRED,
        }
    }
}

// ---- Lifetime bounds (ADR #2 decision 5, adoption) ---------------------

/// The default control-key lifetime — fixed at 30 days by ADR #2 adoption.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// The hard maximum lifetime (implementation parameter, D5b/D6 gate to confirm).
pub const MAX_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);
/// The hard minimum lifetime.
pub const MIN_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// Clamp a requested lifetime into `[MIN_LIFETIME, MAX_LIFETIME]`. There is no
/// path to an unbounded key: even `Duration::MAX` clamps to `MAX_LIFETIME`.
#[must_use]
pub fn clamp_lifetime(requested: Duration) -> Duration {
    requested.clamp(MIN_LIFETIME, MAX_LIFETIME)
}

/// The per-session replay-window size (ADR #2 decision 7; the tested Phase-1
/// window semantics, now keyed by session).
pub const REPLAY_WINDOW: u64 = 64;

/// A monotonic clock, injectable so tests can advance time deterministically and
/// so no caller can supply time to `authorize`.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// Wall-clock time in milliseconds since the Unix epoch.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        // Fail closed on a clock error (a pre-epoch wall clock): return
        // `u64::MAX` so every key reads as expired, never as valid. The overflow
        // branch does the same. Returning 0 here would fail *open* — every
        // expiry check `now >= expires_at` would be false.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(u64::MAX, |d| {
                u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// A granted control key. No public constructor: an instance exists only via a
/// completed pairing ceremony or a load from the persisted store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlKeyRecord {
    pub(crate) key: ControlKey,
    pub(crate) scopes: BTreeSet<Scope>,
    pub(crate) rooms: BTreeSet<String>,
    pub(crate) created_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) last_used_ms: u64,
    pub(crate) revoked: bool,
}

impl ControlKeyRecord {
    /// Build a fresh record from a completed pairing. The lifetime is clamped;
    /// the expiry is `created_at + clamp(lifetime)`. Crate-internal — a host
    /// cannot fabricate a record, closing the Phase-1 `install` bypass.
    pub(crate) fn new(
        key: ControlKey,
        scopes: BTreeSet<Scope>,
        rooms: BTreeSet<String>,
        created_at_ms: u64,
        lifetime: Duration,
    ) -> Self {
        let bounded = clamp_lifetime(lifetime);
        let expires_at_ms = created_at_ms.saturating_add(bounded.as_millis() as u64);
        Self {
            key,
            scopes,
            rooms,
            created_at_ms,
            expires_at_ms,
            last_used_ms: created_at_ms,
            revoked: false,
        }
    }

    /// Reconstruct a record from persisted fields (a load from the companion's
    /// own store). Crate-internal — only `crate::records` calls this, and it
    /// carries an explicit `expires_at_ms` rather than re-deriving it, so a
    /// stored expiry is honored exactly.
    pub(crate) fn from_persisted(
        key: ControlKey,
        scopes: BTreeSet<Scope>,
        rooms: BTreeSet<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
        last_used_ms: u64,
        revoked: bool,
    ) -> Self {
        Self {
            key,
            scopes,
            rooms,
            created_at_ms,
            expires_at_ms,
            last_used_ms,
            revoked,
        }
    }

    fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    #[must_use]
    pub fn key(&self) -> ControlKey {
        self.key
    }
    #[must_use]
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }
    #[must_use]
    pub fn last_used_ms(&self) -> u64 {
        self.last_used_ms
    }
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub fn scopes(&self) -> impl Iterator<Item = Scope> + '_ {
        self.scopes.iter().copied()
    }
    pub fn rooms(&self) -> impl Iterator<Item = &str> {
        self.rooms.iter().map(String::as_str)
    }
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }
    /// The method-registry ids this key may invoke (derived from its scopes).
    #[must_use]
    pub fn granted_methods(&self) -> Vec<u16> {
        use jeliya_protocol::method;
        let mut methods = Vec::new();
        if self.scopes.contains(&Scope::RoomRead) {
            methods.push(method::ROOM_TIMELINE);
            methods.push(method::ROOM_MEMBERS);
        }
        if self.scopes.contains(&Scope::MessageSend) {
            methods.push(method::MESSAGE_SEND);
        }
        methods
    }
}

/// A per-session sliding replay window over RPC nonces. Nonces start at 1; 0 is
/// invalid. Out-of-order delivery inside the window is accepted; exact replays
/// and below-floor nonces are rejected. Holds no time and no key — it lives and
/// dies with its session.
#[derive(Default)]
pub struct ReplayWindow {
    highest: u64,
    seen: BTreeSet<u64>,
}

impl ReplayWindow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a nonce and, on acceptance, record it. On any rejection the window
    /// is unchanged (a denial advances no state).
    pub fn check_and_record(&mut self, nonce: u64) -> Result<(), Denial> {
        if nonce == 0 {
            return Err(Denial::Replay);
        }
        let floor = self.highest.saturating_sub(REPLAY_WINDOW);
        if nonce > self.highest {
            let new_floor = nonce.saturating_sub(REPLAY_WINDOW);
            self.seen.retain(|n| *n > new_floor);
            self.seen.insert(nonce);
            self.highest = nonce;
            Ok(())
        } else if self.seen.contains(&nonce) || nonce <= floor {
            Err(Denial::Replay)
        } else {
            self.seen.insert(nonce);
            Ok(())
        }
    }
}

/// A simple token bucket. `tokens` refills continuously at `refill_per_ms` up to
/// `capacity`; `try_take` succeeds iff enough tokens are available.
struct TokenBucket {
    capacity: f64,
    refill_per_ms: f64,
    tokens: f64,
    last_ms: u64,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_ms: f64, now_ms: u64) -> Self {
        Self {
            capacity,
            refill_per_ms,
            tokens: capacity,
            last_ms: now_ms,
        }
    }

    /// Refill to `now_ms`, then report whether `amount` is available (without
    /// consuming it). Paired with [`TokenBucket::commit`] so a multi-bucket
    /// check can be all-or-nothing.
    fn refill_and_has(&mut self, now_ms: u64, amount: f64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_ms) as f64;
        self.tokens = (self.tokens + elapsed * self.refill_per_ms).min(self.capacity);
        self.last_ms = now_ms;
        self.tokens >= amount
    }

    fn commit(&mut self, amount: f64) {
        self.tokens -= amount;
    }
}

/// Per-key rate-limit state: an RPC-rate bucket and a request-bytes bucket. The
/// buckets are per control key (the resource an origin compromise shares across
/// its tabs/reconnects), while the strike-to-teardown counter that decides
/// whether to *drop a session* is per session ([`SessionStrikes`]) — one abusive
/// session must not tear down a sibling session sharing the same key.
struct KeyRateLimiter {
    rpc: TokenBucket,
    bytes: TokenBucket,
}

/// v1 rate parameters (D5b/D6 gate to confirm).
const RPC_BURST: f64 = 40.0;
const RPC_PER_MS: f64 = 10.0 / 1000.0;
const BYTES_BURST: f64 = 1024.0 * 1024.0;
const BYTES_PER_MS: f64 = 256.0 * 1024.0 / 1000.0;
const STRIKE_WINDOW_MS: u64 = 60_000;
const STRIKE_TEARDOWN: usize = 3;

impl KeyRateLimiter {
    fn new(now_ms: u64) -> Self {
        Self {
            rpc: TokenBucket::new(RPC_BURST, RPC_PER_MS, now_ms),
            bytes: TokenBucket::new(BYTES_BURST, BYTES_PER_MS, now_ms),
        }
    }

    /// Whether one request of `request_bytes` bytes is allowed now. All-or-
    /// nothing: a request denied by either bucket consumes tokens from neither,
    /// so a byte-limited client is not additionally drained of RPC tokens.
    fn allow(&mut self, now_ms: u64, request_bytes: u32) -> bool {
        let bytes = f64::from(request_bytes);
        let has_rpc = self.rpc.refill_and_has(now_ms, 1.0);
        let has_bytes = self.bytes.refill_and_has(now_ms, bytes);
        if has_rpc && has_bytes {
            self.rpc.commit(1.0);
            self.bytes.commit(bytes);
            true
        } else {
            false
        }
    }
}

/// A per-session rolling strike counter. The session records a strike on each
/// rate denial; `record` returns `true` once [`STRIKE_TEARDOWN`] strikes fall
/// inside the [`STRIKE_WINDOW_MS`] window, telling the session to tear down.
/// Per-session so one abusive session cannot tear down a sibling on the same key.
#[derive(Default)]
pub struct SessionStrikes {
    hits: Vec<u64>,
}

impl SessionStrikes {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a rate-limit violation at `now_ms`; return whether the session
    /// should be torn down.
    pub fn record(&mut self, now_ms: u64) -> bool {
        self.hits
            .retain(|t| now_ms.saturating_sub(*t) < STRIKE_WINDOW_MS);
        self.hits.push(now_ms);
        self.hits.len() >= STRIKE_TEARDOWN
    }
}

// v1 handshake-tier rate parameters (ADR #2 decision 8; the spec's handshake
// rows). These bound *handshakes*, keyed by the transport-proven remote id.
const HS_PER_ID_BURST: f64 = 6.0;
const HS_PER_ID_PER_MS: f64 = 6.0 / 60_000.0; // 6 per minute
const HS_GLOBAL_BURST: f64 = 30.0;
const HS_GLOBAL_PER_MS: f64 = 30.0 / 60_000.0; // 30 per minute
const HS_MAX_TRACKED_IDS: usize = 4096;

/// Handshake-tier rate limiting. Keyed by the transport-proven remote id (the
/// iroh `EndpointId`, 32 bytes), this is the one limiter that keys off the
/// *unauthenticated* iroh identity — so it can only ever deny service to that
/// identity, never grant anything. The sans-I/O session core never sees the
/// `EndpointId`; the transport adapter (the companion) holds a `HandshakeLimiter`
/// and calls [`HandshakeLimiter::allow`] before running each handshake, dropping
/// the connection on `false`. The per-id map is bounded (idle buckets are
/// evicted) so a flood of distinct ids cannot grow memory without bound.
pub struct HandshakeLimiter {
    per_id: BTreeMap<[u8; 32], TokenBucket>,
    global: TokenBucket,
}

impl HandshakeLimiter {
    /// A limiter starting at `now_ms` (the transport passes the gateway clock).
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        Self {
            per_id: BTreeMap::new(),
            global: TokenBucket::new(HS_GLOBAL_BURST, HS_GLOBAL_PER_MS, now_ms),
        }
    }

    /// Whether a handshake from `id` is allowed now. All-or-nothing across the
    /// per-id and global buckets: a handshake denied by either consumes neither.
    pub fn allow(&mut self, id: [u8; 32], now_ms: u64) -> bool {
        let allowed = {
            let bucket = self
                .per_id
                .entry(id)
                .or_insert_with(|| TokenBucket::new(HS_PER_ID_BURST, HS_PER_ID_PER_MS, now_ms));
            let has_id = bucket.refill_and_has(now_ms, 1.0);
            let has_global = self.global.refill_and_has(now_ms, 1.0);
            if has_id && has_global {
                bucket.commit(1.0);
                self.global.commit(1.0);
                true
            } else {
                false
            }
        };
        self.gc(now_ms);
        allowed
    }

    /// Evict fully-refilled (idle) per-id buckets when the map grows large. An
    /// idle bucket is indistinguishable from a fresh one, so dropping it changes
    /// no decision.
    fn gc(&mut self, now_ms: u64) {
        if self.per_id.len() <= HS_MAX_TRACKED_IDS {
            return;
        }
        self.per_id
            .retain(|_, b| !b.refill_and_has(now_ms, HS_PER_ID_BURST));
    }
}

/// A session identifier, assigned by the host (the transport). Used to tear
/// down the right connections on revocation.
pub type SessionId = u64;

/// The gateway: the installed control-key records, the per-key rate limiters,
/// the live-session registry, and the clock. All mutation goes through `&mut
/// self`; the host serializes access (the transport is single-threaded per
/// connection and the companion holds one gateway behind a mutex).
pub struct ControlGateway {
    keys: BTreeMap<ControlKey, ControlKeyRecord>,
    limiters: BTreeMap<ControlKey, KeyRateLimiter>,
    live_sessions: BTreeMap<ControlKey, BTreeSet<SessionId>>,
    clock: Box<dyn Clock>,
}

impl ControlGateway {
    /// A gateway on the wall clock.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Box::new(SystemClock))
    }

    #[must_use]
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Self {
            keys: BTreeMap::new(),
            limiters: BTreeMap::new(),
            live_sessions: BTreeMap::new(),
            clock,
        }
    }

    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Install a record produced by a completed pairing ceremony. Replaces any
    /// prior record for the same key and resets its rate limiter.
    pub(crate) fn install(&mut self, record: ControlKeyRecord) {
        let now = self.clock.now_ms();
        self.limiters.insert(record.key, KeyRateLimiter::new(now));
        self.keys.insert(record.key, record);
    }

    /// Admit (or refuse) a control session after the handshake authenticated
    /// `key`. Does not consume rate tokens (admission is rate-limited at the
    /// handshake layer by the host). Returns the record to read from on success.
    pub fn admit_session(&self, key: &ControlKey) -> Result<&ControlKeyRecord, RejectReason> {
        let record = self.keys.get(key).ok_or(RejectReason::UnknownKey)?;
        if record.revoked {
            return Err(RejectReason::Revoked);
        }
        if record.expired(self.clock.now_ms()) {
            return Err(RejectReason::Expired);
        }
        Ok(record)
    }

    /// Charge the per-key rate limiter for one request of `request_bytes` bytes.
    /// Called for *every* request from an admitted key — before method and param
    /// validation — so a compromised origin cannot spend unbounded
    /// decrypt/parse work by sending well-keyed but malformed requests without
    /// hitting the rate limit. Returns `Err(Denial::RateLimited)` when denied;
    /// the per-session strike-to-teardown decision is the caller's
    /// ([`SessionStrikes`]).
    pub fn charge_rate(&mut self, key: &ControlKey, request_bytes: u32) -> Result<(), Denial> {
        let now = self.clock.now_ms();
        let limiter = self
            .limiters
            .entry(*key)
            .or_insert_with(|| KeyRateLimiter::new(now));
        if limiter.allow(now, request_bytes) {
            Ok(())
        } else {
            Err(Denial::RateLimited)
        }
    }

    /// Authorize one scoped, well-formed RPC. Order: identity → revocation →
    /// expiry → scope → room → replay. Rate limiting is charged separately and
    /// earlier via [`ControlGateway::charge_rate`]. On success advances
    /// `last_used` and records the nonce in the caller's session window; on any
    /// denial nothing grant-relevant changes. `replay` is the per-session window.
    pub fn authorize(
        &mut self,
        key: &ControlKey,
        scope: Scope,
        room_id: &str,
        nonce: u64,
        replay: &mut ReplayWindow,
    ) -> Result<(), Denial> {
        let now = self.clock.now_ms();
        let record = self.keys.get_mut(key).ok_or(Denial::UnknownKey)?;
        if record.revoked {
            return Err(Denial::Revoked);
        }
        if record.expired(now) {
            return Err(Denial::Expired);
        }
        if !record.scopes.contains(&scope) {
            return Err(Denial::ScopeDenied);
        }
        if !record.rooms.contains(room_id) {
            return Err(Denial::RoomDenied);
        }
        replay.check_and_record(nonce)?;
        record.last_used_ms = now;
        Ok(())
    }

    /// Register a live session for a key (so revocation can tear it down).
    pub fn open_session(&mut self, key: ControlKey, session: SessionId) {
        self.live_sessions.entry(key).or_default().insert(session);
    }

    /// Deregister a session on normal teardown.
    pub fn close_session(&mut self, key: &ControlKey, session: SessionId) {
        if let Some(set) = self.live_sessions.get_mut(key) {
            set.remove(&session);
            if set.is_empty() {
                self.live_sessions.remove(key);
            }
        }
    }

    /// Revoke a control key immediately, returning the live sessions the host
    /// must tear down. Future admissions and in-flight RPCs under the key fail
    /// closed. The record is retained (revoked) until expiry so a restart cannot
    /// resurrect it. Revoking an unknown key is a no-op.
    pub fn revoke(&mut self, key: &ControlKey) -> Vec<SessionId> {
        if let Some(record) = self.keys.get_mut(key) {
            record.revoked = true;
        }
        self.live_sessions
            .remove(key)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default()
    }

    /// Whether a key is currently installed (not its authorization state).
    #[must_use]
    pub fn contains(&self, key: &ControlKey) -> bool {
        self.keys.contains_key(key)
    }

    /// Evict expired, revoked records (housekeeping; call periodically). A
    /// revoked record is evicted only once it has also expired.
    pub fn evict_expired(&mut self) {
        let now = self.clock.now_ms();
        let dead: Vec<ControlKey> = self
            .keys
            .iter()
            .filter(|(_, r)| r.expired(now))
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            self.keys.remove(&k);
            self.limiters.remove(&k);
            self.live_sessions.remove(&k);
        }
    }

    /// Snapshot the installed records for persistence.
    pub(crate) fn records(&self) -> impl Iterator<Item = &ControlKeyRecord> {
        self.keys.values()
    }

    /// Serialize the installed records to the on-disk JSON the host writes to
    /// `control_keys.json` (atomically, `0600`, per the `localstate.rs`
    /// discipline). Replay windows are per-session and never persisted.
    #[must_use]
    pub fn snapshot_json(&self) -> String {
        crate::records::dump_records(self.records())
    }

    /// Load persisted control-key records from the companion's own store into
    /// this gateway (the legitimate non-ceremony install path — the store is
    /// trusted local state, not a browser input). A malformed store fails
    /// closed. Existing records for a loaded key are replaced.
    pub fn load_persisted(&mut self, json: &str) -> Result<usize, crate::records::RecordError> {
        let records = crate::records::load_records(json)?;
        let count = records.len();
        for record in records {
            self.install(record);
        }
        Ok(count)
    }
}

impl Default for ControlGateway {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Replay window --------------------------------------------------

    #[test]
    fn replay_window_boundaries() {
        let mut w = ReplayWindow::new();
        assert_eq!(
            w.check_and_record(0),
            Err(Denial::Replay),
            "nonce 0 invalid"
        );
        assert!(w.check_and_record(1).is_ok());
        assert_eq!(w.check_and_record(1), Err(Denial::Replay), "exact replay");
        assert!(w.check_and_record(3).is_ok(), "gap accepted");
        assert!(
            w.check_and_record(2).is_ok(),
            "in-window out-of-order accepted"
        );
        assert_eq!(w.check_and_record(2), Err(Denial::Replay));
        // Advance far, then a below-floor nonce is rejected.
        assert!(w.check_and_record(200).is_ok());
        assert_eq!(
            w.check_and_record(200 - REPLAY_WINDOW),
            Err(Denial::Replay),
            "at the floor is too old"
        );
        assert!(
            w.check_and_record(200 - REPLAY_WINDOW + 1).is_ok(),
            "just inside"
        );
    }

    // ---- Lifetime clamp -------------------------------------------------

    #[test]
    fn lifetime_is_always_bounded() {
        assert_eq!(clamp_lifetime(Duration::from_secs(0)), MIN_LIFETIME);
        assert_eq!(clamp_lifetime(Duration::MAX), MAX_LIFETIME);
        assert_eq!(clamp_lifetime(DEFAULT_LIFETIME), DEFAULT_LIFETIME);
        // Even the record constructor cannot mint an unbounded key.
        let rec = ControlKeyRecord::new(
            ControlKey([1; 32]),
            BTreeSet::new(),
            BTreeSet::new(),
            1_000,
            Duration::MAX,
        );
        assert_eq!(rec.expires_at_ms(), 1_000 + MAX_LIFETIME.as_millis() as u64);
    }

    // ---- Per-key rate limiting -----------------------------------------

    #[test]
    fn rpc_burst_then_denied_then_refills() {
        let mut rl = KeyRateLimiter::new(0);
        // Drain the burst (40) at t=0 with tiny requests.
        for _ in 0..40 {
            assert!(rl.allow(0, 1));
        }
        // The 41st in the same instant is denied.
        assert!(!rl.allow(0, 1));
        // After 1s (10 rpc/s refill) at least one token is back.
        assert!(rl.allow(1_000, 1));
    }

    #[test]
    fn byte_limit_denies_without_draining_rpc_tokens() {
        let mut rl = KeyRateLimiter::new(0);
        // A request larger than the 1 MiB byte burst is denied…
        assert!(!rl.allow(0, 2 * 1024 * 1024));
        // …and it did not consume an RPC token (all-or-nothing): a normal
        // request still succeeds immediately.
        assert!(rl.allow(0, 1));
    }

    #[test]
    fn session_strikes_escalate_to_teardown_per_session() {
        // The strike counter is per session, not per key: two independent
        // sessions each take their own strikes.
        let mut a = SessionStrikes::new();
        let mut b = SessionStrikes::new();
        assert!(!a.record(0));
        assert!(!a.record(0));
        assert!(a.record(0), "session A's third strike tears A down");
        // Session B is unaffected by A's strikes.
        assert!(!b.record(0), "session B still on its first strike");
    }

    // ---- Handshake-tier rate limiting ----------------------------------

    #[test]
    fn handshake_limiter_bounds_per_id() {
        let mut hl = HandshakeLimiter::new(0);
        let id = [7u8; 32];
        for _ in 0..6 {
            assert!(hl.allow(id, 0));
        }
        assert!(
            !hl.allow(id, 0),
            "7th handshake from one id in a burst is denied"
        );
        // A different id is independent (until the global cap).
        assert!(hl.allow([8u8; 32], 0));
    }

    #[test]
    fn handshake_limiter_bounds_global() {
        let mut hl = HandshakeLimiter::new(0);
        // 30 distinct ids each do one handshake — that hits the global burst.
        for i in 0..30u8 {
            assert!(hl.allow([i; 32], 0), "id {i} within global burst");
        }
        // The 31st distinct id is denied by the global limiter despite its own
        // per-id bucket being full.
        assert!(!hl.allow([200u8; 32], 0), "global cap reached");
    }

    // ---- Authorization ordering / revocation ----------------------------

    #[test]
    fn authorize_denies_unknown_scope_and_room_before_rate_or_replay() {
        let mut gw = ControlGateway::new();
        let key = ControlKey([9; 32]);
        let rooms: BTreeSet<String> = ["room-1".to_string()].into_iter().collect();
        gw.install(ControlKeyRecord::new(
            key,
            [Scope::RoomRead].into_iter().collect(),
            rooms,
            gw.now_ms(),
            DEFAULT_LIFETIME,
        ));
        let mut replay = ReplayWindow::new();
        // Scope denied (MessageSend not granted).
        assert_eq!(
            gw.authorize(&key, Scope::MessageSend, "room-1", 1, &mut replay)
                .unwrap_err(),
            Denial::ScopeDenied
        );
        // Room denied (room-2 not granted).
        assert_eq!(
            gw.authorize(&key, Scope::RoomRead, "room-2", 1, &mut replay)
                .unwrap_err(),
            Denial::RoomDenied
        );
        // A denial advanced no replay state: nonce 1 is still usable.
        assert!(gw
            .authorize(&key, Scope::RoomRead, "room-1", 1, &mut replay)
            .is_ok());
    }

    #[test]
    fn charge_rate_is_independent_of_authorize() {
        let mut gw = ControlGateway::new();
        let key = ControlKey([3; 32]);
        gw.install(ControlKeyRecord::new(
            key,
            [Scope::RoomRead].into_iter().collect(),
            ["r".to_string()].into_iter().collect(),
            gw.now_ms(),
            DEFAULT_LIFETIME,
        ));
        // A giant request is rate-denied by charge_rate regardless of scope.
        assert_eq!(
            gw.charge_rate(&key, 2 * 1024 * 1024).unwrap_err(),
            Denial::RateLimited
        );
        // A small one is charged fine.
        assert!(gw.charge_rate(&key, 16).is_ok());
    }
}
