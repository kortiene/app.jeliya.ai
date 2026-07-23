//! # jeliya-control — the companion control protocol (D5b/D6)
//!
//! The host-independent implementation of ADR #2's control protocol: the
//! `Noise_XX_25519_AESGCM_SHA256` handshake, the transcript-derived short
//! authentication string, the bounded-lifetime non-extractable-key gateway
//! (scope, per-room binding, per-session replay window, per-key rate limiting,
//! immediate revocation), and the sans-I/O session driver that ties them to the
//! D6 version negotiation and the wire types in [`jeliya_protocol`]. The Iroh
//! transport that carries these frames, and the browser controller that speaks
//! the other end, wire this crate up; this crate owns the security logic they
//! enforce.
//!
//! The normative wire specification is
//! [`docs/control-wire-protocol.md`](../../docs/control-wire-protocol.md); this
//! crate is its enforcing implementation, reviewed at the
//! [D5b/D6 gate](../../docs/phase-1-security-review-scope.md#deferred-surface--the-d5bd6-control-wire-review-gate).
//!
//! ## Relationship to the Phase-1 scaffolding
//!
//! This crate previously held only a transport-free state machine explicitly
//! documented as "scaffolding, not a security boundary" — its public API could
//! bypass the SAS, accept any lifetime, trust a caller-supplied clock, had no
//! rate limiting, and used global (not per-room) scopes (Phase-1 findings
//! F2/F3). Those gaps are closed here: there is a real wire (F2), and the
//! gateway enforces every attributed property with no bypass surface (F3). See
//! [`gateway`] for the point-by-point mapping.
//!
//! ## What still binds the security of this crate
//!
//! - The **companion** must serialize all gateway mutation (one gateway behind
//!   a mutex; the transport is single-threaded per connection).
//! - The **`room.join` confused deputy** (amendment A1) is handled by *absence*:
//!   `room.join` has no method id in v1, so it is unrepresentable on the wire.
//!   When a later version adds it, its handler must carry the companion-surface
//!   human confirmation ADR #2 requires.
//! - Non-extractability is a **browser** property (WebCrypto `extractable:
//!   false`); this crate only ever holds public control keys, never the
//!   browser's private half.

mod crypto;
mod gateway;
mod noise;
mod records;
mod sas;
mod session;

pub use gateway::{
    clamp_lifetime, Clock, ControlGateway, ControlKey, ControlKeyRecord, Denial, HandshakeLimiter,
    RejectReason, ReplayWindow, Scope, SessionId, SessionStrikes, SystemClock, DEFAULT_LIFETIME,
    MAX_LIFETIME, MIN_LIFETIME, REPLAY_WINDOW,
};
pub use noise::{HandshakeState, NoiseError, TransportState};
pub use records::{dump_records, load_records, RecordError, STORE_VERSION};
pub use sas::sas_from_handshake_hash;
pub use session::{Initiator, ManualClock, Out, Responder, SessionError};

/// Re-export the key primitive the companion needs to mint its static pairing
/// identity and the browser's stored public control key.
pub use crypto::KeyPair;
