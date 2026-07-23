//! # jeliya-companion — the control-session runtime (D5b)
//!
//! The async transport that drives the sans-I/O [`jeliya_control`] `Responder`
//! over a real connection: the frame codec, the per-connection protocol loop,
//! the cross-connection pairing-offer registry, revocation teardown, and the
//! dedicated Iroh control-ALPN binding. It holds no daemon token and exposes no
//! public HTTP/WS listener (Phase 2 gate) — the browser reaches it only over the
//! mutually-authenticated Iroh control protocol.
//!
//! The protocol runtime ([`serve_connection`]) is transport-agnostic: it runs
//! over any [`FrameChannel`], so the full pairing + control protocol is
//! exercised end-to-end in-process (over a Tokio duplex) without a socket. The
//! Iroh endpoint binding ([`transport`]) is the thin layer that frames bytes
//! over a QUIC stream on the `/jeliya/control/1` ALPN.
//!
//! Two host seams keep the runtime decoupled: [`ControlDispatch`] executes an
//! authorized scoped RPC against the engine, and [`ControlPolicy`] confirms a
//! pairing on the companion's trusted surface (the SAS comparison the browser
//! origin cannot forge).

mod channel;
mod connection;
mod dispatch;
mod offers;
pub mod transport;

pub use channel::{BoxFuture, ChannelError, DuplexChannel, FrameChannel};
pub use connection::{serve_connection, Revocations};
pub use dispatch::{ControlDispatch, ControlPolicy, PairingDecision};
pub use offers::{companion_fingerprint, Offer, PairingOffers, OFFER_TTL_MS};
pub use transport::{ControlEndpoint, RelayConfig};

#[cfg(test)]
mod tests;
