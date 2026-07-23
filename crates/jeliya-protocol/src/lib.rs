//! # jeliya-protocol — control-wire protocol v1 (D5b/D6)
//!
//! The host-independent, byte-level definition of the companion control wire:
//! the `/jeliya/control/1` framing, the plaintext version/capability hellos
//! (deliverable D6), the transport-phase message encoding, and the method,
//! scope, and error registries. It is **pure encoding**: no cryptography, no
//! I/O, no iroh, no async. The Noise handshake, the gateway, and the transport
//! plumbing live in `jeliya-control` and the companion; this crate is the
//! shared contract they and the browser controller both encode against, so a
//! single conformance corpus (below) pins the wire for every implementation.
//!
//! The full normative specification is
//! [`docs/control-wire-protocol.md`](../../docs/control-wire-protocol.md); this
//! crate is its executable form. Where a value here and the spec disagree, the
//! spec and [ADR #2](../../docs/companion-control-protocol-decision.md) govern
//! and the code is the bug.
//!
//! ## Strictness
//!
//! Every decoder is exact: a frame with an unknown tag, a bad magic, a
//! non-UTF-8 string, an out-of-range count, or trailing bytes is a
//! [`ProtoError`], never a lenient partial parse. At the transport layer a
//! `ProtoError` means "close the connection" — unknown is treated as hostile,
//! not as a forward-compatible extension, because v1 negotiates version in the
//! clear before anything is trusted.

mod codec;
mod frame;
mod hello;
mod message;
mod registry;

pub use codec::{ProtoError, Reader, Writer};
pub use frame::{Frame, FrameType};
pub use hello::{ClientHello, ServerHello, SessionKind, MAGIC, MAX_VERSIONS, ZERO_NONCE};
pub use message::{error_name, MethodCall, Msg};
pub use registry::{error, method, reject, scope, scope_for_method};

/// The dedicated Iroh ALPN the control protocol runs over. The trailing `1` is
/// the ALPN generation, not the negotiated protocol version.
pub const ALPN: &[u8] = b"/jeliya/control/1";

/// The only protocol version this crate defines.
pub const PROTOCOL_VERSION_V1: u16 = 1;

/// The default minimum-safe version floor a companion advertises.
pub const MIN_SAFE_VERSION: u16 = 1;

/// The maximum body length of any single frame (bytes). A larger declared
/// length is rejected before allocation.
pub const MAX_FRAME_LEN: usize = 65_536;

/// The Noise protocol name this wire's handshake instantiates (informational
/// here; realized in `jeliya-control`). Kept beside the wire constants so the
/// two never drift.
pub const NOISE_PROTOCOL_NAME: &str = "Noise_XX_25519_AESGCM_SHA256";

#[cfg(test)]
mod tests;
