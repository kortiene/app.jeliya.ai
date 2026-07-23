//! The v1 method, scope, and error registries. These are the *only* names the
//! wire can express: a controller cannot request a method whose id is not here,
//! and the companion rejects any id it did not advertise. Everything ADR #2
//! lists as separately-approved (`invite.*`, `file.*`, `pipe.*`, `identity.*`,
//! `agent.*`, `room.leave`, `room.join`, plus `daemon.status`,
//! `room.open`/`close`) has deliberately **no id in v1** — it is unrepresentable
//! rather than merely denied.

use crate::codec::ProtoError;

/// Method registry ids (`Request.method`, `SessionAccept.methods`).
pub mod method {
    /// Read a selected room's timeline. Requires scope `room.read` in the room.
    pub const ROOM_TIMELINE: u16 = 0x0001;
    /// Read a selected room's members. Requires scope `room.read` in the room.
    pub const ROOM_MEMBERS: u16 = 0x0002;
    /// Send an idempotent chat message. Requires scope `message.send` in the room.
    pub const MESSAGE_SEND: u16 = 0x0003;

    /// The complete set of v1 methods, in id order.
    pub const ALL: [u16; 3] = [ROOM_TIMELINE, ROOM_MEMBERS, MESSAGE_SEND];
}

/// Scope registry ids (`PairResult.scopes`).
pub mod scope {
    /// Read a selected room's timeline and members.
    pub const ROOM_READ: u16 = 0x0001;
    /// Send chat in a selected room.
    pub const MESSAGE_SEND: u16 = 0x0002;

    /// The complete set of v1 scopes, in id order.
    pub const ALL: [u16; 2] = [ROOM_READ, MESSAGE_SEND];
}

/// `SessionReject.reason` codes.
pub mod reject {
    pub const UNKNOWN_KEY: u16 = 1;
    pub const REVOKED: u16 = 2;
    pub const EXPIRED: u16 = 3;
    pub const BUSY: u16 = 4;
    pub const INCOMPATIBLE: u16 = 5;
}

/// `Response` error codes (`ok = 0`).
pub mod error {
    pub const DENIED_UNKNOWN_KEY: u16 = 0x0001;
    pub const DENIED_REVOKED: u16 = 0x0002;
    pub const DENIED_EXPIRED: u16 = 0x0003;
    pub const DENIED_SCOPE: u16 = 0x0004;
    pub const DENIED_ROOM: u16 = 0x0005;
    pub const DENIED_REPLAY: u16 = 0x0006;
    pub const DENIED_RATE_LIMITED: u16 = 0x0007;
    pub const METHOD_UNKNOWN: u16 = 0x0008;
    pub const PARAMS_INVALID: u16 = 0x0009;
    pub const ENGINE_ERROR: u16 = 0x000A;
}

/// Which scope a method requires. Returns an error for an unknown method id so
/// the caller fails closed with `method_unknown` before any scope evaluation.
pub fn scope_for_method(method_id: u16) -> Result<u16, ProtoError> {
    Ok(match method_id {
        method::ROOM_TIMELINE | method::ROOM_MEMBERS => scope::ROOM_READ,
        method::MESSAGE_SEND => scope::MESSAGE_SEND,
        _ => return Err(ProtoError::BadEnum("method")),
    })
}
