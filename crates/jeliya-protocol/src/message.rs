//! The transport-phase messages carried inside AEAD frames. The plaintext of a
//! `Transport` frame is `u8 msg_type ‖ msg_body`; this module encodes and
//! decodes that plaintext. It never touches ciphertext — sealing/opening is the
//! Noise layer's job in `jeliya-control`.

use crate::codec::{ProtoError, Reader, Writer};
use crate::registry::error;

/// A decoded transport message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    /// `0x01` companion → browser: the method registry this key may use.
    SessionAccept {
        methods: Vec<u16>,
        expires_at_ms: u64,
    },
    /// `0x02` companion → browser: admission refused (see `reject` codes).
    SessionReject { reason: u16 },
    /// `0x03` browser → companion: the browser user confirmed the SAS.
    PairConfirm,
    /// `0x04` companion → browser: the pairing outcome.
    PairResult {
        installed: bool,
        scopes: Vec<u16>,
        rooms: Vec<String>,
        expires_at_ms: u64,
    },
    /// `0x10` browser → companion: a scoped RPC.
    Request {
        nonce: u64,
        method: u16,
        params: Vec<u8>,
    },
    /// `0x11` companion → browser: the RPC result.
    Response { nonce: u64, ok: bool, body: Vec<u8> },
}

const T_SESSION_ACCEPT: u8 = 0x01;
const T_SESSION_REJECT: u8 = 0x02;
const T_PAIR_CONFIRM: u8 = 0x03;
const T_PAIR_RESULT: u8 = 0x04;
const T_REQUEST: u8 = 0x10;
const T_RESPONSE: u8 = 0x11;

/// The maximum entries in any bounded count field (methods, scopes, rooms).
const MAX_LIST: usize = 256;

impl Msg {
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut w = Writer::new();
        match self {
            Msg::SessionAccept {
                methods,
                expires_at_ms,
            } => {
                w.put_u8(T_SESSION_ACCEPT);
                put_u16_list(&mut w, methods, "methods")?;
                w.put_u64(*expires_at_ms);
            }
            Msg::SessionReject { reason } => {
                w.put_u8(T_SESSION_REJECT);
                w.put_u16(*reason);
            }
            Msg::PairConfirm => {
                w.put_u8(T_PAIR_CONFIRM);
            }
            Msg::PairResult {
                installed,
                scopes,
                rooms,
                expires_at_ms,
            } => {
                w.put_u8(T_PAIR_RESULT);
                w.put_u8(u8::from(*installed));
                put_u16_list(&mut w, scopes, "scopes")?;
                if rooms.len() > MAX_LIST {
                    return Err(ProtoError::BadCount("rooms"));
                }
                w.put_u16(rooms.len() as u16);
                for room in rooms {
                    w.put_string(room)?;
                }
                w.put_u64(*expires_at_ms);
            }
            Msg::Request {
                nonce,
                method,
                params,
            } => {
                w.put_u8(T_REQUEST);
                w.put_u64(*nonce);
                w.put_u16(*method);
                w.put_blob(params)?;
            }
            Msg::Response { nonce, ok, body } => {
                w.put_u8(T_RESPONSE);
                w.put_u64(*nonce);
                w.put_u8(u8::from(*ok));
                w.put_blob(body)?;
            }
        }
        Ok(w.into_vec())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut r = Reader::new(buf);
        let msg_type = r.read_u8()?;
        let msg = match msg_type {
            T_SESSION_ACCEPT => {
                let methods = read_u16_list(&mut r, "methods")?;
                let expires_at_ms = r.read_u64()?;
                Msg::SessionAccept {
                    methods,
                    expires_at_ms,
                }
            }
            T_SESSION_REJECT => Msg::SessionReject {
                reason: r.read_u16()?,
            },
            T_PAIR_CONFIRM => Msg::PairConfirm,
            T_PAIR_RESULT => {
                let installed = read_bool(&mut r)?;
                let scopes = read_u16_list(&mut r, "scopes")?;
                let room_count = r.read_u16()? as usize;
                if room_count > MAX_LIST {
                    return Err(ProtoError::BadCount("rooms"));
                }
                let mut rooms = Vec::with_capacity(room_count);
                for _ in 0..room_count {
                    rooms.push(r.read_string()?);
                }
                let expires_at_ms = r.read_u64()?;
                Msg::PairResult {
                    installed,
                    scopes,
                    rooms,
                    expires_at_ms,
                }
            }
            T_REQUEST => Msg::Request {
                nonce: r.read_u64()?,
                method: r.read_u16()?,
                params: r.read_blob()?.to_vec(),
            },
            T_RESPONSE => Msg::Response {
                nonce: r.read_u64()?,
                ok: read_bool(&mut r)?,
                body: r.read_blob()?.to_vec(),
            },
            _ => return Err(ProtoError::BadEnum("msg_type")),
        };
        r.finish()?;
        Ok(msg)
    }

    /// Build an error `Response` carrying a registry error code and message.
    pub fn error_response(nonce: u64, code: u16, message: &str) -> Result<Self, ProtoError> {
        let mut w = Writer::new();
        w.put_u16(code);
        w.put_string(message)?;
        Ok(Msg::Response {
            nonce,
            ok: false,
            body: w.into_vec(),
        })
    }

    /// Decode an error `Response.body` into `(code, message)`. Errors if the
    /// message is not the `u16 code ‖ string` shape.
    pub fn decode_error_body(body: &[u8]) -> Result<(u16, String), ProtoError> {
        let mut r = Reader::new(body);
        let code = r.read_u16()?;
        let message = r.read_string()?;
        r.finish()?;
        Ok((code, message))
    }
}

fn read_bool(r: &mut Reader) -> Result<bool, ProtoError> {
    match r.read_u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProtoError::BadEnum("bool")),
    }
}

fn put_u16_list(w: &mut Writer, list: &[u16], what: &'static str) -> Result<(), ProtoError> {
    if list.len() > MAX_LIST {
        return Err(ProtoError::BadCount(what));
    }
    w.put_u16(list.len() as u16);
    for v in list {
        w.put_u16(*v);
    }
    Ok(())
}

fn read_u16_list(r: &mut Reader, what: &'static str) -> Result<Vec<u16>, ProtoError> {
    let count = r.read_u16()? as usize;
    if count > MAX_LIST {
        return Err(ProtoError::BadCount(what));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.read_u16()?);
    }
    Ok(out)
}

/// The decoded, method-specific parameters of a `Request`. Decoding these from
/// the raw `params` blob is how the companion turns validated wire fields into a
/// daemon dispatch — browser bytes are never forwarded as JSON to the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodCall {
    RoomTimeline {
        room_id: String,
        limit: Option<u32>,
        after: Option<String>,
    },
    RoomMembers {
        room_id: String,
    },
    MessageSend {
        room_id: String,
        body: String,
        client_msg_id: String,
    },
}

impl MethodCall {
    /// Decode the params blob for a method id. An unknown method id is the
    /// caller's responsibility to reject *before* calling this (with
    /// `method_unknown`); this returns `BadEnum("method")` for one as a guard.
    pub fn decode(method_id: u16, params: &[u8]) -> Result<Self, ProtoError> {
        use crate::registry::method;
        let mut r = Reader::new(params);
        let call = match method_id {
            method::ROOM_TIMELINE => {
                let room_id = r.read_string()?;
                let limit = if read_bool(&mut r)? {
                    Some(r.read_u32()?)
                } else {
                    None
                };
                let after = if read_bool(&mut r)? {
                    Some(r.read_string()?)
                } else {
                    None
                };
                MethodCall::RoomTimeline {
                    room_id,
                    limit,
                    after,
                }
            }
            method::ROOM_MEMBERS => MethodCall::RoomMembers {
                room_id: r.read_string()?,
            },
            method::MESSAGE_SEND => MethodCall::MessageSend {
                room_id: r.read_string()?,
                body: r.read_string()?,
                client_msg_id: r.read_string()?,
            },
            _ => return Err(ProtoError::BadEnum("method")),
        };
        r.finish()?;
        Ok(call)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut w = Writer::new();
        match self {
            MethodCall::RoomTimeline {
                room_id,
                limit,
                after,
            } => {
                w.put_string(room_id)?;
                match limit {
                    Some(l) => {
                        w.put_u8(1);
                        w.put_u32(*l);
                    }
                    None => w.put_u8(0),
                }
                match after {
                    Some(a) => {
                        w.put_u8(1);
                        w.put_string(a)?;
                    }
                    None => w.put_u8(0),
                }
            }
            MethodCall::RoomMembers { room_id } => {
                w.put_string(room_id)?;
            }
            MethodCall::MessageSend {
                room_id,
                body,
                client_msg_id,
            } => {
                w.put_string(room_id)?;
                w.put_string(body)?;
                w.put_string(client_msg_id)?;
            }
        }
        Ok(w.into_vec())
    }

    /// The room id this call names (every v1 method is room-scoped).
    #[must_use]
    pub fn room_id(&self) -> &str {
        match self {
            MethodCall::RoomTimeline { room_id, .. }
            | MethodCall::RoomMembers { room_id }
            | MethodCall::MessageSend { room_id, .. } => room_id,
        }
    }
}

/// The registry error name for a `Response` error code, for logging/tests.
#[must_use]
pub fn error_name(code: u16) -> &'static str {
    match code {
        error::DENIED_UNKNOWN_KEY => "denied_unknown_key",
        error::DENIED_REVOKED => "denied_revoked",
        error::DENIED_EXPIRED => "denied_expired",
        error::DENIED_SCOPE => "denied_scope",
        error::DENIED_ROOM => "denied_room",
        error::DENIED_REPLAY => "denied_replay",
        error::DENIED_RATE_LIMITED => "denied_rate_limited",
        error::METHOD_UNKNOWN => "method_unknown",
        error::PARAMS_INVALID => "params_invalid",
        error::ENGINE_ERROR => "engine_error",
        _ => "unknown",
    }
}
