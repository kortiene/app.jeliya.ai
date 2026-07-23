//! The outer frame: `u32 length ‖ u8 frame_type ‖ body`. Frames carry the
//! plaintext hellos, the three Noise handshake messages, and the AEAD
//! transport records. Framing is deliberately dumb — it does not interpret the
//! body — so the same reader serves plaintext and ciphertext alike.

use crate::codec::{ProtoError, Reader, Writer};
use crate::MAX_FRAME_LEN;

/// The frame-type tag. Unknown tags are a protocol error at the transport
/// layer (the receiver closes the connection); this crate only maps the known
/// set and reports the rest as [`ProtoError::BadEnum`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    /// `0x01` browser → companion, plaintext (version/capability offer).
    ClientHello,
    /// `0x02` companion → browser, plaintext (version selection + floor).
    ServerHello,
    /// `0x03` browser → companion, Noise message 1 (`e`).
    Handshake1,
    /// `0x04` companion → browser, Noise message 2 (`e, ee, s, es`).
    Handshake2,
    /// `0x05` browser → companion, Noise message 3 (`s, se`).
    Handshake3,
    /// `0x10` either direction, one AEAD transport record.
    Transport,
}

impl FrameType {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            FrameType::ClientHello => 0x01,
            FrameType::ServerHello => 0x02,
            FrameType::Handshake1 => 0x03,
            FrameType::Handshake2 => 0x04,
            FrameType::Handshake3 => 0x05,
            FrameType::Transport => 0x10,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self, ProtoError> {
        Ok(match tag {
            0x01 => FrameType::ClientHello,
            0x02 => FrameType::ServerHello,
            0x03 => FrameType::Handshake1,
            0x04 => FrameType::Handshake2,
            0x05 => FrameType::Handshake3,
            0x10 => FrameType::Transport,
            _ => return Err(ProtoError::BadEnum("frame_type")),
        })
    }
}

/// One decoded frame. The `body` is uninterpreted bytes; the reader that
/// consumed the frame does not know or care whether the body is a hello, a
/// handshake message, or a ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub body: Vec<u8>,
}

impl Frame {
    #[must_use]
    pub fn new(frame_type: FrameType, body: Vec<u8>) -> Self {
        Self { frame_type, body }
    }

    /// Encode the full frame bytes (`length ‖ type ‖ body`). Errors if the body
    /// exceeds [`MAX_FRAME_LEN`] — an oversized frame is never emitted.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        if self.body.len() > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge);
        }
        let mut w = Writer::new();
        // `length` counts the body only; `frame_type` is a separate byte after
        // it, so the whole frame is `4 + 1 + body.len()` bytes on the wire.
        w.put_u32(self.body.len() as u32);
        w.put_u8(self.frame_type.tag());
        w.put_bytes(&self.body);
        Ok(w.into_vec())
    }

    /// Decode exactly one frame from the front of `buf`, returning the frame and
    /// the number of bytes consumed. Enforces the [`MAX_FRAME_LEN`] cap before
    /// allocating the body, so a hostile length prefix cannot force a large
    /// read. Used by a streaming transport that may hold more than one frame.
    pub fn decode_prefix(buf: &[u8]) -> Result<(Frame, usize), ProtoError> {
        let mut r = Reader::new(buf);
        let len = r.read_u32()? as usize;
        if len > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge);
        }
        let tag = r.read_u8()?;
        let frame_type = FrameType::from_tag(tag)?;
        let body = r.read_take(len)?.to_vec();
        Ok((Frame { frame_type, body }, 5 + len))
    }

    /// Decode exactly one frame that fills `buf` completely (no trailing bytes).
    pub fn decode_exact(buf: &[u8]) -> Result<Frame, ProtoError> {
        let (frame, consumed) = Self::decode_prefix(buf)?;
        if consumed == buf.len() {
            Ok(frame)
        } else {
            Err(ProtoError::TrailingBytes)
        }
    }
}
