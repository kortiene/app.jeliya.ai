//! The plaintext version/capability hellos (deliverable D6). These are the
//! only frames sent in the clear, and they carry no capability detail — just
//! offered versions, the session kind, and (for pairing) the rendezvous nonce.
//! Their exact bytes become the Noise prologue, so any middle-party edit breaks
//! the handshake rather than silently downgrading it.

use crate::codec::{ProtoError, Reader, Writer};
use crate::frame::{Frame, FrameType};

/// The 4-byte magic prefixing both hellos: `JCTL`.
pub const MAGIC: [u8; 4] = *b"JCTL";

/// The maximum number of versions a client may offer.
pub const MAX_VERSIONS: usize = 8;

/// The all-zero pairing nonce a control (already-paired) session must send.
pub const ZERO_NONCE: [u8; 16] = [0u8; 16];

/// Why a session is being opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    /// Enroll a new control key (carries a live rendezvous nonce; no scoped RPC
    /// is ever accepted on this kind).
    Pairing,
    /// Exercise an already-installed control key (nonce field is all-zero).
    Control,
}

impl SessionKind {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            SessionKind::Pairing => 1,
            SessionKind::Control => 2,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self, ProtoError> {
        Ok(match tag {
            1 => SessionKind::Pairing,
            2 => SessionKind::Control,
            _ => return Err(ProtoError::BadEnum("session_kind")),
        })
    }
}

/// The browser's opening offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    /// Supported protocol versions in descending preference; 1..=8 entries.
    pub versions: Vec<u16>,
    pub session_kind: SessionKind,
    /// The rendezvous nonce from the QR/link for a pairing session; all-zero
    /// for a control session (validated on decode).
    pub pairing_nonce: [u8; 16],
}

impl ClientHello {
    pub fn encode_body(&self) -> Result<Vec<u8>, ProtoError> {
        if self.versions.is_empty() || self.versions.len() > MAX_VERSIONS {
            return Err(ProtoError::BadCount("versions"));
        }
        if self.session_kind == SessionKind::Control && self.pairing_nonce != ZERO_NONCE {
            return Err(ProtoError::BadEnum("pairing_nonce"));
        }
        let mut w = Writer::new();
        w.put_bytes(&MAGIC);
        w.put_u8(self.versions.len() as u8);
        for v in &self.versions {
            w.put_u16(*v);
        }
        w.put_u8(self.session_kind.tag());
        w.put_bytes(&self.pairing_nonce);
        Ok(w.into_vec())
    }

    pub fn decode_body(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut r = Reader::new(buf);
        if r.read_array::<4>()? != MAGIC {
            return Err(ProtoError::BadMagic);
        }
        let count = r.read_u8()? as usize;
        if count == 0 || count > MAX_VERSIONS {
            return Err(ProtoError::BadCount("versions"));
        }
        let mut versions = Vec::with_capacity(count);
        for _ in 0..count {
            versions.push(r.read_u16()?);
        }
        let session_kind = SessionKind::from_tag(r.read_u8()?)?;
        let pairing_nonce = r.read_array::<16>()?;
        r.finish()?;
        if session_kind == SessionKind::Control && pairing_nonce != ZERO_NONCE {
            return Err(ProtoError::BadEnum("pairing_nonce"));
        }
        Ok(Self {
            versions,
            session_kind,
            pairing_nonce,
        })
    }

    pub fn to_frame(&self) -> Result<Frame, ProtoError> {
        Ok(Frame::new(FrameType::ClientHello, self.encode_body()?))
    }
}

/// The companion's version selection and minimum-safe floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerHello {
    /// The chosen version, or `0` to mean "no compatible version" (the browser
    /// renders an upgrade prompt; the companion then closes).
    pub version: u16,
    /// The companion-enforced minimum-safe protocol version.
    pub min_version: u16,
}

impl ServerHello {
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_bytes(&MAGIC);
        w.put_u16(self.version);
        w.put_u16(self.min_version);
        w.into_vec()
    }

    pub fn decode_body(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut r = Reader::new(buf);
        if r.read_array::<4>()? != MAGIC {
            return Err(ProtoError::BadMagic);
        }
        let version = r.read_u16()?;
        let min_version = r.read_u16()?;
        r.finish()?;
        Ok(Self {
            version,
            min_version,
        })
    }

    #[must_use]
    pub fn to_frame(&self) -> Frame {
        Frame::new(FrameType::ServerHello, self.encode_body())
    }

    /// Whether the companion found a compatible version.
    #[must_use]
    pub fn is_incompatible(&self) -> bool {
        self.version == 0
    }
}
