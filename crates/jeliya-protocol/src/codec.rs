//! Big-endian, length-prefixed primitive codec shared by every wire type in
//! this crate. All integers are big-endian; all strings are UTF-8 with a
//! `u16` byte-length prefix. The reader is strict: it never over-reads, and a
//! well-formed decode consumes its input exactly (`finish` enforces it), so a
//! frame with trailing bytes is rejected rather than silently truncated.

/// A wire decode/encode error. Every variant is a fail-closed outcome: the
/// caller drops the frame (and, at the transport layer, the connection).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// The input ended before a fixed-size field could be read.
    ShortInput,
    /// A decode left unconsumed trailing bytes (a strict-parse violation).
    TrailingBytes,
    /// A frame declared a body larger than [`crate::MAX_FRAME_LEN`].
    FrameTooLarge,
    /// A string field's length prefix would exceed `u16::MAX` on encode.
    StringTooLong,
    /// A hello frame did not carry the `JCTL` magic.
    BadMagic,
    /// A string field was not valid UTF-8.
    BadUtf8,
    /// A discriminant byte/word did not name a known variant.
    BadEnum(&'static str),
    /// A bounded count (versions, methods, scopes, rooms) was out of range.
    BadCount(&'static str),
}

/// A cursor over an input byte slice. Reads advance the position; every read
/// checks bounds and returns [`ProtoError::ShortInput`] rather than panicking.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.remaining() < n {
            return Err(ProtoError::ShortInput);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn read_u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, ProtoError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, ProtoError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, ProtoError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        let b = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }

    /// Read exactly `n` bytes, borrowing from the input.
    pub fn read_take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        self.take(n)
    }

    /// Read a `u16`-length-prefixed byte blob (not UTF-8-checked).
    pub fn read_blob(&mut self) -> Result<&'a [u8], ProtoError> {
        let len = self.read_u16()? as usize;
        self.take(len)
    }

    /// Read a `u16`-length-prefixed UTF-8 string.
    pub fn read_string(&mut self) -> Result<String, ProtoError> {
        let bytes = self.read_blob()?;
        core_str(bytes)
    }

    /// Consume the reader, erroring if any bytes remain unread.
    pub fn finish(self) -> Result<(), ProtoError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(ProtoError::TrailingBytes)
        }
    }
}

fn core_str(bytes: &[u8]) -> Result<String, ProtoError> {
    core::str::from_utf8(bytes)
        .map(std::string::ToString::to_string)
        .map_err(|_| ProtoError::BadUtf8)
}

/// An append-only big-endian writer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn put_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Write a `u16`-length-prefixed byte blob.
    pub fn put_blob(&mut self, v: &[u8]) -> Result<(), ProtoError> {
        let len = u16::try_from(v.len()).map_err(|_| ProtoError::StringTooLong)?;
        self.put_u16(len);
        self.put_bytes(v);
        Ok(())
    }

    /// Write a `u16`-length-prefixed UTF-8 string.
    pub fn put_string(&mut self, v: &str) -> Result<(), ProtoError> {
        self.put_blob(v.as_bytes())
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}
