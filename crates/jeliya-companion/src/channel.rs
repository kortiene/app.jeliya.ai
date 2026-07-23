//! The async frame channel the connection driver reads and writes, and its
//! error type. A [`FrameChannel`] carries length-prefixed [`Frame`]s over some
//! bidirectional byte stream — an Iroh QUIC stream in production, an in-memory
//! duplex in tests. Keeping the driver behind this trait is what makes the whole
//! control protocol exercisable end-to-end without a socket.
//!
//! Trait methods return boxed `Send` futures (the manual `async-trait` shape)
//! rather than native `async fn`, so the driver's future stays `Send` when the
//! Iroh router spawns it and so a `&dyn FrameChannel` is usable.

use std::future::Future;
use std::pin::Pin;

use jeliya_protocol::{Frame, ProtoError, MAX_FRAME_LEN};

/// A boxed, `Send` future borrowing `'a`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A frame-channel failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// The underlying stream errored or closed mid-frame.
    Io(String),
    /// A frame's declared length exceeded [`MAX_FRAME_LEN`].
    FrameTooLarge,
    /// A frame body failed to decode.
    Proto(ProtoError),
}

impl From<ProtoError> for ChannelError {
    fn from(e: ProtoError) -> Self {
        ChannelError::Proto(e)
    }
}

/// A bidirectional channel of length-prefixed frames.
pub trait FrameChannel: Send {
    /// Read exactly one frame, awaiting more bytes as needed. Errors (including
    /// a clean close mid-stream) end the session.
    fn read_frame(&mut self) -> BoxFuture<'_, Result<Frame, ChannelError>>;
    /// Write one frame.
    fn write_frame(&mut self, frame: Frame) -> BoxFuture<'_, Result<(), ChannelError>>;
    /// Close the send side / connection. Best-effort.
    fn close(&mut self) -> BoxFuture<'_, ()>;
}

/// Decode a frame header (`u32 length ‖ u8 frame_type`) into `(len, type_tag)`,
/// enforcing the [`MAX_FRAME_LEN`] cap before any body is allocated. Shared by
/// every [`FrameChannel`] implementation.
///
/// Returns the declared body length; the caller then reads exactly that many
/// bytes and reconstructs the [`Frame`].
pub fn parse_header(header: &[u8; 5]) -> Result<(usize, u8), ChannelError> {
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if len > MAX_FRAME_LEN {
        return Err(ChannelError::FrameTooLarge);
    }
    Ok((len, header[4]))
}

/// Reassemble a frame from its parsed header tag and body bytes.
pub fn frame_from_parts(type_tag: u8, body: Vec<u8>) -> Result<Frame, ChannelError> {
    let frame_type = jeliya_protocol::FrameType::from_tag(type_tag)?;
    Ok(Frame::new(frame_type, body))
}

/// A [`FrameChannel`] over any Tokio duplex byte stream (`AsyncRead + AsyncWrite`).
/// Used by the tests to run both protocol ends in-process; also a reference for
/// the Iroh binding, which frames bytes the same way over a QUIC stream.
pub struct DuplexChannel<S> {
    stream: S,
}

impl<S> DuplexChannel<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> FrameChannel for DuplexChannel<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    fn read_frame(&mut self) -> BoxFuture<'_, Result<Frame, ChannelError>> {
        Box::pin(async move {
            use tokio::io::AsyncReadExt;
            let mut header = [0u8; 5];
            self.stream
                .read_exact(&mut header)
                .await
                .map_err(|e| ChannelError::Io(e.to_string()))?;
            let (len, tag) = parse_header(&header)?;
            let mut body = vec![0u8; len];
            self.stream
                .read_exact(&mut body)
                .await
                .map_err(|e| ChannelError::Io(e.to_string()))?;
            frame_from_parts(tag, body)
        })
    }

    fn write_frame(&mut self, frame: Frame) -> BoxFuture<'_, Result<(), ChannelError>> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            let bytes = frame.encode()?;
            self.stream
                .write_all(&bytes)
                .await
                .map_err(|e| ChannelError::Io(e.to_string()))?;
            self.stream
                .flush()
                .await
                .map_err(|e| ChannelError::Io(e.to_string()))
        })
    }

    fn close(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            let _ = self.stream.shutdown().await;
        })
    }
}
