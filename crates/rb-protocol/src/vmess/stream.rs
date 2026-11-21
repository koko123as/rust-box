//! A VMess connection as a stream (sing-vmess `clientConn`, `serverConn`)
//! and as a packet connection (`clientPacketConn`, `serverPacketConn`:
//! one chunk per packet, every packet to and from the request's
//! destination).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use rb_adapter::{BoxStream, PacketConn, Socksaddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use super::codec::{BodyReader, BodyWriter, Chunk};

/// Bytes read from the connection at a time.
const READ_SIZE: usize = 16 * 1024;

fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

/// A VMess stream for either side.
pub struct VmessStream<S> {
    inner: S,
    reader: BodyReader,
    writer: BodyWriter,
    /// Wire bytes waiting to be written.
    out: Vec<u8>,
    offset: usize,
    /// Data of the current chunk not returned yet.
    data: Vec<u8>,
    position: usize,
    eof: bool,
}

impl<S> VmessStream<S> {
    pub fn new(inner: S, writer: BodyWriter, reader: BodyReader) -> Self {
        VmessStream { inner, reader, writer, out: Vec::new(), offset: 0, data: Vec::new(), position: 0, eof: false }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncWrite + Unpin> VmessStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.offset < self.out.len() {
            let written = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.offset..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.offset += written;
        }
        self.out.clear();
        self.offset = 0;
        Poll::Ready(Ok(()))
    }

    /// Sends the header alone (sing-vmess `writeHandshake(nil)`).
    pub async fn write_header(&mut self) -> io::Result<()> {
        if let Some(prefix) = self.writer.take_prefix() {
            self.out = prefix;
            self.offset = 0;
        }
        std::future::poll_fn(|cx| {
            ready!(self.poll_drain(cx))?;
            Pin::new(&mut self.inner).poll_flush(cx)
        })
        .await
    }
}

/// Reads more wire bytes into `reader`; false at the end of the stream.
fn poll_fill<R: AsyncRead + Unpin>(
    inner: &mut R,
    reader: &mut BodyReader,
    cx: &mut Context<'_>,
) -> Poll<io::Result<bool>> {
    let raw = reader.raw_mut();
    let start = raw.len();
    raw.resize(start + READ_SIZE, 0);
    let mut buffer = ReadBuf::new(&mut raw[start..]);
    let result = Pin::new(inner).poll_read(cx, &mut buffer);
    let read = buffer.filled().len();
    raw.truncate(start + read);
    ready!(result)?;
    Poll::Ready(Ok(read > 0))
}

impl<S: AsyncRead + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.position < this.data.len() {
                let count = (this.data.len() - this.position).min(buf.remaining());
                buf.put_slice(&this.data[this.position..this.position + count]);
                this.position += count;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.reader.decode()? {
                Some(Chunk::Data(data)) => {
                    this.data = data;
                    this.position = 0;
                }
                Some(Chunk::Eof) => this.eof = true,
                None => {
                    if !ready!(poll_fill(&mut this.inner, &mut this.reader, cx))? {
                        if this.reader.at_boundary() {
                            this.eof = true;
                        } else {
                            return Poll::Ready(Err(crate::framed::eof()));
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Taken at once (encoding advances the ciphers), written out by
        // later calls if the stream is busy.
        this.out = this.writer.encode(data);
        this.offset = 0;
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A VMess UDP request for either side: each chunk is one packet, to and
/// from `destination`. The client's request goes out with the first
/// packet, the server's response before its first reply.
pub struct VmessPacketConn {
    reader: Mutex<(ReadHalf<BoxStream>, BodyReader)>,
    writer: Mutex<(WriteHalf<BoxStream>, BodyWriter)>,
    destination: Socksaddr,
}

impl VmessPacketConn {
    pub fn new(stream: BoxStream, writer: BodyWriter, reader: BodyReader, destination: Socksaddr) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        VmessPacketConn {
            reader: Mutex::new((read_half, reader)),
            writer: Mutex::new((write_half, writer)),
            destination,
        }
    }
}

#[async_trait]
impl PacketConn for VmessPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut guard = self.reader.lock().await;
        let (stream, reader) = &mut *guard;
        loop {
            match reader.decode()? {
                Some(Chunk::Data(data)) => {
                    if data.len() > buffer.len() {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "short buffer"));
                    }
                    buffer[..data.len()].copy_from_slice(&data);
                    return Ok((data.len(), self.destination.clone()));
                }
                Some(Chunk::Eof) => return Err(crate::framed::eof()),
                None => {
                    // Cancel safe: read bytes stay in the reader.
                    let raw = reader.raw_mut();
                    raw.reserve(READ_SIZE);
                    if stream.read_buf(raw).await? == 0 {
                        return Err(if reader.at_boundary() { crate::framed::eof() } else { unexpected_eof() });
                    }
                }
            }
        }
    }

    async fn write_packet(&self, data: &[u8], _address: &Socksaddr) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        let (stream, writer) = &mut *guard;
        let frame = writer.encode(data);
        stream.write_all(&frame).await?;
        stream.flush().await
    }
}
