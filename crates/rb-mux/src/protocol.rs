//! sing-mux wire format: the session request (`protocol.go`
//! `EncodeRequest`/`ReadRequest`), the padding of the first frames
//! (`padding.go`), and the stream request and response (`StreamRequest`,
//! `StreamResponse`), with the brutal exchange (`brutal.go`).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rand::{Rng, RngCore};
use rb_adapter::Socksaddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub const PROTOCOL_SMUX: u8 = 0;
pub const PROTOCOL_YAMUX: u8 = 1;
pub const PROTOCOL_H2MUX: u8 = 2;
pub const VERSION_0: u8 = 0;
pub const VERSION_1: u8 = 1;
/// `sp.mux.sing-box.arpa:444`, where a multiplexed session goes.
pub const DESTINATION_DOMAIN: &str = "sp.mux.sing-box.arpa";
pub const DESTINATION_PORT: u16 = 444;
pub const BRUTAL_EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";
pub const BRUTAL_MIN_SPEED_BPS: u64 = 65536;
pub const FLAG_UDP: u16 = 1;
pub const FLAG_ADDR: u16 = 2;
pub const STATUS_SUCCESS: u8 = 0;
pub const STATUS_ERROR: u8 = 1;
/// Frames padded in each direction (`kFirstPaddings`).
const FIRST_PADDINGS: usize = 16;

pub fn destination() -> Socksaddr {
    Socksaddr::from_host_port(DESTINATION_DOMAIN, DESTINATION_PORT)
}

/// Whether `destination` is the multiplex destination (sing-box compares
/// the whole address).
pub fn is_destination(destination: &Socksaddr) -> bool {
    destination.domain() == Some(DESTINATION_DOMAIN) && destination.port == DESTINATION_PORT
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// The session request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub version: u8,
    pub protocol: u8,
    pub padding: bool,
}

/// `EncodeRequest` (with no payload).
pub fn encode_request(request: &Request) -> Vec<u8> {
    let mut buffer = vec![request.version, request.protocol];
    if request.version == VERSION_1 {
        buffer.push(request.padding as u8);
        if request.padding {
            let length: u16 = rand::rng().random_range(256..768);
            buffer.extend_from_slice(&length.to_be_bytes());
            buffer.resize(buffer.len() + length as usize, 0);
        }
    }
    buffer
}

/// `ReadRequest`.
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Request> {
    let version = reader.read_u8().await?;
    if version > VERSION_1 {
        return Err(invalid(format!("unsupported version: {version}")));
    }
    let protocol = reader.read_u8().await?;
    let mut padding = false;
    if version == VERSION_1 {
        // Go's binary.Read of a bool: any non-zero byte is true.
        padding = reader.read_u8().await? != 0;
        if padding {
            let length = reader.read_u16().await? as usize;
            let mut skip = vec![0u8; length];
            reader.read_exact(&mut skip).await?;
        }
    }
    Ok(Request { version, protocol, padding })
}

/// A stream request: flags and the SOCKS address.
pub fn encode_stream_request(udp: bool, packet_addr: bool, destination: &Socksaddr) -> io::Result<Vec<u8>> {
    let mut flags = 0u16;
    if udp {
        flags |= FLAG_UDP;
    }
    let mut buffer = Vec::new();
    let mut destination = destination.clone();
    if packet_addr {
        flags |= FLAG_ADDR;
        if destination.port == 0 && destination.ip().is_some_and(|ip| ip.is_unspecified()) {
            destination = self::destination();
        }
    }
    buffer.extend_from_slice(&flags.to_be_bytes());
    rb_shadowsocks::write_address(&mut buffer, &destination)?;
    Ok(buffer)
}

/// What a stream request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRequest {
    pub udp: bool,
    pub packet_addr: bool,
    pub destination: Socksaddr,
}

/// `ReadStreamRequest`.
pub async fn read_stream_request<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<StreamRequest> {
    let flags = reader.read_u16().await?;
    let destination = rb_shadowsocks::read_address_from(reader).await?;
    let udp = flags & FLAG_UDP != 0;
    Ok(StreamRequest { udp, packet_addr: udp && flags & FLAG_ADDR != 0, destination })
}

/// Go `varbin.Write` of a string: a uvarint length and the bytes.
pub fn put_string(buffer: &mut Vec<u8>, text: &str) {
    let mut length = text.len() as u64;
    while length >= 0x80 {
        buffer.push(length as u8 | 0x80);
        length >>= 7;
    }
    buffer.push(length as u8);
    buffer.extend_from_slice(text.as_bytes());
}

async fn read_string<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut length = 0u64;
    let mut shift = 0;
    loop {
        let byte = reader.read_u8().await?;
        length |= ((byte & 0x7f) as u64) << shift;
        if byte < 0x80 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(invalid("binary: varint overflows a 64-bit integer"));
        }
    }
    let mut data = vec![0u8; length.min(1 << 16) as usize];
    reader.read_exact(&mut data).await?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// `ReadStreamResponse`: an error status is "remote error: message".
pub async fn read_stream_response<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<()> {
    let status = reader.read_u8().await?;
    if status == STATUS_ERROR {
        let message = read_string(reader).await?;
        return Err(io::Error::other(format!("remote error: {message}")));
    }
    Ok(())
}

/// The error response of a stream (`serverConn.HandshakeFailure`).
pub fn error_response(message: &str) -> Vec<u8> {
    let mut buffer = vec![STATUS_ERROR];
    put_string(&mut buffer, message);
    buffer
}

/// `WriteBrutalResponse`.
pub fn brutal_response(receive_bps: u64, ok: bool, message: &str) -> Vec<u8> {
    let mut buffer = vec![ok as u8];
    if ok {
        buffer.extend_from_slice(&receive_bps.to_be_bytes());
    } else {
        put_string(&mut buffer, message);
    }
    buffer
}

/// `ReadBrutalResponse`.
pub async fn read_brutal_response<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    if reader.read_u8().await? != 0 {
        reader.read_u64().await
    } else {
        Err(io::Error::other(format!("remote error: {}", read_string(reader).await?)))
    }
}

enum PaddingRead {
    /// A padded frame's header, `filled` of 4 bytes read.
    Header([u8; 4], usize),
    /// Data left, then the padding after it.
    Data(usize, usize),
    Padding(usize),
    Plain,
}

/// The padding of the first 16 writes and reads (sing-mux `paddingConn`):
/// `[length u16][padding u16][data][padding]`, plain afterwards.
pub struct PaddingStream<S> {
    inner: S,
    read: PaddingRead,
    reads: usize,
    writes: usize,
    out: Vec<u8>,
    offset: usize,
}

impl<S> PaddingStream<S> {
    pub fn new(inner: S) -> Self {
        PaddingStream { inner, read: PaddingRead::Header([0; 4], 0), reads: 0, writes: 0, out: Vec::new(), offset: 0 }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PaddingStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.read {
                PaddingRead::Plain => return Pin::new(&mut this.inner).poll_read(cx, buf),
                PaddingRead::Header(header, filled) => {
                    let mut read = ReadBuf::new(&mut header[*filled..]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                    let count = read.filled().len();
                    if count == 0 {
                        return Poll::Ready(if *filled == 0 {
                            Ok(())
                        } else {
                            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"))
                        });
                    }
                    *filled += count;
                    if *filled == 4 {
                        let data = u16::from_be_bytes([header[0], header[1]]) as usize;
                        let padding = u16::from_be_bytes([header[2], header[3]]) as usize;
                        this.reads += 1;
                        this.read =
                            if data == 0 { PaddingRead::Padding(padding) } else { PaddingRead::Data(data, padding) };
                    }
                }
                PaddingRead::Data(left, padding) => {
                    let limit = (*left).min(buf.remaining());
                    let mut temp = vec![0u8; limit];
                    let mut read = ReadBuf::new(&mut temp);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                    let count = read.filled().len();
                    if count == 0 && limit > 0 {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")));
                    }
                    buf.put_slice(&temp[..count]);
                    *left -= count;
                    if *left == 0 {
                        this.read = PaddingRead::Padding(*padding);
                    }
                    return Poll::Ready(Ok(()));
                }
                PaddingRead::Padding(left) => {
                    if *left == 0 {
                        this.read = if this.reads < FIRST_PADDINGS {
                            PaddingRead::Header([0; 4], 0)
                        } else {
                            PaddingRead::Plain
                        };
                        continue;
                    }
                    let mut skip = [0u8; 1024];
                    let limit = (*left).min(skip.len());
                    let mut read = ReadBuf::new(&mut skip[..limit]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                    let count = read.filled().len();
                    if count == 0 {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")));
                    }
                    *left -= count;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> PaddingStream<S> {
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
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddingStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if this.writes >= FIRST_PADDINGS {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let data = &data[..data.len().min(65535)];
        let padding: usize = rand::rng().random_range(256..768);
        let mut frame = Vec::with_capacity(4 + data.len() + padding);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(padding as u16).to_be_bytes());
        frame.extend_from_slice(data);
        let start = frame.len();
        frame.resize(start + padding, 0);
        rand::rng().fill_bytes(&mut frame[start..]);
        this.writes += 1;
        this.out = frame;
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
