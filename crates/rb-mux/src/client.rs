//! The sing-mux client (`client.go`, `client_conn.go`): sessions to
//! `sp.mux.sing-box.arpa:444` through the outbound, chosen by
//! `max_connections`, `min_streams` and `max_streams`; a TCP stream sends
//! its request with its first data, UDP goes as packetaddr packets.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{BoxStream, PacketConn, Socksaddr};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::protocol::{self, PaddingStream, Request, PROTOCOL_H2MUX, PROTOCOL_SMUX, PROTOCOL_YAMUX};
use crate::{parse_addr_packet, parse_response, AnySession, FrameReader};

/// sing-mux `TCPTimeout`: how long a new session may take.
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// How the client reaches the server: the outbound's connection to
/// `sp.mux.sing-box.arpa:444`.
#[async_trait]
pub trait MuxDialer: Send + Sync + 'static {
    async fn dial(&self, destination: &Socksaddr) -> io::Result<BoxStream>;
}

/// sing-box `OutboundMultiplexOptions` after its checks.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub protocol: u8,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub padding: bool,
}

impl ClientOptions {
    /// sing-mux `NewClient`: the protocol name, and `min_streams` 8 when
    /// neither `max_streams` nor `max_connections` is set.
    pub fn new(
        protocol: &str,
        max_connections: usize,
        min_streams: usize,
        max_streams: usize,
        padding: bool,
    ) -> Result<Self, String> {
        let protocol = match protocol {
            "" | "h2mux" => PROTOCOL_H2MUX,
            "smux" => PROTOCOL_SMUX,
            "yamux" => PROTOCOL_YAMUX,
            other => return Err(format!("unknown protocol: {other}")),
        };
        let min_streams = if max_streams == 0 && max_connections == 0 { 8 } else { min_streams };
        Ok(ClientOptions { protocol, max_connections, min_streams, max_streams, padding })
    }
}

struct ClientSession {
    session: AnySession,
    streams: AtomicUsize,
}

/// A sing-mux client.
pub struct Client {
    dialer: Arc<dyn MuxDialer>,
    options: ClientOptions,
    sessions: Mutex<Vec<Arc<ClientSession>>>,
}

impl Client {
    pub fn new(dialer: Arc<dyn MuxDialer>, options: ClientOptions) -> Self {
        Client { dialer, options, sessions: Mutex::new(Vec::new()) }
    }

    /// sing-mux `selectSession`.
    fn select(&self, sessions: &[Arc<ClientSession>]) -> Option<Arc<ClientSession>> {
        let session = sessions
            .iter()
            .filter(|session| session.session.can_take_new_request())
            .min_by_key(|session| session.streams.load(Ordering::SeqCst))?;
        let streams = session.streams.load(Ordering::SeqCst);
        if streams == 0 {
            return Some(session.clone());
        }
        let options = &self.options;
        if options.max_connections > 0 {
            if sessions.len() >= options.max_connections || streams < options.min_streams {
                return Some(session.clone());
            }
        } else if options.max_streams > 0 && streams < options.max_streams {
            return Some(session.clone());
        }
        None
    }

    async fn offer(&self) -> io::Result<Arc<ClientSession>> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|session| {
            let closed = session.session.is_closed();
            if closed {
                session.session.close();
            }
            !closed
        });
        let session = match self.select(&sessions) {
            Some(session) => session,
            None => {
                let session = tokio::time::timeout(TCP_TIMEOUT, self.offer_new())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "context deadline exceeded"))??;
                sessions.push(session.clone());
                session
            }
        };
        session.streams.fetch_add(1, Ordering::SeqCst);
        Ok(session)
    }

    async fn offer_new(&self) -> io::Result<Arc<ClientSession>> {
        let mut conn = self.dialer.dial(&protocol::destination()).await?;
        let request = Request {
            version: if self.options.padding { protocol::VERSION_1 } else { protocol::VERSION_0 },
            protocol: self.options.protocol,
            padding: self.options.padding,
        };
        conn.write_all(&protocol::encode_request(&request)).await?;
        let conn: BoxStream = if self.options.padding { Box::new(PaddingStream::new(conn)) } else { conn };
        let session = AnySession::client(conn, self.options.protocol).await?;
        Ok(Arc::new(ClientSession { session, streams: AtomicUsize::new(0) }))
    }

    async fn open_stream(&self) -> io::Result<SessionStream> {
        let mut last_error = None;
        for _ in 0..2 {
            let session = match self.offer().await {
                Ok(session) => session,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            match session.session.open().await {
                Ok(stream) => return Ok(SessionStream { stream, session }),
                Err(error) => {
                    session.streams.fetch_sub(1, Ordering::SeqCst);
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::other("mux: no session")))
    }

    /// A TCP connection to `destination` (sing-mux `DialContext`).
    pub async fn dial_tcp(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let stream = self.open_stream().await?;
        let request = protocol::encode_stream_request(false, false, destination)?;
        Ok(Box::new(ClientConn { stream, request: Some(request), out: Vec::new(), offset: 0, response_read: false }))
    }

    /// The UDP of a connection (sing-mux `ListenPacket`: packetaddr).
    pub async fn listen_packet(&self, destination: &Socksaddr) -> io::Result<rb_adapter::SharedPacketConn> {
        let stream = self.open_stream().await?;
        let request = protocol::encode_stream_request(true, true, destination)?;
        let (reader, writer) = tokio::io::split(Box::new(stream) as BoxStream);
        Ok(Arc::new(ClientPacketAddrConn {
            reader: Mutex::new((FrameReader::new(reader), false)),
            writer: Mutex::new((writer, Some(request))),
        }))
    }

    /// How many sessions are open.
    pub async fn sessions_len(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Closes every session (sing-mux `Reset`).
    pub async fn reset(&self) {
        for session in self.sessions.lock().await.drain(..) {
            session.session.close();
        }
    }
}

/// A stream that gives its session's count back when dropped.
struct SessionStream {
    stream: BoxStream,
    session: Arc<ClientSession>,
}

impl Drop for SessionStream {
    fn drop(&mut self) {
        self.session.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AsyncRead for SessionStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SessionStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A TCP stream of the client (sing-mux `clientConn`).
struct ClientConn {
    stream: SessionStream,
    request: Option<Vec<u8>>,
    out: Vec<u8>,
    offset: usize,
    response_read: bool,
}

impl ClientConn {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.offset < self.out.len() {
            let written = ready!(Pin::new(&mut self.stream).poll_write(cx, &self.out[self.offset..]))?;
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

impl AsyncRead for ClientConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.response_read {
            let mut status = [0u8; 1];
            let mut read = ReadBuf::new(&mut status);
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")));
            }
            if status[0] == protocol::STATUS_ERROR {
                // The message follows; read it whole (it is short).
                let mut rest = Vec::new();
                let mut chunk = [0u8; 512];
                let mut read = ReadBuf::new(&mut chunk);
                if let Poll::Ready(Ok(())) = Pin::new(&mut this.stream).poll_read(cx, &mut read) {
                    rest.extend_from_slice(read.filled());
                }
                let message = decode_message(&rest);
                return Poll::Ready(Err(io::Error::other(format!("remote error: {message}"))));
            }
            this.response_read = true;
        }
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

/// The message of an error response (uvarint length, then the text).
fn decode_message(data: &[u8]) -> String {
    let mut length = 0usize;
    let mut position = 0;
    for (index, byte) in data.iter().enumerate() {
        length |= ((byte & 0x7f) as usize) << (7 * index);
        position = index + 1;
        if *byte < 0x80 {
            break;
        }
    }
    let end = (position + length).min(data.len());
    String::from_utf8_lossy(&data[position.min(end)..end]).into_owned()
}

impl AsyncWrite for ClientConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if let Some(mut request) = this.request.take() {
            request.extend_from_slice(data);
            this.out = request;
            this.offset = 0;
            if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
                return Poll::Ready(Err(error));
            }
            return Poll::Ready(Ok(data.len()));
        }
        Pin::new(&mut this.stream).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// The UDP of the client (sing-mux `clientPacketAddrConn`): each packet
/// is `[address][length u16][data]`.
struct ClientPacketAddrConn {
    reader: Mutex<(FrameReader<ReadHalf<BoxStream>>, bool)>,
    writer: Mutex<(WriteHalf<BoxStream>, Option<Vec<u8>>)>,
}

#[async_trait]
impl PacketConn for ClientPacketAddrConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut guard = self.reader.lock().await;
        let (reader, response_read) = &mut *guard;
        if !*response_read {
            reader.next(parse_response).await??;
            *response_read = true;
        }
        let (address, data) = reader.next(parse_addr_packet).await?;
        if data.len() > buffer.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "short buffer"));
        }
        buffer[..data.len()].copy_from_slice(&data);
        Ok((data.len(), address))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        let (writer, request) = &mut *guard;
        let mut frame = request.take().unwrap_or_default();
        rb_shadowsocks::write_address(&mut frame, address)?;
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        writer.write_all(&frame).await?;
        writer.flush().await
    }
}
