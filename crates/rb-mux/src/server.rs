//! The sing-mux server (`server.go`, `server_conn.go`): a connection to
//! `sp.mux.sing-box.arpa:444` becomes a session whose streams carry TCP
//! connections and UDP packets (with or without addresses), answered
//! with a status byte before the first data.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use rb_adapter::{BoxStream, PacketConn, SharedPacketConn, Socksaddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use crate::protocol::{self, PaddingStream, BRUTAL_EXCHANGE_DOMAIN, STATUS_SUCCESS};
use crate::{parse_addr_packet, parse_len_packet, AnySession, FrameReader};

/// Where the streams of a session go (the inbound's router, with the
/// connection's metadata).
#[async_trait]
pub trait ServerHandler: Send + Sync + 'static {
    async fn new_connection(self: Arc<Self>, destination: Socksaddr, stream: BoxStream);
    async fn new_packet_connection(self: Arc<Self>, destination: Socksaddr, conn: SharedPacketConn);
}

/// sing-box `InboundMultiplexOptions` (brutal is refused by the
/// configuration check).
#[derive(Debug, Clone, Default)]
pub struct ServerOptions {
    /// Reject connections without padding.
    pub padding: bool,
}

/// Serves a multiplexed connection until it ends (sing-mux
/// `Service.NewConnectionEx`); `log_prefix` is the inbound's.
pub async fn serve(
    conn: BoxStream,
    source: std::net::SocketAddr,
    options: &ServerOptions,
    handler: Arc<dyn ServerHandler>,
    log_prefix: String,
) {
    let result = serve_session(conn, options, handler, &log_prefix).await;
    if let Err(error) = result {
        if is_closed(&error) {
            debug!("{log_prefix}: connection closed: {error}");
        } else {
            error!("{log_prefix}: process multiplex connection from {source}: {error}");
        }
    }
}

fn is_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

async fn serve_session(
    mut conn: BoxStream,
    options: &ServerOptions,
    handler: Arc<dyn ServerHandler>,
    log_prefix: &str,
) -> io::Result<()> {
    let request = protocol::read_request(&mut conn).await?;
    let conn: BoxStream = if request.padding {
        Box::new(PaddingStream::new(conn))
    } else if options.padding {
        return Err(io::Error::other("non-padded connection rejected"));
    } else {
        conn
    };
    let session = AnySession::server(conn, request.protocol)?;
    loop {
        let stream = session.accept().await?;
        let handler = handler.clone();
        let log_prefix = log_prefix.to_string();
        tokio::spawn(async move {
            if let Err(error) = new_stream(stream, handler, &log_prefix).await {
                error!("{log_prefix}: process multiplex stream: {error}");
            }
        });
    }
}

async fn new_stream(mut stream: BoxStream, handler: Arc<dyn ServerHandler>, log_prefix: &str) -> io::Result<()> {
    let request = protocol::read_stream_request(&mut stream)
        .await
        .map_err(|error| io::Error::new(error.kind(), format!("read multiplex stream request: {error}")))?;
    let destination = request.destination;
    if !request.udp {
        if destination.domain() == Some(BRUTAL_EXCHANGE_DOMAIN) {
            stream
                .read_u64()
                .await
                .map_err(|error| io::Error::new(error.kind(), format!("read brutal request: {error}")))?;
            // `serverConn` puts the status in front of the first write.
            let mut response = vec![STATUS_SUCCESS];
            response.extend(protocol::brutal_response(0, false, "brutal is not enabled by the server"));
            stream
                .write_all(&response)
                .await
                .map_err(|error| io::Error::new(error.kind(), format!("write brutal response: {error}")))?;
            let _ = stream.shutdown().await;
            return Ok(());
        }
        info!("{log_prefix}: inbound multiplex connection to {destination}");
        let conn = ServerConn { stream, response_written: false, out: Vec::new(), offset: 0 };
        handler.new_connection(destination, Box::new(conn)).await;
    } else {
        let (reader, writer) = tokio::io::split(stream);
        let conn = ServerPacketConn {
            reader: Mutex::new(FrameReader::new(reader)),
            writer: Mutex::new((writer, false)),
            packet_addr: request.packet_addr,
            destination: destination.clone(),
        };
        if request.packet_addr {
            info!("{log_prefix}: inbound multiplex packet connection");
        } else {
            info!("{log_prefix}: inbound multiplex packet connection to {destination}");
        }
        handler.new_packet_connection(destination, Arc::new(conn)).await;
    }
    Ok(())
}

/// A TCP stream of the server (sing-mux `serverConn`): the status byte
/// goes in front of the first write.
struct ServerConn {
    stream: BoxStream,
    response_written: bool,
    out: Vec<u8>,
    offset: usize,
}

impl ServerConn {
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

impl AsyncRead for ServerConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if !this.response_written {
            this.response_written = true;
            let mut out = vec![STATUS_SUCCESS];
            out.extend_from_slice(data);
            this.out = out;
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

/// The UDP of a stream (sing-mux `serverPacketConn` and
/// `serverPacketAddrConn`).
struct ServerPacketConn {
    reader: Mutex<FrameReader<ReadHalf<BoxStream>>>,
    writer: Mutex<(WriteHalf<BoxStream>, bool)>,
    packet_addr: bool,
    destination: Socksaddr,
}

#[async_trait]
impl PacketConn for ServerPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut reader = self.reader.lock().await;
        let (address, data) = if self.packet_addr {
            reader.next(parse_addr_packet).await?
        } else {
            (self.destination.clone(), reader.next(parse_len_packet).await?)
        };
        if data.len() > buffer.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "short buffer"));
        }
        buffer[..data.len()].copy_from_slice(&data);
        Ok((data.len(), address))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        let (writer, response_written) = &mut *guard;
        let mut frame = Vec::with_capacity(3 + 260 + data.len());
        if !*response_written {
            frame.push(STATUS_SUCCESS);
        }
        if self.packet_addr {
            rb_shadowsocks::write_address(&mut frame, address)?;
        }
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        writer.write_all(&frame).await?;
        *response_written = true;
        writer.flush().await
    }
}
