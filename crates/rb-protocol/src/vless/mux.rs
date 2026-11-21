//! The server of a VLESS (and VMess) mux request: Mux.Cool frames carrying
//! TCP and UDP sessions, which is also how XUDP reaches the server
//! (sing-vmess `HandleMuxConnection`).
//!
//! A frame is `length(2) session(2) status option [network address]`, then
//! `length(2) data` when the data option is set. Each new session goes to
//! the handler as a TCP stream or a packet connection; the session's
//! replies are framed back on the same connection. The connection's reads
//! wait while a session does not take its data, as sing-vmess's pipes do.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use rb_adapter::{BoxStream, PacketConn, SharedPacketConn, Socksaddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::sync::mpsc;

use super::packet::{
    NETWORK_TCP, NETWORK_UDP, OPTION_DATA, OPTION_ERROR, STATUS_END, STATUS_KEEP, STATUS_KEEP_ALIVE, STATUS_NEW,
};
use super::protocol;
use crate::framed::cause;

/// Frames queued for the connection's writer.
const WRITE_QUEUE: usize = 64;
/// Data or packets queued for one session.
const SESSION_QUEUE: usize = 16;
/// Largest data of one frame.
const MAX_FRAME_DATA: usize = u16::MAX as usize;

/// Where the sessions of a mux connection go.
#[async_trait]
pub trait MuxHandler: Send + Sync + 'static {
    async fn new_connection(self: Arc<Self>, destination: Socksaddr, stream: BoxStream);
    async fn new_packet_connection(self: Arc<Self>, destination: Socksaddr, conn: SharedPacketConn);
}

enum Sender {
    Tcp(mpsc::Sender<Vec<u8>>),
    Udp(mpsc::Sender<(Vec<u8>, Socksaddr)>),
}

struct Session {
    destination: Socksaddr,
    sender: Sender,
}

/// What every session shares: the open sessions and the frame queue.
struct Shared {
    sessions: Mutex<HashMap<u16, Session>>,
    writer: mpsc::Sender<Vec<u8>>,
}

impl Shared {
    /// sing-vmess `close`: forgets the session and, if it was open, tells
    /// the client it ended.
    fn close(&self, id: u16, error: bool) {
        if self.sessions.lock().unwrap().remove(&id).is_some() {
            self.send_end(id, error);
        }
    }

    fn send_end(&self, id: u16, error: bool) {
        let frame = end_frame(id, error);
        if let Err(mpsc::error::TrySendError::Full(frame)) = self.writer.try_send(frame) {
            let writer = self.writer.clone();
            tokio::spawn(async move {
                let _ = writer.send(frame).await;
            });
        }
    }
}

fn end_frame(id: u16, error: bool) -> Vec<u8> {
    let mut frame = vec![0, 4];
    frame.extend_from_slice(&id.to_be_bytes());
    frame.push(STATUS_END);
    frame.push(if error { OPTION_ERROR } else { 0 });
    frame
}

fn data_frame(id: u16, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + data.len());
    frame.extend_from_slice(&[0, 4]);
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&[STATUS_KEEP, OPTION_DATA]);
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn packet_frame(id: u16, data: &[u8], source: &Socksaddr) -> io::Result<Vec<u8>> {
    if data.len() > MAX_FRAME_DATA {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "mux: packet too large"));
    }
    let address_length = protocol::address_len(source);
    let mut frame = Vec::with_capacity(9 + address_length + data.len());
    frame.extend_from_slice(&((5 + address_length) as u16).to_be_bytes());
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&[STATUS_KEEP, OPTION_DATA, NETWORK_UDP]);
    protocol::write_address(&mut frame, source)?;
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

/// Serves a mux connection until it fails or ends; the error is what
/// sing-vmess returns ("mux connection closed: ...").
pub async fn serve(conn: BoxStream, handler: Arc<dyn MuxHandler>) -> io::Error {
    let (reader, mut writer) = tokio::io::split(conn);
    let (frames, mut queue) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE);
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = queue.recv().await {
            if writer.write_all(&frame).await.is_err() {
                return;
            }
            // Flush once nothing else is waiting, as sing-vmess's
            // buffered writer does.
            if queue.is_empty() && writer.flush().await.is_err() {
                return;
            }
        }
    });
    let shared = Arc::new(Shared { sessions: Mutex::new(HashMap::new()), writer: frames });
    let mut reader = BufReader::new(reader);
    let error = loop {
        if let Err(error) = receive(&mut reader, &shared, &handler).await {
            break error;
        }
    };
    // sing-vmess `cleanup`: every session's pipe closes.
    shared.sessions.lock().unwrap().clear();
    writer_task.abort();
    cause(error, "mux connection closed")
}

async fn receive<R: AsyncRead + Unpin>(
    reader: &mut R,
    shared: &Arc<Shared>,
    handler: &Arc<dyn MuxHandler>,
) -> io::Result<()> {
    let length = match reader.read_u16().await {
        Ok(length) => length as usize,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(cause(crate::framed::eof(), "read frame header"))
        }
        Err(error) => return Err(cause(error, "read frame header")),
    };
    let id = reader.read_u16().await?;
    let status = reader.read_u8().await?;
    let option = reader.read_u8().await?;
    let mut network = 0;
    let mut destination = None;
    if length > 4 {
        let mut metadata = vec![0u8; length - 4];
        reader.read_exact(&mut metadata).await?;
        network = metadata[0];
        let (address, _) = protocol::parse_address(&metadata[1..])?;
        destination = Some(address);
    }
    // The session the frame's data goes to.
    let mut target: Option<(u16, bool)> = None;
    match status {
        STATUS_NEW => {
            let session_destination = destination.clone().unwrap_or_else(|| Socksaddr::from_host_port("0.0.0.0", 0));
            let (sender, is_tcp) = match network {
                NETWORK_TCP => {
                    let (sender, receiver) = mpsc::channel(SESSION_QUEUE);
                    let stream = MuxStream::new(id, receiver, shared.clone());
                    let handler = handler.clone();
                    let destination = session_destination.clone();
                    tokio::spawn(async move { handler.new_connection(destination, Box::new(stream)).await });
                    (Sender::Tcp(sender), true)
                }
                NETWORK_UDP => {
                    let (sender, receiver) = mpsc::channel(SESSION_QUEUE);
                    let conn =
                        MuxPacketConn { id, receiver: tokio::sync::Mutex::new(receiver), shared: shared.clone() };
                    let handler = handler.clone();
                    let destination = session_destination.clone();
                    tokio::spawn(async move { handler.new_packet_connection(destination, Arc::new(conn)).await });
                    (Sender::Udp(sender), false)
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad network: {network}"))),
            };
            shared.sessions.lock().unwrap().insert(id, Session { destination: session_destination, sender });
            target = Some((id, is_tcp));
        }
        STATUS_KEEP => {
            let found =
                shared.sessions.lock().unwrap().get(&id).map(|session| matches!(session.sender, Sender::Tcp(_)));
            match found {
                Some(is_tcp) => target = Some((id, is_tcp)),
                None => shared.send_end(id, true),
            }
        }
        STATUS_END => {
            shared.sessions.lock().unwrap().remove(&id);
        }
        STATUS_KEEP_ALIVE => {}
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad session status: {status}"))),
    }
    if option & OPTION_DATA != OPTION_DATA {
        return Ok(());
    }
    let length = reader.read_u16().await? as usize;
    if length == 0 {
        return Ok(());
    }
    let mut data = vec![0u8; length];
    reader.read_exact(&mut data).await?;
    let Some((id, _)) = target else { return Ok(()) };
    let sender = {
        let sessions = shared.sessions.lock().unwrap();
        match sessions.get(&id) {
            Some(Session { sender: Sender::Tcp(sender), .. }) => Some(Ok(sender.clone())),
            Some(Session { sender: Sender::Udp(sender), destination }) => {
                Some(Err((sender.clone(), destination.clone())))
            }
            None => None,
        }
    };
    let delivered = match sender {
        Some(Ok(sender)) => sender.send(data).await.is_ok(),
        Some(Err((sender, session_destination))) => {
            sender.send((data, destination.unwrap_or(session_destination))).await.is_ok()
        }
        None => true,
    };
    if !delivered {
        shared.close(id, true);
    }
    Ok(())
}

/// Waiting for room in the frame queue.
type Reserve = Pin<Box<dyn Future<Output = Result<mpsc::OwnedPermit<Vec<u8>>, mpsc::error::SendError<()>>> + Send>>;

/// A TCP session of a mux connection (sing-vmess `serverMuxConn`).
pub struct MuxStream {
    id: u16,
    receiver: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    offset: usize,
    shared: Arc<Shared>,
    reserve: Option<Reserve>,
    closed: bool,
}

impl MuxStream {
    fn new(id: u16, receiver: mpsc::Receiver<Vec<u8>>, shared: Arc<Shared>) -> Self {
        MuxStream { id, receiver, pending: Vec::new(), offset: 0, shared, reserve: None, closed: false }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.offset >= self.pending.len() {
            match ready!(self.receiver.poll_recv(cx)) {
                Some(data) => {
                    self.pending = data;
                    self.offset = 0;
                }
                None => return Poll::Ready(Ok(())),
            }
        }
        let count = (self.pending.len() - self.offset).min(buf.remaining());
        let start = self.offset;
        buf.put_slice(&self.pending[start..start + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.reserve.is_none() {
            let writer = self.shared.writer.clone();
            self.reserve = Some(Box::pin(writer.reserve_owned()));
        }
        let permit = ready!(self.reserve.as_mut().unwrap().as_mut().poll(cx));
        self.reserve = None;
        let permit = permit.map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let count = data.len().min(MAX_FRAME_DATA);
        permit.send(data_frame(self.id, &data[..count]));
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            self.shared.close(self.id, false);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        if !self.closed {
            self.shared.close(self.id, false);
        }
    }
}

/// A UDP session of a mux connection (sing-vmess `serverMuxPacketConn`).
pub struct MuxPacketConn {
    id: u16,
    receiver: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, Socksaddr)>>,
    shared: Arc<Shared>,
}

#[async_trait]
impl PacketConn for MuxPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (data, address) = self.receiver.lock().await.recv().await.ok_or_else(crate::framed::eof)?;
        if data.len() > buffer.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("short buffer: mux need {}", data.len())));
        }
        buffer[..data.len()].copy_from_slice(&data);
        Ok((data.len(), address))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let frame = packet_frame(self.id, data, address)?;
        self.shared.writer.send(frame).await.map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

impl Drop for MuxPacketConn {
    fn drop(&mut self) {
        self.shared.close(self.id, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::packet::{encode_xudp_frame, parse_xudp_frame, XudpFrame};

    struct Echo;

    #[async_trait]
    impl MuxHandler for Echo {
        async fn new_connection(self: Arc<Self>, _destination: Socksaddr, mut stream: BoxStream) {
            let mut buffer = [0u8; 64];
            let read = stream.read(&mut buffer).await.unwrap();
            stream.write_all(&buffer[..read]).await.unwrap();
            let _ = stream.shutdown().await;
        }

        async fn new_packet_connection(self: Arc<Self>, destination: Socksaddr, conn: SharedPacketConn) {
            let mut buffer = [0u8; 64];
            for _ in 0..2 {
                let (read, address) = conn.read_packet(&mut buffer).await.unwrap();
                assert_eq!(address, destination);
                conn.write_packet(&buffer[..read], &address).await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn xudp_session_echo() {
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve(Box::new(server), Arc::new(Echo)));
        let (mut read, mut write) = tokio::io::split(client);
        let target = Socksaddr::from_host_port("1.1.1.1", 53);
        write.write_all(&encode_xudp_frame(true, b"one", &target).unwrap()).await.unwrap();
        write.write_all(&encode_xudp_frame(false, b"two", &target).unwrap()).await.unwrap();
        let mut received = Vec::new();
        let mut frames = Vec::new();
        while frames.len() < 2 {
            let mut chunk = [0u8; 256];
            let count = read.read(&mut chunk).await.unwrap();
            received.extend_from_slice(&chunk[..count]);
            // The second reply may arrive with the session's end frame.
            while frames.len() < 2 {
                let Some((frame, used)) = parse_xudp_frame(&received, &target).unwrap() else { break };
                received.drain(..used);
                frames.push(frame);
            }
        }
        assert_eq!(frames[0], XudpFrame::Packet(target.clone(), b"one".to_vec()));
        assert_eq!(frames[1], XudpFrame::Packet(target.clone(), b"two".to_vec()));
        drop(write);
        drop(read);
        let error = task.await.unwrap();
        assert!(error.to_string().starts_with("mux connection closed"), "{error}");
    }

    #[tokio::test]
    async fn tcp_session_echo() {
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(serve(Box::new(server), Arc::new(Echo)));
        let (mut read, mut write) = tokio::io::split(client);
        let mut frame = vec![0, 12, 0, 5, STATUS_NEW, OPTION_DATA, NETWORK_TCP];
        protocol::write_address(&mut frame, &Socksaddr::from_host_port("2.2.2.2", 80)).unwrap();
        frame.extend_from_slice(&[0, 2, b'h', b'i']);
        write.write_all(&frame).await.unwrap();
        let mut reply = [0u8; 10];
        read.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0, 4, 0, 5, STATUS_KEEP, OPTION_DATA, 0, 2, b'h', b'i']);
        let mut end = [0u8; 6];
        read.read_exact(&mut end).await.unwrap();
        assert_eq!(end, [0, 4, 0, 5, STATUS_END, 0]);
    }
}
