//! sing-mux (the `multiplex` field of shadowsocks, trojan, vless and
//! vmess): smux, yamux and h2mux sessions, the padding of the first
//! frames, the client with its connection pool and the server.

pub mod client;
pub mod h2mux;
pub mod protocol;
pub mod server;
pub mod session;

use std::io;

use rb_adapter::{BoxStream, Socksaddr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub use client::{Client, ClientOptions, MuxDialer};
pub use protocol::{is_destination, DESTINATION_DOMAIN, DESTINATION_PORT};
pub use server::{serve, ServerHandler, ServerOptions};

/// A session of any of the three protocols.
pub enum AnySession {
    Stream(session::Session),
    H2Client(h2mux::H2Client),
    H2Server(h2mux::H2Server),
}

impl AnySession {
    /// sing-mux `newClientSession`.
    pub async fn client(conn: BoxStream, protocol: u8) -> io::Result<Self> {
        match protocol {
            protocol::PROTOCOL_H2MUX => Ok(AnySession::H2Client(h2mux::H2Client::new(conn).await?)),
            protocol::PROTOCOL_SMUX => Ok(AnySession::Stream(session::Session::smux(conn, true))),
            protocol::PROTOCOL_YAMUX => Ok(AnySession::Stream(session::Session::yamux(conn, true))),
            other => Err(io::Error::other(format!("unexpected protocol {other}"))),
        }
    }

    /// sing-mux `newServerSession`.
    pub fn server(conn: BoxStream, protocol: u8) -> io::Result<Self> {
        match protocol {
            protocol::PROTOCOL_H2MUX => Ok(AnySession::H2Server(h2mux::H2Server::new(conn))),
            protocol::PROTOCOL_SMUX => Ok(AnySession::Stream(session::Session::smux(conn, false))),
            protocol::PROTOCOL_YAMUX => Ok(AnySession::Stream(session::Session::yamux(conn, false))),
            other => Err(io::Error::other(format!("unexpected protocol {other}"))),
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            AnySession::Stream(session) => session.is_closed(),
            AnySession::H2Client(session) => session.is_closed(),
            AnySession::H2Server(session) => session.is_closed(),
        }
    }

    /// smux and yamux always take new streams; an h2mux client while
    /// its connection is up (Go `ClientConn.CanTakeNewRequest`).
    pub fn can_take_new_request(&self) -> bool {
        match self {
            AnySession::Stream(_) => true,
            AnySession::H2Client(session) => !session.is_closed(),
            AnySession::H2Server(_) => false,
        }
    }

    pub async fn open(&self) -> io::Result<BoxStream> {
        match self {
            AnySession::Stream(session) => Ok(Box::new(session.open().await?)),
            AnySession::H2Client(session) => Ok(Box::new(session.open().await?)),
            AnySession::H2Server(_) => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }

    pub async fn accept(&self) -> io::Result<BoxStream> {
        match self {
            AnySession::Stream(session) => Ok(Box::new(session.accept().await?)),
            AnySession::H2Server(session) => Ok(Box::new(session.accept().await?)),
            AnySession::H2Client(_) => Err(io::Error::from(io::ErrorKind::InvalidInput)),
        }
    }

    pub fn close(&self) {
        match self {
            AnySession::Stream(session) => session.close(),
            AnySession::H2Client(session) => session.close(),
            AnySession::H2Server(session) => session.close(),
        }
    }
}

/// A reader that keeps bytes read past the current frame, so a packet
/// read can be cancelled at any point without losing data.
pub struct FrameReader<R> {
    reader: R,
    pending: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(reader: R) -> Self {
        FrameReader { reader, pending: Vec::new() }
    }

    /// The next frame `parse` finds at the front of the bytes read.
    pub async fn next<T>(&mut self, mut parse: impl FnMut(&[u8]) -> io::Result<Option<(T, usize)>>) -> io::Result<T> {
        loop {
            if let Some((frame, used)) = parse(&self.pending)? {
                self.pending.drain(..used);
                return Ok(frame);
            }
            self.pending.reserve(16 * 1024);
            if self.reader.read_buf(&mut self.pending).await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
            }
        }
    }
}

/// A Go uvarint at the front of `data` and its length.
fn uvarint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in data.iter().take(10).enumerate() {
        value |= ((byte & 0x7f) as u64) << (7 * index);
        if *byte < 0x80 {
            return Some((value, index + 1));
        }
    }
    None
}

/// A stream response at the front of `data`: success, or the remote
/// error.
pub fn parse_response(data: &[u8]) -> io::Result<Option<(io::Result<()>, usize)>> {
    let Some(&status) = data.first() else { return Ok(None) };
    if status != protocol::STATUS_ERROR {
        return Ok(Some((Ok(()), 1)));
    }
    let Some((length, used)) = uvarint(&data[1..]) else { return Ok(None) };
    let end = 1 + used + length as usize;
    if data.len() < end {
        return Ok(None);
    }
    let message = String::from_utf8_lossy(&data[1 + used..end]);
    Ok(Some((Err(io::Error::other(format!("remote error: {message}"))), end)))
}

/// A packet and its address.
pub type AddrPacket = (Socksaddr, Vec<u8>);

/// `[address][length u16][data]` at the front of `data`.
pub fn parse_addr_packet(data: &[u8]) -> io::Result<Option<(AddrPacket, usize)>> {
    let (address, used) = match rb_shadowsocks::read_address(data) {
        Ok(read) => read,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(parse_len_packet(&data[used..])?.map(|(payload, length)| ((address, payload), used + length)))
}

/// `[length u16][data]` at the front of `data`.
pub fn parse_len_packet(data: &[u8]) -> io::Result<Option<(Vec<u8>, usize)>> {
    let Some(length) = data.get(..2).map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) as usize) else {
        return Ok(None);
    };
    Ok((data.len() >= 2 + length).then(|| (data[2..2 + length].to_vec(), 2 + length)))
}

#[cfg(test)]
mod tests;
