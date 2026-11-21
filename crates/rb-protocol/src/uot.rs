//! UDP over TCP (sing `common/uot`, sing-box `common/uot`): UDP packets
//! carried in a proxy's TCP stream to a magic destination.
//!
//! Version 2 (`sp.v2.udp-over-tcp.arpa`) starts with a request (a connect
//! flag and the SOCKS destination); version 1 (`sp.udp-over-tcp.arpa`) has
//! none. Packets are `[address]` (absent in connect mode) `length payload`,
//! with addresses in the family bytes 0 (IPv4), 1 (IPv6), 2 (domain).

use std::io;

use async_trait::async_trait;
use rb_adapter::{BoxStream, PacketConn, Socksaddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

pub const VERSION: u8 = 2;
pub const LEGACY_VERSION: u8 = 1;
pub const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

/// sing `uot.AddrParser`'s family bytes.
const FAMILIES: [u8; 3] = [0x00, 0x01, 0x02];

/// The TCP destination a client of `version` dials (sing `RequestDestination`).
pub fn request_destination(version: u8) -> Socksaddr {
    match version {
        0 | VERSION => Socksaddr::from_host_port(MAGIC_ADDRESS, 0),
        _ => Socksaddr::from_host_port(LEGACY_MAGIC_ADDRESS, 0),
    }
}

/// A version 2 request (sing `uot.Request`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub is_connect: bool,
    pub destination: Socksaddr,
}

impl Request {
    /// sing `EncodeRequest`.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut buffer = vec![self.is_connect as u8];
        rb_shadowsocks::write_address(&mut buffer, &self.destination)?;
        Ok(buffer)
    }

    /// sing `ReadRequest` (the connect flag is a Go bool: anything but 0
    /// is true).
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Request> {
        let is_connect = reader.read_u8().await? != 0;
        let destination = rb_shadowsocks::read_address_from(reader).await?;
        Ok(Request { is_connect, destination })
    }
}

/// The packets of a UoT stream (sing `uot.Conn`), for either side: in
/// connect mode packets carry no address and are all to and from
/// `destination`.
///
/// Reads are cancel safe: bytes read stay buffered until a whole packet is
/// there.
pub struct UotPacketConn {
    reader: Mutex<(ReadHalf<BoxStream>, Vec<u8>)>,
    writer: Mutex<WriteHalf<BoxStream>>,
    is_connect: bool,
    destination: Socksaddr,
}

impl UotPacketConn {
    /// The server side of a stream whose request was read.
    pub fn new(stream: BoxStream, request: Request) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        UotPacketConn {
            reader: Mutex::new((reader, Vec::new())),
            writer: Mutex::new(writer),
            is_connect: request.is_connect,
            destination: request.destination,
        }
    }

    /// The client side (sing `uot.Client.DialEarlyConn`): version 2 sends
    /// its request first (here at once, where sing sends it with the first
    /// packet), version 1 has none and is never in connect mode.
    pub async fn client(mut stream: BoxStream, version: u8, request: Request) -> io::Result<Self> {
        match version {
            0 | VERSION => {
                stream.write_all(&request.encode()?).await?;
                stream.flush().await?;
                Ok(UotPacketConn::new(stream, request))
            }
            LEGACY_VERSION => {
                let request = Request { is_connect: false, destination: request.destination };
                Ok(UotPacketConn::new(stream, request))
            }
            _ => Err(io::Error::other(format!("unknown protocol version: {version}"))),
        }
    }

    /// A whole packet at the front of `buffer`: its address, where its
    /// payload is, and its total length.
    fn parse(&self, buffer: &[u8]) -> io::Result<Option<(Socksaddr, usize, usize)>> {
        let (address, mut position) = if self.is_connect {
            (self.destination.clone(), 0)
        } else {
            match rb_shadowsocks::read_address_with(buffer, FAMILIES) {
                Ok(found) => found,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error),
            }
        };
        let Some(length) = buffer.get(position..position + 2) else { return Ok(None) };
        let length = u16::from_be_bytes([length[0], length[1]]) as usize;
        position += 2;
        if buffer.len() < position + length {
            return Ok(None);
        }
        Ok(Some((address, position, position + length)))
    }
}

#[async_trait]
impl PacketConn for UotPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut guard = self.reader.lock().await;
        let (reader, pending) = &mut *guard;
        loop {
            if let Some((address, start, end)) = self.parse(pending)? {
                let length = end - start;
                if buffer.len() < length {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "UoT read: short buffer"));
                }
                buffer[..length].copy_from_slice(&pending[start..end]);
                pending.drain(..end);
                return Ok((length, address));
            }
            let mut chunk = [0u8; 16 * 1024];
            let read = reader.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "UoT read: EOF"));
            }
            pending.extend_from_slice(&chunk[..read]);
        }
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "UoT: packet too large"));
        }
        let mut frame = Vec::with_capacity(data.len() + 32);
        if !self.is_connect {
            rb_shadowsocks::write_address_with(&mut frame, address, FAMILIES)?;
        }
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        let mut writer = self.writer.lock().await;
        writer.write_all(&frame).await?;
        writer.flush().await
    }
}
