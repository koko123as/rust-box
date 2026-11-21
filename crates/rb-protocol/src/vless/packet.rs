//! The UDP of VLESS: a plain UDP request (`[length][payload]` packets, all
//! to the request's destination), packetaddr (sing-vmess `packetaddr`:
//! each payload starts with its address, inside a request to
//! `sp.packet-addr.v2fly.arpa`) and XUDP (sing-vmess `XUDPConn`: Mux.Cool
//! frames of session 0 inside a mux request, each with its address).
//!
//! Reads are cancel safe (bytes stay buffered until a whole packet is
//! there), as the router requires.

use std::io;
use std::net::IpAddr;

use async_trait::async_trait;
use rb_adapter::{BoxStream, Host, PacketConn, SharedPacketConn, Socksaddr};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use super::protocol::{self, parse_response};
use crate::framed::{self, u16_at, FrameReader};

/// `sp.packet-addr.v2fly.arpa`, the destination of a packetaddr request.
pub const PACKET_ADDR_MAGIC: &str = "sp.packet-addr.v2fly.arpa";

/// Mux.Cool frame status values and options (sing-vmess).
pub const STATUS_NEW: u8 = 1;
pub const STATUS_KEEP: u8 = 2;
pub const STATUS_END: u8 = 3;
pub const STATUS_KEEP_ALIVE: u8 = 4;
pub const OPTION_DATA: u8 = 1;
pub const OPTION_ERROR: u8 = 2;
pub const NETWORK_TCP: u8 = 1;
pub const NETWORK_UDP: u8 = 2;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn copy_out(payload: &[u8], buffer: &mut [u8]) -> usize {
    let length = payload.len().min(buffer.len());
    buffer[..length].copy_from_slice(&payload[..length]);
    length
}

/// A `[length][payload]` packet at the front of `data`.
fn parse_length_packet(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let length = u16_at(data, 0)? as usize;
    (data.len() >= 2 + length).then(|| (data[2..2 + length].to_vec(), 2 + length))
}

fn length_packet(data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() > u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "vless: packet too large"));
    }
    let mut frame = Vec::with_capacity(2 + data.len());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

/// The client of a plain UDP request (sing-vmess `vless.PacketConn` used
/// through `ReadFrom`/`WriteTo`): the request goes out alone before the
/// first packet, the response is read before the first packet, and every
/// packet is to and from `destination`.
pub struct VlessPacketConn {
    reader: Mutex<(FrameReader<ReadHalf<BoxStream>>, bool)>,
    writer: Mutex<(WriteHalf<BoxStream>, Option<Vec<u8>>)>,
    destination: Socksaddr,
}

impl VlessPacketConn {
    pub fn client(stream: BoxStream, uuid: &[u8; 16], destination: Socksaddr) -> io::Result<Self> {
        let request = protocol::encode_packet_request(uuid, &destination)?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(VlessPacketConn {
            reader: Mutex::new((FrameReader::new(reader), false)),
            writer: Mutex::new((writer, Some(request))),
            destination,
        })
    }
}

#[async_trait]
impl PacketConn for VlessPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut guard = self.reader.lock().await;
        let (reader, response_read) = &mut *guard;
        if !*response_read {
            reader.next(|data| Ok(parse_response(data)?.map(|length| ((), length)))).await?;
            *response_read = true;
        }
        let payload = reader.next(|data| Ok(parse_length_packet(data))).await?;
        if payload.len() > buffer.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "short buffer"));
        }
        Ok((copy_out(&payload, buffer), self.destination.clone()))
    }

    async fn write_packet(&self, data: &[u8], _address: &Socksaddr) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        let (writer, request) = &mut *guard;
        let mut frame = request.take().unwrap_or_default();
        frame.extend_from_slice(&length_packet(data)?);
        writer.write_all(&frame).await?;
        writer.flush().await
    }
}

/// The server side of a plain UDP request (sing-vmess `serverPacketConn`):
/// the response `0 0` goes before the first reply.
pub struct ServerPacketConn {
    reader: Mutex<FrameReader<ReadHalf<BoxStream>>>,
    writer: Mutex<(WriteHalf<BoxStream>, bool)>,
    destination: Socksaddr,
}

impl ServerPacketConn {
    pub fn new(stream: BoxStream, destination: Socksaddr) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        ServerPacketConn {
            reader: Mutex::new(FrameReader::new(reader)),
            writer: Mutex::new((writer, false)),
            destination,
        }
    }
}

#[async_trait]
impl PacketConn for ServerPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let payload = self.reader.lock().await.next(|data| Ok(parse_length_packet(data))).await?;
        if payload.len() > buffer.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "short buffer"));
        }
        Ok((copy_out(&payload, buffer), self.destination.clone()))
    }

    async fn write_packet(&self, data: &[u8], _address: &Socksaddr) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        let (writer, response_written) = &mut *guard;
        let mut frame = Vec::new();
        if !*response_written {
            frame.extend_from_slice(&[protocol::VERSION, 0]);
            *response_written = true;
        }
        frame.extend_from_slice(&length_packet(data)?);
        writer.write_all(&frame).await?;
        writer.flush().await
    }
}

/// Writes a packetaddr address (IPv4 1, IPv6 2, then the address and the
/// port); domains are refused (sing-vmess `ErrFqdnUnsupported`).
pub fn write_packet_addr(buffer: &mut Vec<u8>, address: &Socksaddr) -> io::Result<()> {
    match address.host {
        Host::Ip(IpAddr::V4(ip)) => {
            buffer.push(1);
            buffer.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            buffer.push(2);
            buffer.extend_from_slice(&ip.octets());
        }
        Host::Domain(ref domain) => return Err(invalid(format!("packetaddr: fqdn unsupported: {domain}"))),
    }
    buffer.extend_from_slice(&address.port.to_be_bytes());
    Ok(())
}

/// A packetaddr address at the front of `data`, IPv4-mapped addresses
/// unwrapped; its length.
pub fn parse_packet_addr(data: &[u8]) -> io::Result<(Socksaddr, usize)> {
    let eof = framed::eof;
    let (ip, length): (IpAddr, usize) = match data.first() {
        Some(1) => {
            let octets: [u8; 4] = data.get(1..5).ok_or_else(eof)?.try_into().unwrap();
            (octets.into(), 5)
        }
        Some(2) => {
            let octets: [u8; 16] = data.get(1..17).ok_or_else(eof)?.try_into().unwrap();
            (std::net::Ipv6Addr::from(octets).to_canonical(), 17)
        }
        Some(family) => return Err(invalid(format!("unknown address family: {family}"))),
        None => return Err(eof()),
    };
    let port = u16_at(data, length).ok_or_else(eof)?;
    Ok((Socksaddr::new(Host::Ip(ip), port), length + 2))
}

/// packetaddr over another packet connection (sing-vmess
/// `packetaddr.PacketConn`), for both sides: each payload carries its
/// address in front.
pub struct PacketAddrConn {
    inner: SharedPacketConn,
    /// Where the inner packets go (the magic address on the client).
    bind: Socksaddr,
}

impl PacketAddrConn {
    pub fn new(inner: SharedPacketConn, bind: Socksaddr) -> Self {
        PacketAddrConn { inner, bind }
    }
}

#[async_trait]
impl PacketConn for PacketAddrConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut packet = vec![0u8; buffer.len() + 17 + 2];
        let (length, _) = self.inner.read_packet(&mut packet).await?;
        let (address, start) = parse_packet_addr(&packet[..length])?;
        Ok((copy_out(&packet[start..length], buffer), address))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let mut packet = Vec::with_capacity(19 + data.len());
        write_packet_addr(&mut packet, address)?;
        packet.extend_from_slice(data);
        self.inner.write_packet(&packet, &self.bind).await
    }
}

/// One frame an XUDP client reads.
#[derive(Debug, PartialEq, Eq)]
pub enum XudpFrame {
    Packet(Socksaddr, Vec<u8>),
    /// A frame without data (keep alive).
    Skip,
}

/// An XUDP frame at the front of `data` (sing-vmess `XUDPConn.ReadPacket`,
/// kept as it parses, including its fixed reads).
pub fn parse_xudp_frame(data: &[u8], destination: &Socksaddr) -> io::Result<Option<(XudpFrame, usize)>> {
    if data.len() < 6 {
        return Ok(None);
    }
    let length = u16_at(data, 0).unwrap() as usize;
    if length < 4 {
        return Err(invalid(format!("invalid frame length: {length}")));
    }
    let (status, option) = (data[4], data[5]);
    let mut position = 6;
    let mut address = None;
    // The data length, which sing-vmess reads with the metadata.
    let mut data_length = None;
    match status {
        STATUS_NEW => return Err(invalid("unexpected frame new")),
        STATUS_KEEP => {
            if length != 4 {
                let extra = length - 2;
                let Some(metadata) = data.get(6..6 + extra) else { return Ok(None) };
                position += extra;
                let body = metadata.get(1..).ok_or_else(framed::eof)?;
                let (found, used) = protocol::parse_address(body).map_err(|error| {
                    if error.kind() == io::ErrorKind::UnexpectedEof {
                        framed::eof()
                    } else {
                        error
                    }
                })?;
                address = Some(found);
                data_length = u16_at(body, used);
            } else {
                let Some(found) = u16_at(data, 6) else { return Ok(None) };
                position += 2;
                address = Some(destination.clone());
                data_length = Some(found);
            }
        }
        STATUS_END => return Err(framed::eof()),
        STATUS_KEEP_ALIVE => {}
        _ => return Err(invalid(format!("unexpected frame: {status}"))),
    }
    if option & OPTION_ERROR == OPTION_ERROR {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "remote closed: use of closed network connection",
        ));
    }
    if option & OPTION_DATA != OPTION_DATA {
        return Ok(Some((XudpFrame::Skip, position)));
    }
    let length = data_length.ok_or_else(framed::eof)? as usize;
    let Some(payload) = data.get(position..position + length) else { return Ok(None) };
    let address = address.unwrap_or_else(|| destination.clone());
    Ok(Some((XudpFrame::Packet(address, payload.to_vec()), position + length)))
}

/// An XUDP frame of session 0 (sing-vmess `XUDPConn.WritePacket`): `new`
/// for the first packet, `keep` after, each with its address.
pub fn encode_xudp_frame(first: bool, data: &[u8], destination: &Socksaddr) -> io::Result<Vec<u8>> {
    if data.len() > u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "xudp: packet too large"));
    }
    let address_length = protocol::address_len(destination);
    let mut frame = Vec::with_capacity(9 + address_length + data.len());
    frame.extend_from_slice(&((5 + address_length) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0, if first { STATUS_NEW } else { STATUS_KEEP }, OPTION_DATA, NETWORK_UDP]);
    protocol::write_address(&mut frame, destination)?;
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

/// The client side of XUDP over a mux request whose header was sent.
pub struct XudpPacketConn {
    reader: Mutex<FrameReader<ReadHalf<BoxStream>>>,
    writer: Mutex<(WriteHalf<BoxStream>, bool)>,
    destination: Socksaddr,
}

impl XudpPacketConn {
    pub fn new(stream: BoxStream, destination: Socksaddr) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        XudpPacketConn {
            reader: Mutex::new(FrameReader::new(reader)),
            writer: Mutex::new((writer, false)),
            destination,
        }
    }
}

#[async_trait]
impl PacketConn for XudpPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut reader = self.reader.lock().await;
        loop {
            match reader.next(|data| parse_xudp_frame(data, &self.destination)).await? {
                XudpFrame::Packet(address, payload) => return Ok((copy_out(&payload, buffer), address)),
                XudpFrame::Skip => continue,
            }
        }
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        let (writer, written) = &mut *guard;
        let frame = encode_xudp_frame(!*written, data, address)?;
        *written = true;
        writer.write_all(&frame).await?;
        writer.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xudp_frames() {
        let target = Socksaddr::from_host_port("1.1.1.1", 53);
        let first = encode_xudp_frame(true, b"q", &target).unwrap();
        assert_eq!(first, [0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 1, 1, 1, 1, 0, 1, b'q']);
        let next = encode_xudp_frame(false, b"q", &target).unwrap();
        assert_eq!(next[4], STATUS_KEEP);

        // What the sing-vmess mux server writes back.
        let reply = [0, 12, 0, 0, 2, 1, 2, 0, 53, 1, 1, 1, 1, 1, 0, 2, b'o', b'k'];
        let default = Socksaddr::from_host_port("9.9.9.9", 9);
        assert_eq!(
            parse_xudp_frame(&reply, &default).unwrap(),
            Some((XudpFrame::Packet(target.clone(), b"ok".to_vec()), reply.len()))
        );
        assert_eq!(parse_xudp_frame(&reply[..reply.len() - 1], &default).unwrap(), None);
        let short = [0, 4, 0, 0, 2, 1, 0, 1, b'x'];
        assert_eq!(
            parse_xudp_frame(&short, &default).unwrap(),
            Some((XudpFrame::Packet(default.clone(), b"x".to_vec()), short.len()))
        );
        assert_eq!(parse_xudp_frame(&[0, 4, 0, 0, 4, 0], &default).unwrap(), Some((XudpFrame::Skip, 6)));
        assert!(parse_xudp_frame(&[0, 4, 0, 0, 1, 0], &default)
            .unwrap_err()
            .to_string()
            .contains("unexpected frame new"));
        assert!(parse_xudp_frame(&[0, 3, 0, 0, 2, 0], &default)
            .unwrap_err()
            .to_string()
            .contains("invalid frame length: 3"));
        assert_eq!(parse_xudp_frame(&[0, 4, 0, 0, 3, 0], &default).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn packet_addr() {
        let mut buffer = Vec::new();
        write_packet_addr(&mut buffer, &Socksaddr::from_host_port("1.2.3.4", 80)).unwrap();
        assert_eq!(buffer, [1, 1, 2, 3, 4, 0, 80]);
        assert_eq!(parse_packet_addr(&buffer).unwrap(), (Socksaddr::from_host_port("1.2.3.4", 80), 7));
        let v6 = Socksaddr::from_host_port("::ffff:1.2.3.4", 80);
        let mut buffer = Vec::new();
        write_packet_addr(&mut buffer, &Socksaddr::new(Host::Ip("::1".parse().unwrap()), 1)).unwrap();
        assert_eq!(buffer[0], 2);
        assert_eq!(v6.host, Host::Ip("1.2.3.4".parse().unwrap()));
        let error = write_packet_addr(&mut Vec::new(), &Socksaddr::from_host_port("example.com", 1)).unwrap_err();
        assert_eq!(error.to_string(), "packetaddr: fqdn unsupported: example.com");
    }

    #[tokio::test]
    async fn plain_packets() {
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(4096);
        let uuid = [7u8; 16];
        let target = Socksaddr::from_host_port("8.8.8.8", 53);
        let conn = VlessPacketConn::client(Box::new(client), &uuid, target.clone()).unwrap();
        conn.write_packet(b"abc", &target).await.unwrap();
        let mut received = vec![0u8; 17 + 1 + 1 + 7 + 2 + 3];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received[..17], &[0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]);
        assert_eq!(&received[17..], &[0, 2, 0, 53, 1, 8, 8, 8, 8, 0, 3, b'a', b'b', b'c']);
        let reply = ServerPacketConn::new(Box::new(server), target.clone());
        reply.write_packet(b"xy", &target).await.unwrap();
        let mut buffer = [0u8; 16];
        assert_eq!(conn.read_packet(&mut buffer).await.unwrap(), (2, target));
        assert_eq!(&buffer[..2], b"xy");
    }
}
