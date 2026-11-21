//! SOCKS4/4a (no RFC; the original NEC protocol) and SOCKS5 (RFC 1928, with
//! username/password authentication from RFC 1929) server handshakes,
//! mirroring sing-box `sing/protocol/socks`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::net::SocketAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use rb_adapter::{Host, PacketConn, Socksaddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

pub const VERSION4: u8 = 4;
pub const VERSION5: u8 = 5;

const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xff;

const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;

pub const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x03;
const ADDRESS_IPV6: u8 = 0x04;

/// What the client asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// CONNECT, already answered with success.
    Connect,
    /// UDP ASSOCIATE (RFC 1928 section 7), not answered yet: the reply
    /// carries the address of the UDP socket, which the caller opens and
    /// then reports with [`write_bind_reply`].
    UdpAssociate,
}

/// A finished handshake: where the client wants to connect, and as whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    /// For UDP ASSOCIATE, the address the client says it will send from
    /// (usually zero, and not relied on, like sing-box).
    pub destination: Socksaddr,
    pub user: Option<String>,
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Runs a SOCKS4/4a or SOCKS5 server handshake up to the request, and
/// answers a CONNECT with success. `users` empty means no authentication.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    users: &HashMap<String, String>,
) -> io::Result<Request> {
    let version = stream.read_u8().await?;
    match version {
        VERSION5 => handshake5(stream, users).await,
        VERSION4 => handshake4(stream, users).await,
        other => Err(protocol_error(format!("socks: unknown version {other}"))),
    }
}

async fn handshake5<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    users: &HashMap<String, String>,
) -> io::Result<Request> {
    let count = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; count];
    stream.read_exact(&mut methods).await?;
    let wanted = if users.is_empty() { AUTH_NONE } else { AUTH_PASSWORD };
    if !methods.contains(&wanted) {
        stream.write_all(&[VERSION5, AUTH_NO_ACCEPTABLE]).await?;
        return Err(protocol_error("socks5: no acceptable authentication method"));
    }
    stream.write_all(&[VERSION5, wanted]).await?;
    let mut user = None;
    if wanted == AUTH_PASSWORD {
        let version = stream.read_u8().await?;
        if version != 1 {
            return Err(protocol_error(format!("socks5: unknown authentication version {version}")));
        }
        let username = read_string(stream).await?;
        let password = read_string(stream).await?;
        if users.get(&username) != Some(&password) {
            stream.write_all(&[1, 1]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("socks5: authentication failed for {username:?}"),
            ));
        }
        stream.write_all(&[1, 0]).await?;
        user = Some(username);
    }
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION5 {
        return Err(protocol_error(format!("socks5: unknown version {}", header[0])));
    }
    let destination = read_address(stream).await?;
    match header[1] {
        COMMAND_CONNECT => {
            write_reply(stream, REPLY_SUCCEEDED).await?;
            Ok(Request { command: Command::Connect, destination, user })
        }
        COMMAND_UDP_ASSOCIATE => Ok(Request { command: Command::UdpAssociate, destination, user }),
        command => {
            // BIND is not implemented, as in sing-box.
            write_reply(stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
            Err(protocol_error(format!("socks5: command {command} not supported")))
        }
    }
}

async fn write_reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> io::Result<()> {
    stream.write_all(&[VERSION5, code, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0]).await
}

/// Answers a UDP ASSOCIATE with success and the UDP socket's address.
pub async fn write_bind_reply<S: AsyncWrite + Unpin>(stream: &mut S, bind: &Socksaddr) -> io::Result<()> {
    let mut reply = vec![VERSION5, REPLY_SUCCEEDED, 0];
    write_address(&mut reply, bind);
    stream.write_all(&reply).await
}

/// Splits a SOCKS5 UDP request (RFC 1928 section 7: RSV, FRAG, address,
/// data) into its address and data. Fragments (FRAG != 0) are refused, as
/// the RFC allows for a server that does not reassemble.
pub fn decode_udp(packet: &[u8]) -> io::Result<(Socksaddr, &[u8])> {
    if packet.len() < 4 {
        return Err(protocol_error("socks5: UDP packet too short"));
    }
    if packet[2] != 0 {
        return Err(protocol_error("socks5: UDP fragments are not supported"));
    }
    let short = || protocol_error("socks5: UDP packet too short");
    let (host, rest) = match packet[3] {
        ADDRESS_IPV4 => {
            let octets: [u8; 4] = packet.get(4..8).ok_or_else(short)?.try_into().unwrap();
            (Host::Ip(IpAddr::V4(Ipv4Addr::from(octets))), &packet[8..])
        }
        ADDRESS_IPV6 => {
            let octets: [u8; 16] = packet.get(4..20).ok_or_else(short)?.try_into().unwrap();
            (Host::Ip(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical()), &packet[20..])
        }
        ADDRESS_DOMAIN => {
            let length = *packet.get(4).ok_or_else(short)? as usize;
            let domain = packet.get(5..5 + length).ok_or_else(short)?;
            let domain = std::str::from_utf8(domain).map_err(|_| protocol_error("socks: invalid string"))?;
            (Socksaddr::from_host_port(domain, 0).host, &packet[5 + length..])
        }
        other => return Err(protocol_error(format!("socks5: unknown address type {other}"))),
    };
    let port = rest.get(..2).ok_or_else(short)?;
    Ok((Socksaddr::new(host, u16::from_be_bytes([port[0], port[1]])), &rest[2..]))
}

/// Builds a SOCKS5 UDP reply carrying `data` from `source`.
pub fn encode_udp(source: &Socksaddr, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(data.len() + 22);
    packet.extend_from_slice(&[0, 0, 0]);
    write_address(&mut packet, source);
    packet.extend_from_slice(data);
    packet
}

async fn read_string<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<String> {
    let length = stream.read_u8().await? as usize;
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).await?;
    String::from_utf8(bytes).map_err(|_| protocol_error("socks: invalid string"))
}

/// Reads a SOCKS5 address (sing-box `M.SocksaddrSerializer`).
pub async fn read_address<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Socksaddr> {
    let kind = stream.read_u8().await?;
    let host = match kind {
        ADDRESS_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        ADDRESS_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical())
        }
        ADDRESS_DOMAIN => {
            let domain = read_string(stream).await?;
            return Ok(Socksaddr::from_host_port(&domain, stream.read_u16().await?));
        }
        other => return Err(protocol_error(format!("socks5: unknown address type {other}"))),
    };
    Ok(Socksaddr::new(host, stream.read_u16().await?))
}

/// Writes a SOCKS5 address.
pub fn write_address(buffer: &mut Vec<u8>, address: &Socksaddr) {
    match &address.host {
        Host::Ip(IpAddr::V4(ip)) => {
            buffer.push(ADDRESS_IPV4);
            buffer.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            buffer.push(ADDRESS_IPV6);
            buffer.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            buffer.push(ADDRESS_DOMAIN);
            buffer.push(domain.len() as u8);
            buffer.extend_from_slice(domain.as_bytes());
        }
    }
    buffer.extend_from_slice(&address.port.to_be_bytes());
}

/// The UDP side of a UDP ASSOCIATE (sing `socks.AssociatePacketConn` over
/// `bufio.NewServerPacketConn`): packets are taken only from the IP address
/// of the TCP control connection's client, replies go to the address its
/// latest packet came from.
pub struct AssociatePacketConn {
    socket: UdpSocket,
    peer: IpAddr,
    remote: Mutex<Option<SocketAddr>>,
}

impl AssociatePacketConn {
    pub fn new(socket: UdpSocket, peer: IpAddr) -> Self {
        AssociatePacketConn { socket, peer: peer.to_canonical(), remote: Mutex::new(None) }
    }
}

#[async_trait]
impl PacketConn for AssociatePacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut packet = vec![0u8; rb_adapter::MAX_PACKET_SIZE];
        loop {
            let (length, source) = self.socket.recv_from(&mut packet).await?;
            if source.ip().to_canonical() != self.peer {
                continue;
            }
            let (destination, data) = match decode_udp(&packet[..length]) {
                Ok(decoded) => decoded,
                Err(error) => {
                    tracing::debug!(%source, %error, "socks5: dropped UDP packet");
                    continue;
                }
            };
            *self.remote.lock().unwrap() = Some(source);
            let length = data.len().min(buffer.len());
            buffer[..length].copy_from_slice(&data[..length]);
            return Ok((length, destination));
        }
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let Some(remote) = *self.remote.lock().unwrap() else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "socks5: no UDP client yet"));
        };
        self.socket.send_to(&encode_udp(address, data), remote).await.map(|_| ())
    }
}

async fn read_until_nul<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<String> {
    let mut bytes = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            break;
        }
        if bytes.len() >= 255 {
            return Err(protocol_error("socks4: field too long"));
        }
        bytes.push(byte);
    }
    String::from_utf8(bytes).map_err(|_| protocol_error("socks4: invalid string"))
}

async fn handshake4<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    users: &HashMap<String, String>,
) -> io::Result<Request> {
    let command = stream.read_u8().await?;
    let port = stream.read_u16().await?;
    let mut octets = [0u8; 4];
    stream.read_exact(&mut octets).await?;
    let user_id = read_until_nul(stream).await?;
    // SOCKS4a: 0.0.0.x (x != 0) means a domain name follows.
    let host = if octets[..3] == [0, 0, 0] && octets[3] != 0 {
        Socksaddr::from_host_port(&read_until_nul(stream).await?, port).host
    } else {
        Host::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
    };
    // SOCKS4 has no password: with users configured, the user id must be a
    // known username (sing-box checks the same way).
    let rejected = command != COMMAND_CONNECT || (!users.is_empty() && !users.contains_key(&user_id));
    let code = if rejected { 0x5b } else { 0x5a };
    stream.write_all(&[0, code, 0, 0, 0, 0, 0, 0]).await?;
    if rejected {
        return Err(protocol_error("socks4: request rejected"));
    }
    let user = (!users.is_empty()).then_some(user_id);
    Ok(Request { command: Command::Connect, destination: Socksaddr::new(host, port), user })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(client_bytes: &[u8], users: &[(&str, &str)]) -> (io::Result<Request>, Vec<u8>) {
        let users: HashMap<String, String> = users.iter().map(|(u, p)| (u.to_string(), p.to_string())).collect();
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(client_bytes).await.unwrap();
        let result = handshake(&mut server, &users).await;
        drop(server);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        (result, reply)
    }

    #[tokio::test]
    async fn socks5_domain_no_auth() {
        let mut bytes = vec![5, 1, 0, 5, 1, 0, 3, 11];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&443u16.to_be_bytes());
        let (result, reply) = run(&bytes, &[]).await;
        let request = result.unwrap();
        assert_eq!(request.destination.to_string(), "example.com:443");
        assert_eq!(&reply[..2], &[5, 0]);
        assert_eq!(&reply[2..4], &[5, 0]);
    }

    #[tokio::test]
    async fn socks5_password() {
        let mut bytes = vec![5, 2, 0, 2, 1, 1, b'u', 1, b'p', 5, 1, 0, 1, 1, 2, 3, 4, 0, 80];
        let (result, reply) = run(&bytes, &[("u", "p")]).await;
        assert_eq!(result.unwrap().user.as_deref(), Some("u"));
        assert_eq!(&reply[..4], &[5, 2, 1, 0]);
        bytes[8] = b'x';
        let (result, reply) = run(&bytes, &[("u", "p")]).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(&reply[..4], &[5, 2, 1, 1]);
        // No password method offered while users are configured.
        let (result, reply) = run(&[5, 1, 0], &[("u", "p")]).await;
        assert!(result.is_err());
        assert_eq!(reply, vec![5, 0xff]);
    }

    #[tokio::test]
    async fn socks5_udp_associate_and_bind() {
        // UDP ASSOCIATE is returned to the caller unanswered.
        let (result, reply) = run(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0], &[]).await;
        assert_eq!(result.unwrap().command, Command::UdpAssociate);
        assert_eq!(reply, vec![5, 0]);
        // BIND is refused.
        let (result, reply) = run(&[5, 1, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0], &[]).await;
        assert!(result.is_err());
        assert_eq!(reply[3], REPLY_COMMAND_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn bind_reply() {
        let (mut client, mut server) = tokio::io::duplex(64);
        write_bind_reply(&mut server, &Socksaddr::from_host_port("127.0.0.1", 1080)).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0, 0, 1, 127, 0, 0, 1, 0x04, 0x38]);
    }

    #[test]
    fn udp_packets() {
        let packet = encode_udp(&Socksaddr::from_host_port("example.com", 53), b"data");
        assert_eq!(&packet[..5], &[0, 0, 0, ADDRESS_DOMAIN, 11]);
        let (address, data) = decode_udp(&packet).unwrap();
        assert_eq!(address.to_string(), "example.com:53");
        assert_eq!(data, b"data");
        let packet = encode_udp(&Socksaddr::from_host_port("::1", 5353), b"");
        assert_eq!(decode_udp(&packet).unwrap().0.to_string(), "[::1]:5353");
        let mut fragment = encode_udp(&Socksaddr::from_host_port("1.2.3.4", 1), b"x");
        fragment[2] = 1;
        assert!(decode_udp(&fragment).is_err());
        assert!(decode_udp(&[0, 0, 0, ADDRESS_IPV4, 1, 2]).is_err());
        assert!(decode_udp(&[0, 0, 0, ADDRESS_DOMAIN, 9, b'a']).is_err());
    }

    #[tokio::test]
    async fn socks4a() {
        let mut bytes = vec![4, 1, 0, 80, 0, 0, 0, 1, b'i', b'd', 0];
        bytes.extend_from_slice(b"example.org\0");
        let (result, reply) = run(&bytes, &[]).await;
        assert_eq!(result.unwrap().destination.to_string(), "example.org:80");
        assert_eq!(reply[1], 0x5a);
    }

    #[test]
    fn address_roundtrip_bytes() {
        let mut buffer = Vec::new();
        write_address(&mut buffer, &Socksaddr::from_host_port("::1", 53));
        assert_eq!(buffer[0], ADDRESS_IPV6);
        assert_eq!(buffer.len(), 1 + 16 + 2);
    }
}
