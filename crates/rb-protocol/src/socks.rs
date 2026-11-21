//! SOCKS4/4a (no RFC; the original NEC protocol) and SOCKS5 (RFC 1928, with
//! username/password authentication from RFC 1929) server handshakes,
//! mirroring sing-box `sing/protocol/socks`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rb_adapter::{Host, Socksaddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION4: u8 = 4;
pub const VERSION5: u8 = 5;

const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xff;

const COMMAND_CONNECT: u8 = 0x01;

const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x03;
const ADDRESS_IPV6: u8 = 0x04;

/// A finished handshake: where the client wants to connect, and as whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub destination: Socksaddr,
    pub user: Option<String>,
}

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Runs a SOCKS4/4a or SOCKS5 server handshake up to the CONNECT request
/// and answers it with success. `users` empty means no authentication.
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
    if header[1] != COMMAND_CONNECT {
        // UDP ASSOCIATE and BIND are not implemented yet.
        write_reply(stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(protocol_error(format!("socks5: command {} not supported", header[1])));
    }
    write_reply(stream, REPLY_SUCCEEDED).await?;
    Ok(Request { destination, user })
}

async fn write_reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> io::Result<()> {
    stream.write_all(&[VERSION5, code, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0]).await
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
    Ok(Request { destination: Socksaddr::new(host, port), user })
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
    async fn socks5_udp_associate_refused() {
        let (result, reply) = run(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0], &[]).await;
        assert!(result.is_err());
        assert_eq!(reply[3], REPLY_COMMAND_NOT_SUPPORTED);
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
