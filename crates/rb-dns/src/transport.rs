//! DNS transports: `udp` and `tcp` (sing-box `dns/transport/udp.go`,
//! `tcp.go`) and `local`, the system resolver (sing-box
//! `dns/transport/local`).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;

/// TTL given to answers of the local resolver, which reports none.
const LOCAL_TTL: u32 = 10;

#[derive(Debug, Clone)]
pub enum Transport {
    Local,
    Udp(SocketAddr),
    Tcp(SocketAddr),
}

/// Addresses of one query, with the smallest TTL of the records.
#[derive(Debug, Clone, Default)]
pub struct Answer {
    pub addresses: Vec<IpAddr>,
    pub ttl: u32,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn build_query(domain: &str, query_type: u16, id: u16) -> io::Result<Vec<u8>> {
    let name = Name::from_ascii(format!("{domain}.")).map_err(|error| invalid(format!("{domain}: {error}")))?;
    let mut message = Message::new();
    message
        .set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name, RecordType::from(query_type)));
    message.to_vec().map_err(|error| invalid(error.to_string()))
}

/// Reads the addresses out of a response (sing-box `dns.MessageToAddresses`).
pub fn parse_response(data: &[u8], id: u16) -> io::Result<(Answer, bool)> {
    let message = Message::from_vec(data).map_err(|error| invalid(error.to_string()))?;
    if message.id() != id {
        return Err(invalid("DNS response id mismatch"));
    }
    let code = message.response_code();
    if code != ResponseCode::NoError {
        let kind = if code == ResponseCode::NXDomain { io::ErrorKind::NotFound } else { io::ErrorKind::Other };
        return Err(io::Error::new(kind, format!("DNS response code {code}")));
    }
    let mut answer = Answer { addresses: Vec::new(), ttl: u32::MAX };
    for record in message.answers() {
        let address = match record.data() {
            RData::A(a) => IpAddr::V4(a.0),
            RData::AAAA(aaaa) => IpAddr::V6(aaaa.0),
            _ => continue,
        };
        answer.addresses.push(address);
        answer.ttl = answer.ttl.min(record.ttl());
    }
    if answer.addresses.is_empty() {
        answer.ttl = 0;
    }
    Ok((answer, message.truncated()))
}

fn next_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    // Mix a counter with the clock so ids are not trivially predictable.
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    NEXT.fetch_add(1, Ordering::Relaxed) ^ (nanos as u16)
}

impl Transport {
    pub async fn query(&self, domain: &str, query_type: u16, timeout: Duration) -> io::Result<Answer> {
        match self {
            Transport::Local => query_local(domain, query_type).await,
            Transport::Udp(server) => {
                let id = next_id();
                let query = build_query(domain, query_type, id)?;
                let socket = udp_socket(*server).await?;
                socket.send(&query).await?;
                let mut buffer = vec![0u8; 65535];
                loop {
                    let size = socket.recv(&mut buffer).await?;
                    match parse_response(&buffer[..size], id) {
                        // A response truncated over UDP is asked again over TCP.
                        Ok((_, true)) => return exchange_tcp(*server, &query, id, timeout).await,
                        Ok((answer, false)) => return Ok(answer),
                        // Not our response (a late one, or spoofed): keep waiting.
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => continue,
                        Err(error) => return Err(error),
                    }
                }
            }
            Transport::Tcp(server) => {
                let id = next_id();
                let query = build_query(domain, query_type, id)?;
                exchange_tcp(*server, &query, id, timeout).await
            }
        }
    }
}

impl Transport {
    /// Forwards a raw query message and returns the raw response, with the
    /// query's own id (sing-box `DNSTransport.Exchange`). `Ok(None)` for the
    /// local resolver, which cannot forward messages.
    pub async fn exchange(&self, query: &[u8], timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        if query.len() < 12 {
            return Err(invalid("DNS query too short"));
        }
        let original = [query[0], query[1]];
        let id = next_id();
        let mut message = query.to_vec();
        message[..2].copy_from_slice(&id.to_be_bytes());
        let mut response = match self {
            Transport::Local => return Ok(None),
            Transport::Udp(server) => {
                let socket = udp_socket(*server).await?;
                socket.send(&message).await?;
                let mut buffer = vec![0u8; 65535];
                loop {
                    let size = socket.recv(&mut buffer).await?;
                    if size < 12 || buffer[..2] != id.to_be_bytes() {
                        continue;
                    }
                    // TC: ask again over TCP.
                    if buffer[2] & 0x02 != 0 {
                        break exchange_tcp_raw(*server, &message, timeout).await?;
                    }
                    break buffer[..size].to_vec();
                }
            }
            Transport::Tcp(server) => exchange_tcp_raw(*server, &message, timeout).await?,
        };
        if response.len() < 12 || response[..2] != id.to_be_bytes() {
            return Err(invalid("DNS response id mismatch"));
        }
        response[..2].copy_from_slice(&original);
        Ok(Some(response))
    }
}

async fn udp_socket(server: SocketAddr) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if server.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    Ok(socket)
}

async fn exchange_tcp_raw(server: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(server))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS over TCP: connect timed out"))??;
    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(query);
    stream.write_all(&frame).await?;
    let length = stream.read_u16().await? as usize;
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

async fn exchange_tcp(server: SocketAddr, query: &[u8], id: u16, timeout: Duration) -> io::Result<Answer> {
    let response = exchange_tcp_raw(server, query, timeout).await?;
    parse_response(&response, id).map(|(answer, _)| answer)
}

async fn query_local(domain: &str, query_type: u16) -> io::Result<Answer> {
    let addresses: Vec<IpAddr> = tokio::net::lookup_host((domain, 0))
        .await?
        .map(|address| address.ip().to_canonical())
        .filter(|ip| match query_type {
            QTYPE_A => ip.is_ipv4(),
            QTYPE_AAAA => ip.is_ipv6(),
            _ => false,
        })
        .collect();
    let mut unique = Vec::with_capacity(addresses.len());
    for address in addresses {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    let ttl = if unique.is_empty() { 0 } else { LOCAL_TTL };
    Ok(Answer { addresses: unique, ttl })
}
