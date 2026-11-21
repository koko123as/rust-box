//! DNS transports: `udp`, `tcp`, `tls` (DoT), `hosts` and `local`.

mod dot;
mod hosts;
pub use dot::DotTransport;
pub use hosts::HostsTransport;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use rb_adapter::Socksaddr;
use rb_config::HostsDnsServer;
use rb_dialer::Dialer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;

/// TTL given to answers of the local resolver, which reports none.
const LOCAL_TTL: u32 = 10;

/// A DNS server. `udp` and `tcp` dial through the dialer their dial fields
/// describe (sing-box `dns.NewRemoteDialer`).
#[derive(Clone)]
pub enum Transport {
    Local,
    Udp(SocketAddr, Arc<dyn Dialer>),
    Tcp(SocketAddr, Arc<dyn Dialer>),
    Dot(Arc<DotTransport>),
    Hosts(Arc<HostsTransport>),
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Local => f.write_str("Local"),
            Transport::Udp(server, _) => write!(f, "Udp({server})"),
            Transport::Tcp(server, _) => write!(f, "Tcp({server})"),
            Transport::Dot(_) => f.write_str("Dot"),
            Transport::Hosts(_) => f.write_str("Hosts"),
        }
    }
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
    pub(super) fn hosts(options: &HostsDnsServer) -> io::Result<Self> {
        Ok(Transport::Hosts(Arc::new(HostsTransport::new(options)?)))
    }

    pub async fn query(&self, domain: &str, query_type: u16, timeout: Duration) -> io::Result<Answer> {
        match self {
            Transport::Local => query_local(domain, query_type).await,
            Transport::Hosts(hosts) => hosts.query(domain, query_type),
            Transport::Dot(dot) => {
                let id = next_id();
                let query = build_query(domain, query_type, id)?;
                let response = dot.exchange(&query, timeout).await?;
                parse_response(&response, id).map(|(answer, _)| answer)
            }
            Transport::Udp(server, dialer) => {
                let id = next_id();
                let query = build_query(domain, query_type, id)?;
                let socket = dialer.dial_udp(&Socksaddr::from(*server)).await?;
                socket.write_packet(&query, &Socksaddr::from(*server)).await?;
                let mut buffer = vec![0u8; 65535];
                loop {
                    let (size, _) = socket.read_packet(&mut buffer).await?;
                    match parse_response(&buffer[..size], id) {
                        // A response truncated over UDP is asked again over TCP.
                        Ok((_, true)) => {
                            let address = Socksaddr::from(*server);
                            return exchange_tcp(dialer.as_ref(), &address, &query, id, timeout).await;
                        }
                        Ok((answer, false)) => return Ok(answer),
                        // Not our response (a late one, or spoofed): keep waiting.
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => continue,
                        Err(error) => return Err(error),
                    }
                }
            }
            Transport::Tcp(server, dialer) => {
                let id = next_id();
                let query = build_query(domain, query_type, id)?;
                let address = Socksaddr::from(*server);
                exchange_tcp(dialer.as_ref(), &address, &query, id, timeout).await
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
            Transport::Hosts(hosts) => return hosts.exchange(query).map(Some),
            Transport::Udp(server, dialer) => {
                let socket = dialer.dial_udp(&Socksaddr::from(*server)).await?;
                socket.write_packet(&message, &Socksaddr::from(*server)).await?;
                let mut buffer = vec![0u8; 65535];
                loop {
                    let (size, _) = socket.read_packet(&mut buffer).await?;
                    if size < 12 || buffer[..2] != id.to_be_bytes() {
                        continue;
                    }
                    // TC: ask again over TCP.
                    if buffer[2] & 0x02 != 0 {
                        break exchange_tcp_raw(dialer.as_ref(), &Socksaddr::from(*server), &message, timeout).await?;
                    }
                    break buffer[..size].to_vec();
                }
            }
            Transport::Tcp(server, dialer) => {
                exchange_tcp_raw(dialer.as_ref(), &Socksaddr::from(*server), &message, timeout).await?
            }
            Transport::Dot(dot) => dot.exchange(&message, timeout).await?,
        };
        if response.len() < 12 || response[..2] != id.to_be_bytes() {
            return Err(invalid("DNS response id mismatch"));
        }
        response[..2].copy_from_slice(&original);
        Ok(Some(response))
    }
}

async fn exchange_tcp_raw(
    dialer: &dyn Dialer,
    server: &Socksaddr,
    query: &[u8],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(timeout, dialer.dial_tcp(server))
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

async fn exchange_tcp(
    dialer: &dyn Dialer,
    server: &Socksaddr,
    query: &[u8],
    id: u16,
    timeout: Duration,
) -> io::Result<Answer> {
    let response = exchange_tcp_raw(dialer, server, query, timeout).await?;
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
