//! The `socks` and `http` outbounds (sing-box `protocol/socks/outbound.go`,
//! `protocol/http/outbound.go`) with the clients of
//! `sing/protocol/socks/client.go` and `sing/protocol/http/client.go`.
//!
//! Both dial their server through [`rb_dialer::new_outbound_dialer`] (the
//! dial fields, `detour`, `domain_resolver`); `http` wraps that dialer in
//! TLS when `tls` is enabled.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use rb_adapter::{
    BoxStream, DnsResolver, Host, InboundContext, LookupOptions, Network, Outbound, PacketConn, PrefixedStream,
    SharedPacketConn, Socksaddr, MAX_PACKET_SIZE,
};
use rb_config::{HttpOutbound as HttpOutboundOptions, SocksOutbound as SocksOutboundOptions};
use rb_dialer::{dial_serial, new_outbound_dialer, Dialer, DialerEnv};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::socks;

fn protocol_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// sing `socks.Version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    V4,
    V4a,
    V5,
}

impl SocksVersion {
    /// sing `socks.ParseVersion` (empty is 5).
    pub fn parse(version: &str) -> Result<Self, String> {
        match version {
            "4" => Ok(SocksVersion::V4),
            "4a" => Ok(SocksVersion::V4a),
            "" | "5" => Ok(SocksVersion::V5),
            _ => Err(format!("unknown socks version: {version}")),
        }
    }
}

const COMMAND_CONNECT: u8 = 1;
const COMMAND_UDP_ASSOCIATE: u8 = 3;

/// sing `ClientHandshake4`: a SOCKS4 request, SOCKS4a style for anything
/// but an IPv4 destination.
pub async fn client_handshake4<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    command: u8,
    destination: &Socksaddr,
    username: &str,
) -> io::Result<()> {
    if username.len() > 255 {
        return Err(protocol_error("username too long"));
    }
    let mut request = vec![socks::VERSION4, command];
    request.extend_from_slice(&destination.port.to_be_bytes());
    let ipv4 = match destination.host {
        Host::Ip(IpAddr::V4(ip)) => Some(ip),
        _ => None,
    };
    match ipv4 {
        Some(ip) => request.extend_from_slice(&ip.octets()),
        None => request.extend_from_slice(&[0, 0, 0, 1]),
    }
    request.extend_from_slice(username.as_bytes());
    request.push(0);
    if ipv4.is_none() {
        let host = match &destination.host {
            Host::Domain(domain) => domain.clone(),
            Host::Ip(ip) => ip.to_string(),
        };
        if host.len() > 255 {
            return Err(protocol_error("destination hostname too long"));
        }
        request.extend_from_slice(host.as_bytes());
        request.push(0);
    }
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut response = [0u8; 8];
    stream.read_exact(&mut response).await?;
    if response[0] != 0 {
        return Err(protocol_error(format!("excepted socks4 response version 0, got {}", response[0])));
    }
    // 90: request granted.
    if response[1] != 90 {
        return Err(protocol_error(format!("socks4: request rejected, code= {}", response[1])));
    }
    Ok(())
}

/// The address sing puts in a UDP ASSOCIATE request (sing
/// `ClientHandshake5`, kept as it is, including the swapped loopback
/// families for private addresses).
fn associate_address(destination: &Socksaddr) -> Socksaddr {
    let host = match &destination.host {
        Host::Domain(domain) => Host::Domain(domain.clone()),
        Host::Ip(ip) => {
            let private = match ip {
                IpAddr::V4(v4) => v4.is_private(),
                IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
            };
            let global_unicast = match ip {
                IpAddr::V4(v4) => {
                    !(v4.is_unspecified()
                        || v4.is_loopback()
                        || v4.is_link_local()
                        || v4.is_multicast()
                        || v4.is_broadcast())
                }
                IpAddr::V6(v6) => {
                    !(v6.is_unspecified()
                        || v6.is_loopback()
                        || v6.is_multicast()
                        || (v6.segments()[0] & 0xffc0) == 0xfe80)
                }
            };
            Host::Ip(if private {
                if ip.is_ipv6() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                }
            } else if global_unicast {
                if ip.is_ipv6() {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                } else {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                }
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            })
        }
    };
    Socksaddr::new(host, 0)
}

/// sing `ClientHandshake5`: authentication, then the request. Returns the
/// address in the server's reply (the relay address for UDP ASSOCIATE).
pub async fn client_handshake5<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    command: u8,
    destination: &Socksaddr,
    username: &str,
    password: &str,
) -> io::Result<Socksaddr> {
    let method = if username.is_empty() { 0x00 } else { 0x02 };
    stream.write_all(&[socks::VERSION5, 1, method]).await?;
    stream.flush().await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != socks::VERSION5 {
        return Err(protocol_error(format!("socks5: unexpected version {}", reply[0])));
    }
    if reply[1] == 0x02 {
        if username.len() > 255 || password.len() > 255 {
            return Err(protocol_error("socks5: username or password too long"));
        }
        let mut request = vec![1, username.len() as u8];
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        stream.write_all(&request).await?;
        stream.flush().await?;
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).await?;
        if status[1] != 0 {
            return Err(protocol_error("socks5: incorrect user name or password"));
        }
    } else if reply[1] != 0x00 {
        return Err(protocol_error(format!("socks5: unsupported auth method: {}", reply[1])));
    }
    let destination =
        if command == COMMAND_UDP_ASSOCIATE { associate_address(destination) } else { destination.clone() };
    let mut request = vec![socks::VERSION5, command, 0];
    socks::write_address(&mut request, &destination);
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut head = [0u8; 3];
    stream.read_exact(&mut head).await?;
    let bind = socks::read_address(stream).await?;
    if head[1] != socks::REPLY_SUCCEEDED {
        return Err(protocol_error(format!("socks5: request rejected, code={}", head[1])));
    }
    Ok(bind)
}

/// The `socks` outbound.
pub struct SocksOutbound {
    tag: String,
    dialer: Arc<dyn Dialer>,
    dns: Arc<dyn DnsResolver>,
    server: Socksaddr,
    version: SocksVersion,
    username: String,
    password: String,
    networks: Vec<Network>,
}

fn networks(list: &rb_config::NetworkList) -> Vec<Network> {
    list.build().iter().map(|network| if network == "udp" { Network::Udp } else { Network::Tcp }).collect()
}

impl SocksOutbound {
    pub fn new(options: &SocksOutboundOptions, tag: String, env: &DialerEnv) -> Result<Self, String> {
        let version = SocksVersion::parse(&options.version)?;
        if options.udp_over_tcp.as_ref().is_some_and(|uot| uot.enabled) {
            return Err("`udp_over_tcp` is not supported by rust-box yet".into());
        }
        let server = Socksaddr::from_host_port(&options.server, options.server_port);
        let dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/socks[{tag}]"),
        )?;
        Ok(SocksOutbound {
            tag,
            dialer,
            dns: env.dns.clone(),
            server,
            version,
            username: options.username.clone(),
            password: options.password.clone(),
            networks: networks(&options.network),
        })
    }

    /// sing `socks.Client.DialContext` for TCP to one destination.
    async fn connect(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let mut stream = self.dialer.dial_tcp(&self.server).await?;
        match self.version {
            SocksVersion::V4 | SocksVersion::V4a => {
                client_handshake4(&mut stream, COMMAND_CONNECT, destination, &self.username).await?
            }
            SocksVersion::V5 => {
                client_handshake5(&mut stream, COMMAND_CONNECT, destination, &self.username, &self.password).await?;
            }
        }
        Ok(stream)
    }

    /// SOCKS4 (not 4a) resolves domains itself (sing-box `h.resolve`).
    async fn resolved(&self, context: &InboundContext) -> io::Result<Option<Vec<IpAddr>>> {
        let destination = &context.destination;
        let Host::Domain(domain) = &destination.host else { return Ok(None) };
        if self.version != SocksVersion::V4 {
            return Ok(None);
        }
        let addresses = self.dns.lookup(domain, &LookupOptions::for_context(context)).await?;
        if addresses.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{destination}: no addresses")));
        }
        Ok(Some(addresses))
    }
}

#[async_trait]
impl Outbound for SocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "socks"
    }

    fn networks(&self) -> &[Network] {
        &self.networks
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        match self.resolved(context).await? {
            Some(addresses) => {
                let port = context.destination.port;
                let connect =
                    |address: IpAddr| async move { self.connect(&Socksaddr::new(Host::Ip(address), port)).await };
                dial_serial(&addresses, &connect).await
            }
            None => self.connect(&context.destination).await,
        }
    }

    /// A UDP ASSOCIATE (sing `socks.Client.ListenPacket`); SOCKS4 has no UDP.
    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        if self.version != SocksVersion::V5 {
            return Err(protocol_error("socks4: udp unsupported"));
        }
        let destination = &context.destination;
        let mut control = self.dialer.dial_tcp(&self.server).await?;
        let bind =
            client_handshake5(&mut control, COMMAND_UDP_ASSOCIATE, destination, &self.username, &self.password).await?;
        let relay = self.dialer.dial_udp(&bind).await?;
        Ok(Arc::new(SocksPacketConn::new(relay, bind, control)))
    }
}

/// The client side of a UDP association (sing `socks.AssociatePacketConn`):
/// packets carry the SOCKS5 UDP header; the association ends when the
/// control connection closes.
pub struct SocksPacketConn {
    relay: SharedPacketConn,
    bind: Socksaddr,
    closed: watch::Receiver<bool>,
    control: JoinHandle<()>,
}

impl SocksPacketConn {
    fn new(relay: SharedPacketConn, bind: Socksaddr, mut control: BoxStream) -> Self {
        let (sender, closed) = watch::channel(false);
        let control = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            while let Ok(read) = control.read(&mut buffer).await {
                if read == 0 {
                    break;
                }
            }
            let _ = sender.send(true);
        });
        SocksPacketConn { relay, bind, closed, control }
    }
}

impl Drop for SocksPacketConn {
    fn drop(&mut self) {
        // Dropping the task drops the control connection, which ends the
        // association on the server.
        self.control.abort();
    }
}

#[async_trait]
impl PacketConn for SocksPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut closed = self.closed.clone();
        let mut packet = vec![0u8; MAX_PACKET_SIZE];
        loop {
            let (length, _) = tokio::select! {
                read = self.relay.read_packet(&mut packet) => read?,
                _ = closed.wait_for(|closed| *closed) => {
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "socks5: UDP association closed"))
                }
            };
            let Ok((source, data)) = socks::decode_udp(&packet[..length]) else { continue };
            let length = data.len().min(buffer.len());
            buffer[..length].copy_from_slice(&data[..length]);
            return Ok((length, source));
        }
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        self.relay.write_packet(&socks::encode_udp(address, data), &self.bind).await
    }
}

/// Go `textproto.CanonicalMIMEHeaderKey`.
pub fn canonical_header_key(key: &str) -> String {
    let valid = key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
    if !valid {
        return key.to_string();
    }
    let mut upper = true;
    key.chars()
        .map(|c| {
            let mapped = if upper { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
            upper = c == '-';
            mapped
        })
        .collect()
}

/// Go `url.URL.EscapedPath` for a path set with `URLSetPath`.
fn escape_path(path: &str) -> String {
    let mut escaped = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@!'()*".contains(&byte) {
            escaped.push(byte as char);
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

/// The `http` outbound: HTTP CONNECT through the server (sing
/// `http.Client`).
pub struct HttpOutbound {
    tag: String,
    dialer: Arc<dyn Dialer>,
    server: Socksaddr,
    username: String,
    password: String,
    path: String,
    /// The `Host` header, taken out of `headers` (sing `NewClient`).
    host: String,
    headers: BTreeMap<String, Vec<String>>,
}

impl HttpOutbound {
    pub fn new(
        options: &HttpOutboundOptions,
        tag: String,
        env: &DialerEnv,
        certificates: &Arc<rb_certificate::Store>,
    ) -> Result<Self, String> {
        let server = Socksaddr::from_host_port(&options.server, options.server_port);
        let mut dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/http[{tag}]"),
        )?;
        if let Some(tls) = options.tls.as_ref().filter(|tls| tls.enabled) {
            let client = rb_tls::TlsClient::new(tls, &options.server, certificates)?;
            dialer = Arc::new(rb_tls::TlsDialer::new(dialer, client));
        }
        // badoption.HTTPHeader.Build: canonical keys, values in order.
        let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, values) in &options.headers {
            headers.entry(canonical_header_key(key)).or_default().extend(values.iter().cloned());
        }
        let host = headers.remove("Host").and_then(|values| values.into_iter().next()).unwrap_or_default();
        Ok(HttpOutbound {
            tag,
            dialer,
            server,
            username: options.username.clone(),
            password: options.password.clone(),
            path: options.path.clone(),
            host,
            headers,
        })
    }

    /// The CONNECT request as Go's `Request.Write` puts it.
    pub fn request(&self, destination: &Socksaddr) -> io::Result<String> {
        let target = destination.to_string();
        let (host, mut uri) = if !self.host.is_empty() && Some(self.host.as_str()) != destination.domain() {
            if !self.path.is_empty() {
                return Err(io::Error::other("Host header and path are not allowed at the same time"));
            }
            (self.host.clone(), target.clone())
        } else {
            (target.clone(), target.clone())
        };
        if !self.path.is_empty() {
            uri = escape_path(&self.path);
        }
        let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        headers.insert("Proxy-Connection".into(), vec!["Keep-Alive".into()]);
        for (key, values) in &self.headers {
            headers.insert(key.clone(), values.clone());
        }
        if !self.username.is_empty() {
            let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", self.username, self.password));
            headers.entry("Proxy-Authorization".into()).or_default().push(format!("Basic {auth}"));
        }
        let user_agent = headers.remove("User-Agent").and_then(|values| values.into_iter().next());
        let mut request = format!(
            "CONNECT {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {}\r\n",
            user_agent.as_deref().unwrap_or("Go-http-client/1.1")
        );
        for (key, values) in &headers {
            for value in values {
                request.push_str(&format!("{key}: {value}\r\n"));
            }
        }
        request.push_str("\r\n");
        Ok(request)
    }
}

const MAX_RESPONSE_HEADER: usize = 64 * 1024;

#[async_trait]
impl Outbound for HttpOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "http"
    }

    fn networks(&self) -> &[Network] {
        &[Network::Tcp]
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        let request = self.request(&context.destination)?;
        let mut stream = self.dialer.dial_tcp(&self.server).await?;
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut buffer = Vec::with_capacity(1024);
        let header_end = loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
            if buffer.len() > MAX_RESPONSE_HEADER {
                return Err(protocol_error("http: response header too large"));
            }
        };
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        response
            .parse(&buffer[..header_end])
            .map_err(|error| protocol_error(format!("malformed HTTP response: {error}")))?;
        let code = response.code.unwrap_or(0);
        match code {
            200 => {
                let rest = buffer[header_end..].to_vec();
                if rest.is_empty() {
                    Ok(stream)
                } else {
                    Ok(Box::new(PrefixedStream::new(rest, stream)))
                }
            }
            407 => Err(io::Error::new(io::ErrorKind::PermissionDenied, "authentication required")),
            405 => Err(io::Error::other("method not allowed")),
            _ => Err(io::Error::other(format!("unexpected status: {code} {}", response.reason.unwrap_or_default()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_keys() {
        assert_eq!(canonical_header_key("x-forwarded-for"), "X-Forwarded-For");
        assert_eq!(canonical_header_key("HOST"), "Host");
        assert_eq!(canonical_header_key("bad key"), "bad key");
    }

    #[test]
    fn associate_addresses() {
        let address = |text: &str| associate_address(&Socksaddr::from_host_port(text, 53)).to_string();
        assert_eq!(address("8.8.8.8"), "0.0.0.0:0");
        assert_eq!(address("192.168.1.1"), "[::1]:0");
        assert_eq!(address("fd00::1"), "127.0.0.1:0");
        assert_eq!(address("127.0.0.1"), "[::]:0");
        assert_eq!(address("2001:db8::1"), "[::]:0");
        assert_eq!(address("example.com"), "example.com:0");
    }

    #[tokio::test]
    async fn socks5_client_handshake() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let users = std::collections::HashMap::from([("u".to_string(), "p".to_string())]);
        let serve = tokio::spawn(async move { socks::handshake(&mut server, &users).await });
        let destination = Socksaddr::from_host_port("example.com", 443);
        client_handshake5(&mut client, COMMAND_CONNECT, &destination, "u", "p").await.unwrap();
        let request = serve.await.unwrap().unwrap();
        assert_eq!(request.destination, destination);
        assert_eq!(request.user.as_deref(), Some("u"));
    }

    #[tokio::test]
    async fn socks4a_client_handshake() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let serve = tokio::spawn(async move { socks::handshake(&mut server, &std::collections::HashMap::new()).await });
        let destination = Socksaddr::from_host_port("example.com", 80);
        client_handshake4(&mut client, COMMAND_CONNECT, &destination, "").await.unwrap();
        assert_eq!(serve.await.unwrap().unwrap().destination, destination);
    }
}
