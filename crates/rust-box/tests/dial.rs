//! End to end, milestone 3: dial fields (DNS server `detour`, bind
//! addresses, TCP Fast Open), happy-eyeballs in `direct`, the route options
//! (`override_address`/`override_port` for TCP and UDP, `tls_fragment`,
//! `tls_record_fragment`, `bypass`), and the listen fields (default
//! address, inbound `detour`).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rust_box::RustBox;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

async fn tcp_echo(bind: &str) -> Option<SocketAddr> {
    let listener = TcpListener::bind(bind).await.ok()?;
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Some(address)
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..length], peer).await;
        }
    });
    address
}

/// A TCP server that reports everything one connection sent.
async fn capture() -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let sender = sender.clone();
            tokio::spawn(async move {
                let mut data = Vec::new();
                let _ = stream.read_to_end(&mut data).await;
                let _ = sender.send(data).await;
            });
        }
    });
    (address, receiver)
}

/// A DNS server: `dual.test` has A 127.0.0.2 and AAAA ::1, other names
/// A 127.0.0.1. Reports the address each query came from.
async fn dns_server() -> (SocketAddr, mpsc::UnboundedReceiver<SocketAddr>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (sender, receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            let _ = sender.send(peer);
            let query = &buffer[..length];
            let mut end = 12;
            let mut labels = Vec::new();
            while query[end] != 0 {
                let label = query[end] as usize;
                labels.push(String::from_utf8_lossy(&query[end + 1..end + 1 + label]).to_string());
                end += 1 + label;
            }
            let name = labels.join(".");
            let query_type = u16::from_be_bytes([query[end + 1], query[end + 2]]);
            let mut response = query[..end + 5].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            let answer: Option<Vec<u8>> = match (name.as_str(), query_type) {
                ("dual.test", 1) => Some(vec![127, 0, 0, 2]),
                ("dual.test", 28) => Some("::1".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec()),
                (_, 1) => Some(vec![127, 0, 0, 1]),
                _ => None,
            };
            if let Some(data) = answer {
                response[7] = 1;
                response.extend_from_slice(&[0xc0, 0x0c, 0, query_type as u8, 0, 1, 0, 0, 0, 60, 0, data.len() as u8]);
                response.extend_from_slice(&data);
            }
            let _ = socket.send_to(&response, peer).await;
        }
    });
    (address, receiver)
}

async fn start(config: &str) -> (RustBox, Vec<SocketAddr>) {
    let options = rb_config::parse(config).unwrap();
    let instance = RustBox::new(&options).unwrap();
    instance.start().await.unwrap();
    let addresses = instance.inbounds().iter().map(|inbound| inbound.local_addr().unwrap()).collect();
    (instance, addresses)
}

/// A SOCKS5 CONNECT on `stream`; returns the reply code.
async fn socks5_on(stream: &mut TcpStream, host: &str, port: u16) -> u8 {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    reply[1]
}

async fn socks5(proxy: SocketAddr, host: &str, port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    assert_eq!(socks5_on(&mut stream, host, port).await, 0, "socks5 reply");
    stream
}

async fn echoes(stream: &mut TcpStream, data: &[u8]) -> bool {
    if stream.write_all(data).await.is_err() {
        return false;
    }
    let mut buffer = vec![0u8; data.len()];
    matches!(tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buffer)).await, Ok(Ok(_)))
        && buffer == data
}

async fn closed(stream: &mut TcpStream) -> bool {
    let mut buffer = [0u8; 1];
    matches!(tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await, Ok(Ok(0)) | Ok(Err(_)))
}

#[tokio::test]
async fn happy_eyeballs_through_a_dns_detour() {
    // IPv6 loopback is needed for the fallback family.
    let Some(echo6) = tcp_echo("[::1]:0").await else { return };
    let (dns, mut queries) = dns_server().await;
    let config = format!(
        r#"{{
      "dns": {{"servers": [{{"type": "udp", "tag": "fake", "server": "127.0.0.1", "server_port": {},
                            "detour": "bound"}}]}},
      "inbounds": [{{"type": "socks", "tag": "in", "listen_port": 0}}],
      "outbounds": [
        {{"type": "direct", "tag": "direct", "fallback_delay": "10s"}},
        {{"type": "direct", "tag": "bound", "inet4_bind_address": "127.0.0.1", "connect_timeout": "5s"}}
      ],
      "route": {{"final": "direct"}}
    }}"#,
        dns.port()
    );
    let (_instance, inbounds) = start(&config).await;
    // `listen` defaults to 127.0.0.1.
    assert_eq!(inbounds[0].ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    // dual.test: 127.0.0.2 first (refused at once), so ::1 is tried right
    // away instead of after the 10s fallback delay.
    let started = std::time::Instant::now();
    let mut stream = socks5(inbounds[0], "dual.test", echo6.port()).await;
    assert!(echoes(&mut stream, b"over ipv6").await);
    assert!(started.elapsed() < Duration::from_secs(5), "fell back immediately: {:?}", started.elapsed());
    // The DNS queries went out through the `bound` outbound's dialer.
    let peer = tokio::time::timeout(Duration::from_secs(1), queries.recv()).await.unwrap().unwrap();
    assert_eq!(peer.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn dns_detour_to_block_fails_lookups() {
    let echo = tcp_echo("127.0.0.1:0").await.unwrap();
    let (dns, _queries) = dns_server().await;
    let config = format!(
        r#"{{
      "dns": {{"servers": [{{"type": "udp", "server": "127.0.0.1", "server_port": {}, "detour": "block"}}]}},
      "inbounds": [{{"type": "socks", "listen": "127.0.0.1", "listen_port": 0}}],
      "outbounds": [{{"type": "direct", "tag": "direct"}}, {{"type": "block", "tag": "block"}}]
    }}"#,
        dns.port()
    );
    let (_instance, inbounds) = start(&config).await;
    let mut stream = socks5(inbounds[0], "anything.test", echo.port()).await;
    assert!(closed(&mut stream).await, "lookup through the block outbound fails");
    // IP destinations need no lookup.
    let mut stream = socks5(inbounds[0], "127.0.0.1", echo.port()).await;
    assert!(echoes(&mut stream, b"ip").await);
}

#[tokio::test]
async fn override_destination_tcp_and_bypass() {
    let echo = tcp_echo("127.0.0.1:0").await.unwrap();
    let config = format!(
        r#"{{
      "inbounds": [{{"type": "mixed", "listen": "127.0.0.1", "listen_port": 0}}],
      "outbounds": [{{"type": "direct", "tag": "direct", "tcp_fast_open": true}}, {{"type": "block", "tag": "block"}}],
      "route": {{
        "rules": [
          {{"domain": "moved.test", "action": "route-options", "override_address": "127.0.0.1", "override_port": {port}}},
          {{"domain": "moved.test", "outbound": "direct"}},
          {{"domain": "skip.test", "action": "bypass"}},
          {{"domain": "skip.test", "action": "reject"}},
          {{"domain": "by.test", "action": "bypass", "outbound": "direct", "override_address": "127.0.0.1"}},
          {{"ip_cidr": "127.0.0.1/32", "port": {port}, "outbound": "direct"}}
        ],
        "final": "block"
      }}
    }}"#,
        port = echo.port()
    );
    let (_instance, inbounds) = start(&config).await;
    // Overridden address and port, then routed on the new destination,
    // through a direct outbound with TCP Fast Open.
    let mut stream = socks5(inbounds[0], "moved.test", 1).await;
    assert!(echoes(&mut stream, b"moved").await);
    // bypass without an outbound is skipped: the next rule rejects.
    let mut stream = socks5(inbounds[0], "skip.test", echo.port()).await;
    assert!(closed(&mut stream).await);
    // bypass with an outbound routes like route, with its options.
    let mut stream = socks5(inbounds[0], "by.test", echo.port()).await;
    assert!(echoes(&mut stream, b"bypass").await);
}

#[tokio::test]
async fn override_destination_udp_reports_the_original() {
    let echo = udp_echo().await;
    let config = format!(
        r#"{{
      "inbounds": [{{"type": "socks", "listen": "127.0.0.1", "listen_port": 0}}],
      "outbounds": [{{"type": "direct", "tag": "direct"}}],
      "route": {{"rules": [{{"network": "udp", "ip_cidr": "192.0.2.7/32", "action": "route-options",
                             "override_address": "127.0.0.1", "override_port": {}}}]}}
    }}"#,
        echo.port()
    );
    let (_instance, inbounds) = start(&config).await;
    let mut control = TcpStream::connect(inbounds[0]).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    control.read_exact(&mut reply).await.unwrap();
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    let relay = SocketAddr::from(([reply[4], reply[5], reply[6], reply[7]], u16::from_be_bytes([reply[8], reply[9]])));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 192, 0, 2, 7, 0, 5];
    packet.extend_from_slice(b"redirected");
    for _ in 0..2 {
        socket.send_to(&packet, relay).await.unwrap();
        let mut buffer = [0u8; 2048];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        // The echo server answered, and the reply names the original destination.
        assert_eq!(&buffer[..length], &packet[..], "reply from 192.0.2.7:5");
    }
}

/// A ClientHello for `name`.
fn client_hello(name: &str) -> Vec<u8> {
    let mut sni = Vec::new();
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name.as_bytes());
    let mut extensions = vec![0x00, 0x00];
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[9u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[tokio::test]
async fn tls_fragment_and_record_fragment() {
    let (record_server, mut records) = capture().await;
    let (packet_server, mut packets) = capture().await;
    let config = format!(
        r#"{{
      "inbounds": [{{"type": "mixed", "listen": "127.0.0.1", "listen_port": 0}}],
      "outbounds": [{{"type": "direct", "tag": "direct"}}],
      "route": {{"rules": [
        {{"port": {}, "action": "route-options", "tls_record_fragment": true}},
        {{"port": {}, "outbound": "direct", "tls_fragment": true, "tls_fragment_fallback_delay": "5ms"}}
      ]}}
    }}"#,
        record_server.port(),
        packet_server.port()
    );
    let (_instance, inbounds) = start(&config).await;
    let hello = client_hello("www.example.com");

    let mut stream = socks5(inbounds[0], "127.0.0.1", record_server.port()).await;
    stream.write_all(&hello).await.unwrap();
    stream.shutdown().await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), records.recv()).await.unwrap().unwrap();
    // Two TLS records whose payloads are the original handshake message.
    assert_eq!(received.len(), hello.len() + 5);
    let first = u16::from_be_bytes([received[3], received[4]]) as usize;
    let second = &received[5 + first..];
    assert_eq!(&second[..3], &hello[..3]);
    assert_eq!(u16::from_be_bytes([second[3], second[4]]) as usize, second.len() - 5);
    let mut handshake = received[5..5 + first].to_vec();
    handshake.extend_from_slice(&second[5..]);
    assert_eq!(handshake, &hello[5..]);

    // Segments: the bytes arrive unchanged.
    let mut stream = socks5(inbounds[0], "127.0.0.1", packet_server.port()).await;
    stream.write_all(&hello).await.unwrap();
    stream.write_all(b"after").await.unwrap();
    stream.shutdown().await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(10), packets.recv()).await.unwrap().unwrap();
    let mut expected = hello.clone();
    expected.extend_from_slice(b"after");
    assert_eq!(received, expected);
}

#[tokio::test]
async fn inbound_detour_hands_the_connection_over() {
    let echo = tcp_echo("127.0.0.1:0").await.unwrap();
    let config = r#"{
      "inbounds": [
        {"type": "mixed", "tag": "front", "listen": "127.0.0.1", "listen_port": 0, "detour": "inner",
         "tcp_keep_alive": "30s", "reuse_addr": true},
        {"type": "socks", "tag": "inner", "listen": "127.0.0.1", "listen_port": 0}
      ],
      "outbounds": [{"type": "direct", "tag": "direct"}],
      "route": {"rules": [{"inbound": "inner", "outbound": "direct"}, {"action": "reject"}]}
    }"#;
    let (_instance, inbounds) = start(config).await;
    // The front inbound finishes its handshake, then the router hands the
    // stream to `inner`, which speaks SOCKS5 again on it.
    let mut stream = TcpStream::connect(inbounds[0]).await.unwrap();
    assert_eq!(socks5_on(&mut stream, "ignored.test", 1).await, 0);
    assert_eq!(socks5_on(&mut stream, "127.0.0.1", echo.port()).await, 0);
    assert!(echoes(&mut stream, b"nested").await);
    // Connected to `inner` directly, it routes the same way.
    let mut stream = socks5(inbounds[1], "127.0.0.1", echo.port()).await;
    assert!(echoes(&mut stream, b"direct").await);
}
