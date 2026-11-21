//! End to end UDP: SOCKS5 UDP ASSOCIATE through the direct outbound to a
//! local UDP echo server, domain unmapping, `udp_timeout`, reject, and DNS
//! queries answered by `hijack-dns` (over UDP and over TCP).

use std::net::SocketAddr;
use std::time::Duration;

use rust_box::RustBox;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

async fn echo_server() -> SocketAddr {
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

/// A DNS server answering A queries: `localhost` with 127.0.0.1, any other
/// name with 10.1.2.3; other types with no records.
async fn dns_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            let query = &buffer[..length];
            let mut end = 12;
            let mut name = Vec::new();
            while query[end] != 0 {
                let label = query[end] as usize;
                name.push(String::from_utf8_lossy(&query[end + 1..end + 1 + label]).to_string());
                end += 1 + label;
            }
            let question_end = end + 5;
            let query_type = u16::from_be_bytes([query[end + 1], query[end + 2]]);
            let mut response = query[..question_end].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            if query_type == 1 {
                response[7] = 1;
                let ip = if name.join(".") == "localhost" { [127, 0, 0, 1] } else { [10, 1, 2, 3] };
                response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                response.extend_from_slice(&ip);
            }
            let _ = socket.send_to(&response, peer).await;
        }
    });
    address
}

/// A query for `example.test` A with id 0xbeef.
fn dns_query() -> Vec<u8> {
    let mut query = vec![0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07example\x04test\x00\x00\x01\x00\x01");
    query
}

fn check_dns_answer(response: &[u8]) {
    assert_eq!(&response[..2], &[0xbe, 0xef], "id");
    assert!(response[2] & 0x80 != 0, "QR");
    assert_eq!(response[3] & 0x0f, 0, "rcode");
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1, "answers");
    assert_eq!(&response[response.len() - 4..], &[10, 1, 2, 3]);
}

async fn start() -> (RustBox, Vec<SocketAddr>) {
    let dns = dns_server().await;
    let config = format!(
        r#"{{
      "dns": {{"servers": [{{"type": "udp", "tag": "fake", "server": "127.0.0.1", "server_port": {}}}],
               "strategy": "ipv4_only"}},
      "inbounds": [
        {{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}},
        {{"type": "socks", "tag": "in-nomap", "listen": "127.0.0.1", "listen_port": 0}},
        {{"type": "socks", "tag": "in-short", "listen": "127.0.0.1", "listen_port": 0, "udp_timeout": 1}}
      ],
      "outbounds": [{{"type": "direct", "tag": "direct"}}, {{"type": "block", "tag": "block"}}],
      "route": {{
        "rules": [
          {{"action": "sniff"}},
          {{"protocol": "dns", "action": "hijack-dns"}},
          {{"network": "udp", "port": 9, "action": "reject"}},
          {{"inbound": "in-nomap", "action": "route-options", "udp_disable_domain_unmapping": true}},
          {{"network": "udp", "port": 7, "outbound": "block"}}
        ],
        "final": "direct"
      }}
    }}"#,
        dns.port()
    );
    let options = rb_config::parse(&config).unwrap();
    let instance = RustBox::new(&options).unwrap();
    instance.start().await.unwrap();
    let addresses = instance.inbounds().iter().map(|inbound| inbound.local_addr().unwrap()).collect();
    (instance, addresses)
}

/// Opens a UDP association; returns the control connection, the client's
/// UDP socket and the relay address from the reply.
async fn associate(proxy: SocketAddr) -> (TcpStream, UdpSocket, SocketAddr) {
    let mut control = TcpStream::connect(proxy).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1], "associate reply");
    let relay = SocketAddr::from(([reply[4], reply[5], reply[6], reply[7]], u16::from_be_bytes([reply[8], reply[9]])));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    (control, socket, relay)
}

fn socks_udp(host: &str, port: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            packet.extend_from_slice(&[3, host.len() as u8]);
            packet.extend_from_slice(host.as_bytes());
        }
    }
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

/// Receives one SOCKS5 UDP reply: the source it names, and the data.
async fn receive(socket: &UdpSocket) -> (String, Vec<u8>) {
    let mut buffer = [0u8; 2048];
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.expect("reply").unwrap();
    let packet = &buffer[..length];
    let (host, rest) = match packet[3] {
        1 => (format!("{}.{}.{}.{}", packet[4], packet[5], packet[6], packet[7]), &packet[8..]),
        3 => {
            let length = packet[4] as usize;
            (String::from_utf8_lossy(&packet[5..5 + length]).to_string(), &packet[5 + length..])
        }
        other => panic!("address type {other}"),
    };
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    (format!("{host}:{port}"), rest[2..].to_vec())
}

/// Waits until the server closes the control connection.
async fn closed_within(control: &mut TcpStream, limit: Duration) -> bool {
    let mut buffer = [0u8; 1];
    matches!(tokio::time::timeout(limit, control.read(&mut buffer)).await, Ok(Ok(0)) | Ok(Err(_)))
}

#[tokio::test]
async fn socks5_udp_to_echo_server() {
    let echo = echo_server().await;
    let (_instance, inbounds) = start().await;
    let (_control, socket, relay) = associate(inbounds[0]).await;
    socket.send_to(&socks_udp("127.0.0.1", echo.port(), b"first"), relay).await.unwrap();
    assert_eq!(receive(&socket).await, (format!("127.0.0.1:{}", echo.port()), b"first".to_vec()));
    // The same association reaches another destination.
    let other = echo_server().await;
    socket.send_to(&socks_udp("127.0.0.1", other.port(), b"second"), relay).await.unwrap();
    assert_eq!(receive(&socket).await, (format!("127.0.0.1:{}", other.port()), b"second".to_vec()));
}

#[tokio::test]
async fn socks5_udp_domain_unmapping() {
    let echo = echo_server().await;
    let (_instance, inbounds) = start().await;
    // Replies to a domain destination name the domain...
    let (_control, socket, relay) = associate(inbounds[0]).await;
    socket.send_to(&socks_udp("localhost", echo.port(), b"mapped"), relay).await.unwrap();
    assert_eq!(receive(&socket).await, (format!("localhost:{}", echo.port()), b"mapped".to_vec()));
    // ...unless udp_disable_domain_unmapping is set.
    let (_control, socket, relay) = associate(inbounds[1]).await;
    socket.send_to(&socks_udp("localhost", echo.port(), b"unmapped"), relay).await.unwrap();
    assert_eq!(receive(&socket).await, (format!("127.0.0.1:{}", echo.port()), b"unmapped".to_vec()));
}

#[tokio::test]
async fn socks5_udp_hijack_dns() {
    let (_instance, inbounds) = start().await;
    let (_control, socket, relay) = associate(inbounds[0]).await;
    // Sent to an address nobody answers on: the DNS module answers instead.
    socket.send_to(&socks_udp("192.0.2.1", 53, &dns_query()), relay).await.unwrap();
    let (source, response) = receive(&socket).await;
    assert_eq!(source, "192.0.2.1:53");
    check_dns_answer(&response);
}

#[tokio::test]
async fn tcp_hijack_dns() {
    let (_instance, inbounds) = start().await;
    let mut stream = TcpStream::connect(inbounds[0]).await.unwrap();
    stream.write_all(&[5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 0, 53]).await.unwrap();
    let mut reply = [0u8; 12];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[3], 0, "socks5 connect reply");
    let query = dns_query();
    let mut frame = (query.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&query);
    stream.write_all(&frame).await.unwrap();
    let length = tokio::time::timeout(Duration::from_secs(5), stream.read_u16()).await.unwrap().unwrap();
    let mut response = vec![0u8; length as usize];
    stream.read_exact(&mut response).await.unwrap();
    check_dns_answer(&response);
}

#[tokio::test]
async fn socks5_udp_timeout_reject_and_block() {
    let echo = echo_server().await;
    let (_instance, inbounds) = start().await;
    // udp_timeout 1 (second): the association ends when idle.
    let (mut control, socket, relay) = associate(inbounds[2]).await;
    socket.send_to(&socks_udp("127.0.0.1", echo.port(), b"x"), relay).await.unwrap();
    assert_eq!(receive(&socket).await.1, b"x");
    assert!(closed_within(&mut control, Duration::from_secs(5)).await, "idle association closed");
    // Rejected by rule, and refused by the block outbound.
    for port in [9, 7] {
        let (mut control, socket, relay) = associate(inbounds[0]).await;
        socket.send_to(&socks_udp("127.0.0.1", port, b"x"), relay).await.unwrap();
        assert!(closed_within(&mut control, Duration::from_secs(5)).await, "port {port} closed");
    }
}
