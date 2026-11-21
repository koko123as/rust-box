//! The `socks` and `http` outbounds and TLS on the `http` / `mixed`
//! inbounds: rust-box against rust-box, and against the real sing-box when
//! `SING_BOX_BIN` points at it (those cases print a note and pass without).
//!
//! Each case runs a client box (a mixed inbound the test drives with
//! SOCKS5, routed to the outbound under test) and a server box (the inbound
//! under test, routed to direct), with local TCP and UDP echo servers.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rust_box::RustBox;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    address
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Starts a rust-box with `config`; returns it and its inbounds' addresses.
async fn start(config: &Value) -> (RustBox, Vec<SocketAddr>) {
    let options = rb_config::parse(&config.to_string()).unwrap();
    let instance = RustBox::new(&options).unwrap();
    instance.start().await.unwrap();
    let addresses = instance.inbounds().iter().map(|inbound| inbound.local_addr().unwrap()).collect();
    (instance, addresses)
}

/// A sing-box process, killed on drop (with the directory of its config).
struct SingBox(Child, #[allow(dead_code)] tempfile::TempDir);

impl Drop for SingBox {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs the real sing-box with `config` and waits for `port` to accept;
/// `None` when `SING_BOX_BIN` is not set.
async fn sing_box(config: &Value, port: u16) -> Option<SingBox> {
    let binary = match std::env::var("SING_BOX_BIN") {
        Ok(binary) if !binary.is_empty() => binary,
        _ => {
            eprintln!("SING_BOX_BIN not set: skipping the sing-box interop case");
            return None;
        }
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec_pretty(config).unwrap()).unwrap();
    let child = Command::new(binary)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn sing-box");
    let process = SingBox(child, directory);
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Some(process);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("sing-box did not start listening on {port}");
}

/// A SOCKS5 CONNECT through `proxy`.
async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0, 1];
    if let SocketAddr::V4(v4) = target {
        request.extend_from_slice(&v4.ip().octets());
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "socks5 reply");
    stream
}

async fn assert_tcp_echo(proxy: SocketAddr, echo: SocketAddr) {
    let mut stream = socks5_connect(proxy, echo).await;
    stream.write_all(b"hello through the chain").await.unwrap();
    let mut buffer = [0u8; 23];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer, b"hello through the chain");
}

/// A SOCKS5 UDP ASSOCIATE through `proxy`, one datagram to `echo` and back.
async fn assert_udp_echo(proxy: SocketAddr, echo: SocketAddr) {
    let mut control = TcpStream::connect(proxy).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    control.read_exact(&mut reply).await.unwrap();
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!((reply[1], reply[3]), (0, 1), "udp associate reply");
    let relay = SocketAddr::from(([reply[4], reply[5], reply[6], reply[7]], u16::from_be_bytes([reply[8], reply[9]])));
    let relay = if relay.ip().is_unspecified() { SocketAddr::from(([127, 0, 0, 1], relay.port())) } else { relay };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1];
    if let SocketAddr::V4(v4) = echo {
        packet.extend_from_slice(&v4.ip().octets());
    }
    packet.extend_from_slice(&echo.port().to_be_bytes());
    packet.extend_from_slice(b"datagram");
    let mut buffer = [0u8; 2048];
    // UDP may lose the first packet while the chain sets up: retry.
    for _ in 0..5 {
        socket.send_to(&packet, relay).await.unwrap();
        if let Ok(Ok((length, _))) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await {
            assert_eq!(&buffer[..length], &packet[..], "echoed datagram with the echo server's address");
            return;
        }
    }
    panic!("no UDP reply through {proxy}");
}

/// A CA-signed certificate for `example.test` written to a directory.
struct Pki {
    _directory: tempfile::TempDir,
    ca: String,
    cert_path: String,
    key_path: String,
}

fn pki() -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "rust-box test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert =
        rcgen::CertificateParams::new(vec!["example.test".to_string()]).unwrap().signed_by(&key, &ca, &ca_key).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name).to_string_lossy().into_owned();
    let (cert_path, key_path) = (path("cert.pem"), path("key.pem"));
    std::fs::write(Path::new(&cert_path), cert.pem()).unwrap();
    std::fs::write(Path::new(&key_path), key.serialize_pem()).unwrap();
    Pki { _directory: directory, ca: ca.pem(), cert_path, key_path }
}

fn ca_lines(pki: &Pki) -> Vec<String> {
    pki.ca.lines().map(str::to_string).collect()
}

/// A client config: a mixed inbound on `port` (0: any) routed to `outbound`.
fn client_config(port: u16, outbound: Value) -> Value {
    json!({
        "log": {"level": "warn"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound],
    })
}

/// A server config: `inbound` routed to direct.
fn server_config(inbound: Value) -> Value {
    json!({
        "log": {"level": "warn"},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    })
}

fn socks_outbound(server: SocketAddr) -> Value {
    json!({"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": server.port(),
           "username": "user", "password": "pass"})
}

fn socks_inbound(port: u16) -> Value {
    json!({"type": "socks", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
           "users": [{"username": "user", "password": "pass"}]})
}

fn tls_http_inbound(port: u16, pki: &Pki) -> Value {
    json!({"type": "http", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
           "users": [{"username": "user", "password": "pass"}],
           "tls": {"enabled": true, "certificate_path": pki.cert_path, "key_path": pki.key_path}})
}

fn tls_http_outbound(server: SocketAddr, pki: &Pki) -> Value {
    json!({"type": "http", "tag": "proxy", "server": "127.0.0.1", "server_port": server.port(),
           "username": "user", "password": "pass",
           "tls": {"enabled": true, "server_name": "example.test", "certificate": ca_lines(pki)}})
}

#[tokio::test]
async fn rust_box_socks_outbound_to_rust_box_socks_inbound() {
    let (echo, udp) = (tcp_echo().await, udp_echo().await);
    let (_server, servers) = start(&server_config(socks_inbound(0))).await;
    let (_client, clients) = start(&client_config(0, socks_outbound(servers[0]))).await;
    assert_tcp_echo(clients[0], echo).await;
    assert_udp_echo(clients[0], udp).await;

    // SOCKS4a carries TCP only.
    let mut outbound = socks_outbound(servers[0]);
    outbound["version"] = json!("4a");
    outbound["network"] = json!("tcp");
    outbound.as_object_mut().unwrap().remove("password");
    let (_server4, servers4) = start(&server_config(json!({"type": "socks", "listen_port": 0}))).await;
    outbound["server_port"] = json!(servers4[0].port());
    let (_client4, clients4) = start(&client_config(0, outbound)).await;
    assert_tcp_echo(clients4[0], echo).await;
}

#[tokio::test]
async fn rust_box_http_outbound_over_tls_to_rust_box_http_inbound() {
    let echo = tcp_echo().await;
    let pki = pki();
    let (_server, servers) = start(&server_config(tls_http_inbound(0, &pki))).await;
    let (_client, clients) = start(&client_config(0, tls_http_outbound(servers[0], &pki))).await;
    assert_tcp_echo(clients[0], echo).await;

    // Plain HTTP to a mixed inbound.
    let (_mixed, mixed) = start(&server_config(json!({"type": "mixed", "listen_port": 0}))).await;
    let outbound = json!({"type": "http", "server": "127.0.0.1", "server_port": mixed[0].port()});
    let (_plain, plain) = start(&client_config(0, outbound)).await;
    assert_tcp_echo(plain[0], echo).await;
}

#[tokio::test]
async fn socks_outbound_with_wrong_credentials_fails() {
    let echo = tcp_echo().await;
    let (_server, servers) = start(&server_config(socks_inbound(0))).await;
    let mut outbound = socks_outbound(servers[0]);
    outbound["password"] = json!("wrong");
    let (_client, clients) = start(&client_config(0, outbound)).await;
    let mut stream = TcpStream::connect(clients[0]).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    // The route fails: the connection is closed (no relayed data).
    let mut buffer = [0u8; 64];
    let mut all = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Ok(read) = stream.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            all.extend_from_slice(&buffer[..read]);
        }
    })
    .await;
    stream.write_all(b"x").await.ok();
    assert!(all.len() <= 10, "nothing but the SOCKS reply");
}

// ---- interop with the real sing-box ----

#[tokio::test]
async fn interop_rust_box_socks_outbound_to_sing_box_socks_inbound() {
    let (echo, udp) = (tcp_echo().await, udp_echo().await);
    let port = free_port();
    let Some(_sing_box) = sing_box(&server_config(socks_inbound(port)), port).await else { return };
    let (_client, clients) = start(&client_config(0, socks_outbound(SocketAddr::from(([127, 0, 0, 1], port))))).await;
    assert_tcp_echo(clients[0], echo).await;
    assert_udp_echo(clients[0], udp).await;
}

#[tokio::test]
async fn interop_sing_box_socks_outbound_to_rust_box_socks_inbound() {
    let (echo, udp) = (tcp_echo().await, udp_echo().await);
    let (_server, servers) = start(&server_config(socks_inbound(0))).await;
    let port = free_port();
    let Some(_sing_box) = sing_box(&client_config(port, socks_outbound(servers[0])), port).await else { return };
    let proxy = SocketAddr::from(([127, 0, 0, 1], port));
    assert_tcp_echo(proxy, echo).await;
    assert_udp_echo(proxy, udp).await;
}

#[tokio::test]
async fn interop_sing_box_http_outbound_over_tls_to_rust_box_http_inbound() {
    let echo = tcp_echo().await;
    let pki = pki();
    let (_server, servers) = start(&server_config(tls_http_inbound(0, &pki))).await;
    let port = free_port();
    let Some(_sing_box) = sing_box(&client_config(port, tls_http_outbound(servers[0], &pki)), port).await else {
        return;
    };
    assert_tcp_echo(SocketAddr::from(([127, 0, 0, 1], port)), echo).await;
}

#[tokio::test]
async fn interop_rust_box_http_outbound_over_tls_to_sing_box_http_inbound() {
    let echo = tcp_echo().await;
    let pki = pki();
    let port = free_port();
    let Some(_sing_box) = sing_box(&server_config(tls_http_inbound(port, &pki)), port).await else { return };
    let outbound = tls_http_outbound(SocketAddr::from(([127, 0, 0, 1], port)), &pki);
    let (_client, clients) = start(&client_config(0, outbound)).await;
    assert_tcp_echo(clients[0], echo).await;
}

#[tokio::test]
async fn interop_sing_box_socks4_outbound_to_rust_box_mixed_inbound() {
    let echo = tcp_echo().await;
    let (_server, servers) = start(&server_config(json!({"type": "mixed", "listen_port": 0}))).await;
    let port = free_port();
    let outbound = json!({"type": "socks", "server": "127.0.0.1", "server_port": servers[0].port(), "version": "4a"});
    let Some(_sing_box) = sing_box(&client_config(port, outbound), port).await else { return };
    assert_tcp_echo(SocketAddr::from(([127, 0, 0, 1], port)), echo).await;
}
