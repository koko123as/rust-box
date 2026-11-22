//! The `trojan` and `vless` outbounds and inbounds: rust-box against
//! rust-box (TCP, UDP, trojan fallback, every vless packet encoding,
//! Vision), and against the real sing-box when `SING_BOX_BIN` points at it
//! (those cases print a note and pass without).
//!
//! Each case runs a client box (a mixed inbound the test drives with
//! SOCKS5, routed to the outbound under test) and a server box (the
//! inbound under test, routed to direct), with local TCP, UDP and TLS 1.3
//! echo servers. Vision only goes direct for a TLS 1.3 inner connection,
//! so the Vision cases carry one (a rustls client through the SOCKS5
//! tunnel to the TLS echo server).

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rust_box::RustBox;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";
const VISION: &str = "xtls-rprx-vision";

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

/// A TCP server that writes `banner` first, then echoes.
async fn banner_echo(banner: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(banner).await;
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

fn local(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
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

/// Runs sing-box with a QUIC-only inbound and waits until its UDP port is bound.
async fn sing_box_quic(config: &Value, port: u16) -> Option<SingBox> {
    let binary = match std::env::var("SING_BOX_BIN") {
        Ok(binary) if !binary.is_empty() => binary,
        _ => {
            eprintln!("SING_BOX_BIN not set: skipping the sing-box QUIC interop case");
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
    let mut process = SingBox(child, directory);
    for _ in 0..100 {
        if let Some(status) = process.0.try_wait().expect("check sing-box process") {
            panic!("sing-box exited before binding QUIC port {port}: {status}");
        }
        match UdpSocket::bind(("127.0.0.1", port)).await {
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => return Some(process),
            Ok(socket) => drop(socket),
            Err(error) => panic!("check sing-box UDP port {port}: {error}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("sing-box did not bind QUIC UDP port {port}");
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

/// 200 KB both ways through `proxy` to the TCP echo server.
async fn assert_tcp_echo(proxy: SocketAddr, echo: SocketAddr) {
    let stream = socks5_connect(proxy, echo).await;
    let payload: Vec<u8> = (0..200_000u32).map(|index| (index % 253) as u8).collect();
    let (mut reader, mut writer) = stream.into_split();
    let data = payload.clone();
    let writing = tokio::spawn(async move {
        // Keep the write half open: dropping it half-closes the connection,
        // which sing-box answers by closing a non-duplex outbound whole.
        writer.write_all(&data).await.unwrap();
        writer
    });
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), reader.read_exact(&mut echoed)).await.unwrap().unwrap();
    let _writer = writing.await.unwrap();
    assert!(echoed == payload, "TCP echo through {proxy}");
}

/// A SOCKS5 UDP ASSOCIATE through `proxy`, datagrams to `echo` and back.
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
    let relay = if relay.ip().is_unspecified() { local(relay.port()) } else { relay };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut header = vec![0, 0, 0, 1];
    if let SocketAddr::V4(v4) = echo {
        header.extend_from_slice(&v4.ip().octets());
    }
    header.extend_from_slice(&echo.port().to_be_bytes());
    let mut buffer = [0u8; 2048];
    for round in 0..3u8 {
        let mut packet = header.clone();
        packet.extend_from_slice(b"datagram ");
        packet.push(b'0' + round);
        let mut answered = false;
        // UDP may lose the first packet while the chain sets up: retry.
        for _ in 0..5 {
            socket.send_to(&packet, relay).await.unwrap();
            if let Ok(Ok((length, _))) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await
            {
                assert_eq!(&buffer[..length], &packet[..], "echoed datagram with the echo server's address");
                answered = true;
                break;
            }
        }
        assert!(answered, "no UDP reply through {proxy}");
    }
}

/// A CA-signed certificate for `example.test` written to a directory.
struct Pki {
    _directory: tempfile::TempDir,
    ca: String,
    ca_der: rustls::pki_types::CertificateDer<'static>,
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: Vec<u8>,
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
    Pki {
        _directory: directory,
        ca: ca.pem(),
        ca_der: ca.der().clone(),
        cert_der: cert.der().clone(),
        key_der: key.serialize_der(),
        cert_path,
        key_path,
    }
}

fn ca_lines(pki: &Pki) -> Vec<String> {
    pki.ca.lines().map(str::to_string).collect()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A rustls client trusting the test CA, with `alpn`.
fn tls_client(pki: &Pki, alpn: &[&str]) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.ca_der.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.as_bytes().to_vec()).collect();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// A TLS 1.3 echo server for `example.test`.
async fn tls_echo(pki: &Pki) -> SocketAddr {
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![pki.cert_der.clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(pki.key_der.clone().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else { return };
                let (mut reader, mut writer) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                let _ = writer.shutdown().await;
            });
        }
    });
    address
}

/// A TLS 1.3 connection through `proxy` to the TLS echo server, 300 KB
/// both ways (what makes Vision go direct).
async fn assert_tls_echo(proxy: SocketAddr, echo: SocketAddr, pki: &Pki) {
    let stream = socks5_connect(proxy, echo).await;
    let name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
    let stream = tokio::time::timeout(Duration::from_secs(10), tls_client(pki, &[]).connect(name, stream))
        .await
        .unwrap()
        .unwrap();
    let payload: Vec<u8> = (0..300_000u32).map(|index| (index % 249) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let data = payload.clone();
    let writing = tokio::spawn(async move {
        // Keep the write half open: dropping it half-closes the connection,
        // which sing-box answers by closing a non-duplex outbound whole.
        writer.write_all(&data).await.unwrap();
        writer
    });
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), reader.read_exact(&mut echoed)).await.unwrap().unwrap();
    let _writer = writing.await.unwrap();
    assert!(echoed == payload, "TLS echo through {proxy}");
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

fn server_tls(pki: &Pki) -> Value {
    json!({"enabled": true, "certificate_path": pki.cert_path, "key_path": pki.key_path})
}

fn client_tls(pki: &Pki) -> Value {
    json!({"enabled": true, "server_name": "example.test", "certificate": ca_lines(pki)})
}

fn trojan_inbound(port: u16, tls: Option<Value>) -> Value {
    let mut inbound = json!({"type": "trojan", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
                             "users": [{"name": "alice", "password": "trojan-password"}]});
    if let Some(tls) = tls {
        inbound["tls"] = tls;
    }
    inbound
}

fn trojan_outbound(server: SocketAddr, tls: Option<Value>) -> Value {
    let mut outbound = json!({"type": "trojan", "tag": "proxy", "server": "127.0.0.1", "server_port": server.port(),
                              "password": "trojan-password"});
    if let Some(tls) = tls {
        outbound["tls"] = tls;
    }
    outbound
}

fn vless_inbound(port: u16, flow: &str, tls: Option<Value>) -> Value {
    let mut inbound = json!({"type": "vless", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
                             "users": [{"name": "bob", "uuid": UUID, "flow": flow}]});
    if let Some(tls) = tls {
        inbound["tls"] = tls;
    }
    inbound
}

fn vless_outbound(server: SocketAddr, flow: &str, packet_encoding: Option<&str>, tls: Option<Value>) -> Value {
    let mut outbound = json!({"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": server.port(),
                              "uuid": UUID, "flow": flow});
    if let Some(encoding) = packet_encoding {
        outbound["packet_encoding"] = json!(encoding);
    }
    if let Some(tls) = tls {
        outbound["tls"] = tls;
    }
    outbound
}

/// rust-box client → rust-box server, TCP and UDP.
async fn rust_box_chain(outbound: impl FnOnce(SocketAddr) -> Value, inbound: Value, udp: bool) {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    let (_server, servers) = start(&server_config(inbound)).await;
    let (_client, clients) = start(&client_config(0, outbound(servers[0]))).await;
    assert_tcp_echo(clients[0], echo).await;
    if udp {
        assert_udp_echo(clients[0], udp_target).await;
    }
}

#[tokio::test]
async fn rust_box_trojan_over_tls() {
    let pki = pki();
    rust_box_chain(
        |server| trojan_outbound(server, Some(client_tls(&pki))),
        trojan_inbound(0, Some(server_tls(&pki))),
        true,
    )
    .await;
}

#[tokio::test]
async fn rust_box_trojan_plain() {
    rust_box_chain(|server| trojan_outbound(server, None), trojan_inbound(0, None), true).await;
}

#[tokio::test]
async fn rust_box_vless_every_packet_encoding() {
    for encoding in [None, Some("xudp"), Some("packetaddr"), Some("")] {
        rust_box_chain(|server| vless_outbound(server, "", encoding, None), vless_inbound(0, "", None), true).await;
    }
}

#[tokio::test]
async fn rust_box_vless_over_tls() {
    let pki = pki();
    rust_box_chain(
        |server| vless_outbound(server, "", None, Some(client_tls(&pki))),
        vless_inbound(0, "", Some(server_tls(&pki))),
        true,
    )
    .await;
}

#[tokio::test]
async fn rust_box_vless_vision() {
    let pki = pki();
    let (tls_target, echo, udp) = (tls_echo(&pki).await, tcp_echo().await, udp_echo().await);
    let (_server, servers) = start(&server_config(vless_inbound(0, VISION, Some(server_tls(&pki))))).await;
    let outbound = vless_outbound(servers[0], VISION, None, Some(client_tls(&pki)));
    let (_client, clients) = start(&client_config(0, outbound)).await;
    assert_tls_echo(clients[0], tls_target, &pki).await;
    // Not TLS inside: Vision pads, then stops padding, never goes direct.
    assert_tcp_echo(clients[0], echo).await;
    // UDP goes as XUDP through Vision.
    assert_udp_echo(clients[0], udp).await;
}

/// A connection straight to a trojan inbound that is not trojan: with a
/// fallback it reaches the fallback server (its bytes put back in front).
async fn assert_fallback(server: SocketAddr, pki: &Pki, alpn: &[&str], expected_banner: &[u8]) {
    let stream = TcpStream::connect(server).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
    let mut stream = tls_client(pki, alpn).connect(name, stream).await.unwrap();
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    stream.write_all(request).await.unwrap();
    let mut received = vec![0u8; expected_banner.len() + request.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut received)).await.unwrap().unwrap();
    assert_eq!(&received[..expected_banner.len()], expected_banner);
    assert_eq!(&received[expected_banner.len()..], request);
}

/// sing-box `fallbackConnection`: with `fallback_for_alpn` set, an ALPN
/// it has no entry for closes the connection (no default fallback).
async fn assert_fallback_closed(server: SocketAddr, pki: &Pki, alpn: &[&str]) {
    let stream = TcpStream::connect(server).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
    let mut stream = tls_client(pki, alpn).connect(name, stream).await.unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").await.unwrap();
    let mut received = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut received)).await.unwrap();
    assert!(received.is_empty(), "{received:?}");
}

fn fallback_inbound(port: u16, pki: &Pki, fallback: SocketAddr, h2: SocketAddr) -> Value {
    let mut tls = server_tls(pki);
    tls["alpn"] = json!(["h2", "http/1.1"]);
    let mut inbound = trojan_inbound(port, Some(tls));
    inbound["fallback"] = json!({"server": "127.0.0.1", "server_port": fallback.port()});
    inbound["fallback_for_alpn"] = json!({"h2": {"server": "127.0.0.1", "server_port": h2.port()}});
    inbound
}

#[tokio::test]
async fn rust_box_trojan_fallback() {
    let pki = pki();
    let (fallback, h2) = (banner_echo(b"default:").await, banner_echo(b"h2:").await);
    let (_server, servers) = start(&server_config(fallback_inbound(0, &pki, fallback, h2))).await;
    assert_fallback(servers[0], &pki, &[], b"default:").await;
    assert_fallback_closed(servers[0], &pki, &["http/1.1"]).await;
    assert_fallback(servers[0], &pki, &["h2"], b"h2:").await;
    // Trojan itself still works next to the fallback.
    let (_client, clients) = start(&client_config(0, trojan_outbound(servers[0], Some(client_tls(&pki))))).await;
    assert_tcp_echo(clients[0], tcp_echo().await).await;
}

#[tokio::test]
async fn wrong_credentials_carry_nothing() {
    let echo = tcp_echo().await;
    for (inbound, outbound) in [
        (trojan_inbound(0, None), json!({"type": "trojan", "password": "wrong"})),
        (vless_inbound(0, "", None), json!({"type": "vless", "uuid": "00000000-0000-0000-0000-000000000000"})),
        // A Vision user refuses a client without the flow.
        (vless_inbound(0, VISION, None), json!({"type": "vless", "uuid": UUID})),
    ] {
        let (_server, servers) = start(&server_config(inbound)).await;
        let mut outbound = outbound;
        outbound["tag"] = json!("proxy");
        outbound["server"] = json!("127.0.0.1");
        outbound["server_port"] = json!(servers[0].port());
        let (_client, clients) = start(&client_config(0, outbound)).await;
        let mut stream = socks5_connect(clients[0], echo).await;
        stream.write_all(b"ping").await.unwrap();
        let mut buffer = [0u8; 4];
        let result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await;
        assert!(matches!(result, Ok(Ok(0)) | Ok(Err(_)) | Err(_)), "nothing echoed: {result:?}");
    }
}

#[test]
fn build_errors() {
    let build = |config: Value| match rb_config::parse(&config.to_string()) {
        Ok(options) => RustBox::new(&options).err().map(|error| format!("{error:#}")).unwrap_or_default(),
        Err(error) => error.to_string(),
    };
    for (config, needle) in [
        (
            json!({"outbounds": [{"type": "vless", "uuid": UUID, "flow": "xtls-rprx-direct"}]}),
            "unsupported flow: xtls-rprx-direct",
        ),
        (
            json!({"outbounds": [{"type": "vless", "uuid": UUID, "packet_encoding": "raw"}]}),
            "unknown packet encoding: raw",
        ),
        (
            json!({"inbounds": [{"type": "trojan", "users": [{"password": "a"}, {"name": "b", "password": "a"}]}]}),
            "user already exists: password used by 0",
        ),
        (
            json!({"inbounds": [{"type": "trojan", "fallback_for_alpn": {"h2": {"server": "127.0.0.1"}}}]}),
            "fallback for ALPN is not supported without TLS",
        ),
        (json!({"inbounds": [{"type": "tuic"}]}), "inbounds[0].type: `tuic` is not supported by rust-box yet"),
        (
            json!({"inbounds": [{"type": "hysteria2"}]}),
            "inbounds[0].type: `hysteria2` is not supported by rust-box yet",
        ),
    ] {
        let error = build(config.clone());
        assert!(error.contains(needle), "{config}: {error}");
    }
    let http_config = json!({"inbounds": [{"type": "vless", "transport": {"type": "http"}}]});
    let error = build(http_config.clone());
    assert!(error.is_empty(), "{http_config}: {error}");
}

// ---- interop with the real sing-box ----

/// rust-box client → sing-box server (`inbound` on `port`).
async fn interop_to_sing_box(inbound: Value, port: u16, outbound: Value, udp: bool) {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    let Some(_sing_box) = sing_box(&server_config(inbound), port).await else { return };
    let (_client, clients) = start(&client_config(0, outbound)).await;
    assert_tcp_echo(clients[0], echo).await;
    if udp {
        assert_udp_echo(clients[0], udp_target).await;
    }
}

/// sing-box client (`outbound` to the rust-box server) → rust-box server.
async fn interop_from_sing_box(inbound: Value, outbound: impl FnOnce(SocketAddr) -> Value, udp: bool) {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    let (_server, servers) = start(&server_config(inbound)).await;
    let port = free_port();
    let Some(_sing_box) = sing_box(&client_config(port, outbound(servers[0])), port).await else { return };
    assert_tcp_echo(local(port), echo).await;
    if udp {
        assert_udp_echo(local(port), udp_target).await;
    }
}

#[tokio::test]
async fn interop_rust_box_trojan_to_sing_box() {
    let pki = pki();
    let port = free_port();
    let outbound = trojan_outbound(local(port), Some(client_tls(&pki)));
    interop_to_sing_box(trojan_inbound(port, Some(server_tls(&pki))), port, outbound, true).await;
}

#[tokio::test]
async fn interop_sing_box_trojan_to_rust_box() {
    let pki = pki();
    interop_from_sing_box(
        trojan_inbound(0, Some(server_tls(&pki))),
        |server| trojan_outbound(server, Some(client_tls(&pki))),
        true,
    )
    .await;
}

/// The same fallback probes against sing-box's trojan inbound: rust-box's
/// behaves the same (`rust_box_trojan_fallback`).
#[tokio::test]
async fn interop_sing_box_trojan_fallback_behaves_the_same() {
    let pki = pki();
    let (fallback, h2) = (banner_echo(b"default:").await, banner_echo(b"h2:").await);
    let port = free_port();
    let Some(_sing_box) = sing_box(&server_config(fallback_inbound(port, &pki, fallback, h2)), port).await else {
        return;
    };
    assert_fallback(local(port), &pki, &[], b"default:").await;
    assert_fallback_closed(local(port), &pki, &["http/1.1"]).await;
    assert_fallback(local(port), &pki, &["h2"], b"h2:").await;
}

#[tokio::test]
async fn interop_rust_box_vless_to_sing_box() {
    let pki = pki();
    for encoding in [None, Some("packetaddr")] {
        let port = free_port();
        let outbound = vless_outbound(local(port), "", encoding, Some(client_tls(&pki)));
        interop_to_sing_box(vless_inbound(port, "", Some(server_tls(&pki))), port, outbound, true).await;
    }
}

#[tokio::test]
async fn interop_sing_box_vless_to_rust_box() {
    let pki = pki();
    for encoding in [None, Some("packetaddr")] {
        interop_from_sing_box(
            vless_inbound(0, "", Some(server_tls(&pki))),
            |server| vless_outbound(server, "", encoding, Some(client_tls(&pki))),
            true,
        )
        .await;
    }
}

#[tokio::test]
async fn interop_rust_box_vless_vision_to_sing_box() {
    let pki = pki();
    let (tls_target, udp) = (tls_echo(&pki).await, udp_echo().await);
    let port = free_port();
    let Some(_sing_box) = sing_box(&server_config(vless_inbound(port, VISION, Some(server_tls(&pki)))), port).await
    else {
        return;
    };
    let outbound = vless_outbound(local(port), VISION, None, Some(client_tls(&pki)));
    let (_client, clients) = start(&client_config(0, outbound)).await;
    assert_tls_echo(clients[0], tls_target, &pki).await;
    assert_tcp_echo(clients[0], tcp_echo().await).await;
    assert_udp_echo(clients[0], udp).await;
}

#[tokio::test]
async fn interop_sing_box_vless_vision_to_rust_box() {
    let pki = pki();
    let (tls_target, udp) = (tls_echo(&pki).await, udp_echo().await);
    let (_server, servers) = start(&server_config(vless_inbound(0, VISION, Some(server_tls(&pki))))).await;
    let port = free_port();
    let outbound = vless_outbound(servers[0], VISION, None, Some(client_tls(&pki)));
    let Some(_sing_box) = sing_box(&client_config(port, outbound), port).await else { return };
    assert_tls_echo(local(port), tls_target, &pki).await;
    assert_tcp_echo(local(port), tcp_echo().await).await;
    assert_udp_echo(local(port), udp).await;
}

/// Exercises each V2Ray stream transport in both directions against the
/// pinned sing-box CLI. TCP is sufficient here: the transport wraps the
/// already-routed VLESS stream, independently of UDP packet encodings.
#[tokio::test]
async fn interop_vless_v2ray_transports_with_sing_box() {
    let pki = pki();
    for (name, transport) in [
        ("websocket", json!({"type": "ws", "path": "/ws"})),
        ("http2", json!({"type": "http", "host": ["example.test"], "path": "/"})),
        ("grpc", json!({"type": "grpc", "service_name": "vless-test"})),
        ("httpupgrade", json!({"type": "httpupgrade", "host": "example.test", "path": "/upgrade"})),
    ] {
        eprintln!("VLESS transport interop: {name}");

        let port = free_port();
        let mut inbound = vless_inbound(port, "", Some(server_tls(&pki)));
        inbound["transport"] = transport.clone();
        let mut outbound = vless_outbound(local(port), "", None, Some(client_tls(&pki)));
        outbound["transport"] = transport.clone();
        interop_to_sing_box(inbound, port, outbound, false).await;

        let mut inbound = vless_inbound(0, "", Some(server_tls(&pki)));
        inbound["transport"] = transport.clone();
        interop_from_sing_box(
            inbound,
            |server| {
                let mut outbound = vless_outbound(server, "", None, Some(client_tls(&pki)));
                outbound["transport"] = transport;
                outbound
            },
            false,
        )
        .await;
    }
}

/// rust-box TUIC/Hysteria2 client → sing-box QUIC server, TCP streams and UDP.
async fn interop_quic_to_sing_box(inbound: Value, port: u16, outbound: Value) {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    let Some(_sing_box) = sing_box_quic(&server_config(inbound), port).await else { return };
    let (_client, clients) = start(&client_config(0, outbound)).await;
    assert_tcp_echo(clients[0], echo).await;
    assert_udp_echo(clients[0], udp_target).await;
}

#[tokio::test]
async fn interop_rust_box_tuic_to_sing_box() {
    let pki = pki();
    let port = free_port();
    let inbound = json!({
        "type": "tuic", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
        "users": [{"name": "alice", "uuid": UUID, "password": "tuic-password"}],
        "congestion_control": "cubic",
        "tls": server_tls(&pki)
    });
    let outbound = json!({
        "type": "tuic", "tag": "proxy", "server": "127.0.0.1", "server_port": port,
        "uuid": UUID, "password": "tuic-password", "congestion_control": "cubic",
        "tls": client_tls(&pki)
    });
    interop_quic_to_sing_box(inbound, port, outbound).await;
}

#[tokio::test]
async fn interop_rust_box_hysteria2_to_sing_box() {
    let pki = pki();
    let port = free_port();
    // Both sides advertise bandwidth so sing-box selects Brutal; zero rates
    // select BBR-meta2, which Quinn does not implement and rust-box rejects.
    let inbound = json!({
        "type": "hysteria2", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
        "users": [{"name": "alice", "password": "hysteria2-password"}],
        "up_mbps": 10, "down_mbps": 10,
        "tls": server_tls(&pki)
    });
    let outbound = json!({
        "type": "hysteria2", "tag": "proxy", "server": "127.0.0.1", "server_port": port,
        "password": "hysteria2-password", "up_mbps": 10, "down_mbps": 10,
        "disable_chrome_parrot": true, "tls": client_tls(&pki)
    });
    interop_quic_to_sing_box(inbound, port, outbound).await;
}
