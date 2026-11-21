//! Helpers shared by the protocol tests: local echo servers, a rust-box
//! or sing-box (`SING_BOX_BIN`) instance from a JSON config, SOCKS5
//! checks, and a test CA with a certificate for `example.test`.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rust_box::RustBox;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";

pub async fn tcp_echo() -> SocketAddr {
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

pub async fn udp_echo() -> SocketAddr {
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

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub fn local(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Starts a rust-box with `config`; returns it and its inbounds' addresses.
pub async fn start(config: &Value) -> (RustBox, Vec<SocketAddr>) {
    let options = rb_config::parse(&config.to_string()).unwrap();
    let instance = RustBox::new(&options).unwrap();
    instance.start().await.unwrap();
    let addresses = instance.inbounds().iter().map(|inbound| inbound.local_addr().unwrap()).collect();
    (instance, addresses)
}

/// A sing-box process, killed on drop (with the directory of its config).
pub struct SingBox(Child, #[allow(dead_code)] tempfile::TempDir);

impl Drop for SingBox {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs the real sing-box with `config` and waits for `port` to accept;
/// `None` when `SING_BOX_BIN` is not set.
pub async fn sing_box(config: &Value, port: u16) -> Option<SingBox> {
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
pub async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
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
pub async fn assert_tcp_echo(proxy: SocketAddr, echo: SocketAddr) {
    let stream = socks5_connect(proxy, echo).await;
    let payload: Vec<u8> = (0..200_000u32).map(|index| (index % 253) as u8).collect();
    let (mut reader, mut writer) = stream.into_split();
    let data = payload.clone();
    let writing = tokio::spawn(async move { writer.write_all(&data).await.unwrap() });
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), reader.read_exact(&mut echoed)).await.unwrap().unwrap();
    writing.await.unwrap();
    assert!(echoed == payload, "TCP echo through {proxy}");
}

/// A SOCKS5 UDP ASSOCIATE through `proxy`, datagrams to `echo` and back.
pub async fn assert_udp_echo(proxy: SocketAddr, echo: SocketAddr) {
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
pub struct Pki {
    pub _directory: tempfile::TempDir,
    pub ca: String,
    pub ca_der: rustls::pki_types::CertificateDer<'static>,
    pub cert_der: rustls::pki_types::CertificateDer<'static>,
    pub key_der: Vec<u8>,
    pub cert_path: String,
    pub key_path: String,
}

pub fn pki() -> Pki {
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

pub fn ca_lines(pki: &Pki) -> Vec<String> {
    pki.ca.lines().map(str::to_string).collect()
}

/// A client config: a mixed inbound on `port` (0: any) routed to `outbound`.
pub fn client_config(port: u16, outbound: Value) -> Value {
    json!({
        "log": {"level": "warn"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound],
    })
}

/// A server config: `inbound` routed to direct.
pub fn server_config(inbound: Value) -> Value {
    json!({
        "log": {"level": "warn"},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    })
}

pub fn server_tls(pki: &Pki) -> Value {
    json!({"enabled": true, "certificate_path": pki.cert_path, "key_path": pki.key_path})
}

pub fn client_tls(pki: &Pki) -> Value {
    json!({"enabled": true, "server_name": "example.test", "certificate": ca_lines(pki)})
}
