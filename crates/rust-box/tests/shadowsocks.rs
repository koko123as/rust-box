//! The `shadowsocks` outbound and inbound: rust-box against rust-box for
//! every method family (TCP and UDP, multiple users, UDP over TCP, the
//! 2022 relay), and against the real sing-box when `SING_BOX_BIN` points
//! at it (those cases print a note and pass without).
//!
//! Each case runs a client box (a mixed inbound the test drives with
//! SOCKS5, routed to the shadowsocks outbound) and a server box (the
//! shadowsocks inbound, routed to direct), with local TCP and UDP echo
//! servers.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rust_box::RustBox;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// `free_port` releases its probe sockets before the configured listener binds;
/// keep network scenarios from selecting the same port concurrently.
static NETWORK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const PSK16: &str = "AAECAwQFBgcICQoLDA0ODw==";
const UPSK16: &str = "EBESExQVFhcYGRobHB0eHw==";
const UPSK16_B: &str = "ICEiIyQlJicoKSorLC0uLw==";
const PSK32: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

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

/// A port free for both TCP and UDP (a shadowsocks inbound takes both).
fn free_port() -> u16 {
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
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

/// Echoes a short message and 200 KB (many chunks) through `proxy`.
async fn assert_tcp_echo(proxy: SocketAddr, echo: SocketAddr) {
    let mut stream = socks5_connect(proxy, echo).await;
    stream.write_all(b"hello through the chain").await.unwrap();
    let mut buffer = [0u8; 23];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer, b"hello through the chain");
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (mut reader, mut writer) = stream.into_split();
    let sent = big.clone();
    let write = tokio::spawn(async move {
        // Keep the write half open: dropping it half-closes the connection,
        // which sing-box answers by closing a non-duplex outbound whole.
        writer.write_all(&sent).await.unwrap();
        writer
    });
    let mut echoed = vec![0u8; big.len()];
    tokio::time::timeout(Duration::from_secs(20), reader.read_exact(&mut echoed)).await.unwrap().unwrap();
    let _writer = write.await.unwrap();
    assert!(echoed == big, "large echo differs");
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
    let relay = if relay.ip().is_unspecified() { SocketAddr::from(([127, 0, 0, 1], relay.port())) } else { relay };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut header = vec![0, 0, 0, 1];
    if let SocketAddr::V4(v4) = echo {
        header.extend_from_slice(&v4.ip().octets());
    }
    header.extend_from_slice(&echo.port().to_be_bytes());
    let mut buffer = [0u8; 4096];
    for (round, size) in [8usize, 1200].into_iter().enumerate() {
        let mut packet = header.clone();
        packet.extend((0..size).map(|i| (i + round) as u8));
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

fn ss_outbound(port: u16, method: &str, password: &str) -> Value {
    json!({"type": "shadowsocks", "tag": "proxy", "server": "127.0.0.1", "server_port": port,
           "method": method, "password": password})
}

fn ss_inbound(port: u16, method: &str, password: &str) -> Value {
    json!({"type": "shadowsocks", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
           "method": method, "password": password})
}

/// The 2022 multi-user inbound: users `a` (UPSK16) and `b` (UPSK16_B).
fn ss_multi_inbound(port: u16) -> Value {
    json!({"type": "shadowsocks", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
           "method": "2022-blake3-aes-128-gcm", "password": PSK16,
           "users": [{"name": "a", "password": UPSK16}, {"name": "b", "password": UPSK16_B}]})
}

/// rust-box client → rust-box server, TCP and UDP.
async fn rust_box_chain(outbound: Value, inbound: Value) {
    let (echo, udp) = (tcp_echo().await, udp_echo().await);
    let (_server, _) = start(&server_config(inbound)).await;
    let (_client, clients) = start(&client_config(0, outbound)).await;
    assert_tcp_echo(clients[0], echo).await;
    assert_udp_echo(clients[0], udp).await;
}

#[tokio::test]
async fn rust_box_to_rust_box_every_method() {
    let _guard = NETWORK_TEST_LOCK.lock().await;
    for (method, password) in [
        ("none", ""),
        ("aes-128-gcm", "secret"),
        ("aes-192-gcm", "secret"),
        ("aes-256-gcm", "secret"),
        ("chacha20-ietf-poly1305", "secret"),
        ("xchacha20-ietf-poly1305", "secret"),
        ("2022-blake3-aes-128-gcm", PSK16),
        ("2022-blake3-aes-256-gcm", PSK32),
        ("2022-blake3-chacha20-poly1305", PSK32),
    ] {
        eprintln!("method {method}");
        let port = free_port();
        rust_box_chain(ss_outbound(port, method, password), ss_inbound(port, method, password)).await;
    }
}

#[tokio::test]
async fn rust_box_to_rust_box_multi_user() {
    let _guard = NETWORK_TEST_LOCK.lock().await;
    let port = free_port();
    let outbound = ss_outbound(port, "2022-blake3-aes-128-gcm", &format!("{PSK16}:{UPSK16_B}"));
    rust_box_chain(outbound, ss_multi_inbound(port)).await;

    let port = free_port();
    let inbound = json!({"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port, "method": "aes-256-gcm",
                         "users": [{"name": "a", "password": "first"}, {"name": "b", "password": "second"}]});
    rust_box_chain(ss_outbound(port, "aes-256-gcm", "second"), inbound).await;
}

#[tokio::test]
async fn rust_box_to_rust_box_udp_over_tcp() {
    let _guard = NETWORK_TEST_LOCK.lock().await;
    for uot in [json!(true), json!({"enabled": true, "version": 1}), json!({"enabled": true, "version": 2})] {
        let port = free_port();
        let mut outbound = ss_outbound(port, "2022-blake3-aes-128-gcm", PSK16);
        outbound["udp_over_tcp"] = uot;
        // The server takes TCP only: UDP has to come over TCP.
        let mut inbound = ss_inbound(port, "2022-blake3-aes-128-gcm", PSK16);
        inbound["network"] = json!("tcp");
        rust_box_chain(outbound, inbound).await;
    }
}

/// client (iPSK:uPSK) → relay (destination: the server) → server (uPSK).
#[tokio::test]
async fn rust_box_relay() {
    let _guard = NETWORK_TEST_LOCK.lock().await;
    let (echo, udp) = (tcp_echo().await, udp_echo().await);
    let server_port = free_port();
    let (_server, _) = start(&server_config(ss_inbound(server_port, "2022-blake3-aes-128-gcm", UPSK16))).await;
    let relay_port = free_port();
    let relay = json!({"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": relay_port,
                       "method": "2022-blake3-aes-128-gcm", "password": PSK16,
                       "destinations": [{"name": "upstream", "server": "127.0.0.1", "server_port": server_port,
                                         "password": UPSK16}]});
    let (_relay, _) = start(&server_config(relay)).await;
    let outbound = ss_outbound(relay_port, "2022-blake3-aes-128-gcm", &format!("{PSK16}:{UPSK16}"));
    let (_client, clients) = start(&client_config(0, outbound)).await;
    assert_tcp_echo(clients[0], echo).await;
    assert_udp_echo(clients[0], udp).await;
}

#[tokio::test]
async fn wrong_password_carries_nothing() {
    let _guard = NETWORK_TEST_LOCK.lock().await;
    let echo = tcp_echo().await;
    let port = free_port();
    let (_server, _) = start(&server_config(ss_inbound(port, "aes-128-gcm", "right"))).await;
    let (_client, clients) = start(&client_config(0, ss_outbound(port, "aes-128-gcm", "wrong"))).await;
    let mut stream = socks5_connect(clients[0], echo).await;
    stream.write_all(b"ping").await.unwrap();
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await;
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_)) | Err(_)), "no echo with a wrong password");
}

#[test]
fn inbound_option_errors() {
    for (inbound, needle) in [
        (
            json!({"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": PSK16,
                   "users": [{"password": UPSK16}],
                   "destinations": [{"server": "127.0.0.1", "server_port": 1, "password": UPSK16}]}),
            "users and destinations options must not be combined",
        ),
        (
            json!({"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": PSK16, "managed": true,
                   "users": [{"password": UPSK16}]}),
            "users and destinations options are not supported in managed servers",
        ),
        (json!({"type": "shadowsocks", "method": "rc4-md5", "password": "x"}), "unsupported method: rc4-md5"),
        (json!({"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm"}), "missing psk"),
    ] {
        let options = rb_config::parse(&server_config(inbound).to_string()).unwrap();
        let error = RustBox::new(&options).err().unwrap().to_string();
        assert!(error.contains(needle), "{error}");
    }
    let outbound = json!({"type": "shadowsocks", "server": "127.0.0.1", "server_port": 1, "method": "rc4"});
    let options = rb_config::parse(&client_config(0, outbound).to_string()).unwrap();
    let error = RustBox::new(&options).err().unwrap().to_string();
    assert!(error.contains("outbounds[0]: unknown method: rc4"), "{error}");
}

// ---- interop with the real sing-box ----

/// The interop cases: the method, the client's password, the server inbound.
fn interop_cases(port: u16) -> Vec<(&'static str, String, Value)> {
    vec![
        ("aes-128-gcm", "secret".into(), ss_inbound(port, "aes-128-gcm", "secret")),
        ("chacha20-ietf-poly1305", "secret".into(), ss_inbound(port, "chacha20-ietf-poly1305", "secret")),
        ("2022-blake3-aes-128-gcm", PSK16.into(), ss_inbound(port, "2022-blake3-aes-128-gcm", PSK16)),
        ("2022-blake3-aes-128-gcm", format!("{PSK16}:{UPSK16_B}"), ss_multi_inbound(port)),
    ]
}

#[tokio::test]
async fn interop_rust_box_shadowsocks_outbound_to_sing_box_inbound() {
    let _guard = NETWORK_TEST_LOCK.lock().await;
    let (echo, udp) = (tcp_echo().await, udp_echo().await);
    for index in 0..interop_cases(0).len() {
        let port = free_port();
        let (method, password, inbound) = interop_cases(port).swap_remove(index);
        eprintln!("rust-box → sing-box: {method} {password}");
        let Some(_sing_box) = sing_box(&server_config(inbound), port).await else { return };
        let (_client, clients) = start(&client_config(0, ss_outbound(port, method, &password))).await;
        assert_tcp_echo(clients[0], echo).await;
        assert_udp_echo(clients[0], udp).await;
    }
}

#[tokio::test]
async fn interop_sing_box_shadowsocks_outbound_to_rust_box_inbound() {
    let _guard = NETWORK_TEST_LOCK.lock().await;
    let (echo, udp) = (tcp_echo().await, udp_echo().await);
    for index in 0..interop_cases(0).len() {
        let port = free_port();
        let (method, password, inbound) = interop_cases(port).swap_remove(index);
        eprintln!("sing-box → rust-box: {method} {password}");
        let (_server, _) = start(&server_config(inbound)).await;
        let client_port = free_port();
        let Some(_sing_box) =
            sing_box(&client_config(client_port, ss_outbound(port, method, &password)), client_port).await
        else {
            return;
        };
        let proxy = SocketAddr::from(([127, 0, 0, 1], client_port));
        assert_tcp_echo(proxy, echo).await;
        assert_udp_echo(proxy, udp).await;
    }
}

#[tokio::test]
async fn interop_udp_over_tcp_both_ways() {
    let _guard = NETWORK_TEST_LOCK.lock().await;
    let udp = udp_echo().await;
    // rust-box UoT client → sing-box server (TCP only).
    let port = free_port();
    let mut inbound = ss_inbound(port, "2022-blake3-aes-128-gcm", PSK16);
    inbound["network"] = json!("tcp");
    let Some(_sing_box) = sing_box(&server_config(inbound.clone()), port).await else { return };
    let mut outbound = ss_outbound(port, "2022-blake3-aes-128-gcm", PSK16);
    outbound["udp_over_tcp"] = json!(true);
    let (_client, clients) = start(&client_config(0, outbound.clone())).await;
    assert_udp_echo(clients[0], udp).await;

    // sing-box UoT client → rust-box server (TCP only).
    let port = free_port();
    inbound["listen_port"] = json!(port);
    let (_server, _) = start(&server_config(inbound)).await;
    outbound["server_port"] = json!(port);
    let client_port = free_port();
    let Some(_client_box) = sing_box(&client_config(client_port, outbound), client_port).await else { return };
    assert_udp_echo(SocketAddr::from(([127, 0, 0, 1], client_port)), udp).await;
}

/// sing-box client → rust-box relay → sing-box server, and rust-box
/// client → sing-box relay → rust-box server.
#[tokio::test]
async fn interop_relay() {
    let _guard = NETWORK_TEST_LOCK.lock().await;
    let (echo, udp) = (tcp_echo().await, udp_echo().await);
    let relay_inbound = |port: u16, upstream: u16| {
        json!({"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
               "method": "2022-blake3-aes-128-gcm", "password": PSK16,
               "destinations": [{"name": "upstream", "server": "127.0.0.1", "server_port": upstream,
                                 "password": UPSK16}]})
    };
    let client_outbound = |port: u16| ss_outbound(port, "2022-blake3-aes-128-gcm", &format!("{PSK16}:{UPSK16}"));

    let (server_port, relay_port, client_port) = (free_port(), free_port(), free_port());
    let Some(_server) =
        sing_box(&server_config(ss_inbound(server_port, "2022-blake3-aes-128-gcm", UPSK16)), server_port).await
    else {
        return;
    };
    let (_relay, _) = start(&server_config(relay_inbound(relay_port, server_port))).await;
    let Some(_client) = sing_box(&client_config(client_port, client_outbound(relay_port)), client_port).await else {
        return;
    };
    let proxy = SocketAddr::from(([127, 0, 0, 1], client_port));
    assert_tcp_echo(proxy, echo).await;
    assert_udp_echo(proxy, udp).await;

    let (server_port, relay_port) = (free_port(), free_port());
    let (_server2, _) = start(&server_config(ss_inbound(server_port, "2022-blake3-aes-128-gcm", UPSK16))).await;
    let Some(_relay2) = sing_box(&server_config(relay_inbound(relay_port, server_port)), relay_port).await else {
        return;
    };
    let (_client2, clients) = start(&client_config(0, client_outbound(relay_port))).await;
    assert_tcp_echo(clients[0], echo).await;
    assert_udp_echo(clients[0], udp).await;
}
