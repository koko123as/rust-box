//! `multiplex` (sing-mux) on the shadowsocks, trojan, vless and vmess
//! outbounds and inbounds: rust-box against rust-box with each protocol
//! (smux, yamux, h2mux) and padding, trojan-go multiplex on the trojan
//! inbound, and against the real sing-box when `SING_BOX_BIN` points at it
//! (those cases print a note and pass without).

mod common;

use std::net::SocketAddr;

use common::*;
use rb_adapter::Socksaddr;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn multiplex(protocol: &str, padding: bool) -> Value {
    json!({"enabled": true, "protocol": protocol, "padding": padding})
}

/// The server and client sides of each proxy protocol, with `multiplex`.
fn pair(kind: &str, port: u16, server: SocketAddr, inbound_mux: Value, outbound_mux: Value) -> (Value, Value) {
    let (mut inbound, mut outbound) = match kind {
        "shadowsocks" => (
            json!({"type": "shadowsocks", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
                   "method": "aes-128-gcm", "password": "mux-password"}),
            json!({"type": "shadowsocks", "tag": "proxy", "server": "127.0.0.1", "server_port": server.port(),
                   "method": "aes-128-gcm", "password": "mux-password"}),
        ),
        "trojan" => (
            json!({"type": "trojan", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
                   "users": [{"password": "mux-password"}]}),
            json!({"type": "trojan", "tag": "proxy", "server": "127.0.0.1", "server_port": server.port(),
                   "password": "mux-password"}),
        ),
        "vless" => (
            json!({"type": "vless", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
                   "users": [{"uuid": UUID}]}),
            json!({"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": server.port(),
                   "uuid": UUID}),
        ),
        _ => (
            json!({"type": "vmess", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
                   "users": [{"uuid": UUID}]}),
            json!({"type": "vmess", "tag": "proxy", "server": "127.0.0.1", "server_port": server.port(),
                   "uuid": UUID}),
        ),
    };
    inbound["multiplex"] = inbound_mux;
    outbound["multiplex"] = outbound_mux;
    (inbound, outbound)
}

#[tokio::test]
async fn rust_box_every_protocol_and_multiplexer() {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    for kind in ["shadowsocks", "trojan", "vless", "vmess"] {
        for (protocol, padding) in [("smux", false), ("yamux", true), ("h2mux", false), ("", true)] {
            let (inbound, _) = pair(kind, 0, local(0), json!({"enabled": true, "padding": padding}), json!(null));
            let (_server, servers) = start(&server_config(inbound)).await;
            let (_, outbound) = pair(kind, 0, servers[0], json!(null), multiplex(protocol, padding));
            let (_client, clients) = start(&client_config(0, outbound)).await;
            assert_tcp_echo(clients[0], echo).await;
            assert_tcp_echo(clients[0], echo).await;
            assert_udp_echo(clients[0], udp_target).await;
        }
    }
}

#[tokio::test]
async fn padded_server_refuses_plain_client() {
    let echo = tcp_echo().await;
    let (inbound, _) = pair("vmess", 0, local(0), json!({"enabled": true, "padding": true}), json!(null));
    let (_server, servers) = start(&server_config(inbound)).await;
    let (_, outbound) = pair("vmess", 0, servers[0], json!(null), multiplex("smux", false));
    let (_client, clients) = start(&client_config(0, outbound)).await;
    let mut stream = socks5_connect(clients[0], echo).await;
    stream.write_all(b"hello").await.unwrap();
    let mut buffer = [0u8; 5];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buffer)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
}

/// A trojan-go client: smux over the trojan request with command 0x7f.
#[tokio::test]
async fn trojan_go_multiplex() {
    let echo = tcp_echo().await;
    let (inbound, _) = pair("trojan", 0, local(0), json!(null), json!(null));
    let (_server, servers) = start(&server_config(inbound)).await;
    let mut conn = TcpStream::connect(servers[0]).await.unwrap();
    let key = rb_protocol::trojan::key("mux-password");
    let request =
        rb_protocol::trojan::encode_request(&key, 0x7f, &Socksaddr::from_host_port("0.0.0.0", 0), &[]).unwrap();
    conn.write_all(&request).await.unwrap();
    let session = rb_mux::session::Session::smux(Box::new(conn), true);
    for round in 0..3u8 {
        let mut stream = session.open().await.unwrap();
        let mut header = vec![1u8];
        rb_shadowsocks_address(&mut header, echo);
        header.extend_from_slice(&[round; 1000]);
        stream.write_all(&header).await.unwrap();
        let mut echoed = [0u8; 1000];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, [round; 1000]);
    }
}

fn rb_shadowsocks_address(buffer: &mut Vec<u8>, address: SocketAddr) {
    let SocketAddr::V4(v4) = address else { panic!() };
    buffer.push(1);
    buffer.extend_from_slice(&v4.ip().octets());
    buffer.extend_from_slice(&v4.port().to_be_bytes());
}

#[test]
fn build_errors() {
    let options = rb_config::parse(
        &json!({"outbounds": [{"type": "vless", "server": "127.0.0.1", "server_port": 1, "uuid": UUID,
                               "multiplex": {"enabled": true, "protocol": "mplex"}}]})
        .to_string(),
    )
    .unwrap();
    let error = rust_box::RustBox::new(&options).err().unwrap().to_string();
    assert_eq!(error, "outbounds[0]: unknown protocol: mplex");
}

// ---- interop with the real sing-box ----

#[tokio::test]
async fn interop_rust_box_client_to_sing_box_server() {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    for kind in ["shadowsocks", "trojan", "vless", "vmess"] {
        for (protocol, padding) in [("smux", false), ("yamux", false), ("h2mux", true)] {
            let port = free_port();
            let (inbound, outbound) = pair(
                kind,
                port,
                local(port),
                json!({"enabled": true, "padding": padding}),
                multiplex(protocol, padding),
            );
            let Some(_sing_box) = sing_box(&server_config(inbound), port).await else { return };
            let (_client, clients) = start(&client_config(0, outbound)).await;
            assert_tcp_echo(clients[0], echo).await;
            assert_udp_echo(clients[0], udp_target).await;
        }
    }
}

#[tokio::test]
async fn interop_sing_box_client_to_rust_box_server() {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    for kind in ["shadowsocks", "trojan", "vless", "vmess"] {
        for (protocol, padding) in [("smux", true), ("yamux", false), ("h2mux", false)] {
            let (inbound, _) = pair(kind, 0, local(0), json!({"enabled": true, "padding": padding}), json!(null));
            let (_server, servers) = start(&server_config(inbound)).await;
            let port = free_port();
            let (_, outbound) = pair(kind, 0, servers[0], json!(null), multiplex(protocol, padding));
            let Some(_sing_box) = sing_box(&client_config(port, outbound), port).await else { return };
            assert_tcp_echo(local(port), echo).await;
            assert_udp_echo(local(port), udp_target).await;
        }
    }
}
