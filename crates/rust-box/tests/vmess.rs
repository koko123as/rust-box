//! The `vmess` outbound and inbound: rust-box against rust-box (every
//! security, the legacy alterId header, each packet encoding, TLS), and
//! against the real sing-box when `SING_BOX_BIN` points at it (those cases
//! print a note and pass without).

mod common;

use std::net::SocketAddr;

use common::*;
use serde_json::{json, Value};

fn vmess_inbound(port: u16, alter_id: i64, tls: Option<Value>) -> Value {
    let mut inbound = json!({"type": "vmess", "tag": "server", "listen": "127.0.0.1", "listen_port": port,
                             "users": [{"name": "carol", "uuid": UUID, "alterId": alter_id}]});
    if let Some(tls) = tls {
        inbound["tls"] = tls;
    }
    inbound
}

struct Client<'a> {
    security: &'a str,
    alter_id: i64,
    global_padding: bool,
    authenticated_length: bool,
    packet_encoding: &'a str,
}

const PLAIN: Client<'static> =
    Client { security: "", alter_id: 0, global_padding: false, authenticated_length: false, packet_encoding: "" };

fn vmess_outbound(server: SocketAddr, client: &Client, tls: Option<Value>) -> Value {
    let mut outbound = json!({"type": "vmess", "tag": "proxy", "server": "127.0.0.1", "server_port": server.port(),
                              "uuid": UUID, "security": client.security, "alter_id": client.alter_id,
                              "global_padding": client.global_padding,
                              "authenticated_length": client.authenticated_length,
                              "packet_encoding": client.packet_encoding});
    if let Some(tls) = tls {
        outbound["tls"] = tls;
    }
    outbound
}

/// rust-box client → rust-box server, TCP and UDP.
async fn rust_box_chain(outbound: impl FnOnce(SocketAddr) -> Value, inbound: Value) {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    let (_server, servers) = start(&server_config(inbound)).await;
    let (_client, clients) = start(&client_config(0, outbound(servers[0]))).await;
    assert_tcp_echo(clients[0], echo).await;
    assert_udp_echo(clients[0], udp_target).await;
}

#[tokio::test]
async fn rust_box_vmess_every_security() {
    for security in ["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb"] {
        for (global_padding, authenticated_length) in [(false, false), (true, true)] {
            let client = Client { security, global_padding, authenticated_length, ..PLAIN };
            rust_box_chain(|server| vmess_outbound(server, &client, None), vmess_inbound(0, 0, None)).await;
        }
    }
}

#[tokio::test]
async fn rust_box_vmess_legacy_header() {
    for security in ["aes-128-gcm", "aes-128-cfb", "none"] {
        let client = Client { security, alter_id: 1, ..PLAIN };
        rust_box_chain(|server| vmess_outbound(server, &client, None), vmess_inbound(0, 4, None)).await;
    }
}

#[tokio::test]
async fn rust_box_vmess_every_packet_encoding() {
    for packet_encoding in ["", "xudp", "packetaddr"] {
        let client = Client { packet_encoding, ..PLAIN };
        rust_box_chain(|server| vmess_outbound(server, &client, None), vmess_inbound(0, 0, None)).await;
    }
}

#[tokio::test]
async fn rust_box_vmess_over_tls() {
    let pki = pki();
    rust_box_chain(
        |server| vmess_outbound(server, &PLAIN, Some(client_tls(&pki))),
        vmess_inbound(0, 0, Some(server_tls(&pki))),
    )
    .await;
}

#[test]
fn build_errors() {
    for (config, expected) in [
        (
            json!({"outbounds": [{"type": "vmess", "server": "127.0.0.1", "server_port": 1, "uuid": UUID,
                                  "security": "rc4"}]}),
            "outbounds[0]: vmess: unsupported security type: rc4",
        ),
        (
            json!({"outbounds": [{"type": "vmess", "server": "127.0.0.1", "server_port": 1, "uuid": UUID,
                                  "packet_encoding": "x"}]}),
            "outbounds[0]: unknown packet encoding: x",
        ),
    ] {
        let options = rb_config::parse(&config.to_string()).unwrap();
        let error = rust_box::RustBox::new(&options).err().unwrap().to_string();
        assert_eq!(error, expected);
    }
}

// ---- interop with the real sing-box ----

/// rust-box client → sing-box server (`inbound` on `port`).
async fn interop_to_sing_box(inbound: Value, port: u16, outbound: Value) {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    let Some(_sing_box) = sing_box(&server_config(inbound), port).await else { return };
    let (_client, clients) = start(&client_config(0, outbound)).await;
    assert_tcp_echo(clients[0], echo).await;
    assert_udp_echo(clients[0], udp_target).await;
}

/// sing-box client (`outbound` to the rust-box server) → rust-box server.
async fn interop_from_sing_box(inbound: Value, outbound: impl FnOnce(SocketAddr) -> Value) {
    let (echo, udp_target) = (tcp_echo().await, udp_echo().await);
    let (_server, servers) = start(&server_config(inbound)).await;
    let port = free_port();
    let Some(_sing_box) = sing_box(&client_config(port, outbound(servers[0])), port).await else { return };
    assert_tcp_echo(local(port), echo).await;
    assert_udp_echo(local(port), udp_target).await;
}

/// The client settings the interop cases try.
fn interop_clients() -> Vec<Client<'static>> {
    let mut clients = Vec::new();
    for security in ["auto", "none", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb"] {
        clients.push(Client { security, ..PLAIN });
    }
    clients.push(Client { security: "aes-128-gcm", global_padding: true, authenticated_length: true, ..PLAIN });
    clients.push(Client { security: "chacha20-poly1305", global_padding: true, ..PLAIN });
    clients.push(Client { security: "none", authenticated_length: true, ..PLAIN });
    clients.push(Client { security: "aes-128-gcm", alter_id: 1, ..PLAIN });
    clients.push(Client { security: "aes-128-cfb", alter_id: 1, global_padding: true, ..PLAIN });
    clients.push(Client { packet_encoding: "xudp", ..PLAIN });
    clients.push(Client { packet_encoding: "packetaddr", ..PLAIN });
    clients
}

#[tokio::test]
async fn interop_rust_box_vmess_to_sing_box() {
    for client in interop_clients() {
        let port = free_port();
        let outbound = vmess_outbound(local(port), &client, None);
        interop_to_sing_box(vmess_inbound(port, 4, None), port, outbound).await;
    }
}

#[tokio::test]
async fn interop_sing_box_vmess_to_rust_box() {
    for client in interop_clients() {
        interop_from_sing_box(vmess_inbound(0, 4, None), |server| vmess_outbound(server, &client, None)).await;
    }
}

#[tokio::test]
async fn interop_vmess_over_tls() {
    let pki = pki();
    let port = free_port();
    let outbound = vmess_outbound(local(port), &PLAIN, Some(client_tls(&pki)));
    interop_to_sing_box(vmess_inbound(port, 0, Some(server_tls(&pki))), port, outbound).await;
    interop_from_sing_box(vmess_inbound(0, 0, Some(server_tls(&pki))), |server| {
        vmess_outbound(server, &PLAIN, Some(client_tls(&pki)))
    })
    .await;
}
