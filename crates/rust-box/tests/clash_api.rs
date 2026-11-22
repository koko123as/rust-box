//! The Clash API and cache file end to end: groups, the Clash mode,
//! connections and persistence across a restart, and (with
//! `SING_BOX_BIN`) the same requests answered by sing-box compared.
//!
//! These start listeners on fixed local ports picked at run time, so they
//! are `#[ignore]`d: run them with `cargo test -p rust-box --test clash_api
//! -- --ignored`.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SECRET: &str = "m9-secret";

/// One request; the status and the body (as JSON when it parses).
async fn request(api: SocketAddr, method: &str, path: &str, body: Option<&Value>, auth: bool) -> (u16, Value) {
    let mut stream = TcpStream::connect(api).await.unwrap();
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {api}\r\nConnection: close\r\n");
    if auth {
        head.push_str(&format!("Authorization: Bearer {SECRET}\r\n"));
    }
    if !body.is_empty() {
        head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut response)).await.unwrap().unwrap();
    let text = String::from_utf8_lossy(&response).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut decoded = String::new();
        let mut rest = body;
        while let Some((size, tail)) = rest.split_once("\r\n") {
            let size = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            decoded.push_str(&tail[..size]);
            rest = &tail[size + 2..];
        }
        decoded
    } else {
        body.to_string()
    };
    (status, serde_json::from_str(body.trim()).unwrap_or(Value::String(body)))
}

fn config(api_port: u16, mixed_port: u16, cache: &std::path::Path) -> Value {
    json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": mixed_port}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto", "direct", "block"], "default": "direct"},
            {"type": "urltest", "tag": "auto", "outbounds": ["direct"], "url": "http://127.0.0.1:9/"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [
                {"clash_mode": "Direct", "outbound": "direct"},
                {"clash_mode": "Global", "outbound": "proxy"}
            ],
            "final": "proxy"
        },
        "experimental": {
            "cache_file": {"enabled": true, "path": cache.to_str().unwrap()},
            "clash_api": {"external_controller": format!("127.0.0.1:{api_port}"), "secret": SECRET}
        }
    })
}

/// Drops what differs between runs (times, delays, memory, ids).
fn normalize(mut value: Value) -> Value {
    match &mut value {
        Value::Object(map) => {
            for key in ["history", "memory", "start", "id", "uploadTotal", "downloadTotal", "version"] {
                if map.contains_key(key) {
                    map.insert(key.into(), Value::Null);
                }
            }
            for (_, item) in map.iter_mut() {
                *item = normalize(item.take());
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                *item = normalize(item.take());
            }
        }
        _ => {}
    }
    value
}

/// The requests both implementations answer, in order, with their results.
async fn exercise(api: SocketAddr) -> Vec<(String, u16, Value)> {
    let steps: Vec<(&str, &str, Option<Value>, bool)> = vec![
        ("GET", "/", None, false),
        ("GET", "/", None, true),
        ("GET", "/version", None, true),
        ("GET", "/configs", None, true),
        ("GET", "/proxies", None, true),
        ("GET", "/proxies/proxy", None, true),
        ("GET", "/proxies/missing", None, true),
        ("PUT", "/proxies/auto", Some(json!({"name": "direct"})), true),
        ("PUT", "/proxies/proxy", Some(json!({"name": "missing"})), true),
        ("PUT", "/proxies/proxy", Some(json!({"name": "block"})), true),
        ("GET", "/proxies/proxy", None, true),
        ("PATCH", "/configs", Some(json!({"mode": "global"})), true),
        ("PATCH", "/configs", Some(json!({"mode": "unknown"})), true),
        ("GET", "/configs", None, true),
        ("GET", "/proxies/direct/delay?timeout=abc", None, true),
        ("GET", "/group", None, true),
        ("GET", "/group/direct", None, true),
        ("GET", "/providers/proxies", None, true),
        ("GET", "/providers/rules", None, true),
        ("GET", "/providers/proxies/x", None, true),
        ("POST", "/script", None, true),
        ("PATCH", "/script", None, true),
        ("GET", "/profile/tracing", None, true),
        ("POST", "/cache/dns/flush", None, true),
        ("POST", "/cache/fakeip/flush", None, true),
        ("GET", "/dns/query?name=localhost&type=BAD", None, true),
        ("GET", "/connections", None, true),
        ("DELETE", "/connections", None, true),
        ("DELETE", "/connections/00000000-0000-0000-0000-000000000000", None, true),
        ("POST", "/upgrade/ui", None, true),
    ];
    let mut results = Vec::new();
    for (method, path, body, auth) in steps {
        let (status, value) = request(api, method, path, body.as_ref(), auth).await;
        results.push((format!("{method} {path} auth={auth}"), status, normalize(value)));
    }
    results
}

#[tokio::test]
#[ignore = "starts listeners; run with --ignored"]
async fn clash_api_and_cache_file() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("cache.db");
    let api_port = common::free_port();
    let mixed_port = common::free_port();
    let api = common::local(api_port);
    let options = config(api_port, mixed_port, &cache);
    let (instance, _) = common::start(&options).await;

    let (status, body) = request(api, "GET", "/", None, false).await;
    assert_eq!((status, body), (401, json!({"message": "Unauthorized"})));
    let (_, configs) = request(api, "GET", "/configs", None, true).await;
    assert_eq!(configs["mode"], "Rule");
    assert_eq!(configs["mode-list"], json!(["Rule", "Global", "Direct"]));
    let (_, proxies) = request(api, "GET", "/proxies", None, true).await;
    assert_eq!(proxies["proxies"]["GLOBAL"]["all"], json!(["proxy", "auto"]));
    assert_eq!(proxies["proxies"]["proxy"]["now"], "direct");
    assert_eq!(proxies["proxies"]["block"]["type"], "Reject");
    assert_eq!(proxies["proxies"]["auto"]["type"], "URLTest");

    // A connection through the selector shows up with its chain.
    let echo = common::tcp_echo().await;
    let mut stream = common::socks5_connect(common::local(mixed_port), echo).await;
    stream.write_all(b"hello").await.unwrap();
    let mut echoed = [0u8; 5];
    stream.read_exact(&mut echoed).await.unwrap();
    let (_, connections) = request(api, "GET", "/connections", None, true).await;
    let listed = connections["connections"].as_array().unwrap();
    assert_eq!(listed.len(), 1, "{connections}");
    assert_eq!(listed[0]["chains"], json!(["direct", "proxy"]));
    assert_eq!(listed[0]["rule"], "final");
    assert_eq!(listed[0]["metadata"]["type"], "mixed/in");
    assert_eq!(listed[0]["upload"], 5);
    assert_eq!(listed[0]["download"], 5);

    // Closing it through the API ends the proxied connection.
    let (status, _) = request(api, "DELETE", "/connections", None, true).await;
    assert_eq!(status, 204);
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    assert!(closed.is_ok(), "connection still open after DELETE /connections");

    // Selection and mode are kept in the cache file.
    let (status, _) = request(api, "PUT", "/proxies/proxy", Some(&json!({"name": "auto"})), true).await;
    assert_eq!(status, 204);
    let (status, _) = request(api, "PATCH", "/configs", Some(&json!({"mode": "direct"})), true).await;
    assert_eq!(status, 204);
    instance.close().await;
    drop(instance);
    // Aborted accept loops drop their listeners when the runtime next polls them.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (instance, _) = common::start(&options).await;
    let (_, configs) = request(api, "GET", "/configs", None, true).await;
    assert_eq!(configs["mode"], "Direct");
    let (_, proxy) = request(api, "GET", "/proxies/proxy", None, true).await;
    assert_eq!(proxy["now"], "auto");
    instance.close().await;
}

#[tokio::test]
#[ignore = "needs SING_BOX_BIN; run with --ignored"]
async fn clash_api_matches_sing_box() {
    let directory = tempfile::tempdir().unwrap();
    let api_port = common::free_port();
    let mixed_port = common::free_port();
    let sing_box_config = config(api_port, mixed_port, &directory.path().join("sing-box.db"));
    let Some(sing_box) = common::sing_box(&sing_box_config, api_port).await else { return };
    let expected = exercise(common::local(api_port)).await;
    drop(sing_box);

    let api_port = common::free_port();
    let mixed_port = common::free_port();
    let (instance, _) = common::start(&config(api_port, mixed_port, &directory.path().join("rust-box.db"))).await;
    let actual = exercise(common::local(api_port)).await;
    instance.close().await;
    for (expected, actual) in expected.iter().zip(&actual) {
        assert_eq!(expected, actual, "{}", expected.0);
    }
}
