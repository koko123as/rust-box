//! VLESS bytes against what the Go libraries sing-box uses produce
//! (`testdata/vless_vectors.json`, made by `testdata/generate`).

use rb_adapter::Socksaddr;
use rb_protocol::vless::packet::{encode_xudp_frame, write_packet_addr, PACKET_ADDR_MAGIC};
use rb_protocol::vless::protocol::{
    encode_packet_request, encode_request, parse_uuid, Request, COMMAND_MUX, COMMAND_TCP, FLOW_VISION,
};
use serde_json::Value;

const VECTORS: &str = include_str!("../testdata/vless_vectors.json");

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

#[test]
fn uuids_like_sing_vmess() {
    let vectors = vectors();
    for (text, expected) in vectors["uuid"].as_object().unwrap() {
        assert_eq!(parse_uuid(text).to_vec(), hex(expected.as_str().unwrap()), "{text:?}");
    }
}

#[test]
fn requests_like_sing_vmess() {
    let vectors = vectors();
    let requests = &vectors["request"];
    let uuid = parse_uuid("bf000d23-0752-40b4-affe-68f7707a9661");
    let tcp = Request {
        uuid,
        command: COMMAND_TCP,
        destination: Some(Socksaddr::from_host_port("example.com", 443)),
        flow: FLOW_VISION.into(),
    };
    assert_eq!(encode_request(&tcp).unwrap(), hex(requests["tcp_vision_domain"].as_str().unwrap()));
    let ipv6 = Request {
        uuid,
        command: COMMAND_TCP,
        destination: Some(Socksaddr::from_host_port("2001:db8::1", 80)),
        flow: String::new(),
    };
    let mut with_payload = encode_request(&ipv6).unwrap();
    with_payload.extend_from_slice(b"payload");
    assert_eq!(with_payload, hex(requests["tcp_ipv6_payload"].as_str().unwrap()));
    let mux = Request { uuid, command: COMMAND_MUX, destination: None, flow: FLOW_VISION.into() };
    assert_eq!(encode_request(&mux).unwrap(), hex(requests["mux_vision"].as_str().unwrap()));
    assert_eq!(
        encode_packet_request(&uuid, &Socksaddr::from_host_port("1.2.3.4", 53)).unwrap(),
        hex(requests["udp_ipv4"].as_str().unwrap())
    );
    let magic = Socksaddr::from_host_port(PACKET_ADDR_MAGIC, 0);
    let packet_request = encode_packet_request(&uuid, &magic).unwrap();
    assert_eq!(packet_request, hex(requests["udp_packetaddr"].as_str().unwrap()));

    // The packetaddr client's first write: the request, then one packet
    // with its address in front.
    let mut payload = Vec::new();
    write_packet_addr(&mut payload, &Socksaddr::from_host_port("1.1.1.1", 53)).unwrap();
    payload.extend_from_slice(b"query");
    let mut first = packet_request;
    first.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    first.extend_from_slice(&payload);
    assert_eq!(first, hex(vectors["packetaddr_client"].as_str().unwrap()));
}

#[test]
fn xudp_like_sing_vmess() {
    let vectors = vectors();
    let mut frames = encode_xudp_frame(true, b"first", &Socksaddr::from_host_port("8.8.8.8", 53)).unwrap();
    frames.extend_from_slice(
        &encode_xudp_frame(false, b"second", &Socksaddr::from_host_port("example.com", 5353)).unwrap(),
    );
    assert_eq!(frames, hex(vectors["xudp_client"].as_str().unwrap()));
}
