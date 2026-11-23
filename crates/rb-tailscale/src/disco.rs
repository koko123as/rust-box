//! Pure-Rust codecs for Tailscale disco plaintext messages and encrypted envelopes.
//!
//! The pinned Tailscale fork supports more disco types than this module. The
//! UDP relay codecs for types 0x04 through 0x09 are implemented. The module does
//! not implement peer/key lookup, optional Geneve transport wrapping, or endpoint discovery.

use std::{
    fmt,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use crate::NodePublic;

/// The six-byte Tailscale disco packet magic (`TS💬`).
pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];
/// Length of the magic and sender-key prefix, where magicsock starts the sealed box.
pub const DISCO_HEADER_LEN: usize = 6 + 32;
/// Minimum outer wrapper length: magic, sender disco public key, and nonce.
pub const OUTER_HEADER_LEN: usize = DISCO_HEADER_LEN + 24;

const PING: u8 = 0x01;
const PONG: u8 = 0x02;
const CALL_ME_MAYBE: u8 = 0x03;
const BIND_UDP_RELAY_ENDPOINT: u8 = 0x04;
const BIND_UDP_RELAY_ENDPOINT_CHALLENGE: u8 = 0x05;
const BIND_UDP_RELAY_ENDPOINT_ANSWER: u8 = 0x06;
const CALL_ME_MAYBE_VIA: u8 = 0x07;
const ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST: u8 = 0x08;
const ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE: u8 = 0x09;

const UDP_RELAY_ENDPOINT_FIXED_LEN: usize = 3 * 32 + 8 + 4 + 8 + 8;
const UDP_RELAY_ENDPOINT_ADDRPORT_LEN: usize = 18;

/// Fields common to the three fixed-size UDP relay binding handshake messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindUdpRelayEndpointCommon {
    pub vni: u32,
    pub generation: u32,
    pub remote_key: crate::DiscoPublic,
    pub challenge: [u8; 32],
}

/// Endpoint details carried by CallMeMaybeVia and relay-allocation responses.
///
/// Durations are represented as signed nanoseconds, matching Go's `time.Duration`
/// bit pattern on the wire. A zero-value endpoint also represents the pinned
/// Go parser's empty result for a nonzero message version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpRelayEndpoint {
    pub server_disco: crate::DiscoPublic,
    pub client_disco: [crate::DiscoPublic; 2],
    pub lamport_id: u64,
    pub vni: u32,
    pub bind_lifetime_nanos: i64,
    pub steady_state_lifetime_nanos: i64,
    pub addr_ports: Vec<SocketAddr>,
}

impl Default for UdpRelayEndpoint {
    fn default() -> Self {
        Self {
            server_disco: crate::DiscoPublic::from_raw32([0; 32]),
            client_disco: [crate::DiscoPublic::from_raw32([0; 32]); 2],
            lamport_id: 0,
            vni: 0,
            bind_lifetime_nanos: 0,
            steady_state_lifetime_nanos: 0,
            addr_ports: Vec::new(),
        }
    }
}

/// Request to allocate a UDP relay endpoint for two disco clients.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocateUdpRelayEndpointRequest {
    pub client_disco: [crate::DiscoPublic; 2],
    pub generation: u32,
}

impl Default for AllocateUdpRelayEndpointRequest {
    fn default() -> Self {
        Self { client_disco: [crate::DiscoPublic::from_raw32([0; 32]); 2], generation: 0 }
    }
}

/// Semantic representation of the disco plaintext message types implemented here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Ping { tx_id: [u8; 12], node_key: NodePublic, padding: usize },
    Pong { tx_id: [u8; 12], source: SocketAddr },
    CallMeMaybe { endpoints: Vec<SocketAddr> },
    BindUdpRelayEndpoint(BindUdpRelayEndpointCommon),
    BindUdpRelayEndpointChallenge(BindUdpRelayEndpointCommon),
    BindUdpRelayEndpointAnswer(BindUdpRelayEndpointCommon),
    CallMeMaybeVia(UdpRelayEndpoint),
    AllocateUdpRelayEndpointRequest(AllocateUdpRelayEndpointRequest),
    AllocateUdpRelayEndpointResponse { generation: u32, endpoint: UdpRelayEndpoint },
}

/// A malformed or not-yet-implemented disco plaintext message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Fewer bytes than required by the message's fixed fields.
    Short,
    /// A known Tailscale disco type for which this crate has no codec yet.
    UnsupportedType(u8),
    /// A type value not assigned by the pinned Tailscale fork.
    UnknownType(u8),
    /// Checked size arithmetic or a fallible allocation failed.
    Resource,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short => f.write_str("short disco message"),
            Self::UnsupportedType(kind) => write!(f, "unsupported disco message type 0x{kind:02x}"),
            Self::UnknownType(kind) => write!(f, "unknown disco message type 0x{kind:02x}"),
            Self::Resource => f.write_str("disco message size or allocation failure"),
        }
    }
}

impl std::error::Error for Error {}

/// An error while sealing or opening a complete encrypted disco packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketError {
    /// The input does not have the 38-byte magicsock disco prefix and exact magic.
    NotDiscoPacket,
    /// NaCl-compatible box sealing/opening failed.
    Crypto(crate::disco_crypto::Error),
    /// Authenticated plaintext could not be parsed as a supported disco message.
    Plaintext(Error),
    /// Checked output sizing or a fallible allocation failed.
    Resource,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDiscoPacket => f.write_str("not a magicsock disco packet"),
            Self::Crypto(error) => error.fmt(f),
            Self::Plaintext(error) => error.fmt(f),
            Self::Resource => f.write_str("disco packet size or allocation failure"),
        }
    }
}

impl std::error::Error for PacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Plaintext(error) => Some(error),
            Self::NotDiscoPacket | Self::Resource => None,
        }
    }
}

/// Returns true only when `packet` has the complete 62-byte outer header and
/// the exact magic, matching the pinned fork's `LooksLikeDiscoWrapper`.
pub fn looks_like_wrapper(packet: &[u8]) -> bool {
    packet.len() >= OUTER_HEADER_LEN && packet.starts_with(&MAGIC)
}

/// Returns the sender's 32-byte disco public key only for a valid outer wrapper.
pub fn source(packet: &[u8]) -> Option<&[u8]> {
    looks_like_wrapper(packet).then(|| &packet[MAGIC.len()..DISCO_HEADER_LEN])
}

/// Matches magicsock's lower-level packet classifier: 38-byte magic + sender key.
/// This is intentionally less strict than [`looks_like_wrapper`], which mirrors
/// the exported `disco.LooksLikeDiscoWrapper` helper and requires a nonce too.
pub fn packet_looks_like_disco(packet: &[u8]) -> bool {
    packet.len() >= DISCO_HEADER_LEN && packet.starts_with(&MAGIC)
}

/// Seals and wraps a plaintext message as `magic || sender key || NaCl box`.
///
/// This returns only the disco packet. The optional 8-byte Geneve header used by
/// some magicsock relay paths is a separate transport layer. The caller must
/// provide the sender identity and matching precomputed shared key consistently.
pub fn seal_packet(
    sender: &crate::DiscoPublic,
    shared: &crate::disco_crypto::DiscoShared,
    message: &Message,
) -> Result<Vec<u8>, PacketError> {
    let plaintext = encode(message).map_err(PacketError::Plaintext)?;
    let sealed = shared.seal(&plaintext).map_err(PacketError::Crypto)?;
    wrap_sealed(sender, &sealed)
}

/// Opens a magicsock disco packet and parses its authenticated plaintext.
///
/// As in the pinned fork, callers select `shared` using trusted peer/relay state;
/// the sender key in the packet is not independently authenticated or looked up
/// here. A 38–61 byte disco-looking packet proceeds to `DiscoShared::open` and
/// fails there as a short sealed box, matching magicsock's receive sequence.
pub fn open_packet(
    shared: &crate::disco_crypto::DiscoShared,
    packet: &[u8],
) -> Result<(crate::DiscoPublic, Message), PacketError> {
    if !packet_looks_like_disco(packet) {
        return Err(PacketError::NotDiscoPacket);
    }

    let mut sender_bytes = [0; 32];
    sender_bytes.copy_from_slice(&packet[MAGIC.len()..DISCO_HEADER_LEN]);
    let sender = crate::DiscoPublic::from_raw32(sender_bytes);
    let plaintext = shared.open(&packet[DISCO_HEADER_LEN..]).map_err(PacketError::Crypto)?;
    let message = parse(&plaintext).map_err(PacketError::Plaintext)?;
    Ok((sender, message))
}

fn wrap_sealed(sender: &crate::DiscoPublic, sealed: &[u8]) -> Result<Vec<u8>, PacketError> {
    let total_len = DISCO_HEADER_LEN.checked_add(sealed.len()).ok_or(PacketError::Resource)?;
    let mut packet = Vec::new();
    packet.try_reserve_exact(total_len).map_err(|_| PacketError::Resource)?;
    packet.extend_from_slice(&MAGIC);
    packet.extend_from_slice(&sender.raw_bytes());
    packet.extend_from_slice(sealed);
    Ok(packet)
}

/// Parses plaintext inside an authenticated NaCl box.
///
/// Version bytes for Ping, Pong, and UDP relay bind messages are ignored by the
/// pinned fork. CallMeMaybe returns an empty endpoint list for a nonzero
/// version, empty body, or body whose length is not divisible by 18. The relay
/// endpoint types return zero-valued messages for nonzero versions, as Go does.
///
/// As in the Go codec, there is no arbitrary wire-size limit. Allocation is
/// fallible in Rust and returns `Error::Resource` rather than aborting.
pub fn parse(packet: &[u8]) -> Result<Message, Error> {
    if packet.len() < 2 {
        return Err(Error::Short);
    }

    let kind = packet[0];
    let version = packet[1];
    let body = &packet[2..];

    match kind {
        PING => {
            if body.len() < 12 {
                return Err(Error::Short);
            }
            let mut tx_id = [0; 12];
            tx_id.copy_from_slice(&body[..12]);
            let tail = &body[12..];
            let (node_key, padding) = if tail.len() >= 32 {
                let mut raw = [0; 32];
                raw.copy_from_slice(&tail[..32]);
                (NodePublic::from_raw32(raw), tail.len() - 32)
            } else {
                (NodePublic::from_raw32([0; 32]), tail.len())
            };
            Ok(Message::Ping { tx_id, node_key, padding })
        }
        PONG => {
            if body.len() < 30 {
                return Err(Error::Short);
            }
            let mut tx_id = [0; 12];
            tx_id.copy_from_slice(&body[..12]);
            let ip = decode_ip(&body[12..28]);
            let port = u16::from_be_bytes([body[28], body[29]]);
            Ok(Message::Pong { tx_id, source: SocketAddr::new(ip, port) })
        }
        CALL_ME_MAYBE => {
            let (records, remainder) = body.as_chunks::<18>();
            if version != 0 || body.is_empty() || !remainder.is_empty() {
                return Ok(Message::CallMeMaybe { endpoints: Vec::new() });
            }
            let count = records.len();
            let mut endpoints = Vec::new();
            endpoints.try_reserve(count).map_err(|_| Error::Resource)?;
            for record in records {
                endpoints.push(SocketAddr::new(decode_ip(&record[..16]), u16::from_be_bytes([record[16], record[17]])));
            }
            Ok(Message::CallMeMaybe { endpoints })
        }
        BIND_UDP_RELAY_ENDPOINT => Ok(Message::BindUdpRelayEndpoint(parse_bind_udp_relay_endpoint(body)?)),
        BIND_UDP_RELAY_ENDPOINT_CHALLENGE => {
            Ok(Message::BindUdpRelayEndpointChallenge(parse_bind_udp_relay_endpoint(body)?))
        }
        BIND_UDP_RELAY_ENDPOINT_ANSWER => Ok(Message::BindUdpRelayEndpointAnswer(parse_bind_udp_relay_endpoint(body)?)),
        CALL_ME_MAYBE_VIA => {
            if version != 0 {
                return Ok(Message::CallMeMaybeVia(UdpRelayEndpoint::default()));
            }
            Ok(Message::CallMeMaybeVia(parse_udp_relay_endpoint(body)?))
        }
        ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST => {
            if version != 0 {
                return Ok(Message::AllocateUdpRelayEndpointRequest(AllocateUdpRelayEndpointRequest::default()));
            }
            if body.len() < 68 {
                return Err(Error::Short);
            }
            let mut first = [0; 32];
            first.copy_from_slice(&body[..32]);
            let mut second = [0; 32];
            second.copy_from_slice(&body[32..64]);
            let generation = u32::from_be_bytes(body[64..68].try_into().map_err(|_| Error::Short)?);
            Ok(Message::AllocateUdpRelayEndpointRequest(AllocateUdpRelayEndpointRequest {
                client_disco: [crate::DiscoPublic::from_raw32(first), crate::DiscoPublic::from_raw32(second)],
                generation,
            }))
        }
        ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE => {
            if version != 0 {
                return Ok(Message::AllocateUdpRelayEndpointResponse {
                    generation: 0,
                    endpoint: UdpRelayEndpoint::default(),
                });
            }
            if body.len() < 4 {
                return Err(Error::Short);
            }
            let generation = u32::from_be_bytes(body[..4].try_into().map_err(|_| Error::Short)?);
            let endpoint = parse_udp_relay_endpoint(&body[4..])?;
            Ok(Message::AllocateUdpRelayEndpointResponse { generation, endpoint })
        }
        other => Err(Error::UnknownType(other)),
    }
}

fn parse_bind_udp_relay_endpoint(body: &[u8]) -> Result<BindUdpRelayEndpointCommon, Error> {
    if body.len() < 72 {
        return Err(Error::Short);
    }
    let vni = u32::from_be_bytes(body[..4].try_into().map_err(|_| Error::Short)?);
    let generation = u32::from_be_bytes(body[4..8].try_into().map_err(|_| Error::Short)?);
    let mut remote_key = [0; 32];
    remote_key.copy_from_slice(&body[8..40]);
    let mut challenge = [0; 32];
    challenge.copy_from_slice(&body[40..72]);
    Ok(BindUdpRelayEndpointCommon {
        vni,
        generation,
        remote_key: crate::DiscoPublic::from_raw32(remote_key),
        challenge,
    })
}

fn parse_udp_relay_endpoint(body: &[u8]) -> Result<UdpRelayEndpoint, Error> {
    if body.len() < UDP_RELAY_ENDPOINT_FIXED_LEN + UDP_RELAY_ENDPOINT_ADDRPORT_LEN
        || !(body.len() - UDP_RELAY_ENDPOINT_FIXED_LEN).is_multiple_of(UDP_RELAY_ENDPOINT_ADDRPORT_LEN)
    {
        return Err(Error::Short);
    }

    let mut server_disco = [0; 32];
    server_disco.copy_from_slice(&body[..32]);
    let mut first_client = [0; 32];
    first_client.copy_from_slice(&body[32..64]);
    let mut second_client = [0; 32];
    second_client.copy_from_slice(&body[64..96]);
    let lamport_id = u64::from_be_bytes(body[96..104].try_into().map_err(|_| Error::Short)?);
    let vni = u32::from_be_bytes(body[104..108].try_into().map_err(|_| Error::Short)?);
    let bind_lifetime_nanos = i64::from_be_bytes(body[108..116].try_into().map_err(|_| Error::Short)?);
    let steady_state_lifetime_nanos = i64::from_be_bytes(body[116..124].try_into().map_err(|_| Error::Short)?);

    let (records, remainder) = body[UDP_RELAY_ENDPOINT_FIXED_LEN..].as_chunks::<UDP_RELAY_ENDPOINT_ADDRPORT_LEN>();
    if !remainder.is_empty() {
        return Err(Error::Short);
    }
    let mut addr_ports = Vec::new();
    addr_ports.try_reserve(records.len()).map_err(|_| Error::Resource)?;
    for record in records {
        addr_ports.push(SocketAddr::new(decode_ip(&record[..16]), u16::from_be_bytes([record[16], record[17]])));
    }

    Ok(UdpRelayEndpoint {
        server_disco: crate::DiscoPublic::from_raw32(server_disco),
        client_disco: [crate::DiscoPublic::from_raw32(first_client), crate::DiscoPublic::from_raw32(second_client)],
        lamport_id,
        vni,
        bind_lifetime_nanos,
        steady_state_lifetime_nanos,
        addr_ports,
    })
}

/// Encodes a supported plaintext message into a new byte vector.
///
/// The pinned Go API appends to a caller-provided slice; this API instead
/// returns a new vector. Output bytes otherwise follow the same message rules.
/// Fallible reservation is used, but no non-Go 1 MiB protocol limit is added.
pub fn encode(message: &Message) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    match message {
        Message::Ping { tx_id, node_key, padding } => {
            let key_len = if node_key.is_zero() { 0 } else { 32 };
            let total_len =
                14usize.checked_add(key_len).and_then(|n| n.checked_add(*padding)).ok_or(Error::Resource)?;
            output.try_reserve(total_len).map_err(|_| Error::Resource)?;
            output.extend_from_slice(&[PING, 0]);
            output.extend_from_slice(tx_id);
            if key_len != 0 {
                output.extend_from_slice(&node_key.raw_bytes());
            }
            output.resize(total_len, 0);
        }
        Message::Pong { tx_id, source } => {
            output.try_reserve(32).map_err(|_| Error::Resource)?;
            output.extend_from_slice(&[PONG, 0]);
            output.extend_from_slice(tx_id);
            output.extend_from_slice(&encode_ip(source.ip()));
            output.extend_from_slice(&source.port().to_be_bytes());
        }
        Message::CallMeMaybe { endpoints } => {
            let total_len = endpoints.len().checked_mul(18).and_then(|n| n.checked_add(2)).ok_or(Error::Resource)?;
            output.try_reserve(total_len).map_err(|_| Error::Resource)?;
            output.extend_from_slice(&[CALL_ME_MAYBE, 0]);
            for endpoint in endpoints {
                output.extend_from_slice(&encode_ip(endpoint.ip()));
                output.extend_from_slice(&endpoint.port().to_be_bytes());
            }
        }
        Message::BindUdpRelayEndpoint(common) => {
            encode_bind_udp_relay_endpoint(&mut output, BIND_UDP_RELAY_ENDPOINT, common)?
        }
        Message::BindUdpRelayEndpointChallenge(common) => {
            encode_bind_udp_relay_endpoint(&mut output, BIND_UDP_RELAY_ENDPOINT_CHALLENGE, common)?
        }
        Message::BindUdpRelayEndpointAnswer(common) => {
            encode_bind_udp_relay_endpoint(&mut output, BIND_UDP_RELAY_ENDPOINT_ANSWER, common)?
        }
        Message::CallMeMaybeVia(endpoint) => {
            output.try_reserve(2).map_err(|_| Error::Resource)?;
            output.extend_from_slice(&[CALL_ME_MAYBE_VIA, 0]);
            encode_udp_relay_endpoint(&mut output, endpoint)?;
        }
        Message::AllocateUdpRelayEndpointRequest(request) => {
            output.try_reserve(70).map_err(|_| Error::Resource)?;
            output.extend_from_slice(&[ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST, 0]);
            for key in request.client_disco {
                output.extend_from_slice(&key.raw_bytes());
            }
            output.extend_from_slice(&request.generation.to_be_bytes());
        }
        Message::AllocateUdpRelayEndpointResponse { generation, endpoint } => {
            output.try_reserve(6).map_err(|_| Error::Resource)?;
            output.extend_from_slice(&[ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE, 0]);
            output.extend_from_slice(&generation.to_be_bytes());
            encode_udp_relay_endpoint(&mut output, endpoint)?;
        }
    }
    Ok(output)
}

fn encode_bind_udp_relay_endpoint(
    output: &mut Vec<u8>,
    kind: u8,
    common: &BindUdpRelayEndpointCommon,
) -> Result<(), Error> {
    output.try_reserve(74).map_err(|_| Error::Resource)?;
    output.extend_from_slice(&[kind, 0]);
    output.extend_from_slice(&common.vni.to_be_bytes());
    output.extend_from_slice(&common.generation.to_be_bytes());
    output.extend_from_slice(&common.remote_key.raw_bytes());
    output.extend_from_slice(&common.challenge);
    Ok(())
}

fn encode_udp_relay_endpoint(output: &mut Vec<u8>, endpoint: &UdpRelayEndpoint) -> Result<(), Error> {
    let address_len = endpoint.addr_ports.len().checked_mul(UDP_RELAY_ENDPOINT_ADDRPORT_LEN).ok_or(Error::Resource)?;
    let total_len = UDP_RELAY_ENDPOINT_FIXED_LEN.checked_add(address_len).ok_or(Error::Resource)?;
    output.try_reserve(total_len).map_err(|_| Error::Resource)?;
    output.extend_from_slice(&endpoint.server_disco.raw_bytes());
    for key in endpoint.client_disco {
        output.extend_from_slice(&key.raw_bytes());
    }
    output.extend_from_slice(&endpoint.lamport_id.to_be_bytes());
    output.extend_from_slice(&endpoint.vni.to_be_bytes());
    output.extend_from_slice(&endpoint.bind_lifetime_nanos.to_be_bytes());
    output.extend_from_slice(&endpoint.steady_state_lifetime_nanos.to_be_bytes());
    for address in &endpoint.addr_ports {
        output.extend_from_slice(&encode_ip(address.ip()));
        output.extend_from_slice(&address.port().to_be_bytes());
    }
    Ok(())
}

fn decode_ip(bytes: &[u8]) -> IpAddr {
    let mut raw = [0; 16];
    raw.copy_from_slice(&bytes[..16]);
    let address = Ipv6Addr::from(raw);
    address.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(address))
}

fn encode_ip(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped().octets(),
        IpAddr::V6(ipv6) => ipv6.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> NodePublic {
        NodePublic::from_raw32([byte; 32])
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs.iter().map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
    }

    const ALICE_PRIVATE_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const BOB_PUBLIC_HEX: &str = "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466";

    fn decode_hex32(input: &str) -> [u8; 32] {
        let decoded = decode_hex(input);
        let mut output = [0; 32];
        assert_eq!(decoded.len(), output.len());
        output.copy_from_slice(&decoded);
        output
    }

    fn wrapper_shared_and_sender() -> (crate::disco_crypto::DiscoShared, crate::DiscoPublic) {
        let alice = crate::DiscoPrivate::from_raw32(decode_hex32(ALICE_PRIVATE_HEX));
        let sender = crate::DiscoPublic::from_raw32(decode_hex32(BOB_PUBLIC_HEX));
        (alice.shared(&sender).unwrap(), sender)
    }

    fn hex(input: &[u8]) -> String {
        input.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn marshal_matches_real_pinned_go_fork_vectors() {
        // Generated by disco.Message.AppendMarshal in the actual Go module
        // github.com/sagernet/tailscale@79c1732442a9dfba9f80512247432a6ab7faca67,
        // using Go 1.26.8. These are not a second transcription of the codec.
        let tx_id = core::array::from_fn(|index| index as u8);
        let messages = [
            Message::Ping { tx_id, node_key: key(0x5a), padding: 3 },
            Message::Pong { tx_id, source: "192.0.2.1:8080".parse().unwrap() },
            Message::CallMeMaybe {
                endpoints: vec!["203.0.113.4:5000".parse().unwrap(), "[2001:db8::1]:53".parse().unwrap()],
            },
        ];
        let expected = [
            "0100000102030405060708090a0b5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000000",
            "0200000102030405060708090a0b00000000000000000000ffffc00002011f90",
            "030000000000000000000000ffffcb007104138820010db80000000000000000000000010035",
        ];
        for (message, expected_hex) in messages.iter().zip(expected) {
            let wire = encode(message).unwrap();
            let hex: String = wire.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, expected_hex);
            assert_eq!(parse(&wire).unwrap(), *message);
        }
    }

    #[test]
    fn ping_matches_go_keyless_padding_and_ignores_version() {
        let mut frame = vec![PING, 77];
        frame.extend(0..12);
        frame.extend([0, 0]);
        let tx_id = core::array::from_fn(|index| index as u8);
        assert_eq!(parse(&frame).unwrap(), Message::Ping { tx_id, node_key: key(0), padding: 2 });
        assert_eq!(
            encode(&Message::Ping { tx_id, node_key: key(0), padding: 2 }).unwrap(),
            [vec![PING, 0], (0..12).collect(), vec![0, 0]].concat()
        );

        let mut short_tail = vec![PING, 0];
        short_tail.extend(0..12);
        short_tail.extend([0x5a; 31]);
        assert_eq!(parse(&short_tail).unwrap(), Message::Ping { tx_id, node_key: key(0), padding: 31 });
    }

    #[test]
    fn ping_with_node_key_counts_only_bytes_after_key_as_padding() {
        let mut frame = vec![PING, 0];
        frame.extend(0..12);
        frame.extend([0x5a; 32]);
        frame.extend([0, 0, 0]);
        assert_eq!(
            parse(&frame).unwrap(),
            Message::Ping { tx_id: core::array::from_fn(|index| index as u8), node_key: key(0x5a), padding: 3 }
        );
    }

    #[test]
    fn pong_unmaps_mapped_ipv4_ignores_version_and_trailing_bytes() {
        let frame = [
            vec![PONG, 9],
            (0..12).collect::<Vec<_>>(),
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1],
            vec![0x1f, 0x90, 9, 8],
        ]
        .concat();
        let parsed = parse(&frame).unwrap();
        assert_eq!(
            parsed,
            Message::Pong {
                tx_id: core::array::from_fn(|index| index as u8),
                source: "192.0.2.1:8080".parse().unwrap(),
            }
        );
        let mut canonical = frame[..32].to_vec();
        canonical[1] = 0;
        assert_eq!(encode(&parsed).unwrap(), canonical);
    }

    #[test]
    fn call_me_maybe_maps_endpoints_and_returns_empty_for_go_malformed_cases() {
        let frame =
            [vec![CALL_ME_MAYBE, 0], vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 4, 0x13, 0x88]]
                .concat();
        let parsed = parse(&frame).unwrap();
        assert_eq!(parsed, Message::CallMeMaybe { endpoints: vec!["203.0.113.4:5000".parse().unwrap()] });
        assert_eq!(encode(&parsed).unwrap(), frame);
        assert_eq!(parse(&[CALL_ME_MAYBE, 0]).unwrap(), Message::CallMeMaybe { endpoints: Vec::new() });
        assert_eq!(parse(&[CALL_ME_MAYBE, 0, 1]).unwrap(), Message::CallMeMaybe { endpoints: Vec::new() });
        let mut nonzero_version = frame;
        nonzero_version[1] = 1;
        assert_eq!(parse(&nonzero_version).unwrap(), Message::CallMeMaybe { endpoints: Vec::new() });
    }

    #[test]
    fn udp_relay_bind_messages_match_real_go_vectors_and_ignore_version_and_trailing_bytes() {
        // Generated by AppendMarshal and Parse in the pinned Go fork at
        // github.com/sagernet/tailscale@79c1732442a9dfba9f80512247432a6ab7faca67.
        const GO_BODY_HEX: &str = "01020304a0b0c0d011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222";
        let common = BindUdpRelayEndpointCommon {
            vni: 0x0102_0304,
            generation: 0xa0b0_c0d0,
            remote_key: crate::DiscoPublic::from_raw32([0x11; 32]),
            challenge: [0x22; 32],
        };

        for kind in BIND_UDP_RELAY_ENDPOINT..=BIND_UDP_RELAY_ENDPOINT_ANSWER {
            let message = match kind {
                BIND_UDP_RELAY_ENDPOINT => Message::BindUdpRelayEndpoint(common.clone()),
                BIND_UDP_RELAY_ENDPOINT_CHALLENGE => Message::BindUdpRelayEndpointChallenge(common.clone()),
                BIND_UDP_RELAY_ENDPOINT_ANSWER => Message::BindUdpRelayEndpointAnswer(common.clone()),
                _ => unreachable!(),
            };
            let expected = decode_hex(&format!("{kind:02x}00{GO_BODY_HEX}"));
            assert_eq!(encode(&message).unwrap(), expected);
            assert_eq!(parse(&expected).unwrap(), message);

            let mut versioned_with_tail = expected.clone();
            versioned_with_tail[1] = 99;
            versioned_with_tail.extend_from_slice(&[0xaa, 0xbb]);
            let parsed = parse(&versioned_with_tail).unwrap();
            assert_eq!(parsed, message);
            assert_eq!(encode(&parsed).unwrap(), expected);

            let mut short = vec![kind, 0];
            short.resize(2 + 71, 0);
            assert_eq!(parse(&short), Err(Error::Short));
        }
    }

    fn disco_key(byte: u8) -> crate::DiscoPublic {
        crate::DiscoPublic::from_raw32([byte; 32])
    }

    fn go_endpoint() -> UdpRelayEndpoint {
        UdpRelayEndpoint {
            server_disco: disco_key(0x10),
            client_disco: [disco_key(0x11), disco_key(0x12)],
            lamport_id: 0x0102_0304_0506_0708,
            vni: 0x1122_3344,
            bind_lifetime_nanos: 10_000_000_000,
            steady_state_lifetime_nanos: 3_600_000_000_000,
            addr_ports: vec!["192.0.2.1:41641".parse().unwrap(), "[2001:db8::1]:443".parse().unwrap()],
        }
    }

    #[test]
    fn relay_endpoint_via_and_allocation_messages_match_real_go_vectors() {
        // Generated by AppendMarshal and Parse in the pinned Go fork; the fixed
        // endpoint portion includes two AddrPorts (IPv4-mapped and native IPv6).
        const GO_ENDPOINT_BODY: &str = concat!(
            "1010101010101010101010101010101010101010101010101010101010101010",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "1212121212121212121212121212121212121212121212121212121212121212",
            "01020304050607081122334400000002540be4000000034630b8a000",
            "00000000000000000000ffffc0000201a2a9",
            "20010db800000000000000000000000101bb"
        );
        let endpoint = go_endpoint();
        let request = AllocateUdpRelayEndpointRequest {
            client_disco: [disco_key(0x11), disco_key(0x12)],
            generation: 0xa0b0_c0d0,
        };
        let messages = [
            Message::CallMeMaybeVia(endpoint.clone()),
            Message::AllocateUdpRelayEndpointRequest(request.clone()),
            Message::AllocateUdpRelayEndpointResponse { generation: 0xa0b0_c0d0, endpoint: endpoint.clone() },
        ];
        let request_hex = format!("0800{}{}a0b0c0d0", "11".repeat(32), "12".repeat(32));
        let expected = [
            decode_hex(&format!("0700{GO_ENDPOINT_BODY}")),
            decode_hex(&request_hex),
            decode_hex(&format!("0900a0b0c0d0{GO_ENDPOINT_BODY}")),
        ];
        for (message, expected_wire) in messages.iter().zip(expected) {
            assert_eq!(encode(message).unwrap(), expected_wire);
            assert_eq!(parse(&expected_wire).unwrap(), *message);
        }
    }

    #[test]
    fn zero_value_endpoint_marshal_matches_go_even_when_parse_rejects_it() {
        let via = encode(&Message::CallMeMaybeVia(UdpRelayEndpoint::default())).unwrap();
        assert_eq!(via.len(), 2 + UDP_RELAY_ENDPOINT_FIXED_LEN);
        assert_eq!(parse(&via), Err(Error::Short));

        let response =
            encode(&Message::AllocateUdpRelayEndpointResponse { generation: 0, endpoint: UdpRelayEndpoint::default() })
                .unwrap();
        assert_eq!(response.len(), 2 + 4 + UDP_RELAY_ENDPOINT_FIXED_LEN);
        assert_eq!(parse(&response), Err(Error::Short));
    }

    #[test]
    fn relay_endpoint_nonzero_versions_return_go_zero_values() {
        assert_eq!(parse(&[CALL_ME_MAYBE_VIA, 1, 0xaa]), Ok(Message::CallMeMaybeVia(UdpRelayEndpoint::default())));
        assert_eq!(
            parse(&[ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST, 1, 0xaa]),
            Ok(Message::AllocateUdpRelayEndpointRequest(AllocateUdpRelayEndpointRequest::default()))
        );
        assert_eq!(
            parse(&[ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE, 1, 0xaa]),
            Ok(Message::AllocateUdpRelayEndpointResponse { generation: 0, endpoint: UdpRelayEndpoint::default() })
        );
    }

    #[test]
    fn relay_endpoint_length_and_tail_rules_match_go() {
        for body_len in
            [0, UDP_RELAY_ENDPOINT_FIXED_LEN - 1, UDP_RELAY_ENDPOINT_FIXED_LEN, UDP_RELAY_ENDPOINT_FIXED_LEN + 17]
        {
            let mut frame = vec![CALL_ME_MAYBE_VIA, 0];
            frame.resize(2 + body_len, 0);
            assert_eq!(parse(&frame), Err(Error::Short), "CallMeMaybeVia body length {body_len}");
        }

        let mut short_request = vec![ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST, 0];
        short_request.resize(2 + 67, 0);
        assert_eq!(parse(&short_request), Err(Error::Short));
        let mut request_with_tail =
            encode(&Message::AllocateUdpRelayEndpointRequest(AllocateUdpRelayEndpointRequest::default())).unwrap();
        request_with_tail.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(
            parse(&request_with_tail),
            Ok(Message::AllocateUdpRelayEndpointRequest(AllocateUdpRelayEndpointRequest::default()))
        );

        for body_len in [4, 4 + UDP_RELAY_ENDPOINT_FIXED_LEN, 4 + UDP_RELAY_ENDPOINT_FIXED_LEN + 19] {
            let mut frame = vec![ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE, 0];
            frame.resize(2 + body_len, 0);
            assert_eq!(parse(&frame), Err(Error::Short), "allocation response body length {body_len}");
        }
        let mut response_with_bad_tail =
            encode(&Message::AllocateUdpRelayEndpointResponse { generation: 7, endpoint: go_endpoint() }).unwrap();
        response_with_bad_tail.push(0xaa);
        assert_eq!(parse(&response_with_bad_tail), Err(Error::Short));
    }

    #[test]
    fn wrapper_requires_full_outer_header_and_exact_magic() {
        let mut packet = vec![0; OUTER_HEADER_LEN];
        packet[..6].copy_from_slice(&MAGIC);
        for (index, byte) in packet[MAGIC.len()..DISCO_HEADER_LEN].iter_mut().enumerate() {
            *byte = (index + 6) as u8;
        }
        assert!(!looks_like_wrapper(&packet[..OUTER_HEADER_LEN - 1]));
        assert!(looks_like_wrapper(&packet));
        assert_eq!(source(&packet), Some(&packet[MAGIC.len()..DISCO_HEADER_LEN]));
        packet[0] = 0;
        assert!(!looks_like_wrapper(&packet));
        assert_eq!(source(&packet), None);
    }

    #[test]
    fn packet_classifier_matches_magicsock_38_byte_prefix_not_62_byte_helper() {
        let mut packet = vec![0; OUTER_HEADER_LEN - 1];
        packet[..MAGIC.len()].copy_from_slice(&MAGIC);
        assert!(!packet_looks_like_disco(&packet[..DISCO_HEADER_LEN - 1]));
        assert!(packet_looks_like_disco(&packet[..DISCO_HEADER_LEN]));
        assert!(packet_looks_like_disco(&packet));
        assert!(!looks_like_wrapper(&packet));
        packet[0] ^= 1;
        assert!(!packet_looks_like_disco(&packet));
    }

    #[test]
    fn rust_packet_seal_and_open_use_go_outer_envelope_layout() {
        let (shared, sender) = wrapper_shared_and_sender();
        let message =
            Message::Ping { tx_id: core::array::from_fn(|index| index as u8), node_key: key(0x5a), padding: 3 };
        let packet = seal_packet(&sender, &shared, &message).unwrap();
        assert!(packet_looks_like_disco(&packet));
        assert!(looks_like_wrapper(&packet));
        assert_eq!(&packet[..MAGIC.len()], &MAGIC);
        assert_eq!(&packet[MAGIC.len()..DISCO_HEADER_LEN], &sender.raw_bytes());
        assert_eq!(source(&packet), Some(&packet[MAGIC.len()..DISCO_HEADER_LEN]));
        assert_eq!(open_packet(&shared, &packet), Ok((sender, message)));

        if std::env::var_os("RB_TAILSCALE_PRINT_DISCO_PACKET").is_some() {
            println!("RUST_PACKET_HEX={}", hex(&packet));
        }
    }

    #[test]
    fn rust_opens_a_fixed_nonce_packet_emitted_by_the_pinned_go_fork() {
        // Generated by Go disco.Message.AppendMarshal + box.SealAfterPrecomputation
        // from the exact pinned fork; sender public key and shared key match the fixture above.
        const GO_PACKET_HEX: &str = "5453f09f92ac64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d484660a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021451806653df2bd27698a0983b8d93c88b3b47fd33ad5008f63b0b477b0852b4bb49f8a03c4ddf1e78df98c14558f02f077a1996cade7aef28d78e76c13493659b3";
        let (shared, expected_sender) = wrapper_shared_and_sender();
        let packet = decode_hex(GO_PACKET_HEX);
        let (sender, message) = open_packet(&shared, &packet).unwrap();
        assert_eq!(sender, expected_sender);
        assert_eq!(
            message,
            Message::Ping { tx_id: core::array::from_fn(|index| index as u8), node_key: key(0x5a), padding: 3 }
        );
    }

    #[test]
    fn packet_open_matches_go_short_box_and_authentication_failure_order() {
        let (shared, _) = wrapper_shared_and_sender();
        let mut not_packet = vec![0; DISCO_HEADER_LEN - 1];
        not_packet[..MAGIC.len()].copy_from_slice(&MAGIC);
        assert_eq!(open_packet(&shared, &not_packet), Err(PacketError::NotDiscoPacket));

        for (length, got) in [(DISCO_HEADER_LEN, 0), (OUTER_HEADER_LEN - 1, 23)] {
            let mut short = vec![0; length];
            short[..MAGIC.len()].copy_from_slice(&MAGIC);
            assert_eq!(
                open_packet(&shared, &short),
                Err(PacketError::Crypto(crate::disco_crypto::Error::ShortCiphertext { got, want: 24 }))
            );
        }

        let mut nonce_only = vec![0; OUTER_HEADER_LEN];
        nonce_only[..MAGIC.len()].copy_from_slice(&MAGIC);
        assert_eq!(
            open_packet(&shared, &nonce_only),
            Err(PacketError::Crypto(crate::disco_crypto::Error::Authentication))
        );
    }

    #[test]
    fn packet_open_parses_only_after_authentication() {
        let (shared, sender) = wrapper_shared_and_sender();
        let sealed_unknown = shared.seal(&[0x63, 0]).unwrap();
        let packet = wrap_sealed(&sender, &sealed_unknown).unwrap();
        assert_eq!(open_packet(&shared, &packet), Err(PacketError::Plaintext(Error::UnknownType(0x63))));

        let mut tampered = packet;
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            open_packet(&shared, &tampered),
            Err(PacketError::Crypto(crate::disco_crypto::Error::Authentication))
        );
    }

    #[test]
    fn unsupported_and_unknown_types_fail_explicitly_and_short_frames_fail() {
        assert_eq!(parse(&[]), Err(Error::Short));
        assert_eq!(parse(&[PING, 0]), Err(Error::Short));
        assert_eq!(parse(&[PONG, 0, 0]), Err(Error::Short));
        for kind in CALL_ME_MAYBE_VIA..=ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE {
            assert_eq!(parse(&[kind, 0]), Err(Error::Short));
        }
        assert_eq!(parse(&[0x63, 0]), Err(Error::UnknownType(0x63)));
    }

    #[test]
    fn no_arbitrary_one_mib_protocol_limit_is_imposed() {
        let count = 60_000;
        let mut large = vec![CALL_ME_MAYBE, 0];
        large.resize(2 + 18 * count, 0);
        assert_eq!(parse(&large).unwrap(), Message::CallMeMaybe { endpoints: vec!["[::]:0".parse().unwrap(); count] });
        let encoded = encode(&Message::CallMeMaybe { endpoints: vec!["[::]:0".parse().unwrap(); count] }).unwrap();
        assert_eq!(encoded.len(), 2 + 18 * count);
    }
}
