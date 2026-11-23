//! Pure-Rust codecs for the implemented Tailscale disco plaintext messages.
//!
//! The pinned Tailscale fork supports more disco types than this module. Types
//! 0x04 through 0x09 are reported as unsupported; unknown types are distinct.
//! This module does not implement NaCl box encryption, outer packet runtime,
//! UDP relay handshakes, or endpoint discovery.

use std::{
    fmt,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use crate::NodePublic;

/// The six-byte Tailscale disco packet magic (`TS💬`).
pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];
/// Minimum outer wrapper length: magic, sender disco public key, and nonce.
pub const OUTER_HEADER_LEN: usize = 6 + 32 + 24;

const PING: u8 = 0x01;
const PONG: u8 = 0x02;
const CALL_ME_MAYBE: u8 = 0x03;

/// Semantic representation of the three disco plaintext message types
/// currently implemented here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Ping { tx_id: [u8; 12], node_key: NodePublic, padding: usize },
    Pong { tx_id: [u8; 12], source: SocketAddr },
    CallMeMaybe { endpoints: Vec<SocketAddr> },
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

/// Returns true only when `packet` has the complete 62-byte outer header and
/// the exact magic, matching the pinned fork's `LooksLikeDiscoWrapper`.
pub fn looks_like_wrapper(packet: &[u8]) -> bool {
    packet.len() >= OUTER_HEADER_LEN && packet.starts_with(&MAGIC)
}

/// Returns the sender's 32-byte disco public key only for a valid outer wrapper.
pub fn source(packet: &[u8]) -> Option<&[u8]> {
    looks_like_wrapper(packet).then(|| &packet[6..38])
}

/// Parses plaintext inside an authenticated NaCl box.
///
/// Version bytes for Ping and Pong are ignored by the pinned fork. CallMeMaybe
/// returns an empty endpoint list for a nonzero version, empty body, or body
/// whose length is not divisible by 18. The fork's other assigned message
/// types (0x04..=0x09) fail explicitly here rather than being silently ignored.
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
        0x04..=0x09 => Err(Error::UnsupportedType(kind)),
        other => Err(Error::UnknownType(other)),
    }
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
    }
    Ok(output)
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
    fn wrapper_requires_full_outer_header_and_exact_magic() {
        let mut packet = vec![0; OUTER_HEADER_LEN];
        packet[..6].copy_from_slice(&MAGIC);
        for (index, byte) in packet[6..38].iter_mut().enumerate() {
            *byte = (index + 6) as u8;
        }
        assert!(!looks_like_wrapper(&packet[..OUTER_HEADER_LEN - 1]));
        assert!(looks_like_wrapper(&packet));
        assert_eq!(source(&packet), Some(&packet[6..38]));
        packet[0] = 0;
        assert!(!looks_like_wrapper(&packet));
        assert_eq!(source(&packet), None);
    }

    #[test]
    fn unsupported_and_unknown_types_fail_explicitly_and_short_frames_fail() {
        assert_eq!(parse(&[]), Err(Error::Short));
        assert_eq!(parse(&[PING, 0]), Err(Error::Short));
        assert_eq!(parse(&[PONG, 0, 0]), Err(Error::Short));
        for kind in 0x04..=0x09 {
            assert_eq!(parse(&[kind, 0]), Err(Error::UnsupportedType(kind)));
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
