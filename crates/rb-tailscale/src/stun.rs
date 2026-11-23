//! Pure-Rust implementation of the pinned Tailscale fork's STUN binding-request helpers.
//!
//! This module covers binding request/response helpers, TxID generation, and the
//! fork's Tailscale-specific request parser. It does not implement STUN networking.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand::rand_core::OsRng;
use rand::TryCryptoRng;

const HEADER_LEN: usize = 20;
const TX_ID_LEN: usize = 12;
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const FINGERPRINT_XOR: u32 = 0x5354_554e;
const SOFTWARE_ATTRIBUTE: u16 = 0x8022;
const FINGERPRINT_ATTRIBUTE: u16 = 0x8028;
const SOFTWARE: &[u8; 8] = b"tailnode";
const FINGERPRINT_LEN: usize = 8;
const REQUEST_LEN: usize = 40;
const MAPPED_ADDRESS_ATTRIBUTE: u16 = 0x0001;
const XOR_MAPPED_ADDRESS_ATTRIBUTE: u16 = 0x0020;
const XOR_MAPPED_ADDRESS_ALT_ATTRIBUTE: u16 = 0x8020;

/// A STUN transaction ID, matching the pinned fork's `[12]byte` `TxID`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TxId([u8; TX_ID_LEN]);

impl TxId {
    /// Constructs a transaction ID from its exact wire bytes.
    pub const fn from_bytes(bytes: [u8; TX_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the exact 12-byte wire representation.
    pub const fn as_bytes(&self) -> &[u8; TX_ID_LEN] {
        &self.0
    }

    /// Generates a transaction ID using only the operating-system CSPRNG.
    ///
    /// Unlike the pinned Go helper, randomness failure is returned rather than
    /// panicking; callers must stop rather than substitute weaker entropy.
    pub fn generate() -> Result<Self, TxIdGenerationError> {
        let mut rng = OsRng;
        generate_tx_id_with_rng(&mut rng)
    }
}

/// An OS cryptographic entropy error while generating a STUN transaction ID.
#[derive(Debug)]
pub struct TxIdGenerationError(String);

impl fmt::Display for TxIdGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OS cryptographic random number generation failed: {}", self.0)
    }
}

impl Error for TxIdGenerationError {}

/// Errors returned by the pinned fork's STUN request and response parsers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    NotStun,
    NotBindingRequest,
    NotSuccessResponse,
    MalformedAttributes,
    WrongSoftware,
    NoFingerprint,
    WrongFingerprint,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotStun => "response is not a STUN packet",
            Self::NotBindingRequest => "STUN request not a binding request",
            Self::NotSuccessResponse => "STUN packet is not a response",
            Self::MalformedAttributes => "STUN response has malformed attributes",
            Self::WrongSoftware => "STUN request came from non-Tailscale software",
            Self::NoFingerprint => "STUN request didn't end in fingerprint",
            Self::WrongFingerprint => "STUN request had bogus fingerprint",
        })
    }
}

impl Error for ParseError {}

/// A STUN response parsing error with the transaction-ID return value preserved.
///
/// The pinned Go parser returns a copied TxID for a non-success response, an
/// oversized advertised attribute length, or a response with no mapped address;
/// malformed attribute traversal or address values return a zero TxID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseParseError {
    pub transaction_id: TxId,
    pub cause: ParseError,
}

impl fmt::Display for ResponseParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.cause, formatter)
    }
}

impl Error for ResponseParseError {}

/// Reports whether a packet passes the pinned fork's minimal STUN header test.
///
/// This deliberately does not validate the message type, length field, or
/// attributes; the pinned Go `stun.Is` checks only these same three conditions.
pub fn is_stun(packet: &[u8]) -> bool {
    packet.len() >= HEADER_LEN && packet[0] & 0xc0 == 0 && packet[4..8] == MAGIC_COOKIE
}

/// Builds the pinned fork's 40-byte STUN binding request for `tx_id`.
///
/// The fixed SOFTWARE attribute is `tailnode`; the final FINGERPRINT attribute
/// is CRC-32/IEEE over all preceding bytes XOR `0x5354554e`.
pub fn build_binding_request(tx_id: TxId) -> [u8; REQUEST_LEN] {
    let mut packet = [0; REQUEST_LEN];
    packet[..2].copy_from_slice(&[0x00, 0x01]);
    packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
    packet[4..8].copy_from_slice(&MAGIC_COOKIE);
    packet[8..HEADER_LEN].copy_from_slice(tx_id.as_bytes());

    packet[20..22].copy_from_slice(&SOFTWARE_ATTRIBUTE.to_be_bytes());
    packet[22..24].copy_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    packet[24..32].copy_from_slice(SOFTWARE);

    packet[32..34].copy_from_slice(&FINGERPRINT_ATTRIBUTE.to_be_bytes());
    packet[34..36].copy_from_slice(&4_u16.to_be_bytes());
    let fingerprint = fingerprint(&packet[..32]);
    packet[36..40].copy_from_slice(&fingerprint.to_be_bytes());
    packet
}

/// Builds the pinned fork's STUN binding response for an optional address.
///
/// `None` models an invalid Go `netip.AddrPort` and returns an empty packet. IPv4,
/// IPv6, and IPv4-mapped IPv6 inputs retain the fork's family and XOR behavior.
pub fn build_binding_response(tx_id: TxId, addr_port: Option<SocketAddr>) -> Vec<u8> {
    let Some(addr_port) = addr_port else {
        return Vec::new();
    };
    let (family, address_bytes) = match addr_port.ip() {
        IpAddr::V4(address) => (1_u8, address.octets().to_vec()),
        IpAddr::V6(address) => (2_u8, address.octets().to_vec()),
    };
    let attributes_len = 8 + address_bytes.len();
    let attribute_value_len = 4 + address_bytes.len();
    let mut packet = Vec::with_capacity(HEADER_LEN + attributes_len);
    packet.extend_from_slice(&[0x01, 0x01]);
    packet.extend_from_slice(&(attributes_len as u16).to_be_bytes());
    packet.extend_from_slice(&MAGIC_COOKIE);
    packet.extend_from_slice(tx_id.as_bytes());
    packet.extend_from_slice(&XOR_MAPPED_ADDRESS_ATTRIBUTE.to_be_bytes());
    packet.extend_from_slice(&(attribute_value_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, family]);
    packet.extend_from_slice(&(addr_port.port() ^ 0x2112).to_be_bytes());
    for (index, byte) in address_bytes.into_iter().enumerate() {
        let mask =
            if index < MAGIC_COOKIE.len() { MAGIC_COOKIE[index] } else { tx_id.as_bytes()[index - MAGIC_COOKIE.len()] };
        packet.push(byte ^ mask);
    }
    packet
}

/// Parses a STUN binding request that advertises the Tailscale `tailnode` software.
///
/// This preserves the pinned parser's validation order and quirks: it ignores the
/// STUN header length, parses all bytes after the 20-byte header, accepts arbitrary
/// attribute padding, and requires the final attribute type to be FINGERPRINT.
pub fn parse_binding_request(packet: &[u8]) -> Result<TxId, ParseError> {
    if !is_stun(packet) {
        return Err(ParseError::NotStun);
    }
    if packet[..2] != [0x00, 0x01] {
        return Err(ParseError::NotBindingRequest);
    }

    let mut tx_id = [0; TX_ID_LEN];
    tx_id.copy_from_slice(&packet[8..HEADER_LEN]);

    let mut software_ok = false;
    let mut last_attribute = None;
    let mut got_fingerprint = 0_u32;
    foreach_attribute(&packet[HEADER_LEN..], |attribute_type, value| {
        last_attribute = Some(attribute_type);
        if attribute_type == SOFTWARE_ATTRIBUTE && value == SOFTWARE {
            software_ok = true;
        }
        if attribute_type == FINGERPRINT_ATTRIBUTE && value.len() == 4 {
            got_fingerprint = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        }
        Ok(())
    })?;

    if !software_ok {
        return Err(ParseError::WrongSoftware);
    }
    if last_attribute != Some(FINGERPRINT_ATTRIBUTE) {
        return Err(ParseError::NoFingerprint);
    }

    let fingerprint_end = packet.len() - FINGERPRINT_LEN;
    let expected_fingerprint = fingerprint(&packet[..fingerprint_end]);
    if got_fingerprint != expected_fingerprint {
        return Err(ParseError::WrongFingerprint);
    }
    Ok(TxId(tx_id))
}

/// Parses a successful binding response, preferring XOR-MAPPED-ADDRESS.
///
/// This mirrors the pinned fork's error return values, including the copied TxID
/// on `NotSuccessResponse`, oversized advertised lengths, and absent addresses;
/// malformed attribute traversal or address values return a zero TxID.
pub fn parse_binding_response(packet: &[u8]) -> Result<(TxId, SocketAddr), ResponseParseError> {
    if !is_stun(packet) {
        return Err(response_parse_error(TxId::from_bytes([0; TX_ID_LEN]), ParseError::NotStun));
    }
    let mut tx_id = [0; TX_ID_LEN];
    tx_id.copy_from_slice(&packet[8..HEADER_LEN]);
    let tx_id = TxId(tx_id);
    if packet[..2] != [0x01, 0x01] {
        return Err(response_parse_error(tx_id, ParseError::NotSuccessResponse));
    }

    let attributes_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let mut attributes = &packet[HEADER_LEN..];
    if attributes_len > attributes.len() {
        return Err(response_parse_error(tx_id, ParseError::MalformedAttributes));
    }
    attributes = &attributes[..attributes_len];

    let mut xor_mapped_address = None;
    let mut fallback_address = None;
    if let Err(error) = foreach_attribute(attributes, |attribute_type, value| {
        match attribute_type {
            XOR_MAPPED_ADDRESS_ATTRIBUTE | XOR_MAPPED_ADDRESS_ALT_ATTRIBUTE => {
                xor_mapped_address = Some(parse_xor_mapped_address(tx_id, value)?);
            }
            MAPPED_ADDRESS_ATTRIBUTE => {
                fallback_address = Some(parse_mapped_address(value)?);
            }
            _ => {}
        }
        Ok(())
    }) {
        return Err(response_parse_error(TxId::from_bytes([0; TX_ID_LEN]), error));
    }

    if let Some(address) = xor_mapped_address {
        return Ok((tx_id, address));
    }
    if let Some(address) = fallback_address {
        return Ok((tx_id, address));
    }
    Err(response_parse_error(tx_id, ParseError::MalformedAttributes))
}

fn response_parse_error(transaction_id: TxId, cause: ParseError) -> ResponseParseError {
    ResponseParseError { transaction_id, cause }
}

fn foreach_attribute<F>(mut attributes: &[u8], mut visit: F) -> Result<(), ParseError>
where
    F: FnMut(u16, &[u8]) -> Result<(), ParseError>,
{
    while !attributes.is_empty() {
        if attributes.len() < 4 {
            return Err(ParseError::MalformedAttributes);
        }
        let attribute_type = u16::from_be_bytes([attributes[0], attributes[1]]);
        let value_len = usize::from(u16::from_be_bytes([attributes[2], attributes[3]]));
        let padded_value_len = (value_len + 3) & !3;
        attributes = &attributes[4..];
        if padded_value_len > attributes.len() {
            return Err(ParseError::MalformedAttributes);
        }
        visit(attribute_type, &attributes[..value_len])?;
        attributes = &attributes[padded_value_len..];
    }
    Ok(())
}

fn parse_xor_mapped_address(tx_id: TxId, value: &[u8]) -> Result<SocketAddr, ParseError> {
    parse_address_attribute(value, Some(tx_id))
}

fn parse_mapped_address(value: &[u8]) -> Result<SocketAddr, ParseError> {
    parse_address_attribute(value, None)
}

fn parse_address_attribute(value: &[u8], xor_with: Option<TxId>) -> Result<SocketAddr, ParseError> {
    if value.len() < 4 {
        return Err(ParseError::MalformedAttributes);
    }
    let family = value[1];
    let address_len = match family {
        1 => 4,
        2 => 16,
        _ => return Err(ParseError::MalformedAttributes),
    };
    if value.len() - 4 < address_len {
        return Err(ParseError::MalformedAttributes);
    }
    let mut address_bytes = value[4..4 + address_len].to_vec();
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if let Some(tx_id) = xor_with {
        port ^= 0x2112;
        for (index, byte) in address_bytes.iter_mut().enumerate() {
            let mask = if index < MAGIC_COOKIE.len() {
                MAGIC_COOKIE[index]
            } else {
                tx_id.as_bytes()[index - MAGIC_COOKIE.len()]
            };
            *byte ^= mask;
        }
    }
    socket_addr_from_octets(family, &address_bytes, port)
}

fn socket_addr_from_octets(family: u8, address_bytes: &[u8], port: u16) -> Result<SocketAddr, ParseError> {
    match family {
        1 => {
            let mut octets = [0; 4];
            octets.copy_from_slice(&address_bytes[..4]);
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        2 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&address_bytes[..16]);
            let address = Ipv6Addr::from(octets);
            let ip = address.to_ipv4().map_or(IpAddr::V6(address), IpAddr::V4);
            Ok(SocketAddr::new(ip, port))
        }
        _ => Err(ParseError::MalformedAttributes),
    }
}

fn generate_tx_id_with_rng<R>(rng: &mut R) -> Result<TxId, TxIdGenerationError>
where
    R: TryCryptoRng,
    R::Error: fmt::Display,
{
    let mut bytes = [0; TX_ID_LEN];
    if let Err(error) = rng.try_fill_bytes(&mut bytes) {
        bytes.fill(0);
        return Err(TxIdGenerationError(error.to_string()));
    }
    Ok(TxId(bytes))
}

fn fingerprint(input: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in input {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 { crc >> 1 } else { (crc >> 1) ^ 0xedb8_8320 };
        }
    }
    !crc ^ FINGERPRINT_XOR
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::io;
    use std::net::SocketAddr;

    use rand::{TryCryptoRng, TryRngCore};

    use super::{
        build_binding_request, build_binding_response, fingerprint, is_stun, parse_binding_request,
        parse_binding_response, ParseError, ResponseParseError, TxId,
    };

    const TX_ID_BYTES: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    const GO_REQUEST: [u8; 40] = [
        0x00, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x80, 0x22, 0x00, 0x08, 0x74, 0x61, 0x69, 0x6c, 0x6e, 0x6f, 0x64, 0x65, 0x80, 0x28, 0x00, 0x04,
        0x8a, 0xab, 0xad, 0x90,
    ];
    const GO_RESPONSE_V4: [u8; 32] = [
        0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xf5, 0x23, 0xe1, 0x12, 0xa6, 0x45,
    ];
    const GO_RESPONSE_V6: [u8; 44] = [
        0x01, 0x01, 0x00, 0x18, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0x2d, 0x98, 0x01, 0x13, 0xa9, 0xfa, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x18, 0x3f,
    ];
    const GO_RESPONSE_MAPPED_V6: [u8; 44] = [
        0x01, 0x01, 0x00, 0x18, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xde, 0xe8, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0xf9, 0xf8, 0xc8, 0x09, 0x08, 0x0c,
    ];

    fn sample_request() -> Vec<u8> {
        build_binding_request(TxId::from_bytes(TX_ID_BYTES)).to_vec()
    }

    fn recompute_fingerprint(packet: &mut [u8]) {
        let fingerprint_start = packet.len() - 8;
        let value = fingerprint(&packet[..fingerprint_start]);
        let value_start = packet.len() - 4;
        packet[value_start..].copy_from_slice(&value.to_be_bytes());
    }

    fn make_attribute(attribute_type: u16, value: &[u8]) -> Vec<u8> {
        let padded_len = (value.len() + 3) & !3;
        let mut attribute = Vec::with_capacity(4 + padded_len);
        attribute.extend_from_slice(&attribute_type.to_be_bytes());
        attribute.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attribute.extend_from_slice(value);
        attribute.resize(4 + padded_len, 0);
        attribute
    }

    fn response_with_attributes(tx_id: TxId, attributes: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(20 + attributes.len());
        response.extend_from_slice(&[0x01, 0x01]);
        response.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(tx_id.as_bytes());
        response.extend_from_slice(attributes);
        response
    }

    #[test]
    fn request_bytes_and_binding_parse_match_real_pinned_go_fork() {
        let tx_id = TxId::from_bytes(TX_ID_BYTES);
        let request = build_binding_request(tx_id);
        assert_eq!(request, GO_REQUEST);
        assert!(is_stun(&request));
        assert_eq!(parse_binding_request(&request), Ok(tx_id));
    }

    #[test]
    fn response_builder_matches_pinned_go_v4_v6_and_mapped_v6_bytes() {
        let tx_id = TxId::from_bytes(TX_ID_BYTES);
        let v4 = "192.0.2.7:54321".parse::<SocketAddr>().unwrap();
        let v6 = "[2001:db8::1234]:3210".parse::<SocketAddr>().unwrap();
        let mapped_v6 = "[::ffff:192.0.2.7]:65530".parse::<SocketAddr>().unwrap();

        assert_eq!(build_binding_response(tx_id, Some(v4)).as_slice(), &GO_RESPONSE_V4);
        assert_eq!(build_binding_response(tx_id, Some(v6)).as_slice(), &GO_RESPONSE_V6);
        assert_eq!(build_binding_response(tx_id, Some(mapped_v6)).as_slice(), &GO_RESPONSE_MAPPED_V6);
        assert!(build_binding_response(tx_id, None).is_empty());
    }

    #[test]
    fn response_parser_matches_pinned_go_xor_alt_and_ipv4_mapped_unmap() {
        let tx_id = TxId::from_bytes(TX_ID_BYTES);
        let v4 = "192.0.2.7:54321".parse::<SocketAddr>().unwrap();
        let v6 = "[2001:db8::1234]:3210".parse::<SocketAddr>().unwrap();
        let mapped_v4 = "192.0.2.7:65530".parse::<SocketAddr>().unwrap();

        assert_eq!(parse_binding_response(&GO_RESPONSE_V4), Ok((tx_id, v4)));
        assert_eq!(parse_binding_response(&GO_RESPONSE_V6), Ok((tx_id, v6)));
        assert_eq!(parse_binding_response(&GO_RESPONSE_MAPPED_V6), Ok((tx_id, mapped_v4)));

        let mut alternate_xor_type = GO_RESPONSE_V4;
        alternate_xor_type[20..22].copy_from_slice(&0x8020_u16.to_be_bytes());
        assert_eq!(parse_binding_response(&alternate_xor_type), Ok((tx_id, v4)));
    }

    #[test]
    fn response_parser_prefers_xor_then_falls_back_to_mapped_and_ignores_tail() {
        let tx_id = TxId::from_bytes(TX_ID_BYTES);
        let fallback = "192.0.2.9:4660".parse::<SocketAddr>().unwrap();
        let mapped_value = [0, 1, 0x12, 0x34, 192, 0, 2, 9];
        let mapped_attribute = make_attribute(1, &mapped_value);
        let only_mapped = response_with_attributes(tx_id, &mapped_attribute);
        assert_eq!(parse_binding_response(&only_mapped), Ok((tx_id, fallback)));

        let xor_attribute = make_attribute(0x0020, &GO_RESPONSE_V4[24..32]);
        let mut both = xor_attribute;
        both.extend_from_slice(&mapped_attribute);
        let both = response_with_attributes(tx_id, &both);
        assert_eq!(parse_binding_response(&both), Ok((tx_id, "192.0.2.7:54321".parse().unwrap())));

        let mut trailing = GO_RESPONSE_V4.to_vec();
        trailing.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parse_binding_response(&trailing), Ok((tx_id, "192.0.2.7:54321".parse().unwrap())));
    }

    #[test]
    fn response_parser_preserves_pinned_go_error_precedence_and_txid_results() {
        let tx_id = TxId::from_bytes(TX_ID_BYTES);
        let zero_tx_id = TxId::from_bytes([0; 12]);

        assert_eq!(
            parse_binding_response(&[0; 20]),
            Err(ResponseParseError { transaction_id: zero_tx_id, cause: ParseError::NotStun }),
        );
        let mut wrong_cookie = GO_RESPONSE_V4;
        wrong_cookie[7] ^= 1;
        assert_eq!(
            parse_binding_response(&wrong_cookie),
            Err(ResponseParseError { transaction_id: zero_tx_id, cause: ParseError::NotStun }),
        );
        let request = build_binding_request(tx_id);
        assert_eq!(
            parse_binding_response(&request),
            Err(ResponseParseError { transaction_id: tx_id, cause: ParseError::NotSuccessResponse }),
        );

        let mut oversized_attribute_length = GO_RESPONSE_V4;
        oversized_attribute_length[2..4].copy_from_slice(&64_u16.to_be_bytes());
        assert_eq!(
            parse_binding_response(&oversized_attribute_length),
            Err(ResponseParseError { transaction_id: tx_id, cause: ParseError::MalformedAttributes }),
        );

        let truncated_attribute = response_with_attributes(tx_id, &[0x00, 0x20, 0x00, 0x04, 0x00, 0x01]);
        assert_eq!(
            parse_binding_response(&truncated_attribute),
            Err(ResponseParseError { transaction_id: zero_tx_id, cause: ParseError::MalformedAttributes }),
        );

        let short_address = response_with_attributes(tx_id, &make_attribute(0x0020, &[0, 1, 0]));
        assert_eq!(
            parse_binding_response(&short_address),
            Err(ResponseParseError { transaction_id: zero_tx_id, cause: ParseError::MalformedAttributes }),
        );

        let unknown_family = response_with_attributes(tx_id, &make_attribute(0x0020, &[0, 3, 0x12, 0x34, 1, 2, 3, 4]));
        assert_eq!(
            parse_binding_response(&unknown_family),
            Err(ResponseParseError { transaction_id: zero_tx_id, cause: ParseError::MalformedAttributes }),
        );

        let short_mapped_address = response_with_attributes(tx_id, &make_attribute(1, &[0, 1, 0x12, 0x34]));
        assert_eq!(
            parse_binding_response(&short_mapped_address),
            Err(ResponseParseError { transaction_id: zero_tx_id, cause: ParseError::MalformedAttributes }),
        );

        let unknown_only = response_with_attributes(tx_id, &make_attribute(0x9999, &[1, 2, 3, 4]));
        assert_eq!(
            parse_binding_response(&unknown_only),
            Err(ResponseParseError { transaction_id: tx_id, cause: ParseError::MalformedAttributes }),
        );
        let zero_attributes = response_with_attributes(tx_id, &[]);
        assert_eq!(
            parse_binding_response(&zero_attributes),
            Err(ResponseParseError { transaction_id: tx_id, cause: ParseError::MalformedAttributes }),
        );
    }

    #[test]
    fn is_stun_keeps_the_pinned_forks_minimal_header_semantics() {
        let request = sample_request();
        assert!(is_stun(&request));

        let mut wrong_type = request.clone();
        wrong_type[1] = 2;
        assert!(is_stun(&wrong_type));

        let mut bad_top_bits = request.clone();
        bad_top_bits[0] = 0x40;
        assert!(!is_stun(&bad_top_bits));

        let mut bad_cookie = request.clone();
        bad_cookie[7] ^= 1;
        assert!(!is_stun(&bad_cookie));
        assert!(!is_stun(&request[..19]));
    }

    #[test]
    fn parser_error_precedence_and_ignored_header_length_match_go() {
        let request = sample_request();

        let mut wrong_cookie = request.clone();
        wrong_cookie[7] ^= 1;
        assert_eq!(parse_binding_request(&wrong_cookie), Err(ParseError::NotStun));

        let mut not_binding = request.clone();
        not_binding[1] = 2;
        assert_eq!(parse_binding_request(&not_binding), Err(ParseError::NotBindingRequest));

        let mut malformed = [request[..20].to_vec(), vec![0x80, 0x22, 0]].concat();
        assert_eq!(parse_binding_request(&malformed), Err(ParseError::MalformedAttributes));
        malformed[1] = 2;
        assert_eq!(parse_binding_request(&malformed), Err(ParseError::NotBindingRequest));

        let no_attributes = request[..20].to_vec();
        assert_eq!(parse_binding_request(&no_attributes), Err(ParseError::WrongSoftware));

        let mut wrong_software = request.clone();
        wrong_software[24] = b'T';
        recompute_fingerprint(&mut wrong_software);
        assert_eq!(parse_binding_request(&wrong_software), Err(ParseError::WrongSoftware));

        let missing_fingerprint = request[..32].to_vec();
        assert_eq!(parse_binding_request(&missing_fingerprint), Err(ParseError::NoFingerprint));

        let mut wrong_software_without_fingerprint = request[..32].to_vec();
        wrong_software_without_fingerprint[24] = b'T';
        assert_eq!(parse_binding_request(&wrong_software_without_fingerprint), Err(ParseError::WrongSoftware));

        let mut bad_fingerprint = request;
        *bad_fingerprint.last_mut().unwrap() ^= 1;
        assert_eq!(parse_binding_request(&bad_fingerprint), Err(ParseError::WrongFingerprint));
    }

    #[test]
    fn parse_error_text_matches_pinned_go_fork() {
        let cases = [
            (ParseError::NotStun, "response is not a STUN packet"),
            (ParseError::NotBindingRequest, "STUN request not a binding request"),
            (ParseError::NotSuccessResponse, "STUN packet is not a response"),
            (ParseError::MalformedAttributes, "STUN response has malformed attributes"),
            (ParseError::WrongSoftware, "STUN request came from non-Tailscale software"),
            (ParseError::NoFingerprint, "STUN request didn't end in fingerprint"),
            (ParseError::WrongFingerprint, "STUN request had bogus fingerprint"),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn attribute_padding_and_header_length_behavior_match_go() {
        let tx_id = TxId::from_bytes(TX_ID_BYTES);
        let request = sample_request();

        let mut mismatched_header_length = request.clone();
        mismatched_header_length[2..4].copy_from_slice(&0_u16.to_be_bytes());
        recompute_fingerprint(&mut mismatched_header_length);
        assert_eq!(parse_binding_request(&mismatched_header_length), Ok(tx_id));

        let mut nonzero_padding = request[..32].to_vec();
        nonzero_padding.extend_from_slice(&[0x90, 0x00, 0x00, 0x01, 0xaa, 0x66, 0x77, 0x88]);
        nonzero_padding.extend_from_slice(&request[32..]);
        nonzero_padding[2..4].copy_from_slice(&28_u16.to_be_bytes());
        recompute_fingerprint(&mut nonzero_padding);
        assert_eq!(parse_binding_request(&nonzero_padding), Ok(tx_id));

        let mut zero_length_unknown = request[..32].to_vec();
        zero_length_unknown.extend_from_slice(&[0x90, 0x00, 0x00, 0x00]);
        zero_length_unknown.extend_from_slice(&request[32..]);
        zero_length_unknown[2..4].copy_from_slice(&24_u16.to_be_bytes());
        recompute_fingerprint(&mut zero_length_unknown);
        assert_eq!(parse_binding_request(&zero_length_unknown), Ok(tx_id));

        let mut trailing_attribute = request;
        trailing_attribute.extend_from_slice(&[0x90, 0x00, 0x00, 0x00]);
        assert_eq!(parse_binding_request(&trailing_attribute), Err(ParseError::NoFingerprint));
    }

    #[test]
    fn tx_id_generation_uses_csprng_and_returns_entropy_errors() {
        let generated = super::generate_tx_id_with_rng(&mut FixedRng).unwrap();
        assert_eq!(generated.as_bytes(), &[0x5a; 12]);

        let error = super::generate_tx_id_with_rng(&mut FailingRng).unwrap_err();
        assert!(error.to_string().contains("entropy unavailable"));
    }

    struct FixedRng;

    impl TryRngCore for FixedRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0x5a5a_5a5a)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0x5a5a_5a5a_5a5a_5a5a)
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            destination.fill(0x5a);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedRng {}

    struct FailingRng;

    impl TryRngCore for FailingRng {
        type Error = io::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(io::Error::other("entropy unavailable"))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(io::Error::other("entropy unavailable"))
        }

        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            Err(io::Error::other("entropy unavailable"))
        }
    }

    impl TryCryptoRng for FailingRng {}
}
