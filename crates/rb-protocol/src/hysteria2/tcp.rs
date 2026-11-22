//! Hysteria2 TCP proxy framing from sing-quic `hysteria2/internal/protocol/proxy.go`.
//!
//! Each proxied TCP connection is a raw QUIC bidirectional stream. The client
//! begins with frame type 0x401, a QUIC-varint-length destination string, and
//! a QUIC-varint-length random padding string; the server replies with a
//! status byte, message, and padding before proxy payload starts.
use std::io;

const TCP_REQUEST_FRAME: u64 = 0x401;
const MAX_DESTINATION_LEN: usize = 2048;
const MAX_MESSAGE_LEN: usize = 2048;
const MAX_PADDING_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponsePrefix {
    pub status: u8,
    pub message: Vec<u8>,
    pub consumed: usize,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn put_varint(output: &mut Vec<u8>, value: u64) -> io::Result<()> {
    if value < (1 << 6) {
        output.push(value as u8);
    } else if value < (1 << 14) {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else if value < (1 << 62) {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        return Err(invalid("QUIC varint exceeds 62 bits"));
    }
    Ok(())
}

fn take_varint(input: &[u8], position: &mut usize) -> io::Result<u64> {
    let first = *input.get(*position).ok_or_else(|| invalid("truncated QUIC varint"))?;
    let length = 1usize << (first >> 6);
    let end = position.checked_add(length).ok_or_else(|| invalid("length overflow"))?;
    let encoded = input.get(*position..end).ok_or_else(|| invalid("truncated QUIC varint"))?;
    let mut value = (encoded[0] & 0x3f) as u64;
    for byte in &encoded[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *position = end;
    Ok(value)
}

/// Encodes the opening frame for a Hysteria2 TCP request.
pub fn encode_tcp_request(destination: &str, padding: &[u8]) -> io::Result<Vec<u8>> {
    if destination.is_empty() || destination.len() > MAX_DESTINATION_LEN {
        return Err(invalid("invalid Hysteria2 TCP destination length"));
    }
    if padding.len() > MAX_PADDING_LEN {
        return Err(invalid("Hysteria2 TCP padding exceeds the limit"));
    }
    let mut output = Vec::with_capacity(24 + destination.len() + padding.len());
    put_varint(&mut output, TCP_REQUEST_FRAME)?;
    put_varint(&mut output, destination.len() as u64)?;
    output.extend_from_slice(destination.as_bytes());
    put_varint(&mut output, padding.len() as u64)?;
    output.extend_from_slice(padding);
    Ok(output)
}

/// Decodes the server's TCP response prefix, preserving its message bytes.
/// `consumed` identifies the first byte of proxied TCP payload, if any.
pub fn decode_tcp_response_prefix(input: &[u8]) -> io::Result<TcpResponsePrefix> {
    let status = *input.first().ok_or_else(|| invalid("truncated Hysteria2 TCP response"))?;
    let mut position = 1;
    let message_length = usize::try_from(take_varint(input, &mut position)?)
        .map_err(|_| invalid("Hysteria2 TCP message length overflow"))?;
    if message_length > MAX_MESSAGE_LEN {
        return Err(invalid("Hysteria2 TCP message exceeds the limit"));
    }
    let message_end = position.checked_add(message_length).ok_or_else(|| invalid("length overflow"))?;
    let message = input.get(position..message_end).ok_or_else(|| invalid("truncated Hysteria2 TCP message"))?.to_vec();
    position = message_end;
    let padding_length = usize::try_from(take_varint(input, &mut position)?)
        .map_err(|_| invalid("Hysteria2 TCP padding length overflow"))?;
    if padding_length > MAX_PADDING_LEN {
        return Err(invalid("Hysteria2 TCP padding exceeds the limit"));
    }
    let consumed = position.checked_add(padding_length).ok_or_else(|| invalid("length overflow"))?;
    if input.get(position..consumed).is_none() {
        return Err(invalid("truncated Hysteria2 TCP padding"));
    }
    Ok(TcpResponsePrefix { status, message, consumed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_request_uses_upstream_frame_and_quic_varints() {
        let encoded = encode_tcp_request("example.com:443", b"pad").unwrap();
        let mut position = 0;
        assert_eq!(take_varint(&encoded, &mut position).unwrap(), TCP_REQUEST_FRAME);
        let address_length = take_varint(&encoded, &mut position).unwrap() as usize;
        assert_eq!(&encoded[position..position + address_length], b"example.com:443");
        position += address_length;
        let padding_length = take_varint(&encoded, &mut position).unwrap() as usize;
        assert_eq!(&encoded[position..position + padding_length], b"pad");
        assert_eq!(position + padding_length, encoded.len());
    }

    #[test]
    fn tcp_response_prefix_preserves_status_message_padding_and_payload_boundary() {
        let mut encoded = vec![0];
        put_varint(&mut encoded, 3).unwrap();
        encoded.extend_from_slice(b"ok!");
        put_varint(&mut encoded, 2).unwrap();
        encoded.extend_from_slice(b"xy");
        encoded.extend_from_slice(b"payload");

        let prefix = decode_tcp_response_prefix(&encoded).unwrap();
        assert_eq!(prefix.status, 0);
        assert_eq!(prefix.message, b"ok!");
        assert_eq!(&encoded[prefix.consumed..], b"payload");
    }

    #[test]
    fn tcp_response_prefix_rejects_truncation_and_oversized_lengths() {
        assert!(decode_tcp_response_prefix(&[]).is_err());
        assert!(decode_tcp_response_prefix(&[0, 3, b'o']).is_err());
        let mut oversized = vec![0];
        put_varint(&mut oversized, (MAX_MESSAGE_LEN + 1) as u64).unwrap();
        assert!(decode_tcp_response_prefix(&oversized).is_err());
    }

    #[test]
    fn tcp_request_rejects_empty_or_oversized_fields() {
        assert!(encode_tcp_request("", b"").is_err());
        assert!(encode_tcp_request(&"x".repeat(MAX_DESTINATION_LEN + 1), b"").is_err());
        assert!(encode_tcp_request("example.com:443", &vec![0; MAX_PADDING_LEN + 1]).is_err());
    }
}
