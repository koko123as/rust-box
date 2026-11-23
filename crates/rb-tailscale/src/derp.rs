//! DERP slice primitives from the Tailscale fork pinned by sing-box v1.14.4.
//!
//! This module provides header codecs, bounded frame slice reads/writes, a
//! server-greeting parser, ClientInfo JSON encoding and in-memory encrypted frame
//! construction, and bounded in-memory ServerInfo frame/payload parsing. Node-key
//! box primitives live in `disco_crypto`; a streaming DERP client/server,
//! transport lifecycle, and server authentication remain unimplemented.

use std::error::Error;
use std::fmt;

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::{disco_crypto::NodeBoxError, NodePrivate, NodePublic};

/// A DERP frame header contains a type byte and a big-endian u32 payload length.
pub const FRAME_HEADER_LEN: usize = 5;
/// Maximum payload length accepted by the pinned fork's `WriteFrame`.
pub const MAX_FRAME_WRITE_SIZE: usize = 10 << 20;
/// Maximum single frame payload accepted by the pinned fork's `Client.Recv`.
pub const MAX_CLIENT_RECV_FRAME_LEN: usize = 1 << 20;
/// Magic prefix of a DERP server-key greeting.
pub const MAGIC: [u8; 8] = *b"DERP\xf0\x9f\x94\x91";
/// The server-key frame type.
pub const FRAME_SERVER_KEY: FrameType = FrameType(0x01);
/// The client-info frame type.
pub const FRAME_CLIENT_INFO: FrameType = FrameType(0x02);
/// The server-info frame type.
pub const FRAME_SERVER_INFO: FrameType = FrameType(0x03);
/// DERP protocol version advertised by the pinned fork.
pub const PROTOCOL_VERSION: isize = 2;

/// A raw DERP frame type. Unknown values are preserved, as in Go's `FrameType`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameType(pub u8);

/// The type and payload length of a DERP frame, excluding the five-byte header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub frame_type: FrameType,
    pub frame_len: u32,
}

impl FrameHeader {
    /// Encodes a frame header without writing a payload or flushing a stream.
    pub fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let length = self.frame_len.to_be_bytes();
        [self.frame_type.0, length[0], length[1], length[2], length[3]]
    }
}

/// An incomplete header or a frame type differing from the expected type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameHeaderError {
    /// A complete five-byte header was not available; the input was not consumed.
    Incomplete,
    /// The header was consumed and its actual length is retained, as in the Go fork.
    UnexpectedType { got: FrameType, want: FrameType, frame_len: u32 },
}

impl fmt::Display for FrameHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Incomplete => f.write_str("EOF"),
            Self::UnexpectedType { got, want, .. } => {
                write!(f, "bad frame type 0x{:X}, want 0x{:X}", got.0, want.0)
            }
        }
    }
}

impl Error for FrameHeaderError {}

/// Reads a complete header and advances `input` only on success.
///
/// This slice API models available bytes only. It cannot represent buffered I/O
/// failures other than missing bytes, and it does not read the payload.
pub fn read_frame_header(input: &mut &[u8]) -> Result<FrameHeader, FrameHeaderError> {
    let Some(header) = input.get(..FRAME_HEADER_LEN) else {
        return Err(FrameHeaderError::Incomplete);
    };
    let frame = FrameHeader {
        frame_type: FrameType(header[0]),
        frame_len: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
    };
    *input = &input[FRAME_HEADER_LEN..];
    Ok(frame)
}

/// Reads and consumes a complete header before comparing its type.
///
/// On mismatch, the error retains the decoded length; Go returns the length
/// alongside the error despite the upstream comment saying otherwise.
pub fn read_frame_type_header(input: &mut &[u8], want: FrameType) -> Result<u32, FrameHeaderError> {
    let header = read_frame_header(input)?;
    if header.frame_type != want {
        return Err(FrameHeaderError::UnexpectedType { got: header.frame_type, want, frame_len: header.frame_len });
    }
    Ok(header.frame_len)
}

/// The result of the pinned fork's bounded frame read on a byte slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadFrameError {
    /// The complete header was unavailable; no input was consumed.
    IncompleteHeader,
    /// The header was consumed but no payload bytes were consumed.
    ExceedsLimit { frame_len: u32, max_size: u32 },
    /// A payload read started with no available bytes, or a discard ended early.
    EndOfInput,
    /// A payload read received some, but not all, required bytes.
    UnexpectedEndOfInput,
    /// The whole payload was consumed, but only the output prefix was copied.
    ShortBuffer { header: FrameHeader },
}

impl fmt::Display for ReadFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::IncompleteHeader | Self::EndOfInput => f.write_str("EOF"),
            Self::UnexpectedEndOfInput => f.write_str("unexpected EOF"),
            Self::ExceedsLimit { frame_len, max_size } => {
                write!(f, "frame header size {frame_len} exceeds reader limit of {max_size}")
            }
            Self::ShortBuffer { .. } => f.write_str("short buffer"),
        }
    }
}

impl Error for ReadFrameError {}

/// Failure to append a complete frame to an output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteFrameError {
    /// The payload exceeds the pinned fork's 10 MiB write limit.
    UnreasonablyLarge,
    /// Output buffer allocation failed; no frame bytes were appended.
    Allocation,
}

impl fmt::Display for WriteFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreasonablyLarge => f.write_str("unreasonably large frame write"),
            Self::Allocation => f.write_str("unable to allocate DERP frame buffer"),
        }
    }
}

impl Error for WriteFrameError {}

/// Appends a frame header and payload, rejecting payloads over 10 MiB before
/// changing `output`, as in the fork's `WriteFrame` size check.
///
/// Unlike Go's buffered writer, this writes to a `Vec`, does not flush a stream,
/// and reports allocation failure without appending a partial frame.
pub fn write_frame(output: &mut Vec<u8>, frame_type: FrameType, payload: &[u8]) -> Result<(), WriteFrameError> {
    if payload.len() > MAX_FRAME_WRITE_SIZE {
        return Err(WriteFrameError::UnreasonablyLarge);
    }
    output.try_reserve(FRAME_HEADER_LEN + payload.len()).map_err(|_| WriteFrameError::Allocation)?;
    let header = FrameHeader { frame_type, frame_len: payload.len() as u32 };
    output.extend_from_slice(&header.encode());
    output.extend_from_slice(payload);
    Ok(())
}

/// Reads a bounded DERP frame into `output`, consuming discarded payload bytes
/// when the output is shorter than the advertised frame, matching Go `readFrame`.
///
/// Missing bytes are treated as end-of-input; this slice interface cannot model
/// arbitrary I/O errors or wait for more data. An over-limit error consumes only
/// the header; callers must not continue parsing that payload as a fresh frame.
pub fn read_frame(input: &mut &[u8], max_size: u32, output: &mut [u8]) -> Result<FrameHeader, ReadFrameError> {
    let header = read_frame_header(input).map_err(|_| ReadFrameError::IncompleteHeader)?;
    if header.frame_len > max_size {
        return Err(ReadFrameError::ExceedsLimit { frame_len: header.frame_len, max_size });
    }

    let frame_len = header.frame_len as usize;
    let copy_len = frame_len.min(output.len());
    let available = copy_len.min(input.len());
    output[..available].copy_from_slice(&input[..available]);
    *input = &input[available..];
    if available < copy_len {
        return Err(if available == 0 { ReadFrameError::EndOfInput } else { ReadFrameError::UnexpectedEndOfInput });
    }
    let discard = frame_len - copy_len;
    if input.len() < discard {
        *input = &[];
        return Err(ReadFrameError::EndOfInput);
    }
    *input = &input[discard..];
    if discard != 0 {
        return Err(ReadFrameError::ShortBuffer { header });
    }
    Ok(header)
}

/// Failure to parse a DERP server-key greeting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerGreetingError {
    Read(ReadFrameError),
    Invalid,
}

impl fmt::Display for ServerGreetingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(err) => err.fmt(f),
            Self::Invalid => f.write_str("invalid server greeting"),
        }
    }
}

impl Error for ServerGreetingError {}

/// Parses the server-key greeting using the fork's 1024-byte frame limit.
/// Extra payload bytes are consumed and ignored, as in `recvServerKey`.
///
/// This parser accepts a zero public key like the fork's parser. It does not
/// authenticate the server, establish encryption, or authorize a connection.
pub fn read_server_greeting(input: &mut &[u8]) -> Result<NodePublic, ServerGreetingError> {
    let mut body = [0u8; 40];
    let header = match read_frame(input, 1 << 10, &mut body) {
        Ok(header) | Err(ReadFrameError::ShortBuffer { header }) => header,
        Err(err) => return Err(ServerGreetingError::Read(err)),
    };
    if header.frame_len < body.len() as u32 || header.frame_type != FRAME_SERVER_KEY || body[..MAGIC.len()] != MAGIC {
        return Err(ServerGreetingError::Invalid);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[MAGIC.len()..]);
    Ok(NodePublic::from_raw32(key))
}

/// Client metadata encoded by the pinned fork before NaCl box sealing.
///
/// This type only serializes the plaintext JSON; it does not seal or transmit a
/// DERP ClientInfo frame. Its field omission, order, and string escaping match
/// Go `encoding/json` for the corresponding fork `derp.ClientInfo` fields.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ClientInfo {
    /// Zero means omitted, matching the fork's `meshKey,omitzero` tag.
    pub mesh_key: [u8; 32],
    /// Zero means omitted, matching the fork's `version,omitempty` tag.
    pub version: isize,
    /// Always emitted, matching the untagged exported Go field.
    pub can_ack_pings: bool,
    /// False means omitted, matching `json:",omitempty"`.
    pub is_prober: bool,
    /// Empty means omitted, matching `json:",omitempty"`.
    pub app_name: String,
}

impl ClientInfo {
    /// Encodes the plaintext exactly in the pinned Go fork's struct field order.
    pub fn to_json(&self) -> String {
        let mut output = String::from("{");
        let mut first = true;
        if self.mesh_key.iter().any(|byte| *byte != 0) {
            push_json_field_name(&mut output, &mut first, "meshKey");
            output.push('"');
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for byte in self.mesh_key {
                output.push(HEX[(byte >> 4) as usize] as char);
                output.push(HEX[(byte & 0x0f) as usize] as char);
            }
            output.push('"');
        }
        if self.version != 0 {
            push_json_field_name(&mut output, &mut first, "version");
            output.push_str(&self.version.to_string());
        }
        push_json_field_name(&mut output, &mut first, "CanAckPings");
        output.push_str(if self.can_ack_pings { "true" } else { "false" });
        if self.is_prober {
            push_json_field_name(&mut output, &mut first, "IsProber");
            output.push_str("true");
        }
        if !self.app_name.is_empty() {
            push_json_field_name(&mut output, &mut first, "AppName");
            push_go_json_string(&mut output, &self.app_name);
        }
        output.push('}');
        output
    }
}

/// Failure to build a complete ClientInfo frame in memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientInfoFrameError {
    Box(NodeBoxError),
    Allocation,
    Frame(WriteFrameError),
}

impl fmt::Display for ClientInfoFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Box(error) => error.fmt(f),
            Self::Allocation => f.write_str("unable to allocate DERP ClientInfo frame buffer"),
            Self::Frame(error) => error.fmt(f),
        }
    }
}

impl Error for ClientInfoFrameError {}

/// Builds a complete ClientInfo frame in memory using a fresh OS-CSPRNG nonce.
///
/// The result includes the five-byte frame header, sender's raw 32-byte node
/// public key, and NaCl-boxed ClientInfo JSON. It does not write to or flush a
/// stream, authenticate the server greeting, or manage a DERP connection.
pub fn build_client_info_frame(
    private: &NodePrivate,
    server: &NodePublic,
    info: &ClientInfo,
) -> Result<Vec<u8>, ClientInfoFrameError> {
    let sender = private.public().map_err(|_| ClientInfoFrameError::Box(NodeBoxError::ZeroPrivateKey))?;
    let plaintext = info.to_json();
    let sealed = private.seal_to(server, plaintext.as_bytes()).map_err(ClientInfoFrameError::Box)?;
    encode_client_info_frame(sender, &sealed)
}

#[cfg(test)]
fn build_client_info_frame_with_nonce(
    private: &NodePrivate,
    server: &NodePublic,
    info: &ClientInfo,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, ClientInfoFrameError> {
    let sender = private.public().map_err(|_| ClientInfoFrameError::Box(NodeBoxError::ZeroPrivateKey))?;
    let plaintext = info.to_json();
    let sealed = private.seal_to_with_nonce(server, plaintext.as_bytes(), nonce).map_err(ClientInfoFrameError::Box)?;
    encode_client_info_frame(sender, &sealed)
}

fn encode_client_info_frame(sender: NodePublic, sealed: &[u8]) -> Result<Vec<u8>, ClientInfoFrameError> {
    let payload_len = 32usize.checked_add(sealed.len()).ok_or(ClientInfoFrameError::Allocation)?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(payload_len).map_err(|_| ClientInfoFrameError::Allocation)?;
    payload.extend_from_slice(&sender.raw_bytes());
    payload.extend_from_slice(sealed);

    let mut frame = Vec::new();
    write_frame(&mut frame, FRAME_CLIENT_INFO, &payload).map_err(ClientInfoFrameError::Frame)?;
    Ok(frame)
}

/// NaCl box nonce size used by DERP ServerInfo payloads.
pub const SERVER_INFO_NONCE_LEN: usize = 24;
/// Maximum plaintext ServerInfo size accepted by the pinned fork.
pub const MAX_SERVER_INFO_JSON_LEN: usize = 1 << 20;
/// Maximum encrypted ServerInfo payload accepted by the pinned fork.
pub const MAX_SERVER_INFO_PAYLOAD_LEN: usize = SERVER_INFO_NONCE_LEN + MAX_SERVER_INFO_JSON_LEN;

/// The numeric rate limits carried by the pinned fork's DERP ServerInfo JSON.
///
/// The decoder preserves Go's ASCII case-insensitive field matching, duplicate
/// field order, null-as-no-op behavior, and signed 64-bit integer range. It
/// rejects non-ASCII field names rather than silently misreading Go's Unicode
/// simple-fold matches; malformed UTF-8 and Go's exact JSON error wording also
/// intentionally remain outside this parser's compatibility claim.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerInfo {
    pub version: i64,
    pub token_bucket_bytes_per_second: i64,
    pub token_bucket_bytes_burst: i64,
}

impl<'de> Deserialize<'de> for ServerInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ServerInfoVisitor;

        impl<'de> Visitor<'de> for ServerInfoVisitor {
            type Value = ServerInfo;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a DERP ServerInfo object or null")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ServerInfo::default())
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut info = ServerInfo::default();
                while let Some(field) = map.next_key::<String>()? {
                    if !field.is_ascii() {
                        return Err(de::Error::custom("non-ASCII ServerInfo field names are unsupported"));
                    }
                    if field.eq_ignore_ascii_case("version") {
                        if let Some(value) = map.next_value::<Option<i64>>()? {
                            info.version = value;
                        }
                    } else if field.eq_ignore_ascii_case("TokenBucketBytesPerSecond") {
                        if let Some(value) = map.next_value::<Option<i64>>()? {
                            info.token_bucket_bytes_per_second = value;
                        }
                    } else if field.eq_ignore_ascii_case("TokenBucketBytesBurst") {
                        if let Some(value) = map.next_value::<Option<i64>>()? {
                            info.token_bucket_bytes_burst = value;
                        }
                    } else {
                        let _: IgnoredAny = map.next_value()?;
                    }
                }
                Ok(info)
            }
        }

        deserializer.deserialize_any(ServerInfoVisitor)
    }
}

/// Errors while validating and opening an encrypted DERP ServerInfo payload.
#[derive(Debug)]
pub enum ServerInfoError {
    ShortFrame { got: usize },
    LongFrame { got: usize, max: usize },
    Box(NodeBoxError),
    Json(serde_json::Error),
}

impl fmt::Display for ServerInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortFrame { .. } => f.write_str("short serverInfo frame"),
            Self::LongFrame { .. } => f.write_str("long serverInfo frame"),
            Self::Box(error) => write!(f, "failed to open DERP ServerInfo box: {error}"),
            Self::Json(error) => write!(f, "invalid JSON: {error}"),
        }
    }
}

impl Error for ServerInfoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Box(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::ShortFrame { .. } | Self::LongFrame { .. } => None,
        }
    }
}

/// Opens and parses a DERP ServerInfo encrypted payload (without its 5-byte
/// frame header), matching the pinned fork's nonce/size checks and box layout.
///
/// Authentication is checked before JSON parsing, so unauthenticated plaintext
/// is never returned. This helper does not read a frame from a stream, validate
/// the DERP greeting, establish connection state, or update a rate limiter.
pub fn parse_server_info_payload(
    client_private: &NodePrivate,
    server_public: &NodePublic,
    payload: &[u8],
) -> Result<ServerInfo, ServerInfoError> {
    if payload.len() < SERVER_INFO_NONCE_LEN {
        return Err(ServerInfoError::ShortFrame { got: payload.len() });
    }
    if payload.len() > MAX_SERVER_INFO_PAYLOAD_LEN {
        return Err(ServerInfoError::LongFrame { got: payload.len(), max: MAX_SERVER_INFO_PAYLOAD_LEN });
    }
    let plaintext = client_private.open_from(server_public, payload).map_err(ServerInfoError::Box)?;
    serde_json::from_slice(&plaintext).map_err(ServerInfoError::Json)
}

/// Failures while decoding one complete in-memory ServerInfo DERP frame.
#[derive(Debug)]
pub enum ServerInfoFrameError {
    IncompleteHeader,
    Oversized { frame_len: u32, max_size: usize },
    IncompletePayload { expected: usize, got: usize },
    UnexpectedType { got: FrameType },
    Payload(ServerInfoError),
}

impl fmt::Display for ServerInfoFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteHeader => f.write_str("EOF"),
            Self::Oversized { frame_len, .. } => write!(f, "unexpectedly large frame of {frame_len} bytes returned"),
            Self::IncompletePayload { got: 0, .. } => f.write_str("EOF"),
            Self::IncompletePayload { .. } => f.write_str("unexpected EOF"),
            Self::UnexpectedType { got } => {
                write!(f, "bad frame type 0x{:X}, want 0x{:X}", got.0, FRAME_SERVER_INFO.0)
            }
            Self::Payload(error) => error.fmt(f),
        }
    }
}

impl Error for ServerInfoFrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Payload(error) => Some(error),
            Self::IncompleteHeader
            | Self::Oversized { .. }
            | Self::IncompletePayload { .. }
            | Self::UnexpectedType { .. } => None,
        }
    }
}

/// Parses one complete ServerInfo frame from an in-memory byte slice.
///
/// The returned `usize` is the number of bytes consumed, so a following frame
/// can remain in the same input. This applies the pinned fork's `Client.Recv`
/// 1 MiB frame limit before payload processing and then delegates to
/// [`parse_server_info_payload`]. Unlike `Client.Recv`, this strict helper
/// returns an error for a non-ServerInfo frame instead of skipping it, and it
/// does not implement stream I/O, buffering, connection state, or flushing.
pub fn parse_server_info_frame(
    client_private: &NodePrivate,
    server_public: &NodePublic,
    frame: &[u8],
) -> Result<(ServerInfo, usize), ServerInfoFrameError> {
    let mut after_header = frame;
    let header = read_frame_header(&mut after_header).map_err(|_| ServerInfoFrameError::IncompleteHeader)?;
    if header.frame_len > MAX_CLIENT_RECV_FRAME_LEN as u32 {
        return Err(ServerInfoFrameError::Oversized {
            frame_len: header.frame_len,
            max_size: MAX_CLIENT_RECV_FRAME_LEN,
        });
    }
    let payload_len = header.frame_len as usize;
    let available = after_header.len().min(payload_len);
    if available < payload_len {
        return Err(ServerInfoFrameError::IncompletePayload { expected: payload_len, got: available });
    }
    if header.frame_type != FRAME_SERVER_INFO {
        return Err(ServerInfoFrameError::UnexpectedType { got: header.frame_type });
    }
    let info = parse_server_info_payload(client_private, server_public, &after_header[..payload_len])
        .map_err(ServerInfoFrameError::Payload)?;
    Ok((info, FRAME_HEADER_LEN + payload_len))
}

fn push_json_field_name(output: &mut String, first: &mut bool, name: &str) {
    if !*first {
        output.push(',');
    }
    *first = false;
    output.push('"');
    output.push_str(name);
    output.push_str("\":");
}

fn push_go_json_string(output: &mut String, value: &str) {
    let encoded = serde_json::to_string(value).expect("a Rust string is always JSON-serializable");
    for character in encoded.chars() {
        match character {
            '<' => output.push_str("\\u003c"),
            '>' => output.push_str("\\u003e"),
            '&' => output.push_str("\\u0026"),
            '\u{2028}' => output.push_str("\\u2028"),
            '\u{2029}' => output.push_str("\\u2029"),
            other => output.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_client_info_frame, build_client_info_frame_with_nonce, read_frame, read_frame_header,
        read_frame_type_header, read_server_greeting, write_frame, ClientInfo, ClientInfoFrameError, FrameHeader,
        FrameHeaderError, FrameType, ReadFrameError, ServerGreetingError, WriteFrameError, FRAME_CLIENT_INFO,
        FRAME_SERVER_KEY, MAGIC, MAX_FRAME_WRITE_SIZE, PROTOCOL_VERSION,
    };
    use crate::{disco_crypto::NodeBoxError, NodePrivate, NodePublic};

    fn decode_hex(input: &str) -> Vec<u8> {
        let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs.iter().map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
    }

    #[test]
    fn client_info_frame_matches_pinned_go_send_client_key_vector() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();
        let info = ClientInfo {
            mesh_key: std::array::from_fn(|index| index as u8),
            version: PROTOCOL_VERSION,
            can_ack_pings: true,
            is_prober: true,
            app_name: "rust-box".to_owned(),
        };
        let nonce = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51,
            0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        ];
        let actual = build_client_info_frame_with_nonce(&alice, &bob_public, &info, &nonce).unwrap();
        let expected = decode_hex("02000000da8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f404142434445464748494a4b4c4d4e4f5051525354555657147303b734c84218a6821b8dee24d22ac5172debbee276b1da71a1409d48486a531776a875c9d0971161c587ba67a3d2ed00c683094a625a11c10abc9d0385c219127178b0b738ea5398c692734938b6c0994ce794c17e230c9e26b5663a6b77eaa2080b9d358beef3dad000b7081fafc273be933efcaeaa98c6467c436f71cb0800f28203d5475722631274fc55ff8f67757a9331be93ca2a1f5f6bb3661f03e1d9");
        assert_eq!(actual, expected);

        let mut remaining = actual.as_slice();
        let mut payload = vec![0; actual.len() - super::FRAME_HEADER_LEN];
        let header = read_frame(&mut remaining, MAX_FRAME_WRITE_SIZE as u32, &mut payload).unwrap();
        assert_eq!(header.frame_type, FRAME_CLIENT_INFO);
        assert_eq!(header.frame_len as usize, payload.len());
        assert!(remaining.is_empty());
        let alice_public = alice.public().unwrap();
        assert_eq!(&payload[..32], &alice_public.raw_bytes());
        assert_eq!(bob.open_from(&alice_public, &payload[32..]).unwrap(), info.to_json().as_bytes());
    }

    #[test]
    fn client_info_frame_builder_uses_fresh_nonce_and_fails_closed_on_zero_keys() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();
        let info = ClientInfo { version: PROTOCOL_VERSION, ..ClientInfo::default() };
        let first = build_client_info_frame(&alice, &bob_public, &info).unwrap();
        let second = build_client_info_frame(&alice, &bob_public, &info).unwrap();
        assert_eq!(&first[..super::FRAME_HEADER_LEN], &second[..super::FRAME_HEADER_LEN]);
        assert_ne!(
            &first[super::FRAME_HEADER_LEN + 32..super::FRAME_HEADER_LEN + 32 + 24],
            &second[super::FRAME_HEADER_LEN + 32..super::FRAME_HEADER_LEN + 32 + 24]
        );

        let zero_private = NodePrivate::from_text(&format!("privkey:{}", "00".repeat(32))).unwrap();
        assert_eq!(
            build_client_info_frame(&zero_private, &bob_public, &info),
            Err(ClientInfoFrameError::Box(NodeBoxError::ZeroPrivateKey))
        );
        assert_eq!(
            build_client_info_frame(&alice, &NodePublic::from_raw32([0; 32]), &info),
            Err(ClientInfoFrameError::Box(NodeBoxError::ZeroPeerPublicKey))
        );
    }

    #[test]
    fn server_info_payload_opens_pinned_go_box_fixture() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let payload = decode_hex("808182838485868788898a8b8c8d8e8f90919293949596972a5043cecfb67d977e3a71109462311a38a15b673d7b2bf55da90ef8f0d0c5313f73665a84fefee88e79c04d9f28b8eedadcd657528c5f0c7a08671cf92cd641f0e77fae5c0817566ac2b69be71d61523ec54dd49e137aaa9e0e19cb487e0f7557d9");
        let info = super::parse_server_info_payload(&alice, &bob.public().unwrap(), &payload).unwrap();
        assert_eq!(
            info,
            super::ServerInfo {
                version: 2,
                token_bucket_bytes_per_second: 16_777_216,
                token_bucket_bytes_burst: 4_194_304,
            }
        );
    }

    #[test]
    fn server_info_payload_enforces_length_and_authentication_before_json() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();

        assert!(matches!(
            super::parse_server_info_payload(&alice, &bob_public, &[0; 23]),
            Err(super::ServerInfoError::ShortFrame { got: 23 })
        ));
        assert!(matches!(
            super::parse_server_info_payload(
                &alice,
                &bob_public,
                &vec![0; super::MAX_SERVER_INFO_PAYLOAD_LEN + 1]
            ),
            Err(super::ServerInfoError::LongFrame { got, max })
                if got == super::MAX_SERVER_INFO_PAYLOAD_LEN + 1 && max == super::MAX_SERVER_INFO_PAYLOAD_LEN
        ));
        assert!(matches!(
            super::parse_server_info_payload(&alice, &bob_public, &[0; super::SERVER_INFO_NONCE_LEN]),
            Err(super::ServerInfoError::Box(NodeBoxError::Authentication))
        ));

        let mut tampered = decode_hex("808182838485868788898a8b8c8d8e8f90919293949596972a5043cecfb67d977e3a71109462311a38a15b673d7b2bf55da90ef8f0d0c5313f73665a84fefee88e79c04d9f28b8eedadcd657528c5f0c7a08671cf92cd641f0e77fae5c0817566ac2b69be71d61523ec54dd49e137aaa9e0e19cb487e0f7557d9");
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            super::parse_server_info_payload(&alice, &bob_public, &tampered),
            Err(super::ServerInfoError::Box(NodeBoxError::Authentication))
        ));
        assert!(matches!(
            super::parse_server_info_payload(&alice, &NodePublic::from_raw32([0; 32]), &[0; 24]),
            Err(super::ServerInfoError::Box(NodeBoxError::ZeroPeerPublicKey))
        ));
    }

    #[test]
    fn server_info_frame_consumes_one_bounded_frame_and_preserves_the_next() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let payload = decode_hex("808182838485868788898a8b8c8d8e8f90919293949596972a5043cecfb67d977e3a71109462311a38a15b673d7b2bf55da90ef8f0d0c5313f73665a84fefee88e79c04d9f28b8eedadcd657528c5f0c7a08671cf92cd641f0e77fae5c0817566ac2b69be71d61523ec54dd49e137aaa9e0e19cb487e0f7557d9");
        let mut wire = Vec::new();
        write_frame(&mut wire, super::FRAME_SERVER_INFO, &payload).unwrap();
        let consumed = wire.len();
        wire.extend_from_slice(&[0x06, 0, 0, 0, 0]);

        let (info, frame_len) = super::parse_server_info_frame(&alice, &bob.public().unwrap(), &wire).unwrap();
        assert_eq!(frame_len, consumed);
        assert_eq!(&wire[frame_len..], &[0x06, 0, 0, 0, 0]);
        assert_eq!(info.version, 2);
        assert_eq!(info.token_bucket_bytes_per_second, 16_777_216);
        assert_eq!(info.token_bucket_bytes_burst, 4_194_304);
    }

    #[test]
    fn server_info_frame_matches_client_recv_header_and_size_failure_order() {
        let alice =
            NodePrivate::from_text("privkey:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let bob =
            NodePrivate::from_text("privkey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
        let bob_public = bob.public().unwrap();

        for len in 0..super::FRAME_HEADER_LEN {
            assert!(matches!(
                super::parse_server_info_frame(&alice, &bob_public, &[0; 5][..len]),
                Err(super::ServerInfoFrameError::IncompleteHeader)
            ));
        }
        let too_large = FrameHeader {
            frame_type: super::FRAME_SERVER_INFO,
            frame_len: (super::MAX_CLIENT_RECV_FRAME_LEN + 1) as u32,
        }
        .encode();
        let oversized_error = super::parse_server_info_frame(&alice, &bob_public, &too_large).unwrap_err();
        assert_eq!(
            oversized_error.to_string(),
            format!("unexpectedly large frame of {} bytes returned", super::MAX_CLIENT_RECV_FRAME_LEN + 1)
        );
        assert!(matches!(
            oversized_error,
            super::ServerInfoFrameError::Oversized { frame_len, max_size }
                if frame_len == (super::MAX_CLIENT_RECV_FRAME_LEN + 1) as u32
                    && max_size == super::MAX_CLIENT_RECV_FRAME_LEN
        ));

        let short = FrameHeader { frame_type: super::FRAME_SERVER_INFO, frame_len: 4 }
            .encode()
            .into_iter()
            .chain([1, 2])
            .collect::<Vec<_>>();
        assert!(matches!(
            super::parse_server_info_frame(&alice, &bob_public, &short),
            Err(super::ServerInfoFrameError::IncompletePayload { expected: 4, got: 2 })
        ));

        let mut wrong_type = Vec::new();
        write_frame(&mut wrong_type, FRAME_CLIENT_INFO, &[0; 24]).unwrap();
        assert!(matches!(
            super::parse_server_info_frame(&alice, &bob_public, &wrong_type),
            Err(super::ServerInfoFrameError::UnexpectedType { got: FRAME_CLIENT_INFO })
        ));
    }

    #[test]
    fn server_info_json_matches_pinned_go_ascii_field_semantics() {
        use super::ServerInfo;

        assert_eq!(serde_json::from_str::<ServerInfo>("{}").unwrap(), ServerInfo::default());
        assert_eq!(serde_json::from_str::<ServerInfo>("null").unwrap(), ServerInfo::default());
        assert_eq!(
            serde_json::from_str::<ServerInfo>(
                r#"{"VERSION":1,"Version":2,"version":null,"tokenbucketbytespersecond":12,"TOKENBUCKETBYTESBURST":34,"other":{"nested":[1,true,null]}}"#
            )
            .unwrap(),
            ServerInfo { version: 2, token_bucket_bytes_per_second: 12, token_bucket_bytes_burst: 34 }
        );
        assert_eq!(
            serde_json::from_str::<ServerInfo>(
                r#"{"version":9223372036854775807,"TokenBucketBytesBurst":-9223372036854775808}"#
            )
            .unwrap(),
            ServerInfo { version: i64::MAX, token_bucket_bytes_per_second: 0, token_bucket_bytes_burst: i64::MIN }
        );
        for invalid in [
            r#"{"version":9223372036854775808}"#,
            r#"{"version":1.0}"#,
            r#"{"version":"2"}"#,
            "[]",
            "{} {}",
            r#"{"Verſion":2}"#,
        ] {
            assert!(serde_json::from_str::<ServerInfo>(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn client_info_json_matches_pinned_go_encoding_json_oracle() {
        assert_eq!(FRAME_CLIENT_INFO, FrameType(0x02));
        assert_eq!(PROTOCOL_VERSION, 2);
        assert_eq!(ClientInfo::default().to_json(), r#"{"CanAckPings":false}"#);

        let defaults = ClientInfo { version: PROTOCOL_VERSION, ..ClientInfo::default() };
        assert_eq!(defaults.to_json(), r#"{"version":2,"CanAckPings":false}"#);

        let ack = ClientInfo { version: PROTOCOL_VERSION, can_ack_pings: true, ..ClientInfo::default() };
        assert_eq!(ack.to_json(), r#"{"version":2,"CanAckPings":true}"#);

        let full = ClientInfo {
            mesh_key: std::array::from_fn(|index| index as u8),
            version: PROTOCOL_VERSION,
            can_ack_pings: true,
            is_prober: true,
            app_name: "<>& \" \\ /\n\t\u{2028}\u{2029}é".to_owned(),
        };
        assert_eq!(
            full.to_json(),
            r#"{"meshKey":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","version":2,"CanAckPings":true,"IsProber":true,"AppName":"\u003c\u003e\u0026 \" \\ /\n\t\u2028\u2029é"}"#
        );

        let omission = ClientInfo { app_name: "cue".to_owned(), ..ClientInfo::default() };
        assert_eq!(omission.to_json(), r#"{"CanAckPings":false,"AppName":"cue"}"#);
    }

    #[test]
    fn header_bytes_match_pinned_go_source_oracle() {
        for (kind, len, bytes) in [
            (0x01, 0, [0x01, 0, 0, 0, 0]),
            (0x12, 1, [0x12, 0, 0, 0, 1]),
            (0xff, 0x0102_0304, [0xff, 1, 2, 3, 4]),
            (0x00, u32::MAX, [0x00, 0xff, 0xff, 0xff, 0xff]),
        ] {
            let header = FrameHeader { frame_type: FrameType(kind), frame_len: len };
            assert_eq!(header.encode(), bytes);
            let input = [bytes.as_slice(), &[0xaa]].concat();
            let mut remaining = input.as_slice();
            assert_eq!(read_frame_header(&mut remaining), Ok(header));
            assert_eq!(remaining, [0xaa]);
        }
    }

    #[test]
    fn write_frame_matches_pinned_go_size_and_wire_boundaries() {
        for len in [0, 1, MAX_FRAME_WRITE_SIZE] {
            let payload = vec![0x5a; len];
            let mut output = vec![0xaa];
            assert_eq!(write_frame(&mut output, FrameType(0xff), &payload), Ok(()));
            assert_eq!(output.len(), 1 + 5 + len);
            assert_eq!(&output[..6], &[0xaa, 0xff, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
            assert_eq!(&output[6..], payload);
        }
        let mut output = vec![0xaa];
        let oversized = vec![0x5a; MAX_FRAME_WRITE_SIZE + 1];
        let error = write_frame(&mut output, FrameType(0xff), &oversized).unwrap_err();
        assert_eq!(error, WriteFrameError::UnreasonablyLarge);
        assert_eq!(error.to_string(), "unreasonably large frame write");
        assert_eq!(output, [0xaa]);
    }

    #[test]
    fn incomplete_header_does_not_consume_input() {
        let bytes = [0x01, 2, 3, 4];
        for n in 0..bytes.len() + 1 {
            let mut input = &bytes[..n];
            assert_eq!(read_frame_header(&mut input), Err(FrameHeaderError::Incomplete));
            assert_eq!(input, &bytes[..n]);
            assert_eq!(read_frame_type_header(&mut input, FrameType(1)), Err(FrameHeaderError::Incomplete));
            assert_eq!(input, &bytes[..n]);
        }
        assert_eq!(FrameHeaderError::Incomplete.to_string(), "EOF");
    }

    #[test]
    fn type_mismatch_consumes_header_and_preserves_length() {
        let bytes = [0x12, 1, 2, 3, 4, 0xaa];
        let mut input = bytes.as_slice();
        assert_eq!(read_frame_type_header(&mut input, FrameType(0x12)), Ok(0x0102_0304));
        assert_eq!(input, &[0xaa]);

        let mut input = bytes.as_slice();
        let err = read_frame_type_header(&mut input, FrameType(0x13)).unwrap_err();
        assert_eq!(
            err,
            FrameHeaderError::UnexpectedType { got: FrameType(0x12), want: FrameType(0x13), frame_len: 0x0102_0304 }
        );
        assert_eq!(err.to_string(), "bad frame type 0x12, want 0x13");
        assert_eq!(input, &[0xaa]);
    }

    #[test]
    fn bounded_read_matches_pinned_go_source_oracle() {
        let header3 = FrameHeader { frame_type: FrameType(0x12), frame_len: 3 };
        let header0 = FrameHeader { frame_type: FrameType(0x12), frame_len: 0 };
        type Case<'a> = (&'a str, &'a [u8], u32, usize, Result<FrameHeader, ReadFrameError>, &'a [u8], &'a [u8]);
        let cases: &[Case<'_>] = &[
            (
                "short_header",
                &[0x12, 0, 0, 0],
                4,
                4,
                Err(ReadFrameError::IncompleteHeader),
                &[0xee; 4],
                &[0x12, 0, 0, 0],
            ),
            ("empty", &[0x12, 0, 0, 0, 0, 0xaa], 0, 0, Ok(header0), &[], &[0xaa]),
            ("full", &[0x12, 0, 0, 0, 3, 1, 2, 3, 0xaa], 3, 3, Ok(header3), &[1, 2, 3], &[0xaa]),
            (
                "short_buffer",
                &[0x12, 0, 0, 0, 3, 1, 2, 3, 0xaa],
                3,
                1,
                Err(ReadFrameError::ShortBuffer { header: header3 }),
                &[1],
                &[0xaa],
            ),
            (
                "zero_buffer",
                &[0x12, 0, 0, 0, 3, 1, 2, 3, 0xaa],
                3,
                0,
                Err(ReadFrameError::ShortBuffer { header: header3 }),
                &[],
                &[0xaa],
            ),
            (
                "too_large",
                &[0x12, 0, 0, 0, 3, 1, 2, 3, 0xaa],
                2,
                3,
                Err(ReadFrameError::ExceedsLimit { frame_len: 3, max_size: 2 }),
                &[0xee; 3],
                &[1, 2, 3, 0xaa],
            ),
            ("body_empty", &[0x12, 0, 0, 0, 3], 3, 3, Err(ReadFrameError::EndOfInput), &[0xee; 3], &[]),
            (
                "body_partial",
                &[0x12, 0, 0, 0, 3, 1, 2],
                3,
                3,
                Err(ReadFrameError::UnexpectedEndOfInput),
                &[1, 2, 0xee],
                &[],
            ),
            ("discard_empty", &[0x12, 0, 0, 0, 3, 1], 3, 1, Err(ReadFrameError::EndOfInput), &[1], &[]),
            ("discard_partial", &[0x12, 0, 0, 0, 3, 1, 2], 3, 1, Err(ReadFrameError::EndOfInput), &[1], &[]),
        ];
        for &(name, data, max, output_len, expected, expected_output, expected_remaining) in cases {
            let mut input = data;
            let mut output = vec![0xee; output_len];
            assert_eq!(read_frame(&mut input, max, &mut output), expected, "{name}");
            assert_eq!(output, expected_output, "{name} output");
            assert_eq!(input, expected_remaining, "{name} remaining input");
        }
        assert_eq!(
            ReadFrameError::ExceedsLimit { frame_len: 3, max_size: 2 }.to_string(),
            "frame header size 3 exceeds reader limit of 2"
        );
        assert_eq!(ReadFrameError::EndOfInput.to_string(), "EOF");
        assert_eq!(ReadFrameError::UnexpectedEndOfInput.to_string(), "unexpected EOF");
        assert_eq!(ReadFrameError::ShortBuffer { header: header3 }.to_string(), "short buffer");
    }

    #[test]
    fn server_greeting_matches_source_derived_go_oracle() {
        for len in [40usize, 41, 1024] {
            let mut body = vec![0x5a; len];
            body[..8].copy_from_slice(&MAGIC);
            let mut wire = Vec::new();
            write_frame(&mut wire, FRAME_SERVER_KEY, &body).unwrap();
            wire.push(0xaa);
            let mut input = wire.as_slice();
            assert_eq!(read_server_greeting(&mut input).unwrap().raw_bytes(), [0x5a; 32]);
            assert_eq!(input, &[0xaa]);
        }

        let mut body = [0x5a; 40];
        body[..8].copy_from_slice(&MAGIC);
        for (kind, payload) in [(FrameType(0x12), body.as_slice()), (FRAME_SERVER_KEY, &body[..39])] {
            let mut wire = Vec::new();
            write_frame(&mut wire, kind, payload).unwrap();
            wire.push(0xaa);
            let mut input = wire.as_slice();
            assert_eq!(read_server_greeting(&mut input), Err(ServerGreetingError::Invalid));
            assert_eq!(input, &[0xaa]);
        }
        body[0] ^= 1;
        let mut wire = Vec::new();
        write_frame(&mut wire, FRAME_SERVER_KEY, &body).unwrap();
        let mut input = wire.as_slice();
        assert_eq!(read_server_greeting(&mut input).unwrap_err().to_string(), "invalid server greeting");

        body[..8].copy_from_slice(&MAGIC);
        body[8..].fill(0);
        wire.clear();
        write_frame(&mut wire, FRAME_SERVER_KEY, &body).unwrap();
        let mut input = wire.as_slice();
        assert!(read_server_greeting(&mut input).unwrap().is_zero());

        wire = FrameHeader { frame_type: FRAME_SERVER_KEY, frame_len: 1025 }.encode().to_vec();
        wire.extend_from_slice(&[0x5a; 1025]);
        wire.push(0xaa);
        let mut input = wire.as_slice();
        assert_eq!(
            read_server_greeting(&mut input),
            Err(ServerGreetingError::Read(ReadFrameError::ExceedsLimit { frame_len: 1025, max_size: 1024 }))
        );
        assert_eq!(input.len(), 1026);

        wire = FrameHeader { frame_type: FRAME_SERVER_KEY, frame_len: 40 }.encode().to_vec();
        wire.extend_from_slice(&body[..39]);
        let mut input = wire.as_slice();
        assert_eq!(
            read_server_greeting(&mut input),
            Err(ServerGreetingError::Read(ReadFrameError::UnexpectedEndOfInput))
        );
        assert!(input.is_empty());
    }
}
