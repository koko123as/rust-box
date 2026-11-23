//! DERP frame-header primitives from the Tailscale fork pinned by sing-box v1.14.4.
//!
//! These are slice-based codecs, not a streaming DERP client or server. They do
//! not validate frame types or apply a payload limit; callers must enforce their
//! own protocol-state and resource limits before consuming untrusted payloads.

use std::error::Error;
use std::fmt;

use crate::NodePublic;

/// A DERP frame header contains a type byte and a big-endian u32 payload length.
pub const FRAME_HEADER_LEN: usize = 5;
/// Maximum payload length accepted by the pinned fork's `WriteFrame`.
pub const MAX_FRAME_WRITE_SIZE: usize = 10 << 20;
/// Magic prefix of a DERP server-key greeting.
pub const MAGIC: [u8; 8] = *b"DERP\xf0\x9f\x94\x91";
/// The server-key frame type.
pub const FRAME_SERVER_KEY: FrameType = FrameType(0x01);

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

#[cfg(test)]
mod tests {
    use super::{
        read_frame, read_frame_header, read_frame_type_header, read_server_greeting, write_frame, FrameHeader,
        FrameHeaderError, FrameType, ReadFrameError, ServerGreetingError, WriteFrameError, FRAME_SERVER_KEY, MAGIC,
        MAX_FRAME_WRITE_SIZE,
    };

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
