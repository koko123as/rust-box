//! DERP frame-header primitives from the Tailscale fork pinned by sing-box v1.14.4.
//!
//! These are slice-based codecs, not a streaming DERP client or server. They do
//! not validate frame types or apply a payload limit; callers must enforce their
//! own protocol-state and resource limits before consuming untrusted payloads.

use std::error::Error;
use std::fmt;

/// A DERP frame header contains a type byte and a big-endian u32 payload length.
pub const FRAME_HEADER_LEN: usize = 5;

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

#[cfg(test)]
mod tests {
    use super::{read_frame_header, read_frame_type_header, FrameHeader, FrameHeaderError, FrameType};

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
}
