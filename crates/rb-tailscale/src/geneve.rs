//! Pure-Rust codec for the fixed-size Geneve header used by the pinned Tailscale fork.
//!
//! The Go fork does not implement Geneve options: encoding always writes an
//! option length of zero, while decoding reads the fixed fields and ignores
//! option and reserved bits. This module preserves those wire semantics.

use std::{error::Error as StdError, fmt};

/// Length of the fixed Geneve header, in bytes.
pub const FIXED_HEADER_LENGTH: usize = 8;
/// IEEE Ethertype used by the pinned fork for disco payloads.
pub const PROTOCOL_DISCO: u16 = 0x7a11;
/// IEEE Ethertype used by the pinned fork for WireGuard payloads.
pub const PROTOCOL_WIREGUARD: u16 = 0x7a12;

const VNI_SET_MASK: u32 = 0xff00_0000;
const VNI_VALUE_MASK: u32 = !VNI_SET_MASK;

/// A 24-bit Geneve VNI with the pinned fork's explicit set/unset state.
///
/// Setting an out-of-range value clamps it to the low 24 bits, matching the Go
/// `VirtualNetworkID.Set` and `Get` methods.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtualNetworkId(u32);

impl VirtualNetworkId {
    /// Returns whether [`Self::set`] or decoding has initialized this VNI.
    pub const fn is_set(self) -> bool {
        self.0 & VNI_SET_MASK != 0
    }

    /// Sets a VNI, clamping it to the 24 bits carried on the wire.
    pub fn set(&mut self, vni: u32) {
        self.0 = vni | VNI_SET_MASK;
    }

    /// Returns the low 24-bit VNI value.
    pub const fn get(self) -> u32 {
        self.0 & VNI_VALUE_MASK
    }
}

/// The fixed 8-byte Geneve header used by Tailscale.
///
/// Version is two bits on the wire. The encoder accepts values 0 through 3,
/// writes no options, and requires a set VNI. The decoder mirrors the pinned
/// fork: it does not validate option length, reserved bits, version, or protocol.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeneveHeader {
    pub version: u8,
    pub protocol: u16,
    pub vni: VirtualNetworkId,
    pub control: bool,
}

/// Errors returned by the pinned Geneve fixed-header encoder and decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneveError {
    /// The supplied buffer is shorter than the fixed 8-byte header.
    ShortBuffer,
    /// The encoder was given a header whose VNI has not been initialized.
    VniUnset,
    /// The encoder was given a version outside the two-bit wire range.
    VersionOutOfRange(u8),
}

impl fmt::Display for GeneveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortBuffer => f.write_str("short buffer"),
            Self::VniUnset => f.write_str("VNI is unset"),
            Self::VersionOutOfRange(_) => f.write_str("version must be <= 3"),
        }
    }
}

impl StdError for GeneveError {}

impl GeneveHeader {
    /// Encodes the fixed header into the start of `output`.
    ///
    /// Error precedence matches the pinned fork: short buffer, unset VNI, then
    /// out-of-range version. Bytes after the first eight are left unchanged.
    pub fn encode(&self, output: &mut [u8]) -> Result<(), GeneveError> {
        if output.len() < FIXED_HEADER_LENGTH {
            return Err(GeneveError::ShortBuffer);
        }
        if !self.vni.is_set() {
            return Err(GeneveError::VniUnset);
        }
        if self.version > 3 {
            return Err(GeneveError::VersionOutOfRange(self.version));
        }

        output[0] = self.version << 6;
        output[1] = if self.control { 0x80 } else { 0 };
        output[2..4].copy_from_slice(&self.protocol.to_be_bytes());
        output[4..8].copy_from_slice(&(self.vni.get() << 8).to_be_bytes());
        Ok(())
    }

    /// Decodes a fixed header into a fresh value.
    pub fn decode(input: &[u8]) -> Result<Self, GeneveError> {
        let mut header = Self::default();
        header.decode_into(input)?;
        Ok(header)
    }

    /// Decodes into this value, preserving the pinned Go decoder's stateful
    /// control-bit behavior: a wire control bit of zero does not clear a
    /// previously true `control` field. A short input leaves this value intact.
    pub fn decode_into(&mut self, input: &[u8]) -> Result<(), GeneveError> {
        if input.len() < FIXED_HEADER_LENGTH {
            return Err(GeneveError::ShortBuffer);
        }

        self.version = input[0] >> 6;
        if input[1] & 0x80 != 0 {
            self.control = true;
        }
        self.protocol = u16::from_be_bytes([input[2], input[3]]);
        let vni = u32::from_be_bytes([input[4], input[5], input[6], input[7]]) >> 8;
        self.vni.set(vni);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{GeneveError, GeneveHeader, VirtualNetworkId, FIXED_HEADER_LENGTH, PROTOCOL_DISCO, PROTOCOL_WIREGUARD};

    fn vni(value: u32) -> VirtualNetworkId {
        let mut id = VirtualNetworkId::default();
        id.set(value);
        id
    }

    #[test]
    fn encode_matches_pinned_go_geneve_vectors_and_preserves_tail() {
        let vectors = [
            (
                GeneveHeader { version: 0, protocol: PROTOCOL_DISCO, vni: vni(0x123456), control: true },
                [0x00, 0x80, 0x7a, 0x11, 0x12, 0x34, 0x56, 0x00],
            ),
            (
                GeneveHeader { version: 3, protocol: 0x6558, vni: vni(0x00ff_ffff), control: false },
                [0xc0, 0x00, 0x65, 0x58, 0xff, 0xff, 0xff, 0x00],
            ),
        ];

        for (header, expected) in vectors {
            let mut output = [0xa5; FIXED_HEADER_LENGTH];
            header.encode(&mut output).unwrap();
            assert_eq!(output, expected);
        }

        let header = GeneveHeader { version: 1, protocol: PROTOCOL_WIREGUARD, vni: vni(0xdead_beef), control: true };
        let mut output = [0xa5; 10];
        header.encode(&mut output).unwrap();
        assert_eq!(output, [0x40, 0x80, 0x7a, 0x12, 0xad, 0xbe, 0xef, 0x00, 0xa5, 0xa5]);
    }

    #[test]
    fn virtual_network_id_matches_pinned_go_set_get_and_clamping() {
        let mut id = VirtualNetworkId::default();
        assert!(!id.is_set());
        assert_eq!(id.get(), 0);

        id.set(0);
        assert!(id.is_set());
        assert_eq!(id.get(), 0);

        id.set(0xdead_beef);
        assert!(id.is_set());
        assert_eq!(id.get(), 0x00ad_beef);
    }

    #[test]
    fn decode_matches_go_and_ignores_option_and_reserved_bits() {
        let header = GeneveHeader::decode(&[0x85, 0x7f, 0x12, 0x34, 0xab, 0xcd, 0xef, 0xff]).unwrap();
        assert_eq!(header.version, 2);
        assert!(!header.control);
        assert_eq!(header.protocol, 0x1234);
        assert!(header.vni.is_set());
        assert_eq!(header.vni.get(), 0x00ab_cdef);
    }

    #[test]
    fn decode_into_matches_go_control_stickiness_and_short_input_state() {
        let mut header = GeneveHeader { control: true, ..GeneveHeader::default() };
        header.decode_into(&[0, 0, 0x7a, 0x11, 0, 0, 1, 0]).unwrap();
        assert!(header.control);
        assert_eq!(header.protocol, PROTOCOL_DISCO);
        assert_eq!(header.vni.get(), 1);

        let before = header.clone();
        assert_eq!(header.decode_into(&[1, 2, 3, 4, 5, 6, 7]), Err(GeneveError::ShortBuffer));
        assert_eq!(header, before);
    }

    #[test]
    fn encode_matches_go_error_precedence_text_and_does_not_mutate_on_error() {
        let mut short = [0xa5; FIXED_HEADER_LENGTH - 1];
        assert_eq!(GeneveHeader::default().encode(&mut short), Err(GeneveError::ShortBuffer));
        assert_eq!(short, [0xa5; FIXED_HEADER_LENGTH - 1]);
        assert_eq!(GeneveError::ShortBuffer.to_string(), "short buffer");

        let mut output = [0xa5; FIXED_HEADER_LENGTH];
        assert_eq!(GeneveHeader::default().encode(&mut output), Err(GeneveError::VniUnset));
        assert_eq!(output, [0xa5; FIXED_HEADER_LENGTH]);
        assert_eq!(GeneveError::VniUnset.to_string(), "VNI is unset");

        let invalid_version = GeneveHeader { version: 4, vni: vni(1), ..GeneveHeader::default() };
        assert_eq!(invalid_version.encode(&mut output), Err(GeneveError::VersionOutOfRange(4)));
        assert_eq!(output, [0xa5; FIXED_HEADER_LENGTH]);
        assert_eq!(GeneveError::VersionOutOfRange(4).to_string(), "version must be <= 3");
    }
}
