//! Pure Rust primitives ported from the Tailscale fork pinned by sing-box v1.14.4.
//!
//! This crate implements machine, node, and disco X25519 key primitives, DiscoShared
//! and NodePrivate NaCl box encryption, Go-oracle-tested plaintext codecs for disco
//! types 0x01 through 0x09, encrypted packet-envelope helpers, the fixed Geneve
//! header, and source-derived magicsock packet classification, STUN binding
//! request/response helpers, and Tailscale address classification and 4-to-6/6-to-4
//! mapping helpers, plus bounded DERP slice and blocking-stream frame codecs, an
//! in-memory client key-exchange state machine and encrypted ClientInfo frame
//! construction, and bounded in-memory ServerInfo frame/payload parsing with
//! message and send-rate configuration mapping.
//! This crate is not a full Tailscale endpoint runtime.

pub mod derp;
pub mod disco;
pub mod disco_crypto;
pub mod geneve;
pub mod packet_classifier;
pub mod stun;
pub mod tsaddr;

use std::error::Error;
use std::fmt;
use std::fmt::Write as _;

use boringtun::x25519::{PublicKey as X25519PublicKey, StaticSecret};
use rand::rand_core::OsRng;
use rand::TryCryptoRng;
use zeroize::Zeroize;

const PRIVATE_TEXT_PREFIX: &str = "privkey:";
const MACHINE_PUBLIC_TEXT_PREFIX: &str = "mkey:";
const NODE_PUBLIC_TEXT_PREFIX: &str = "nodekey:";
const DISCO_PUBLIC_TEXT_PREFIX: &str = "discokey:";
const NODE_PUBLIC_BINARY_PREFIX: &[u8; 2] = b"np";
const KEY_BYTES: usize = 32;

/// A malformed typed key string. Error text deliberately never includes the input,
/// which may contain a private key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KeyParseError {
    WrongPrefix { expected: &'static str },
    WrongLength { got: usize, want: usize },
    InvalidHex,
}

impl fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPrefix { expected } => {
                write!(f, "key hex string doesn't have expected type prefix {expected}")
            }
            Self::WrongLength { got, want } => write!(f, "key hex has the wrong size, got {got} want {want}"),
            Self::InvalidHex => f.write_str("invalid hex character in key"),
        }
    }
}

impl Error for KeyParseError {}

/// A malformed NodePublic binary encoding.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KeyBinaryError {
    WrongPrefix,
    WrongLength { got: usize, want: usize },
}

impl fmt::Display for KeyBinaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPrefix => f.write_str("missing/incorrect type prefix np"),
            Self::WrongLength { got, want } => write!(f, "incorrect len for NodePublic ({got} != {want})"),
        }
    }
}

impl Error for KeyBinaryError {}

/// A zero private key cannot be used to derive a public key.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ZeroPrivateKey;

impl fmt::Display for ZeroPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cannot derive a public key from a zero private key")
    }
}

impl Error for ZeroPrivateKey {}

/// OS cryptographic entropy was unavailable. Key generation never falls back to
/// a weaker or deterministic source.
#[derive(Debug)]
pub struct KeyGenerationError(String);

impl fmt::Display for KeyGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OS cryptographic random number generation failed: {}", self.0)
    }
}

impl Error for KeyGenerationError {}

/// A Tailscale MachinePrivate key used by the coordination control protocol.
///
/// Its persisted text representation is `privkey:` followed by 64 hexadecimal
/// digits, matching the pinned Tailscale fork. Debug output is intentionally
/// redacted.
#[derive(Clone)]
pub struct MachinePrivate(StaticSecret);

impl MachinePrivate {
    /// Generates a clamped 32-byte key using only the operating system CSPRNG.
    pub fn generate() -> Result<Self, KeyGenerationError> {
        let mut rng = OsRng;
        generate_private(&mut rng).map(Self)
    }

    /// Parses the fork's `privkey:` plus 64-hex-digit representation. Hex digits
    /// may be upper- or lower-case; the type prefix is case-sensitive.
    pub fn from_text(input: &str) -> Result<Self, KeyParseError> {
        parse_private(input, PRIVATE_TEXT_PREFIX).map(Self)
    }

    /// Returns the fork's canonical lower-case persisted representation.
    pub fn to_text(&self) -> String {
        encode_hex_key(PRIVATE_TEXT_PREFIX, self.0.as_bytes())
    }

    /// Returns a copy of the raw private-key bytes for protocol operations.
    pub fn raw_bytes(&self) -> [u8; KEY_BYTES] {
        self.0.to_bytes()
    }

    pub fn is_zero(&self) -> bool {
        is_zero(self.0.as_bytes())
    }

    /// Derives the X25519 public key using the same clamped scalar operation as
    /// the pinned fork's `curve25519.ScalarBaseMult`.
    pub fn public(&self) -> Result<MachinePublic, ZeroPrivateKey> {
        if self.is_zero() {
            return Err(ZeroPrivateKey);
        }
        Ok(MachinePublic(X25519PublicKey::from(&self.0).to_bytes()))
    }
}

impl fmt::Debug for MachinePrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MachinePrivate(REDACTED)")
    }
}

/// A Tailscale MachinePublic key, serialized as `mkey:` plus 64 hex digits.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MachinePublic([u8; KEY_BYTES]);

impl MachinePublic {
    pub fn from_text(input: &str) -> Result<Self, KeyParseError> {
        decode_hex_key(input, MACHINE_PUBLIC_TEXT_PREFIX).map(Self)
    }

    pub fn to_text(self) -> String {
        encode_hex_key(MACHINE_PUBLIC_TEXT_PREFIX, &self.0)
    }

    pub fn from_raw32(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn raw_bytes(self) -> [u8; KEY_BYTES] {
        self.0
    }

    pub fn is_zero(self) -> bool {
        is_zero(&self.0)
    }
}

impl fmt::Debug for MachinePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MachinePublic").field(&self.to_text()).finish()
    }
}

impl fmt::Display for MachinePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

/// A Tailscale NodePrivate key used for WireGuard and DERP communications.
///
/// Its persisted text representation is `privkey:` followed by 64 hexadecimal
/// digits, matching the pinned Tailscale fork. Debug output is intentionally
/// redacted.
#[derive(Clone)]
pub struct NodePrivate(StaticSecret);

impl NodePrivate {
    /// Generates a clamped 32-byte key using only the operating system CSPRNG.
    pub fn generate() -> Result<Self, KeyGenerationError> {
        let mut rng = OsRng;
        generate_private(&mut rng).map(Self)
    }

    pub fn from_text(input: &str) -> Result<Self, KeyParseError> {
        parse_private(input, PRIVATE_TEXT_PREFIX).map(Self)
    }

    pub fn to_text(&self) -> String {
        encode_hex_key(PRIVATE_TEXT_PREFIX, self.0.as_bytes())
    }

    pub fn raw_bytes(&self) -> [u8; KEY_BYTES] {
        self.0.to_bytes()
    }

    pub fn is_zero(&self) -> bool {
        is_zero(self.0.as_bytes())
    }

    pub fn public(&self) -> Result<NodePublic, ZeroPrivateKey> {
        if self.is_zero() {
            return Err(ZeroPrivateKey);
        }
        Ok(NodePublic(X25519PublicKey::from(&self.0).to_bytes()))
    }
}

impl fmt::Debug for NodePrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NodePrivate(REDACTED)")
    }
}

/// A Tailscale NodePublic key, with text form `nodekey:` plus 64 hex digits and
/// binary form `np` plus 32 raw bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NodePublic([u8; KEY_BYTES]);

impl NodePublic {
    pub fn from_text(input: &str) -> Result<Self, KeyParseError> {
        decode_hex_key(input, NODE_PUBLIC_TEXT_PREFIX).map(Self)
    }

    pub fn to_text(self) -> String {
        encode_hex_key(NODE_PUBLIC_TEXT_PREFIX, &self.0)
    }

    pub fn from_raw32(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn raw_bytes(self) -> [u8; KEY_BYTES] {
        self.0
    }

    pub fn is_zero(self) -> bool {
        is_zero(&self.0)
    }

    pub fn to_binary(self) -> [u8; 2 + KEY_BYTES] {
        let mut output = [0; 2 + KEY_BYTES];
        output[..2].copy_from_slice(NODE_PUBLIC_BINARY_PREFIX);
        output[2..].copy_from_slice(&self.0);
        output
    }

    /// Parses exactly the Tailscale `np` binary format; prefix is checked before
    /// length, matching the pinned fork.
    pub fn from_binary(input: &[u8]) -> Result<Self, KeyBinaryError> {
        if !input.starts_with(NODE_PUBLIC_BINARY_PREFIX) {
            return Err(KeyBinaryError::WrongPrefix);
        }
        let want = NODE_PUBLIC_BINARY_PREFIX.len() + KEY_BYTES;
        if input.len() != want {
            return Err(KeyBinaryError::WrongLength { got: input.len(), want });
        }
        let mut raw = [0; KEY_BYTES];
        raw.copy_from_slice(&input[NODE_PUBLIC_BINARY_PREFIX.len()..]);
        Ok(Self(raw))
    }
}

impl fmt::Debug for NodePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NodePublic").field(&self.to_text()).finish()
    }
}

impl fmt::Display for NodePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

/// A Tailscale DiscoPrivate key used for peer path discovery.
///
/// The pinned fork has no text encoding for this private key; its raw form is
/// exactly 32 bytes. Shared-secret derivation is provided by `disco_crypto`.
#[derive(Clone)]
pub struct DiscoPrivate(StaticSecret);

impl DiscoPrivate {
    /// Generates a clamped private key using only the operating system CSPRNG.
    pub fn generate() -> Result<Self, KeyGenerationError> {
        let mut rng = OsRng;
        generate_private(&mut rng).map(Self)
    }

    pub fn from_raw32(mut bytes: [u8; KEY_BYTES]) -> Self {
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        Self(secret)
    }

    pub fn is_zero(&self) -> bool {
        is_zero(self.0.as_bytes())
    }

    /// Derives the X25519 public key; a zero private key is rejected.
    pub fn public(&self) -> Result<DiscoPublic, ZeroPrivateKey> {
        if self.is_zero() {
            return Err(ZeroPrivateKey);
        }
        Ok(DiscoPublic(X25519PublicKey::from(&self.0).to_bytes()))
    }
}

impl fmt::Debug for DiscoPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DiscoPrivate(REDACTED)")
    }
}

/// A Tailscale DiscoPublic key, serialized as `discokey:` plus 64 hex digits.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct DiscoPublic([u8; KEY_BYTES]);

impl DiscoPublic {
    pub fn from_text(input: &str) -> Result<Self, KeyParseError> {
        decode_hex_key(input, DISCO_PUBLIC_TEXT_PREFIX).map(Self)
    }

    pub fn to_text(self) -> String {
        encode_hex_key(DISCO_PUBLIC_TEXT_PREFIX, &self.0)
    }

    pub fn from_raw32(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn raw_bytes(self) -> [u8; KEY_BYTES] {
        self.0
    }

    pub fn is_zero(self) -> bool {
        is_zero(&self.0)
    }
}

impl fmt::Debug for DiscoPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DiscoPublic").field(&self.to_text()).finish()
    }
}

impl fmt::Display for DiscoPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

fn parse_private(input: &str, prefix: &'static str) -> Result<StaticSecret, KeyParseError> {
    let mut bytes = decode_hex_key(input, prefix)?;
    let secret = StaticSecret::from(bytes);
    bytes.zeroize();
    Ok(secret)
}

fn decode_hex_key(input: &str, prefix: &'static str) -> Result<[u8; KEY_BYTES], KeyParseError> {
    let input = input.as_bytes();
    let prefix_bytes = prefix.as_bytes();
    if !input.starts_with(prefix_bytes) {
        return Err(KeyParseError::WrongPrefix { expected: prefix });
    }
    let encoded = &input[prefix_bytes.len()..];
    let want = KEY_BYTES * 2;
    if encoded.len() != want {
        return Err(KeyParseError::WrongLength { got: encoded.len(), want });
    }
    let mut output = [0; KEY_BYTES];
    for (index, pair) in encoded.as_chunks::<2>().0.iter().enumerate() {
        let Some(high) = hex_value(pair[0]) else {
            output.zeroize();
            return Err(KeyParseError::InvalidHex);
        };
        let Some(low) = hex_value(pair[1]) else {
            output.zeroize();
            return Err(KeyParseError::InvalidHex);
        };
        output[index] = high << 4 | low;
    }
    Ok(output)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_hex_key(prefix: &str, key: &[u8; KEY_BYTES]) -> String {
    let mut result = String::with_capacity(prefix.len() + KEY_BYTES * 2);
    result.push_str(prefix);
    for byte in key {
        write!(result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

fn is_zero(bytes: &[u8; KEY_BYTES]) -> bool {
    bytes.iter().fold(0u8, |accumulator, byte| accumulator | byte) == 0
}

fn generate_private<R>(rng: &mut R) -> Result<StaticSecret, KeyGenerationError>
where
    R: TryCryptoRng,
    R::Error: fmt::Display,
{
    let mut bytes = [0; KEY_BYTES];
    if let Err(error) = rng.try_fill_bytes(&mut bytes) {
        bytes.zeroize();
        return Err(KeyGenerationError(error.to_string()));
    }
    // Match types/key/util.go: clamp25519Private.
    bytes[0] &= 248;
    bytes[31] = (bytes[31] & 127) | 64;
    let secret = StaticSecret::from(bytes);
    bytes.zeroize();
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::io;

    use rand::{TryCryptoRng, TryRngCore};

    use super::{
        generate_private, DiscoPrivate, DiscoPublic, KeyBinaryError, KeyParseError, MachinePrivate, NodePrivate,
        NodePublic, ZeroPrivateKey,
    };

    const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    #[test]
    fn machine_and_node_text_formats_and_x25519_vector_match() {
        let machine = MachinePrivate::from_text(&format!("privkey:{ALICE_PRIVATE}")).unwrap();
        assert_eq!(machine.to_text(), format!("privkey:{ALICE_PRIVATE}"));
        assert_eq!(machine.public().unwrap().to_text(), format!("mkey:{ALICE_PUBLIC}"));

        let node = NodePrivate::from_text(&format!("privkey:{ALICE_PRIVATE}")).unwrap();
        assert_eq!(node.to_text(), format!("privkey:{ALICE_PRIVATE}"));
        let node_public = node.public().unwrap();
        assert_eq!(node_public.to_text(), format!("nodekey:{ALICE_PUBLIC}"));
        assert_eq!(NodePublic::from_text(&node_public.to_text()).unwrap(), node_public);
    }

    #[test]
    fn disco_key_raw_public_and_text_match_pinned_fork() {
        let raw = NodePrivate::from_text(&format!("privkey:{ALICE_PRIVATE}")).unwrap().raw_bytes();
        let private = DiscoPrivate::from_raw32(raw);
        assert_eq!(format!("{private:?}"), "DiscoPrivate(REDACTED)");
        let public = private.public().unwrap();
        assert_eq!(public.to_text(), format!("discokey:{ALICE_PUBLIC}"));
        assert_eq!(DiscoPublic::from_text(&public.to_text()).unwrap(), public);
        assert_eq!(DiscoPublic::from_raw32(public.raw_bytes()), public);
        assert_eq!(DiscoPublic::from_text(&format!("discokey:{}", ALICE_PUBLIC.to_ascii_uppercase())).unwrap(), public);
        assert_eq!(
            DiscoPublic::from_text(&format!("Discokey:{ALICE_PUBLIC}")).unwrap_err(),
            KeyParseError::WrongPrefix { expected: "discokey:" }
        );
        assert!(DiscoPublic::from_raw32([0; 32]).is_zero());
        assert_eq!(DiscoPrivate::from_raw32([0; 32]).public(), Err(ZeroPrivateKey));
        assert!(DiscoPublic::from_raw32([0; 32]) < public);
    }

    #[test]
    fn typed_key_parser_matches_prefix_length_and_hex_rules_without_echoing_input() {
        let uppercase = format!("privkey:{}", ALICE_PRIVATE.to_ascii_uppercase());
        assert_eq!(NodePrivate::from_text(&uppercase).unwrap().to_text(), format!("privkey:{ALICE_PRIVATE}"));
        assert_eq!(
            NodePrivate::from_text(&format!("Nodekey:{ALICE_PRIVATE}")).unwrap_err(),
            KeyParseError::WrongPrefix { expected: "privkey:" }
        );
        assert_eq!(NodePrivate::from_text("privkey:01").unwrap_err(), KeyParseError::WrongLength { got: 2, want: 64 });
        let secret_marker = format!("privkey:{}", "z".repeat(64));
        let error = NodePrivate::from_text(&secret_marker).unwrap_err();
        assert_eq!(error, KeyParseError::InvalidHex);
        assert!(!error.to_string().contains(&secret_marker));
    }

    #[test]
    fn node_public_binary_encoding_is_exact_and_strict() {
        let node_public = NodePublic::from_text(&format!("nodekey:{ALICE_PUBLIC}")).unwrap();
        let binary = node_public.to_binary();
        assert_eq!(&binary[..2], b"np");
        assert_eq!(NodePublic::from_binary(&binary).unwrap(), node_public);
        assert_eq!(NodePublic::from_binary(b"xx"), Err(KeyBinaryError::WrongPrefix));
        assert_eq!(NodePublic::from_binary(b"np"), Err(KeyBinaryError::WrongLength { got: 2, want: 34 }));
    }

    #[test]
    fn zero_private_key_is_parsed_but_cannot_derive_public_key() {
        let zero = NodePrivate::from_text(&format!("privkey:{}", "00".repeat(32))).unwrap();
        assert!(zero.is_zero());
        assert_eq!(zero.public(), Err(ZeroPrivateKey));
    }

    #[test]
    fn generated_private_keys_use_exact_tailscale_clamp_and_entropy_failure_is_closed() {
        let mut fixed = FixedRng;
        let secret = generate_private(&mut fixed).unwrap();
        let bytes = secret.to_bytes();
        assert_eq!(bytes[0], 0xf8);
        assert_eq!(bytes[31], 0x7f);
        assert!(bytes[1..31].iter().all(|byte| *byte == 0xff));

        let mut failing = FailingRng;
        let error = generate_private(&mut failing).err().expect("fallible entropy failure must not generate a key");
        assert!(error.to_string().contains("entropy unavailable"));
    }

    struct FixedRng;

    impl TryRngCore for FixedRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::MAX)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::MAX)
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            destination.fill(0xff);
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
