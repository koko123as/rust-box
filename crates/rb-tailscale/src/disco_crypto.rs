//! Pure-Rust NaCl box-compatible encryption for Tailscale Disco and node-key DERP messages.
//!
//! The pinned Go fork encodes a packet as `nonce || tag || ciphertext`, with
//! the Poly1305 tag before the XSalsa20 ciphertext. RustCrypto's
//! `crypto_secretbox` implements this exact layout. Go accepts non-contributory
//! X25519 inputs and derives a key from the all-zero DH result; this module
//! deliberately rejects those inputs instead of reproducing that unsafe edge
//! case. That is an explicit fail-closed compatibility difference.

use std::{error::Error as StdError, fmt};

use boringtun::x25519::PublicKey as X25519PublicKey;
use crypto_secretbox::{aead::Aead, aead::KeyInit, Nonce, XSalsa20Poly1305};
use rand::{rand_core::OsRng, TryCryptoRng};
use salsa20::{
    cipher::consts::{U10, U16},
    cipher::generic_array::GenericArray,
    hsalsa,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{DiscoPrivate, DiscoPublic, NodePrivate, NodePublic};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Errors from deriving, sealing, or opening a DiscoShared message.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// The private key is all zero, which the pinned Go fork panics on.
    ZeroPrivateKey,
    /// X25519 produced a non-contributory (all-zero) shared value.
    NonContributoryPeer,
    /// The operating system cryptographic random source failed.
    Entropy(String),
    /// The wire packet is shorter than the fixed nonce prefix.
    ShortCiphertext { got: usize, want: usize },
    /// Poly1305 authentication failed or ciphertext was malformed.
    Authentication,
    /// Checked output sizing or a fallible allocation failed.
    Resource,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPrivateKey => f.write_str("cannot derive DiscoShared from a zero private key"),
            Self::NonContributoryPeer => f.write_str("refusing non-contributory X25519 peer key"),
            Self::Entropy(error) => write!(f, "OS cryptographic random number generation failed: {error}"),
            Self::ShortCiphertext { got, want } => {
                write!(f, "short DiscoShared ciphertext: got {got}, want at least {want}")
            }
            Self::Authentication => f.write_str("DiscoShared authentication failed"),
            Self::Resource => f.write_str("DiscoShared message size or allocation failure"),
        }
    }
}

impl StdError for Error {}

/// Errors from sealing or opening a NaCl box with a node key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NodeBoxError {
    ZeroPrivateKey,
    ZeroPeerPublicKey,
    NonContributoryPeer,
    Entropy(String),
    ShortCiphertext { got: usize, want: usize },
    Authentication,
    Resource,
}

impl fmt::Display for NodeBoxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPrivateKey => f.write_str("cannot use NaCl box with a zero node private key"),
            Self::ZeroPeerPublicKey => f.write_str("cannot use NaCl box with a zero node public key"),
            Self::NonContributoryPeer => f.write_str("refusing non-contributory X25519 peer key"),
            Self::Entropy(error) => write!(f, "OS cryptographic random number generation failed: {error}"),
            Self::ShortCiphertext { got, want } => {
                write!(f, "short NaCl box ciphertext: got {got}, want at least {want}")
            }
            Self::Authentication => f.write_str("NaCl box authentication failed"),
            Self::Resource => f.write_str("NaCl box message size or allocation failure"),
        }
    }
}

impl StdError for NodeBoxError {}

/// A precomputed XSalsa20-Poly1305 key for one local and one peer Disco key.
/// Debug output is redacted; the underlying cipher erases its key on drop.
pub struct DiscoShared(XSalsa20Poly1305);

impl fmt::Debug for DiscoShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DiscoShared(REDACTED)")
    }
}

impl DiscoPrivate {
    /// Computes the Tailscale NaCl box precomputation for `peer`.
    ///
    /// The pinned fork panics for a zero private key and accepts nonzero
    /// low-order peer keys. This API returns an error for both zero private
    /// keys and non-contributory DH results, so it does not claim byte-for-byte
    /// compatibility for those unsafe Go edge cases.
    pub fn shared(&self, peer: &DiscoPublic) -> Result<DiscoShared, Error> {
        if self.is_zero() {
            return Err(Error::ZeroPrivateKey);
        }

        let peer_x25519 = X25519PublicKey::from(peer.raw_bytes());
        let dh = self.0.diffie_hellman(&peer_x25519);
        if !dh.was_contributory() {
            return Err(Error::NonContributoryPeer);
        }

        // NaCl box.Precompute is X25519 followed by HSalsa20(shared, zero16).
        // Erase the intermediate DH output and the HSalsa key after the cipher
        // has copied it into its zeroizing crypto_secretbox key storage.
        let mut dh_bytes = dh.to_bytes();
        let zero_nonce: GenericArray<u8, U16> = GenericArray::default();
        let hsalsa_key = Zeroizing::new(hsalsa::<U10>(salsa20::Key::from_slice(&dh_bytes), &zero_nonce));
        dh_bytes.zeroize();
        let cipher_key = crypto_secretbox::Key::from_slice(&hsalsa_key);
        Ok(DiscoShared(XSalsa20Poly1305::new(cipher_key)))
    }
}

impl DiscoShared {
    /// Seals a plaintext using a fresh 24-byte OS-CSPRNG nonce.
    ///
    /// The returned bytes are `nonce || tag || ciphertext`, matching
    /// `types/key.DiscoShared.Seal` in the fork. There is no arbitrary wire-size
    /// cap. Entropy failures are returned; no fallback nonce is used.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut rng = OsRng;
        self.seal_with_rng(plaintext, &mut rng)
    }

    /// Opens an authenticated `nonce || tag || ciphertext` packet.
    ///
    /// No plaintext is returned unless Poly1305 authentication succeeds.
    pub fn open(&self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        if packet.len() < NONCE_LEN {
            return Err(Error::ShortCiphertext { got: packet.len(), want: NONCE_LEN });
        }
        let nonce = Nonce::from_slice(&packet[..NONCE_LEN]);
        self.0.decrypt(nonce, &packet[NONCE_LEN..]).map_err(|_| Error::Authentication)
    }

    fn seal_with_rng<R>(&self, plaintext: &[u8], rng: &mut R) -> Result<Vec<u8>, Error>
    where
        R: TryCryptoRng,
        R::Error: fmt::Display,
    {
        let mut nonce = [0u8; NONCE_LEN];
        if let Err(error) = rng.try_fill_bytes(&mut nonce) {
            nonce.zeroize();
            return Err(Error::Entropy(error.to_string()));
        }
        self.seal_with_nonce(plaintext, &nonce)
    }

    fn seal_with_nonce(&self, plaintext: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>, Error> {
        let encrypted_len = plaintext.len().checked_add(TAG_LEN).ok_or(Error::Resource)?;
        let total_len = NONCE_LEN.checked_add(encrypted_len).ok_or(Error::Resource)?;
        let mut packet = Vec::new();
        packet.try_reserve_exact(total_len).map_err(|_| Error::Resource)?;
        let encrypted = self.0.encrypt(Nonce::from_slice(nonce), plaintext).map_err(|_| Error::Resource)?;
        packet.extend_from_slice(nonce);
        packet.extend_from_slice(&encrypted);
        Ok(packet)
    }
}

impl NodePrivate {
    /// Seals to `peer` as `nonce || NaCl box ciphertext`, matching the pinned
    /// fork's `NodePrivate.SealTo` layout. A fresh OS-CSPRNG nonce is mandatory;
    /// entropy failure returns an error without fallback.
    pub fn seal_to(&self, peer: &NodePublic, plaintext: &[u8]) -> Result<Vec<u8>, NodeBoxError> {
        let mut rng = OsRng;
        self.seal_to_with_rng(peer, plaintext, &mut rng)
    }

    /// Opens an authenticated `nonce || box ciphertext` packet from `peer`.
    /// No plaintext is returned unless Poly1305 authentication succeeds.
    pub fn open_from(&self, peer: &NodePublic, packet: &[u8]) -> Result<Vec<u8>, NodeBoxError> {
        let cipher = node_box_cipher(self, peer)?;
        if packet.len() < NONCE_LEN {
            return Err(NodeBoxError::ShortCiphertext { got: packet.len(), want: NONCE_LEN });
        }
        let nonce = Nonce::from_slice(&packet[..NONCE_LEN]);
        cipher.decrypt(nonce, &packet[NONCE_LEN..]).map_err(|_| NodeBoxError::Authentication)
    }

    fn seal_to_with_rng<R>(&self, peer: &NodePublic, plaintext: &[u8], rng: &mut R) -> Result<Vec<u8>, NodeBoxError>
    where
        R: TryCryptoRng,
        R::Error: fmt::Display,
    {
        let cipher = node_box_cipher(self, peer)?;
        let mut nonce = [0u8; NONCE_LEN];
        if let Err(error) = rng.try_fill_bytes(&mut nonce) {
            nonce.zeroize();
            return Err(NodeBoxError::Entropy(error.to_string()));
        }
        self.seal_to_with_cipher_and_nonce(&cipher, plaintext, &nonce)
    }

    #[cfg(test)]
    fn seal_to_with_nonce(
        &self,
        peer: &NodePublic,
        plaintext: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>, NodeBoxError> {
        let cipher = node_box_cipher(self, peer)?;
        self.seal_to_with_cipher_and_nonce(&cipher, plaintext, nonce)
    }

    fn seal_to_with_cipher_and_nonce(
        &self,
        cipher: &XSalsa20Poly1305,
        plaintext: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>, NodeBoxError> {
        let encrypted_len = plaintext.len().checked_add(TAG_LEN).ok_or(NodeBoxError::Resource)?;
        let total_len = NONCE_LEN.checked_add(encrypted_len).ok_or(NodeBoxError::Resource)?;
        let mut packet = Vec::new();
        packet.try_reserve_exact(total_len).map_err(|_| NodeBoxError::Resource)?;
        let encrypted = cipher.encrypt(Nonce::from_slice(nonce), plaintext).map_err(|_| NodeBoxError::Resource)?;
        packet.extend_from_slice(nonce);
        packet.extend_from_slice(&encrypted);
        Ok(packet)
    }
}

fn node_box_cipher(private: &NodePrivate, peer: &NodePublic) -> Result<XSalsa20Poly1305, NodeBoxError> {
    if private.is_zero() {
        return Err(NodeBoxError::ZeroPrivateKey);
    }
    if peer.is_zero() {
        return Err(NodeBoxError::ZeroPeerPublicKey);
    }
    let peer_x25519 = X25519PublicKey::from(peer.raw_bytes());
    let dh = private.0.diffie_hellman(&peer_x25519);
    if !dh.was_contributory() {
        return Err(NodeBoxError::NonContributoryPeer);
    }
    let mut dh_bytes = dh.to_bytes();
    let zero_nonce: GenericArray<u8, U16> = GenericArray::default();
    let hsalsa_key = Zeroizing::new(hsalsa::<U10>(salsa20::Key::from_slice(&dh_bytes), &zero_nonce));
    dh_bytes.zeroize();
    Ok(XSalsa20Poly1305::new(crypto_secretbox::Key::from_slice(&hsalsa_key)))
}

#[cfg(test)]
mod tests {
    use std::io;

    use rand::{TryCryptoRng, TryRngCore};

    use super::{DiscoShared, Error, NodeBoxError, NONCE_LEN};
    use crate::{DiscoPrivate, DiscoPublic, NodePrivate, NodePublic};

    const ALICE_PRIVATE: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const BOB_PUBLIC: &str = "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466";
    const NODE_ALICE_PRIVATE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const NODE_BOB_PRIVATE: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const NODE_ALICE_PUBLIC: &str = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
    const NODE_BOB_PUBLIC: &str = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
    const NODE_NONCE: [u8; NONCE_LEN] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51,
        0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    const NONCE: [u8; NONCE_LEN] = [
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
    ];

    fn shared() -> DiscoShared {
        let alice = DiscoPrivate::from_raw32(decode_hex(ALICE_PRIVATE));
        let bob = DiscoPublic::from_raw32(decode_hex(BOB_PUBLIC));
        alice.shared(&bob).unwrap()
    }

    fn decode_hex(input: &str) -> [u8; 32] {
        let mut out = [0; 32];
        for (index, pair) in input.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let hex = std::str::from_utf8(pair).unwrap();
            out[index] = u8::from_str_radix(hex, 16).unwrap();
        }
        out
    }

    fn hex(input: &[u8]) -> String {
        input.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn decode_wire(input: &str) -> Vec<u8> {
        let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs.iter().map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
    }

    #[test]
    fn node_private_seal_open_match_fixed_go_box_vector() {
        let alice = NodePrivate::from_text(&format!("privkey:{NODE_ALICE_PRIVATE}")).unwrap();
        let bob = NodePrivate::from_text(&format!("privkey:{NODE_BOB_PRIVATE}")).unwrap();
        let alice_public = alice.public().unwrap();
        let bob_public = bob.public().unwrap();
        assert_eq!(alice_public.raw_bytes(), decode_hex(NODE_ALICE_PUBLIC));
        assert_eq!(bob_public.raw_bytes(), decode_hex(NODE_BOB_PUBLIC));

        let plaintext = b"{\"version\":2,\"CanAckPings\":false}";
        let go_wire = decode_wire(
            "404142434445464748494a4b4c4d4e4f50515253545556574967ed374b28c33fc5736ccb6d0bd713c51736ebbff954bbcd71a150815a3b3a0d6425f015948ec55275cfd6eb33e08ea0",
        );
        assert_eq!(alice.seal_to_with_nonce(&bob_public, plaintext, &NODE_NONCE).unwrap(), go_wire,);
        assert_eq!(bob.open_from(&alice_public, &go_wire).unwrap(), plaintext);
    }

    #[test]
    fn node_private_box_rejects_invalid_keys_short_packets_and_tampering() {
        let alice = NodePrivate::from_text(&format!("privkey:{NODE_ALICE_PRIVATE}")).unwrap();
        let bob = NodePrivate::from_text(&format!("privkey:{NODE_BOB_PRIVATE}")).unwrap();
        let alice_public = alice.public().unwrap();
        let bob_public = bob.public().unwrap();

        assert_eq!(bob.open_from(&alice_public, &[]), Err(NodeBoxError::ShortCiphertext { got: 0, want: NONCE_LEN }));
        let mut packet = alice.seal_to_with_nonce(&bob_public, b"authenticated", &NODE_NONCE).unwrap();
        for index in [0, NONCE_LEN, NONCE_LEN + 16] {
            let mut tampered = packet.clone();
            tampered[index] ^= 1;
            assert_eq!(bob.open_from(&alice_public, &tampered), Err(NodeBoxError::Authentication), "byte {index}");
        }
        packet.truncate(NONCE_LEN + 15);
        assert_eq!(bob.open_from(&alice_public, &packet), Err(NodeBoxError::Authentication));

        let zero_private = NodePrivate::from_text(&format!("privkey:{}", "00".repeat(32))).unwrap();
        assert_eq!(zero_private.seal_to(&bob_public, b"x"), Err(NodeBoxError::ZeroPrivateKey));
        assert_eq!(zero_private.open_from(&bob_public, &[]), Err(NodeBoxError::ZeroPrivateKey));
        assert_eq!(alice.seal_to(&NodePublic::from_raw32([0; 32]), b"x"), Err(NodeBoxError::ZeroPeerPublicKey));
        let low_order = NodePublic::from_raw32([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(alice.seal_to(&low_order, b"x"), Err(NodeBoxError::NonContributoryPeer));
    }

    #[test]
    fn node_private_box_uses_fresh_os_nonce_and_fails_closed_on_entropy_error() {
        let alice = NodePrivate::from_text(&format!("privkey:{NODE_ALICE_PRIVATE}")).unwrap();
        let bob = NodePrivate::from_text(&format!("privkey:{NODE_BOB_PRIVATE}")).unwrap();
        let bob_public = bob.public().unwrap();
        let first = alice.seal_to(&bob_public, b"fresh nonce").unwrap();
        let second = alice.seal_to(&bob_public, b"fresh nonce").unwrap();
        assert_eq!(bob.open_from(&alice.public().unwrap(), &first).unwrap(), b"fresh nonce");
        assert_eq!(bob.open_from(&alice.public().unwrap(), &second).unwrap(), b"fresh nonce");
        assert_ne!(&first[..NONCE_LEN], &second[..NONCE_LEN]);

        let mut failed_rng = FailingRng;
        assert_eq!(
            alice.seal_to_with_rng(&bob_public, b"no fallback", &mut failed_rng).unwrap_err(),
            NodeBoxError::Entropy("test entropy unavailable".to_owned()),
        );
    }

    #[test]
    fn fixed_nonce_seal_matches_real_pinned_go_box_bytes_and_opens_go_vectors() {
        // These packets were emitted by box.SealAfterPrecomputation using the
        // pinned Go fork's DiscoPrivate.Shared and verified by its DiscoShared.Open.
        let vectors = [
            (0, "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021e5ce198bff0cd53ff7ccd54834cff461"),
            (1, "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021bbe034a8be27bdc0056d692c9f32aa48b2"),
            (31, "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021f2c34a60c6a428616e56ca20b530fb7fb2b57dd13cd3028d6dbeb675b6837f1efed4c24a8a92bdaacfbacc5513c846"),
            (32, "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021753b517140f66a59c4a9824472c581d0b2b57dd13cd3028d6dbeb675b6837f1efed4c24a8a92bdaacfbacc5513c846b5"),
            (33, "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021f94edb3fc352d942461be634f210f8ccb2b57dd13cd3028d6dbeb675b6837f1efed4c24a8a92bdaacfbacc5513c846b50d"),
        ];
        let shared = shared();
        assert_eq!(format!("{shared:?}"), "DiscoShared(REDACTED)");
        for (length, go_wire_hex) in vectors {
            let plaintext: Vec<u8> = (0..length).map(|byte| byte as u8).collect();
            let go_wire = decode_wire(go_wire_hex);
            let rust_wire = shared.seal_with_nonce(&plaintext, &NONCE).unwrap();
            assert_eq!(rust_wire, go_wire, "wire mismatch for plaintext length {length}");
            assert_eq!(shared.open(&go_wire).unwrap(), plaintext);
            println!("RUST_WIRE n={length} {}", hex(&rust_wire));
        }
    }

    #[test]
    fn open_rejects_short_packets_and_nonce_tag_or_ciphertext_tampering() {
        let shared = shared();
        assert_eq!(shared.open(&[]), Err(Error::ShortCiphertext { got: 0, want: NONCE_LEN }));
        assert_eq!(shared.open(&[0; NONCE_LEN - 1]), Err(Error::ShortCiphertext { got: 23, want: NONCE_LEN }));
        assert_eq!(shared.open(&[0; NONCE_LEN]), Err(Error::Authentication));

        let mut packet = shared.seal_with_nonce(b"authenticated payload", &NONCE).unwrap();
        for index in [0, NONCE_LEN, NONCE_LEN + 16] {
            let mut tampered = packet.clone();
            tampered[index] ^= 1;
            assert_eq!(shared.open(&tampered), Err(Error::Authentication), "tamper at byte {index}");
        }
        packet.truncate(NONCE_LEN + 15);
        assert_eq!(shared.open(&packet), Err(Error::Authentication));
    }

    #[test]
    fn rejects_zero_private_and_non_contributory_peer_keys() {
        let peer = DiscoPublic::from_raw32(decode_hex(BOB_PUBLIC));
        assert_eq!(DiscoPrivate::from_raw32([0; 32]).shared(&peer).unwrap_err(), Error::ZeroPrivateKey);

        let private = DiscoPrivate::from_raw32(decode_hex(ALICE_PRIVATE));
        assert_eq!(private.shared(&DiscoPublic::from_raw32([0; 32])).unwrap_err(), Error::NonContributoryPeer);
        let low_order = DiscoPublic::from_raw32([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(private.shared(&low_order).unwrap_err(), Error::NonContributoryPeer);
    }

    #[test]
    fn os_random_nonce_round_trips_and_entropy_failure_never_falls_back() {
        let shared = shared();
        let plaintext = b"fresh nonce";
        let first = shared.seal(plaintext).unwrap();
        let second = shared.seal(plaintext).unwrap();
        assert_eq!(shared.open(&first).unwrap(), plaintext);
        assert_eq!(shared.open(&second).unwrap(), plaintext);
        assert_ne!(&first[..NONCE_LEN], &second[..NONCE_LEN]);

        let mut failed_rng = FailingRng;
        assert_eq!(
            shared.seal_with_rng(plaintext, &mut failed_rng).unwrap_err(),
            Error::Entropy("test entropy unavailable".to_owned())
        );
    }

    #[test]
    fn encryption_does_not_add_an_arbitrary_one_mib_wire_limit() {
        let shared = shared();
        let plaintext = vec![0x5a; 1024 * 1024 + 1];
        let packet = shared.seal_with_nonce(&plaintext, &NONCE).unwrap();
        assert_eq!(packet.len(), NONCE_LEN + 16 + plaintext.len());
        assert_eq!(shared.open(&packet).unwrap(), plaintext);
    }

    struct FailingRng;

    impl TryRngCore for FailingRng {
        type Error = io::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(io::Error::other("test entropy unavailable"))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(io::Error::other("test entropy unavailable"))
        }

        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            Err(io::Error::other("test entropy unavailable"))
        }
    }

    impl TryCryptoRng for FailingRng {}
}
