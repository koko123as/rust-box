use alloc::vec::Vec;

use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{ClientHelloExtensionOrderEntry, ClientHelloExtensionOrderError};

/// One entry in a locally constructed ClientHello extension profile.
#[allow(dead_code)] // Caller-side profile mapping is a later fork step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ClientHelloExtensionProfileEntry {
    /// A typed extension. It is emitted when the handshake constructs it.
    Typed(ExtensionType),
    /// A non-GREASE unknown extension with a fixed payload.
    Opaque { extension_type: ExtensionType, payload: Vec<u8> },
    /// An RFC 8701 extension whose codepoint is chosen per connection.
    Grease { payload: Vec<u8> },
}

/// Structured extension ordering for a client profile.
///
/// This controls ordering and locally constructed unknown extensions only. It
/// does not construct typed extension payloads. In particular, key shares stay
/// in the typed TLS key-exchange path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientHelloExtensionProfile {
    entries: Vec<ClientHelloExtensionProfileEntry>,
}

impl ClientHelloExtensionProfile {
    #[allow(dead_code)] // Caller-side profile mapping is a later fork step.
    pub(crate) fn new(entries: Vec<ClientHelloExtensionProfileEntry>) -> Result<Self, ClientHelloExtensionOrderError> {
        let mut seen = Vec::with_capacity(entries.len());
        let mut grease_count = 0;

        for entry in &entries {
            match entry {
                ClientHelloExtensionProfileEntry::Typed(extension_type) => {
                    if let ExtensionType::Unknown(codepoint) = extension_type {
                        return Err(ClientHelloExtensionOrderError::TypedUnknownExtension(*codepoint));
                    }
                    if seen.contains(extension_type) {
                        return Err(ClientHelloExtensionOrderError::DuplicateExtension(u16::from(*extension_type)));
                    }
                    seen.push(*extension_type);
                }
                ClientHelloExtensionProfileEntry::Opaque { extension_type, payload } => {
                    if seen.contains(extension_type) {
                        return Err(ClientHelloExtensionOrderError::DuplicateExtension(u16::from(*extension_type)));
                    }
                    if *extension_type == ExtensionType::PreSharedKey {
                        return Err(ClientHelloExtensionOrderError::OpaquePreSharedKey);
                    }
                    let ExtensionType::Unknown(codepoint) = extension_type else {
                        return Err(ClientHelloExtensionOrderError::OpaqueKnownExtension(u16::from(*extension_type)));
                    };
                    if is_grease_codepoint(*codepoint) {
                        return Err(ClientHelloExtensionOrderError::StaticGreaseCodepoint(*codepoint));
                    }
                    if payload.len() > usize::from(u16::MAX) {
                        return Err(ClientHelloExtensionOrderError::OpaqueExtensionTooLong);
                    }
                    seen.push(*extension_type);
                }
                ClientHelloExtensionProfileEntry::Grease { payload } => {
                    if payload.len() > usize::from(u16::MAX) {
                        return Err(ClientHelloExtensionOrderError::OpaqueExtensionTooLong);
                    }
                    grease_count += 1;
                }
            }
        }

        if grease_count > 16 {
            return Err(ClientHelloExtensionOrderError::TooManyGreaseExtensions);
        }

        Ok(Self { entries })
    }

    /// Shuffles ordinary entries using the pinned uTLS Go 1.20 small-n algorithm.
    #[allow(dead_code)] // Called only by the staged, disabled uTLS profile builder.
    pub(crate) fn shuffle_utls_extensions(&mut self, seed: i64) {
        let reserved_slots = self
            .entries
            .iter()
            .map(|entry| match entry {
                ClientHelloExtensionProfileEntry::Grease { .. }
                | ClientHelloExtensionProfileEntry::Typed(ExtensionType::Padding | ExtensionType::PreSharedKey) => true,
                _ => false,
            })
            .collect::<Vec<_>>();
        super::go_math_rand::shuffle_with_reserved_slots(&mut self.entries, &reserved_slots, seed);
    }

    pub(crate) fn grease_count(&self) -> usize {
        self.entries.iter().filter(|entry| matches!(entry, ClientHelloExtensionProfileEntry::Grease { .. })).count()
    }

    /// Resolves dynamic GREASE codepoints once for this connection. The caller
    /// retains the returned order for every ClientHello in the handshake,
    /// including a possible HelloRetryRequest retry.
    pub(crate) fn instantiate(
        &self,
        grease_seeds: &[u16],
    ) -> Result<Vec<ClientHelloExtensionOrderEntry>, ClientHelloExtensionOrderError> {
        if grease_seeds.len() != self.grease_count() {
            return Err(ClientHelloExtensionOrderError::InvalidGreaseSeedCount);
        }

        let mut reserved = self
            .entries
            .iter()
            .filter_map(|entry| match entry {
                ClientHelloExtensionProfileEntry::Typed(extension_type)
                | ClientHelloExtensionProfileEntry::Opaque { extension_type, .. } => Some(*extension_type),
                ClientHelloExtensionProfileEntry::Grease { .. } => None,
            })
            .collect::<Vec<_>>();
        let mut seed_iter = grease_seeds.iter();
        let mut resolved = Vec::with_capacity(self.entries.len());

        for entry in &self.entries {
            match entry {
                ClientHelloExtensionProfileEntry::Typed(extension_type) => {
                    resolved.push(ClientHelloExtensionOrderEntry::Typed(*extension_type));
                }
                ClientHelloExtensionProfileEntry::Opaque { extension_type, payload } => {
                    resolved.push(ClientHelloExtensionOrderEntry::Opaque {
                        extension_type: *extension_type,
                        payload: payload.clone(),
                    });
                }
                ClientHelloExtensionProfileEntry::Grease { payload } => {
                    let seed = *seed_iter.next().expect("GREASE seed count was checked before resolving the profile");
                    let mut codepoint = utls_grease_codepoint(seed);
                    if reserved.contains(&ExtensionType::Unknown(codepoint)) {
                        // Match uTLS v1.8.7's collision handling for its two GREASE extensions.
                        codepoint = utls_grease_codepoint(seed ^ 0x1010);
                    }
                    if reserved.contains(&ExtensionType::Unknown(codepoint)) {
                        // Additional profile GREASE entries still need a unique codepoint.
                        codepoint = (0u8..16)
                            .map(|index| 0x0a0a_u16 + u16::from(index) * 0x1010)
                            .find(|codepoint| !reserved.contains(&ExtensionType::Unknown(*codepoint)))
                            .ok_or(ClientHelloExtensionOrderError::NoGreaseCodepointAvailable)?;
                    }
                    let extension_type = ExtensionType::Unknown(codepoint);
                    reserved.push(extension_type);
                    resolved.push(ClientHelloExtensionOrderEntry::Opaque { extension_type, payload: payload.clone() });
                }
            }
        }

        Ok(resolved)
    }

    /// Drops absent typed extensions for the current handshake stage. This
    /// permits conditional extensions such as `cookie` to appear after HRR.
    pub(crate) fn order_for_present_extensions(
        instantiated: &[ClientHelloExtensionOrderEntry],
        present: &[ExtensionType],
    ) -> Vec<ClientHelloExtensionOrderEntry> {
        instantiated
            .iter()
            .filter(|entry| match entry {
                ClientHelloExtensionOrderEntry::Typed(extension_type) => present.contains(extension_type),
                ClientHelloExtensionOrderEntry::Opaque { .. } => true,
            })
            .cloned()
            .collect()
    }
}

#[allow(dead_code)] // Used by the staged profile constructor above.
fn is_grease_codepoint(codepoint: u16) -> bool {
    let high = (codepoint >> 8) as u8;
    let low = codepoint as u8;
    high == low && high & 0x0f == 0x0a
}

/// Maps a uTLS GREASE seed to its repeated-byte `0x?a?a` codepoint.
fn utls_grease_codepoint(seed: u16) -> u16 {
    let octet = (seed & 0x00f0) | 0x000a;
    octet | (octet << 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn resolves_distinct_grease_values_and_preserves_template_order() {
        let profile = ClientHelloExtensionProfile::new(vec![
            ClientHelloExtensionProfileEntry::Grease { payload: vec![0] },
            ClientHelloExtensionProfileEntry::Typed(ExtensionType::ServerName),
            ClientHelloExtensionProfileEntry::Grease { payload: vec![] },
            ClientHelloExtensionProfileEntry::Typed(ExtensionType::KeyShare),
        ])
        .unwrap();

        let order = profile.instantiate(&[2, 2]).unwrap();
        assert_eq!(order.len(), 4);
        assert_eq!(
            order[0],
            ClientHelloExtensionOrderEntry::Opaque { extension_type: ExtensionType::Unknown(0x0a0a), payload: vec![0] }
        );
        assert_eq!(order[1], ClientHelloExtensionOrderEntry::Typed(ExtensionType::ServerName));
        assert_eq!(
            order[2],
            ClientHelloExtensionOrderEntry::Opaque { extension_type: ExtensionType::Unknown(0x1a1a), payload: vec![] }
        );
        assert_eq!(order[3], ClientHelloExtensionOrderEntry::Typed(ExtensionType::KeyShare));
    }

    #[test]
    fn utls_grease_seed_mapping_matches_pinned_formula_and_collision_rule() {
        for (seed, expected) in [
            (0x0000, 0x0a0a),
            (0x0010, 0x1a1a),
            (0x0050, 0x5a5a),
            (0x00a5, 0xaaaa),
            (0x00f0, 0xfafa),
            (0x0100, 0x0a0a),
            (0xffff, 0xfafa),
        ] {
            let codepoint = utls_grease_codepoint(seed);
            assert_eq!(codepoint, expected);
            assert!(is_grease_codepoint(codepoint));
        }

        let profile = ClientHelloExtensionProfile::new(vec![
            ClientHelloExtensionProfileEntry::Grease { payload: vec![] },
            ClientHelloExtensionProfileEntry::Grease { payload: vec![0] },
        ])
        .unwrap();
        let resolved = profile.instantiate(&[0x0000, 0x0100]).unwrap();
        assert_eq!(
            resolved,
            vec![
                ClientHelloExtensionOrderEntry::Opaque {
                    extension_type: ExtensionType::Unknown(0x0a0a),
                    payload: vec![],
                },
                ClientHelloExtensionOrderEntry::Opaque {
                    extension_type: ExtensionType::Unknown(0x1a1a),
                    payload: vec![0],
                },
            ]
        );
    }

    #[test]
    fn filters_conditional_typed_extensions_without_dropping_opaque_entries() {
        let order = vec![
            ClientHelloExtensionOrderEntry::Typed(ExtensionType::Cookie),
            ClientHelloExtensionOrderEntry::Opaque { extension_type: ExtensionType::Unknown(0x1234), payload: vec![] },
            ClientHelloExtensionOrderEntry::Typed(ExtensionType::KeyShare),
        ];
        let filtered = ClientHelloExtensionProfile::order_for_present_extensions(&order, &[ExtensionType::KeyShare]);
        assert_eq!(
            filtered,
            vec![
                ClientHelloExtensionOrderEntry::Opaque {
                    extension_type: ExtensionType::Unknown(0x1234),
                    payload: vec![],
                },
                ClientHelloExtensionOrderEntry::Typed(ExtensionType::KeyShare),
            ]
        );
    }

    #[test]
    fn utls_shuffle_matches_go_and_keeps_grease_padding_and_psk_slots_fixed() {
        let mut entries = Vec::new();
        for slot in 0..18 {
            entries.push(match slot {
                0 | 17 => ClientHelloExtensionProfileEntry::Grease { payload: vec![slot as u8] },
                3 => ClientHelloExtensionProfileEntry::Typed(ExtensionType::Padding),
                14 => ClientHelloExtensionProfileEntry::Typed(ExtensionType::PreSharedKey),
                _ => ClientHelloExtensionProfileEntry::Opaque {
                    extension_type: ExtensionType::Unknown(0x1200 + slot as u16),
                    payload: vec![slot as u8],
                },
            });
        }
        let original_entries = entries.clone();
        let mut profile = ClientHelloExtensionProfile::new(entries).unwrap();

        profile.shuffle_utls_extensions(1);

        const GO_SHUFFLE_ORDER: [usize; 18] = [0, 12, 7, 3, 6, 16, 13, 4, 2, 9, 1, 11, 8, 5, 14, 10, 15, 17];
        let expected_entries = GO_SHUFFLE_ORDER.map(|slot| original_entries[slot].clone());
        assert_eq!(profile.entries, expected_entries);
    }

    #[test]
    fn rejects_known_opaque_static_grease_and_wrong_seed_count() {
        assert_eq!(
            ClientHelloExtensionProfile::new(vec![ClientHelloExtensionProfileEntry::Opaque {
                extension_type: ExtensionType::KeyShare,
                payload: vec![0],
            }]),
            Err(ClientHelloExtensionOrderError::OpaqueKnownExtension(0x0033))
        );
        assert_eq!(
            ClientHelloExtensionProfile::new(vec![ClientHelloExtensionProfileEntry::Opaque {
                extension_type: ExtensionType::Unknown(0x0a0a),
                payload: vec![],
            }]),
            Err(ClientHelloExtensionOrderError::StaticGreaseCodepoint(0x0a0a))
        );
        assert_eq!(
            ClientHelloExtensionProfile::new(vec![ClientHelloExtensionProfileEntry::Typed(ExtensionType::Unknown(
                0x1234
            ),)]),
            Err(ClientHelloExtensionOrderError::TypedUnknownExtension(0x1234))
        );

        let profile =
            ClientHelloExtensionProfile::new(vec![ClientHelloExtensionProfileEntry::Grease { payload: vec![] }])
                .unwrap();
        assert_eq!(profile.instantiate(&[]), Err(ClientHelloExtensionOrderError::InvalidGreaseSeedCount));
    }
}
