#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use pki_types::{CertificateDer, ServerName};

use crate::client::{ClientConfig, ClientConnection, Resumption, Tls12Resumption};
use crate::crypto::CryptoProvider;
use crate::enums::{CipherSuite, ContentType, ProtocolVersion, SignatureScheme};
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::Reader;
use crate::msgs::enums::{Compression, ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, HelloRetryRequest, Random,
    ServerHelloPayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload, OutboundOpaqueMessage};
use crate::sync::Arc;
use crate::{Error, PeerIncompatible, PeerMisbehaved, RootCertStore};

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use std::sync::OnceLock;

    use super::super::*;
    use crate::client::AlwaysResolvesClientRawPublicKeys;
    use crate::crypto::cipher::{MessageDecrypter, MessageEncrypter};
    use crate::crypto::tls13::OkmBlock;
    use crate::enums::{CertificateType, HandshakeType};
    use crate::msgs::base::{Payload, PayloadU8};
    use crate::msgs::ccs::ChangeCipherSpecPayload;
    use crate::msgs::codec::Codec;
    use crate::msgs::client_hello_profile::{
        ClientHelloExtensionProfile, ClientHelloExtensionProfileEntry,
    };
    use crate::msgs::enums::ECCurveType;
    use crate::msgs::handshake::{
        CertificateChain, CertificateEntry, CertificatePayloadTls13, EcParameters,
        HelloRetryRequestExtensions, KeyShareEntry, ProtocolName, ServerEcdhParams,
        ServerExtensions, ServerKeyExchange, ServerKeyExchangeParams, ServerKeyExchangePayload,
        SingleProtocolName,
    };
    use crate::msgs::message::{InboundOpaqueMessage, PlainMessage};
    use crate::pki_types::pem::PemObject;
    use crate::pki_types::{PrivateKeyDer, UnixTime};
    use crate::sign::CertifiedKey;
    use crate::tls13::key_schedule::{
        derive_traffic_iv, derive_traffic_key, hkdf_expand_label_block,
    };
    use crate::verify::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use crate::{DigitallySignedStruct, DistinguishedName, KeyLog, version};

    #[test]
    fn client_hello_profile_utls_shuffle_orders_wire_extensions_and_reuses_grease_after_hrr() {
        let mut config = ClientConfig::builder_with_provider(super::provider::default_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        let baseline = client_hello_sent_for_config(config.clone()).unwrap();
        let typed_extensions = baseline.extensions.collect_used();
        assert!(typed_extensions.contains(&ExtensionType::KeyShare));
        assert!(!typed_extensions.contains(&ExtensionType::ApplicationSettings));
        config.application_settings_protocols = Some(vec![b"h2".to_vec()]);
        let mut typed_extensions = typed_extensions;
        typed_extensions.push(ExtensionType::ApplicationSettings);

        let mut profile_entries = vec![
            ClientHelloExtensionProfileEntry::Grease { payload: vec![0x41] },
            ClientHelloExtensionProfileEntry::Opaque {
                extension_type: ExtensionType::Unknown(0x1234),
                payload: vec![0xaa, 0xbb],
            },
            ClientHelloExtensionProfileEntry::Typed(ExtensionType::Cookie),
        ];
        profile_entries.extend(
            typed_extensions
                .iter()
                .copied()
                .map(ClientHelloExtensionProfileEntry::Typed),
        );
        assert!(profile_entries.len() <= 17);
        let mut dummy_extension = 0x1300;
        while profile_entries.len() < 17 {
            profile_entries.push(ClientHelloExtensionProfileEntry::Opaque {
                extension_type: ExtensionType::Unknown(dummy_extension),
                payload: vec![0xf0],
            });
            dummy_extension += 1;
        }
        profile_entries.push(ClientHelloExtensionProfileEntry::Grease { payload: vec![0x42] });
        assert_eq!(profile_entries.len(), 18);

        let template_entries = profile_entries.clone();
        let mut profile = ClientHelloExtensionProfile::new(profile_entries).unwrap();
        profile.shuffle_utls_extensions(1);
        config.client_hello_extension_profile = Some(profile);

        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut first_bytes = Vec::new();
        conn.write_tls(&mut first_bytes).unwrap();
        let first_extensions = client_hello_extensions_from_wire(&first_bytes);
        let first_grease_extension = first_extensions[0].0;
        let last_grease_extension = first_extensions.last().unwrap().0;
        let expected_types_for = |include_cookie: bool| {
            const GO_SHUFFLE_ORDER: [usize; 18] =
                [0, 12, 3, 7, 14, 16, 13, 4, 2, 9, 1, 11, 8, 5, 6, 10, 15, 17];
            GO_SHUFFLE_ORDER
                .into_iter()
                .filter_map(|slot| match &template_entries[slot] {
                    ClientHelloExtensionProfileEntry::Grease { .. } if slot == 0 => {
                        Some(first_grease_extension)
                    }
                    ClientHelloExtensionProfileEntry::Grease { .. } => Some(last_grease_extension),
                    ClientHelloExtensionProfileEntry::Typed(ExtensionType::Cookie) if !include_cookie => None,
                    ClientHelloExtensionProfileEntry::Typed(extension_type) => Some(*extension_type),
                    ClientHelloExtensionProfileEntry::Opaque { extension_type, .. } => Some(*extension_type),
                })
                .collect::<Vec<_>>()
        };
        let first_extension_types = first_extensions
            .iter()
            .map(|(extension_type, _)| *extension_type)
            .collect::<Vec<_>>();
        assert_eq!(first_extension_types, expected_types_for(false));
        assert_eq!(first_extensions[0].1, vec![0x41]);
        assert_eq!(first_extensions.last().unwrap().1.as_slice(), &[0x42]);
        let opaque_extension = first_extensions
            .iter()
            .find(|(extension_type, _)| *extension_type == ExtensionType::Unknown(0x1234))
            .unwrap();
        assert_eq!(opaque_extension.1.as_slice(), &[0xaa, 0xbb]);
        let application_settings = first_extensions
            .iter()
            .find(|(extension_type, _)| *extension_type == ExtensionType::ApplicationSettings)
            .unwrap();
        assert_eq!(u16::from(application_settings.0), 0x44cd);
        assert_eq!(application_settings.1.as_slice(), b"\x00\x03\x02h2");
        for grease_extension in [first_grease_extension, last_grease_extension] {
            let grease_codepoint = u16::from(grease_extension);
            assert_eq!((grease_codepoint >> 8) as u8, grease_codepoint as u8);
            assert_eq!(grease_codepoint as u8 & 0x0f, 0x0a);
        }
        assert_ne!(first_grease_extension, last_grease_extension);

        let first_hello = client_hello_from_wire(&first_bytes);
        let first_key_share = first_hello.extensions.key_shares.as_ref().unwrap()[0].group;
        let hrr = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: first_hello.session_id,
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    extensions: HelloRetryRequestExtensions {
                        cookie: Some(PayloadU16::new(vec![1, 2, 3, 4])),
                        supported_versions: Some(ProtocolVersion::TLSv1_3),
                        ..HelloRetryRequestExtensions::default()
                    },
                }),
            )),
        };
        conn.read_tls(&mut hrr.into_wire_bytes().as_slice()).unwrap();
        conn.process_new_packets().unwrap();

        let mut retry_bytes = Vec::new();
        conn.write_tls(&mut retry_bytes).unwrap();
        let retry_extensions = client_hello_extensions_from_wire(&retry_bytes);
        let retry_extension_types = retry_extensions
            .iter()
            .map(|(extension_type, _)| *extension_type)
            .collect::<Vec<_>>();
        assert_eq!(retry_extension_types, expected_types_for(true));
        assert_eq!(
            retry_extensions
                .iter()
                .find(|(extension_type, _)| *extension_type == ExtensionType::ApplicationSettings),
            first_extensions
                .iter()
                .find(|(extension_type, _)| *extension_type == ExtensionType::ApplicationSettings)
        );
        assert_eq!(retry_extensions[0].0, first_grease_extension);
        assert_eq!(retry_extensions.last().unwrap().0, last_grease_extension);
        assert_eq!(retry_extensions[0].1, vec![0x41]);
        assert_eq!(retry_extensions.last().unwrap().1.as_slice(), &[0x42]);
        assert!(retry_extensions.iter().any(|(extension_type, _)| *extension_type == ExtensionType::Cookie));
        let retry_hello = client_hello_from_wire(&retry_bytes);
        assert_eq!(
            retry_hello.extensions.key_shares.as_ref().unwrap()[0].group,
            first_key_share
        );
    }

    /// Tests that session_ticket(35) extension
    /// is not sent if the client does not support TLS 1.2.
    #[test]
    fn test_no_session_ticket_request_on_tls_1_3() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        config.resumption = Resumption::in_memory_sessions(128)
            .tls12_resumption(Tls12Resumption::SessionIdOrTickets);
        let ch = client_hello_sent_for_config(config).unwrap();
        assert!(ch.extensions.session_ticket.is_none());
    }

    #[test]
    fn test_no_renegotiation_scsv_on_tls_1_3() {
        let ch = client_hello_sent_for_config(
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth(),
        )
        .unwrap();
        assert!(
            !ch.cipher_suites
                .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        );
    }

    #[test]
    fn test_client_does_not_offer_sha1() {
        for version in crate::ALL_VERSIONS {
            let config =
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_root_certificates(roots())
                    .with_no_client_auth();
            let ch = client_hello_sent_for_config(config).unwrap();
            assert!(
                !ch.extensions
                    .signature_schemes
                    .as_ref()
                    .unwrap()
                    .contains(&SignatureScheme::RSA_PKCS1_SHA1),
                "sha1 unexpectedly offered"
            );
        }
    }

    #[test]
    fn test_client_rejects_hrr_with_varied_session_id() {
        let config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        // server replies with HRR, but does not echo `session_id` as required.
        let hrr = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: HelloRetryRequestExtensions {
                        cookie: Some(PayloadU16::new(vec![1, 2, 3, 4])),
                        ..HelloRetryRequestExtensions::default()
                    },
                }),
            )),
        };

        conn.read_tls(&mut hrr.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId.into()
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
        let mut config =
            ClientConfig::builder_with_provider(super::provider::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots())
                .with_no_client_auth();
        if config.provider.fips() {
            assert!(config.require_ems);
        } else {
            config.require_ems = true;
        }

        let config = Arc::new(config);
        let mut conn =
            ClientConnection::new(config.clone(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random::new(config.provider.secure_random).unwrap(),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions::default()),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets(),
            Err(PeerIncompatible::ExtendedMasterSecretExtensionRequired.into())
        );
    }

    #[test]
    fn cas_extension_in_client_hello_if_server_verifier_requests_it() {
        let cas_sending_server_verifier =
            ServerVerifierWithAuthorityNames(vec![DistinguishedName::from(b"hello".to_vec())]);

        for (protocol_version, cas_extension_expected) in
            [(&version::TLS12, false), (&version::TLS13, true)]
        {
            let client_hello = client_hello_sent_for_config(
                ClientConfig::builder_with_provider(super::provider::default_provider().into())
                    .with_protocol_versions(&[protocol_version])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(cas_sending_server_verifier.clone()))
                    .with_no_client_auth(),
            )
            .unwrap();
            assert_eq!(
                client_hello
                    .extensions
                    .certificate_authority_names
                    .is_some(),
                cas_extension_expected
            );
        }
    }

    /// Regression test for <https://github.com/seanmonstar/reqwest/issues/2191>
    #[cfg(feature = "tls12")]
    #[test]
    fn test_client_with_custom_verifier_can_accept_ecdsa_sha1_signatures() {
        let verifier = Arc::new(ExpectSha1EcdsaVerifier::default());
        let config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0u8; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_2,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        extended_master_secret_ack: Some(()),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let cert = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::Certificate(CertificateChain(vec![CertificateDer::from(
                    &b"does not matter"[..],
                )])),
            )),
        };
        conn.read_tls(&mut cert.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_kx = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Known(
                    ServerKeyExchange {
                        dss: DigitallySignedStruct::new(
                            SignatureScheme::ECDSA_SHA1_Legacy,
                            b"also does not matter".to_vec(),
                        ),
                        params: ServerKeyExchangeParams::Ecdh(ServerEcdhParams {
                            curve_params: EcParameters {
                                curve_type: ECCurveType::NamedCurve,
                                named_group: NamedGroup::X25519,
                            },
                            public: PayloadU8::new(vec![0xab; 32]),
                        }),
                    },
                )),
            )),
        };
        conn.read_tls(&mut server_kx.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let server_done = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHelloDone,
            )),
        };
        conn.read_tls(&mut server_done.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        assert!(
            verifier
                .seen_sha1_signature
                .load(Ordering::SeqCst)
        );
    }

    #[derive(Debug, Default)]
    struct ExpectSha1EcdsaVerifier {
        seen_sha1_signature: AtomicBool,
    }

    impl ServerCertVerifier for ExpectSha1EcdsaVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            assert_eq!(dss.scheme, SignatureScheme::ECDSA_SHA1_Legacy);
            self.seen_sha1_signature
                .store(true, Ordering::SeqCst);
            Ok(HandshakeSignatureValid::assertion())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_SHA1_Legacy]
        }
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions::default()),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_offers_x509_id() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::X509),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509_by_omission() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_rejects_server_that_only_demands_x509() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::X509),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Err(PeerIncompatible::IncorrectCertificateTypeExtension.into())
        );
    }

    #[test]
    fn test_client_requiring_rpk_accepts_rpk_server() {
        assert_eq!(
            client_requiring_rpk_receives_server_ee(ServerExtensions {
                client_certificate_type: Some(CertificateType::RawPublicKey),
                server_certificate_type: Some(CertificateType::RawPublicKey),
                ..ServerExtensions::default()
            }),
            Ok(())
        );
    }

    #[test]
    fn client_rejects_application_settings_response_without_alpn() {
        assert_eq!(
            client_receives_application_settings(None).map(|_| ()),
            Err(Error::General(
                "tls: server sent application settings without ALPN".into()
            ))
        );
    }

    #[test]
    fn client_records_application_settings_response_after_alpn_negotiation() {
        let conn = client_receives_application_settings(Some(SingleProtocolName::new(
            ProtocolName::from(b"h2".to_vec()),
        )))
        .unwrap();
        assert!(conn.core.data.application_settings_response_received);
    }

    fn client_receives_application_settings(
        selected_protocol: Option<SingleProtocolName>,
    ) -> Result<ClientConnection, Error> {
        let fake_server_crypto = Arc::new(FakeServerCrypto::new());
        let mut config = client_config_for_rpk(fake_server_crypto.clone());
        config.alpn_protocols = vec![b"h2".to_vec()];
        config.application_settings_protocols = Some(vec![b"h2".to_vec()]);
        let mut conn = ClientConnection::new(
            config.into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_3,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        key_share: Some(KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(vec![0xaa; 32]),
                        }),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let ee = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::EncryptedExtensions(Box::new(ServerExtensions {
                    selected_protocol,
                    application_settings: Some(Payload::empty()),
                    client_certificate_type: Some(CertificateType::RawPublicKey),
                    server_certificate_type: Some(CertificateType::RawPublicKey),
                    ..ServerExtensions::default()
                })),
            )),
        };
        let mut encrypter = fake_server_crypto.server_handshake_encrypter();
        let encrypted_ee = encrypter
            .encrypt(PlainMessage::from(ee).borrow_outbound(), 0)
            .unwrap();
        conn.read_tls(&mut encrypted_ee.encode().as_slice())
            .unwrap();
        conn.process_new_packets()?;
        Ok(conn)
    }

    #[test]
    fn client_sends_encrypted_application_settings_before_finished_and_hashes_it() {
        let fake_server_crypto = Arc::new(FakeServerCrypto::new());
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptTestServerCertificate))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.application_settings_protocols = Some(vec![b"h2".to_vec()]);
        config.key_log = fake_server_crypto.clone();

        let mut client = ClientConnection::new(
            config.into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut client_hello_record = Vec::new();
        client.write_tls(&mut client_hello_record).unwrap();
        assert_eq!(
            client_hello_record[0],
            u8::from(ContentType::Handshake),
            "first client record must contain ClientHello"
        );
        let client_hello_record_len =
            u16::from_be_bytes([client_hello_record[3], client_hello_record[4]]) as usize;
        let client_hello_end = 5 + client_hello_record_len;
        assert!(client_hello_end <= client_hello_record.len());
        let client_hello_handshake = &client_hello_record[5..client_hello_end];
        assert_eq!(
            client_hello_handshake[0],
            u8::from(HandshakeType::ClientHello)
        );

        if std::env::var_os("RUSTLS_M10_CLIENT_HELLO_DUMP").is_some() {
            let hex = hex::encode(&client_hello_record[..client_hello_end]);
            std::eprintln!("RUSTLS_M10_CLIENT_HELLO={hex}");
        }

        // The transcript is over handshake messages, not TLS record headers.
        let mut transcript = client_hello_handshake.to_vec();
        let server_hello = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_3,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        key_share: Some(KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(vec![0xaa; 32]),
                        }),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        let server_hello_record = server_hello.into_wire_bytes();
        transcript.extend_from_slice(&server_hello_record[5..]);
        client.read_tls(&mut server_hello_record.as_slice()).unwrap();
        client.process_new_packets().unwrap();

        let server_encrypted_extensions = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::EncryptedExtensions(Box::new(ServerExtensions {
                    selected_protocol: Some(SingleProtocolName::new(ProtocolName::from(
                        b"h2".to_vec(),
                    ))),
                    application_settings: Some(Payload::empty()),
                    ..ServerExtensions::default()
                })),
            )),
        };
        let server_certificate = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::CertificateTls13(CertificatePayloadTls13 {
                    context: PayloadU8::empty(),
                    entries: vec![CertificateEntry::new(CertificateDer::from(
                        b"test-only synthetic certificate".to_vec(),
                    ))],
                }),
            )),
        };
        let server_certificate_verify = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::CertificateVerify(DigitallySignedStruct::new(
                    SignatureScheme::RSA_PSS_SHA256,
                    vec![0xaa],
                )),
            )),
        };

        let suite = super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap();
        let mut server_encrypter = fake_server_crypto.server_handshake_encrypter();
        let mut server_flight = Vec::new();
        server_flight.extend(encrypt_handshake_and_update_transcript(
            server_encrypted_extensions,
            server_encrypter.as_mut(),
            0,
            &mut transcript,
        ));
        server_flight.extend(encrypt_handshake_and_update_transcript(
            server_certificate,
            server_encrypter.as_mut(),
            1,
            &mut transcript,
        ));
        server_flight.extend(encrypt_handshake_and_update_transcript(
            server_certificate_verify,
            server_encrypter.as_mut(),
            2,
            &mut transcript,
        ));

        let server_finished_verify_data = tls13_finished_verify_data(
            fake_server_crypto.server_handshake_secret.get().unwrap(),
            &transcript,
            suite,
        );
        server_flight.extend(encrypt_handshake_and_update_transcript(
            Message {
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::handshake(HandshakeMessagePayload(
                    HandshakePayload::Finished(Payload::new(server_finished_verify_data)),
                )),
            },
            server_encrypter.as_mut(),
            3,
            &mut transcript,
        ));

        client.read_tls(&mut server_flight.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        assert!(!client.is_handshaking());
        assert_eq!(client.alpn_protocol(), Some(b"h2".as_slice()));

        let mut encrypted_client_flight = Vec::new();
        client.write_tls(&mut encrypted_client_flight).unwrap();
        assert!(!encrypted_client_flight.is_empty());

        let mut client_transcript = transcript.clone();
        let mut client_decrypter = fake_server_crypto.client_handshake_decrypter();
        let mut client_handshake_messages = Vec::new();
        let mut record_sequence = 0;
        let mut record_offset = 0;
        let mut client_finished_verify_data = None;

        while record_offset < encrypted_client_flight.len() {
            let header_end = record_offset + 5;
            assert!(header_end <= encrypted_client_flight.len());
            let record_len = u16::from_be_bytes([
                encrypted_client_flight[record_offset + 3],
                encrypted_client_flight[record_offset + 4],
            ]) as usize;
            let record_end = header_end + record_len;
            assert!(record_end <= encrypted_client_flight.len());
            let content_type = encrypted_client_flight[record_offset];

            if content_type == u8::from(ContentType::ChangeCipherSpec) {
                assert_eq!(&encrypted_client_flight[header_end..record_end], &[1]);
                record_offset = record_end;
                continue;
            }

            assert_eq!(
                content_type,
                u8::from(ContentType::ApplicationData)
            );
            let mut ciphertext = encrypted_client_flight[header_end..record_end].to_vec();
            let decrypted = client_decrypter
                .decrypt(
                    InboundOpaqueMessage::new(
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        &mut ciphertext,
                    ),
                    record_sequence,
                )
                .unwrap();
            record_sequence += 1;
            assert_eq!(decrypted.typ, ContentType::Handshake);
            assert_eq!(decrypted.version, ProtocolVersion::TLSv1_3);

            let mut reader = Reader::init(decrypted.payload);
            while reader.any_left() {
                let message = HandshakeMessagePayload::read_version(
                    &mut reader,
                    ProtocolVersion::TLSv1_3,
                )
                .unwrap();
                let encoded = message.get_encoding();
                match message.0 {
                    HandshakePayload::EncryptedExtensions(extensions) => {
                        assert_eq!(
                            extensions.collect_used(),
                            vec![ExtensionType::ApplicationSettings]
                        );
                        assert!(extensions
                            .application_settings
                            .as_ref()
                            .unwrap()
                            .bytes()
                            .is_empty());
                        client_handshake_messages.push(HandshakeType::EncryptedExtensions);
                        client_transcript.extend_from_slice(&encoded);
                    }
                    HandshakePayload::Finished(verify_data) => {
                        let expected = tls13_finished_verify_data(
                            fake_server_crypto.client_handshake_secret.get().unwrap(),
                            &client_transcript,
                            suite,
                        );
                        assert_eq!(verify_data.bytes(), expected.as_slice());
                        let missing_alps = tls13_finished_verify_data(
                            fake_server_crypto.client_handshake_secret.get().unwrap(),
                            &transcript,
                            suite,
                        );
                        assert_ne!(verify_data.bytes(), missing_alps.as_slice());
                        client_finished_verify_data = Some(verify_data.bytes().to_vec());
                        client_handshake_messages.push(HandshakeType::Finished);
                    }
                    other => panic!("unexpected client handshake message: {other:?}"),
                }
            }
            record_offset = record_end;
        }

        assert_eq!(
            client_handshake_messages,
            [HandshakeType::EncryptedExtensions, HandshakeType::Finished]
        );
        assert!(client_finished_verify_data.is_some());
    }

    fn client_requiring_rpk_receives_server_ee(
        encrypted_extensions: ServerExtensions<'_>,
    ) -> Result<(), Error> {
        let fake_server_crypto = Arc::new(FakeServerCrypto::new());
        let mut conn = ClientConnection::new(
            client_config_for_rpk(fake_server_crypto.clone()).into(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_3,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        key_share: Some(KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(vec![0xaa; 32]),
                        }),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let ee = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::EncryptedExtensions(Box::new(encrypted_extensions)),
            )),
        };

        let mut encrypter = fake_server_crypto.server_handshake_encrypter();
        let enc_ee = encrypter
            .encrypt(PlainMessage::from(ee).borrow_outbound(), 0)
            .unwrap();
        conn.read_tls(&mut enc_ee.encode().as_slice())
            .unwrap();
        conn.process_new_packets().map(|_| ())
    }

    fn encrypt_handshake_and_update_transcript(
        message: Message<'_>,
        encrypter: &mut dyn MessageEncrypter,
        sequence: u64,
        transcript: &mut Vec<u8>,
    ) -> Vec<u8> {
        let plaintext = PlainMessage::from(message);
        transcript.extend_from_slice(plaintext.payload.bytes());
        encrypter
            .encrypt(plaintext.borrow_outbound(), sequence)
            .unwrap()
            .encode()
    }

    fn tls13_finished_verify_data(
        traffic_secret: &[u8],
        transcript: &[u8],
        suite: &crate::tls13::Tls13CipherSuite,
    ) -> Vec<u8> {
        let traffic_secret = OkmBlock::new(traffic_secret);
        let expander = suite.hkdf_provider.expander_for_okm(&traffic_secret);
        let finished_key = hkdf_expand_label_block(expander.as_ref(), b"finished", &[]);
        let transcript_hash = suite.common.hash_provider.hash(transcript);
        suite
            .hkdf_provider
            .hmac_sign(&finished_key, transcript_hash.as_ref())
            .as_ref()
            .to_vec()
    }

    #[test]
    fn test_client_rejects_protected_change_cipher_spec() {
        let fake_server_crypto = Arc::new(FakeServerCrypto::new());
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth();
        config.key_log = fake_server_crypto.clone();
        let mut conn =
            ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())
                .unwrap();
        let mut sent = Vec::new();
        conn.write_tls(&mut sent).unwrap();

        let sh = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    random: Random([0; 32]),
                    compression_method: Compression::Null,
                    cipher_suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
                    legacy_version: ProtocolVersion::TLSv1_3,
                    session_id: SessionId::empty(),
                    extensions: Box::new(ServerExtensions {
                        key_share: Some(KeyShareEntry {
                            group: NamedGroup::X25519,
                            payload: PayloadU16::new(vec![0xaa; 32]),
                        }),
                        ..ServerExtensions::default()
                    }),
                }),
            )),
        };
        conn.read_tls(&mut sh.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        // A change_cipher_spec protected under the handshake keys is not a
        // compatibility-mode CCS, and must not be dropped like one.
        let ccs = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload),
        };

        let mut encrypter = fake_server_crypto.server_handshake_encrypter();
        let enc_ccs = encrypter
            .encrypt(PlainMessage::from(ccs).borrow_outbound(), 0)
            .unwrap();
        conn.read_tls(&mut enc_ccs.encode().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::IllegalMiddleboxChangeCipherSpec.into()
        );
    }

    fn client_config_for_rpk(key_log: Arc<dyn KeyLog>) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(x25519_provider().into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerVerifierRequiringRpk))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(Arc::new(
                client_certified_key(),
            ))));
        config.key_log = key_log;
        config
    }

    fn client_certified_key() -> CertifiedKey {
        let key = super::provider::default_provider()
            .key_provider
            .load_private_key(client_key())
            .unwrap();
        let public_key_as_cert = vec![CertificateDer::from(
            key.public_key()
                .unwrap()
                .as_ref()
                .to_vec(),
        )];
        CertifiedKey::new(public_key_as_cert, key)
    }

    fn client_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/rsa-2048/client.key").as_slice(),
        )
        .unwrap()
    }

    fn x25519_provider() -> CryptoProvider {
        // ensures X25519 is offered irrespective of cfg(feature = "fips"), which eases
        // creation of fake server messages.
        CryptoProvider {
            kx_groups: vec![super::provider::kx_group::X25519],
            ..super::provider::default_provider()
        }
    }

    #[derive(Clone, Debug)]
    struct ServerVerifierWithAuthorityNames(Vec<DistinguishedName>);

    impl ServerCertVerifier for ServerVerifierWithAuthorityNames {
        fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
            Some(self.0.as_slice())
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            unreachable!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }
    }

    #[derive(Debug)]
    struct ServerVerifierRequiringRpk;

    impl ServerCertVerifier for ServerVerifierRequiringRpk {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            todo!()
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA1]
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct AcceptTestServerCertificate;

    impl ServerCertVerifier for AcceptTestServerCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PSS_SHA256]
        }
    }

    #[derive(Debug)]
    struct FakeServerCrypto {
        server_handshake_secret: OnceLock<Vec<u8>>,
        client_handshake_secret: OnceLock<Vec<u8>>,
    }

    impl FakeServerCrypto {
        fn new() -> Self {
            Self {
                server_handshake_secret: OnceLock::new(),
                client_handshake_secret: OnceLock::new(),
            }
        }

        fn server_handshake_encrypter(&self) -> Box<dyn MessageEncrypter> {
            let cipher_suite = super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap();

            let secret = self
                .server_handshake_secret
                .get()
                .unwrap();

            let expander = cipher_suite
                .hkdf_provider
                .expander_for_okm(&OkmBlock::new(secret));

            // Derive Encrypter
            let key = derive_traffic_key(expander.as_ref(), cipher_suite.aead_alg);
            let iv = derive_traffic_iv(expander.as_ref());
            cipher_suite.aead_alg.encrypter(key, iv)
        }

        fn client_handshake_decrypter(&self) -> Box<dyn MessageDecrypter> {
            let cipher_suite = super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap();

            let secret = self.client_handshake_secret.get().unwrap();
            let expander = cipher_suite
                .hkdf_provider
                .expander_for_okm(&OkmBlock::new(secret));
            let key = derive_traffic_key(expander.as_ref(), cipher_suite.aead_alg);
            let iv = derive_traffic_iv(expander.as_ref());
            cipher_suite.aead_alg.decrypter(key, iv)
        }
    }

    impl KeyLog for FakeServerCrypto {
        fn will_log(&self, _label: &str) -> bool {
            true
        }

        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
                self.server_handshake_secret
                    .set(secret.to_vec())
                    .unwrap();
            } else if label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET" {
                self.client_handshake_secret
                    .set(secret.to_vec())
                    .unwrap();
            }
        }
    }
}

// invalid with fips, as we can't offer X25519 separately
#[cfg(all(
    feature = "aws-lc-rs",
    feature = "prefer-post-quantum",
    not(feature = "fips")
))]
#[test]
fn hybrid_kx_component_share_offered_if_supported_separately() {
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(crate::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 2);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
    assert_eq!(key_shares[1].group, NamedGroup::X25519);
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn hybrid_kx_component_share_not_offered_unless_supported_separately() {
    use crate::crypto::aws_lc_rs;
    let provider = CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    };
    let ch = client_hello_sent_for_config(
        ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth(),
    )
    .unwrap();

    let key_shares = ch
        .extensions
        .key_shares
        .as_ref()
        .unwrap();
    assert_eq!(key_shares.len(), 1);
    assert_eq!(key_shares[0].group, NamedGroup::X25519MLKEM768);
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn client_hello_x25519_mlkem768_share_matches_utls_chrome133_wire_shape() {
    use crate::crypto::aws_lc_rs;

    let provider = CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    };
    let config = ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots())
        .with_no_client_auth();
    let wire = client_hello_wire_for_config(config).unwrap();
    let key_share = client_hello_extensions_from_wire(&wire)
        .into_iter()
        .find(|(extension_type, _)| *extension_type == ExtensionType::KeyShare)
        .unwrap()
        .1;

    // uTLS v1.8.7 Chrome 133 emits ML-KEM-768 EncapsulationKey768 (1184 bytes)
    // followed by the X25519 public key (32 bytes) for group 0x11ec. These bytes
    // are ephemeral, so pin the wire structure rather than their values.
    const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;
    const X25519_PUBLIC_KEY_LEN: usize = 32;
    let hybrid_share_len = MLKEM768_ENCAPSULATION_KEY_LEN + X25519_PUBLIC_KEY_LEN;
    let entry_len = 4 + hybrid_share_len;
    assert_eq!(key_share.len(), 2 + entry_len);
    assert_eq!(&key_share[..2], &u16::try_from(entry_len).unwrap().to_be_bytes());
    assert_eq!(&key_share[2..4], &[0x11, 0xec]);
    assert_eq!(
        &key_share[4..6],
        &u16::try_from(hybrid_share_len).unwrap().to_be_bytes()
    );
    let (mlkem_encapsulation_key, x25519_public_key) =
        key_share[6..].split_at(MLKEM768_ENCAPSULATION_KEY_LEN);
    assert_eq!(mlkem_encapsulation_key.len(), MLKEM768_ENCAPSULATION_KEY_LEN);
    assert_eq!(x25519_public_key.len(), X25519_PUBLIC_KEY_LEN);
}

fn client_hello_sent_for_config(config: ClientConfig) -> Result<ClientHelloPayload, Error> {
    let bytes = client_hello_wire_for_config(config)?;

    let message = OutboundOpaqueMessage::read(&mut Reader::init(&bytes))
        .unwrap()
        .into_plain_message();

    match Message::try_from(message).unwrap() {
        Message {
            payload:
                MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(ch)),
                    ..
                },
            ..
        } => Ok(ch),
        other => panic!("unexpected message {other:?}"),
    }
}

fn client_hello_wire_for_config(config: ClientConfig) -> Result<Vec<u8>, Error> {
    let mut conn =
        ClientConnection::new(config.into(), ServerName::try_from("localhost").unwrap())?;
    let mut bytes = Vec::new();
    conn.write_tls(&mut bytes).unwrap();
    Ok(bytes)
}

fn client_hello_from_wire(bytes: &[u8]) -> ClientHelloPayload {
    let mut reader = Reader::init(bytes);
    while reader.any_left() {
        let record = OutboundOpaqueMessage::read(&mut reader).unwrap();
        if record.typ != ContentType::Handshake {
            continue;
        }
        return match Message::try_from(record.into_plain_message()).unwrap() {
            Message {
                payload:
                    MessagePayload::Handshake {
                        parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(hello)),
                        ..
                    },
                ..
            } => hello,
            other => panic!("unexpected message {other:?}"),
        };
    }
    panic!("no ClientHello record in wire bytes");
}

fn client_hello_extensions_from_wire(bytes: &[u8]) -> Vec<(ExtensionType, Vec<u8>)> {
    let mut record_offset = 0;
    while record_offset < bytes.len() {
        assert!(bytes.len() - record_offset >= 5);
        let record_type = bytes[record_offset];
        let record_length = usize::from(u16::from_be_bytes([
            bytes[record_offset + 3],
            bytes[record_offset + 4],
        ]));
        let record_end = record_offset + 5 + record_length;
        assert!(record_end <= bytes.len());

        if record_type == u8::from(ContentType::Handshake) {
            let payload = &bytes[record_offset + 5..record_end];
            assert!(payload.len() >= 4);
            if payload[0] == 0x01 {
                let mut cursor = 4 + 2 + 32;
                cursor += 1 + usize::from(payload[cursor]);
                let cipher_suites_length = usize::from(u16::from_be_bytes([
                    payload[cursor],
                    payload[cursor + 1],
                ]));
                cursor += 2 + cipher_suites_length;
                cursor += 1 + usize::from(payload[cursor]);
                let extensions_length = usize::from(u16::from_be_bytes([
                    payload[cursor],
                    payload[cursor + 1],
                ]));
                cursor += 2;
                let extensions_end = cursor + extensions_length;
                assert_eq!(extensions_end, payload.len());

                let mut extensions = Vec::new();
                while cursor < extensions_end {
                    let extension_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
                    let extension_length = usize::from(u16::from_be_bytes([
                        payload[cursor + 2],
                        payload[cursor + 3],
                    ]));
                    cursor += 4;
                    assert!(cursor + extension_length <= extensions_end);
                    extensions.push((
                        ExtensionType::from(extension_type),
                        payload[cursor..cursor + extension_length].to_vec(),
                    ));
                    cursor += extension_length;
                }
                return extensions;
            }
        }

        record_offset = record_end;
    }
    panic!("no ClientHello record in wire bytes");
}

fn roots() -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(CertificateDer::from_slice(include_bytes!(
        "../../../test-ca/rsa-2048/ca.der"
    )))
    .unwrap();
    r
}
