//! TLS options: sing-box `option.InboundTLSOptions` and
//! `option.OutboundTLSOptions` (`docs/configuration/shared/tls.md`).
//!
//! The objects parse every field sing-box v1.14.4 has. Fields rust-box
//! cannot honor are rejected by [`InboundTlsOptions::validate`] /
//! [`OutboundTlsOptions::validate`] with their path, and only when TLS is
//! `enabled` (sing-box ignores the whole object otherwise). Errors sing-box
//! itself reports while building the TLS config (an unknown cipher suite, a
//! missing key) come from `rb-tls` when the inbound or outbound is built.

use std::fmt;

use base64::Engine as _;
use serde::de::{self, Deserializer};
use serde::Deserialize;
use serde_json::Value;

use crate::types::{Duration, Listable};
use crate::ConfigError;

/// A TLS key exchange group (sing-box `option.CurvePreference`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurvePreference {
    P256,
    P384,
    P521,
    X25519,
    X25519Mlkem768,
}

impl CurvePreference {
    pub fn name(self) -> &'static str {
        match self {
            CurvePreference::P256 => "P256",
            CurvePreference::P384 => "P384",
            CurvePreference::P521 => "P521",
            CurvePreference::X25519 => "X25519",
            CurvePreference::X25519Mlkem768 => "X25519MLKEM768",
        }
    }
}

impl<'de> Deserialize<'de> for CurvePreference {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Ok(match name.to_ascii_uppercase().as_str() {
            "P256" => CurvePreference::P256,
            "P384" => CurvePreference::P384,
            "P521" => CurvePreference::P521,
            "X25519" => CurvePreference::X25519,
            "X25519MLKEM768" => CurvePreference::X25519Mlkem768,
            _ => return Err(de::Error::custom(format!("unknown curve name: {name}"))),
        })
    }
}

/// sing-box `option.ClientAuthType` (Go `tls.ClientAuthType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientAuthType {
    #[default]
    No,
    Request,
    RequireAny,
    VerifyIfGiven,
    RequireAndVerify,
}

impl<'de> Deserialize<'de> for ClientAuthType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Ok(match name.as_str() {
            "no" => ClientAuthType::No,
            "request" => ClientAuthType::Request,
            "require-any" => ClientAuthType::RequireAny,
            "verify-if-given" => ClientAuthType::VerifyIfGiven,
            "require-and-verify" => ClientAuthType::RequireAndVerify,
            _ => return Err(de::Error::custom(format!("unknown client authentication type: {name}"))),
        })
    }
}

/// Bytes written as a base64 string (Go's JSON encoding of `[]byte`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Base64Bytes(pub Vec<u8>);

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = Base64Bytes;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a base64 string")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Base64Bytes, E> {
                // Go's decoder skips line breaks.
                let clean: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
                base64::engine::general_purpose::STANDARD
                    .decode(clean)
                    .map(Base64Bytes)
                    .map_err(|error| E::custom(format!("illegal base64 data: {error}")))
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// Whether a nested object such as `ech`, `reality` or `utls` asks for its
/// feature (`"enabled": true`).
fn object_enabled(value: &Option<Value>) -> bool {
    matches!(value, Some(Value::Object(object)) if object.get("enabled") == Some(&Value::Bool(true)))
}

fn unsupported(path: &str, name: &str) -> ConfigError {
    ConfigError::Field { path: format!("{path}.{name}"), message: format!("`{name}` is not supported by rust-box yet") }
}

/// Curves rust-box (rustls with the ring provider) has.
fn check_curves(path: &str, curves: &Listable<CurvePreference>) -> Result<(), ConfigError> {
    for curve in curves.iter() {
        if matches!(curve, CurvePreference::P521 | CurvePreference::X25519Mlkem768) {
            return Err(ConfigError::Field {
                path: format!("{path}.curve_preferences"),
                message: format!("curve {} is not supported by rust-box yet", curve.name()),
            });
        }
    }
    Ok(())
}

/// sing-box `option.InboundTLSOptions`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundTlsOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: String,
    /// Server side: with no certificate, a self-signed one is made per
    /// connection (sing-box `GenerateKeyPair`).
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Listable<String>,
    #[serde(default)]
    pub min_version: String,
    #[serde(default)]
    pub max_version: String,
    #[serde(default)]
    pub cipher_suites: Listable<String>,
    #[serde(default)]
    pub curve_preferences: Listable<CurvePreference>,
    #[serde(default)]
    pub certificate: Listable<String>,
    #[serde(default)]
    pub certificate_path: String,
    #[serde(default)]
    pub client_authentication: ClientAuthType,
    #[serde(default)]
    pub client_certificate: Listable<String>,
    #[serde(default)]
    pub client_certificate_path: Listable<String>,
    #[serde(default)]
    pub client_certificate_public_key_sha256: Listable<Base64Bytes>,
    #[serde(default)]
    pub key: Listable<String>,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub kernel_tx: bool,
    #[serde(default)]
    pub kernel_rx: bool,
    #[serde(default)]
    pub handshake_timeout: Duration,
    /// Not supported: rejected when present.
    #[serde(default)]
    pub certificate_provider: Option<Value>,
    /// Not supported: rejected when present.
    #[serde(default)]
    pub acme: Option<Value>,
    /// Not supported: rejected when enabled.
    #[serde(default)]
    pub ech: Option<Value>,
    /// Not supported: rejected when enabled.
    #[serde(default)]
    pub reality: Option<Value>,
}

impl InboundTlsOptions {
    /// Rejects, with their path, the fields rust-box cannot honor. `path`
    /// is the path of the `tls` object itself.
    pub fn validate(&self, path: &str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.certificate_provider.is_some() {
            return Err(unsupported(path, "certificate_provider"));
        }
        if self.acme.is_some() {
            return Err(unsupported(path, "acme"));
        }
        if object_enabled(&self.ech) {
            return Err(unsupported(path, "ech"));
        }
        if object_enabled(&self.reality) {
            return Err(unsupported(path, "reality"));
        }
        if self.kernel_tx {
            return Err(unsupported(path, "kernel_tx"));
        }
        if self.kernel_rx {
            return Err(unsupported(path, "kernel_rx"));
        }
        check_curves(path, &self.curve_preferences)
    }
}

/// sing-box `option.OutboundTLSOptions`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundTlsOptions {
    #[serde(default)]
    pub enabled: bool,
    /// `go` (the default) only; `apple` and `windows` are rejected.
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub disable_sni: bool,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Listable<String>,
    #[serde(default)]
    pub min_version: String,
    #[serde(default)]
    pub max_version: String,
    #[serde(default)]
    pub cipher_suites: Listable<String>,
    #[serde(default)]
    pub curve_preferences: Listable<CurvePreference>,
    #[serde(default)]
    pub certificate: Listable<String>,
    #[serde(default)]
    pub certificate_path: String,
    #[serde(default)]
    pub certificate_public_key_sha256: Listable<Base64Bytes>,
    #[serde(default)]
    pub client_certificate: Listable<String>,
    #[serde(default)]
    pub client_certificate_path: String,
    #[serde(default)]
    pub client_key: Listable<String>,
    #[serde(default)]
    pub client_key_path: String,
    #[serde(default)]
    pub fragment: bool,
    #[serde(default)]
    pub fragment_fallback_delay: Duration,
    #[serde(default)]
    pub record_fragment: bool,
    /// Not supported: rejected when set.
    #[serde(default)]
    pub spoof: String,
    #[serde(default)]
    pub spoof_method: String,
    #[serde(default)]
    pub kernel_tx: bool,
    #[serde(default)]
    pub kernel_rx: bool,
    #[serde(default)]
    pub handshake_timeout: Duration,
    /// Not supported: rejected when enabled.
    #[serde(default)]
    pub ech: Option<Value>,
    #[serde(default)]
    pub utls: Option<Value>,
    #[serde(default)]
    pub reality: Option<Value>,
}

impl OutboundTlsOptions {
    /// Rejects, with their path, the fields rust-box cannot honor. `path`
    /// is the path of the `tls` object itself.
    pub fn validate(&self, path: &str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        match self.engine.as_str() {
            "" | "go" => {}
            "apple" | "windows" => {
                return Err(ConfigError::Field {
                    path: format!("{path}.engine"),
                    message: format!("TLS engine `{}` is not supported by rust-box yet", self.engine),
                })
            }
            _ => {
                return Err(ConfigError::Field {
                    path: format!("{path}.engine"),
                    message: format!("unknown tls engine: {}", self.engine),
                })
            }
        }
        if object_enabled(&self.ech) {
            return Err(unsupported(path, "ech"));
        }
        if object_enabled(&self.utls) {
            return Err(unsupported(path, "utls"));
        }
        if object_enabled(&self.reality) {
            return Err(unsupported(path, "reality"));
        }
        if !self.spoof.is_empty() {
            return Err(unsupported(path, "spoof"));
        }
        if !self.spoof_method.is_empty() {
            return Err(unsupported(path, "spoof_method"));
        }
        if self.kernel_tx {
            return Err(unsupported(path, "kernel_tx"));
        }
        if self.kernel_rx {
            return Err(unsupported(path, "kernel_rx"));
        }
        check_curves(path, &self.curve_preferences)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inbound() {
        let options: InboundTlsOptions = serde_json::from_str(
            r#"{"enabled":true,"server_name":"a.com","alpn":"h2","min_version":"1.2","max_version":"1.3",
                "cipher_suites":["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],"curve_preferences":["x25519","P256"],
                "certificate":["-----BEGIN CERTIFICATE-----","x"],"key_path":"/k.pem",
                "client_authentication":"verify-if-given","client_certificate_path":"/ca.pem",
                "client_certificate_public_key_sha256":"AAEC","handshake_timeout":"3s",
                "ech":{"enabled":false},"reality":null}"#,
        )
        .unwrap();
        assert_eq!(options.alpn.0, vec!["h2"]);
        assert_eq!(options.curve_preferences.0, vec![CurvePreference::X25519, CurvePreference::P256]);
        assert_eq!(options.client_authentication, ClientAuthType::VerifyIfGiven);
        assert_eq!(options.client_certificate_public_key_sha256.0, vec![Base64Bytes(vec![0, 1, 2])]);
        assert_eq!(options.client_certificate_path.0, vec!["/ca.pem"]);
        options.validate("inbounds[0].tls").unwrap();
    }

    #[test]
    fn rejects_unsupported() {
        let inbound = |json: &str| {
            let options: InboundTlsOptions = serde_json::from_str(json).unwrap();
            options.validate("inbounds[0].tls").unwrap_err().to_string()
        };
        assert_eq!(
            inbound(r#"{"enabled":true,"reality":{"enabled":true}}"#),
            "inbounds[0].tls.reality: `reality` is not supported by rust-box yet"
        );
        assert!(inbound(r#"{"enabled":true,"acme":{"domain":"a.com"}}"#).contains("tls.acme"));
        assert!(inbound(r#"{"enabled":true,"kernel_tx":true}"#).contains("tls.kernel_tx"));
        assert!(inbound(r#"{"enabled":true,"certificate_provider":"x"}"#).contains("tls.certificate_provider"));
        assert!(inbound(r#"{"enabled":true,"curve_preferences":"P521"}"#).contains("curve P521"));
        // Disabled TLS is ignored entirely, as in sing-box.
        let options: InboundTlsOptions = serde_json::from_str(r#"{"reality":{"enabled":true}}"#).unwrap();
        options.validate("x").unwrap();

        let outbound = |json: &str| {
            let options: OutboundTlsOptions = serde_json::from_str(json).unwrap();
            options.validate("outbounds[0].tls").unwrap_err().to_string()
        };
        assert!(outbound(r#"{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}}"#).contains("tls.utls"));
        assert!(outbound(r#"{"enabled":true,"ech":{"enabled":true}}"#).contains("tls.ech"));
        assert!(outbound(r#"{"enabled":true,"spoof":"a.com"}"#).contains("tls.spoof"));
        assert!(outbound(r#"{"enabled":true,"kernel_rx":true}"#).contains("tls.kernel_rx"));
        assert!(outbound(r#"{"enabled":true,"engine":"apple"}"#).contains("tls.engine"));
        assert!(outbound(r#"{"enabled":true,"engine":"x"}"#).contains("unknown tls engine: x"));
        assert!(outbound(r#"{"enabled":true,"curve_preferences":"X25519MLKEM768"}"#).contains("X25519MLKEM768"));

        assert!(serde_json::from_str::<OutboundTlsOptions>(r#"{"curve_preferences":"P999"}"#)
            .unwrap_err()
            .to_string()
            .contains("unknown curve name: P999"));
        assert!(serde_json::from_str::<InboundTlsOptions>(r#"{"client_authentication":"maybe"}"#)
            .unwrap_err()
            .to_string()
            .contains("unknown client authentication type: maybe"));
        assert!(serde_json::from_str::<OutboundTlsOptions>(r#"{"bogus":1}"#).is_err());
    }
}
