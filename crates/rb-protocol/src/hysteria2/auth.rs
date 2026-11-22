//! Hysteria2 HTTP/3 authentication headers from sing-quic
//! `hysteria2/internal/protocol/http.go`.
use std::io;

use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use rand::Rng;

pub const AUTH_HOST: &str = "hysteria";
pub const AUTH_PATH: &str = "/auth";
pub const AUTH_OK_STATUS: u16 = 233;

const HEADER_AUTH: HeaderName = HeaderName::from_static("hysteria-auth");
const HEADER_UDP_ENABLED: HeaderName = HeaderName::from_static("hysteria-udp");
const HEADER_CC_RX: HeaderName = HeaderName::from_static("hysteria-cc-rx");
const HEADER_PADDING: HeaderName = HeaderName::from_static("hysteria-padding");
const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub password: String,
    /// Receive bandwidth in bits per second; zero requests server-side detection.
    pub receive_bps: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthResponse {
    pub udp_enabled: bool,
    /// Zero means unlimited; `receive_auto` requests bandwidth detection.
    pub receive_bps: u64,
    pub receive_auto: bool,
}

impl AuthRequest {
    /// Converts the request to the upstream headers and generates 256–2047
    /// random ASCII padding characters, matching sing-quic's half-open range.
    pub fn headers(&self) -> io::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        let auth = HeaderValue::from_bytes(self.password.as_bytes())
            .map_err(|error| invalid(format!("invalid Hysteria2 auth header: {error}")))?;
        let receive_bps = HeaderValue::from_str(&self.receive_bps.to_string())
            .map_err(|error| invalid(format!("invalid Hysteria2 receive bandwidth header: {error}")))?;
        let padding = random_padding(256, 2048);
        let padding = HeaderValue::from_bytes(&padding)
            .map_err(|error| invalid(format!("invalid Hysteria2 padding header: {error}")))?;
        headers.insert(HEADER_AUTH, auth);
        headers.insert(HEADER_CC_RX, receive_bps);
        headers.insert(HEADER_PADDING, padding);
        Ok(headers)
    }
}

impl AuthResponse {
    /// Reads response headers using sing-quic's parse-failure-to-zero behavior.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let udp_enabled =
            headers.get(&HEADER_UDP_ENABLED).and_then(|value| value.to_str().ok()).is_some_and(parse_go_bool);
        let receive_header = headers.get(&HEADER_CC_RX).and_then(|value| value.to_str().ok()).unwrap_or_default();
        let receive_auto = receive_header == "auto";
        let receive_bps = if receive_auto { 0 } else { receive_header.parse().unwrap_or(0) };
        Self { udp_enabled, receive_bps, receive_auto }
    }
}

fn parse_go_bool(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "1" | "t" | "true")
}

fn random_padding(minimum: usize, maximum_exclusive: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let length = rng.random_range(minimum..maximum_exclusive);
    (0..length).map(|_| PADDING_CHARS[rng.random_range(0..PADDING_CHARS.len())]).collect()
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_headers_match_upstream_names_and_ranges() {
        let headers = AuthRequest { password: "secret".into(), receive_bps: 12_000_000 }.headers().unwrap();
        assert_eq!(headers.get("hysteria-auth").unwrap(), "secret");
        assert_eq!(headers.get("hysteria-cc-rx").unwrap(), "12000000");
        let padding = headers.get("hysteria-padding").unwrap().as_bytes();
        assert!((256..2048).contains(&padding.len()));
        assert!(padding.iter().all(|byte| PADDING_CHARS.contains(byte)));
    }

    #[test]
    fn auth_response_parses_bandwidth_and_udp_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("hysteria-udp", HeaderValue::from_static("true"));
        headers.insert("hysteria-cc-rx", HeaderValue::from_static("8000000"));
        assert_eq!(
            AuthResponse::from_headers(&headers),
            AuthResponse { udp_enabled: true, receive_bps: 8_000_000, receive_auto: false }
        );

        headers.insert("hysteria-cc-rx", HeaderValue::from_static("auto"));
        assert_eq!(
            AuthResponse::from_headers(&headers),
            AuthResponse { udp_enabled: true, receive_bps: 0, receive_auto: true }
        );
    }

    #[test]
    fn auth_response_malformed_headers_use_upstream_zero_defaults() {
        let mut headers = HeaderMap::new();
        headers.insert("hysteria-udp", HeaderValue::from_static("unknown"));
        headers.insert("hysteria-cc-rx", HeaderValue::from_static("not-a-number"));
        assert_eq!(AuthResponse::from_headers(&headers), AuthResponse::default());
    }
}
