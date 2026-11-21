//! Shared option types, mirroring sing-box `option/types.go` and
//! `sing/common/json/badoption`.

use std::fmt;
use std::time::Duration as StdDuration;

use serde::de::{self, Deserializer};
use serde::Deserialize;

/// A value that may be written as a single item or as an array
/// (sing-box `badoption.Listable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listable<T>(pub Vec<T>);

impl<T> Default for Listable<T> {
    fn default() -> Self {
        Listable(Vec::new())
    }
}

impl<T> Listable<T> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Listable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany<T> {
            Many(Vec<T>),
            One(T),
        }
        Ok(match OneOrMany::deserialize(deserializer)? {
            OneOrMany::Many(items) => Listable(items),
            OneOrMany::One(item) => Listable(vec![item]),
        })
    }
}

/// A Go-style duration string such as `300ms`, `5s` or `1h30m`
/// (sing-box `badoption.Duration`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Duration(pub StdDuration);

impl Duration {
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text == "0" || text.is_empty() {
            return Ok(Duration(StdDuration::ZERO));
        }
        let bytes = text.as_bytes();
        let mut index = 0;
        let mut total = 0f64;
        while index < bytes.len() {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
                index += 1;
            }
            if start == index {
                return Err(format!("invalid duration {text:?}"));
            }
            let number: f64 = text[start..index].parse().map_err(|_| format!("invalid duration {text:?}"))?;
            let unit_start = index;
            while index < bytes.len() && !(bytes[index].is_ascii_digit() || bytes[index] == b'.') {
                index += 1;
            }
            let seconds = match &text[unit_start..index] {
                "ns" => 1e-9,
                "us" | "µs" => 1e-6,
                "ms" => 1e-3,
                "s" => 1.0,
                "m" => 60.0,
                "h" => 3600.0,
                unit => return Err(format!("invalid duration unit {unit:?} in {text:?}")),
            };
            total += number * seconds;
        }
        Ok(Duration(StdDuration::from_secs_f64(total)))
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = Duration;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a duration string such as \"5s\"")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Duration, E> {
                Duration::parse(value).map_err(E::custom)
            }
            // badoption.Duration also accepts a number of nanoseconds.
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Duration, E> {
                Ok(Duration(StdDuration::from_nanos(value)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// An inbound's `udp_timeout`: a duration string, or a bare number of
/// seconds (sing-box `option.UDPTimeoutCompat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UdpTimeout(pub Duration);

impl<'de> Deserialize<'de> for UdpTimeout {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = UdpTimeout;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a number of seconds or a duration string such as \"5m\"")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<UdpTimeout, E> {
                Duration::parse(value).map(UdpTimeout).map_err(E::custom)
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<UdpTimeout, E> {
                Ok(UdpTimeout(Duration(StdDuration::from_secs(value))))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<UdpTimeout, E> {
                u64::try_from(value).map_err(|_| E::custom("negative udp_timeout")).and_then(|v| self.visit_u64(v))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// sing-box `DomainStrategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum DomainStrategy {
    #[default]
    #[serde(rename = "", alias = "as_is")]
    AsIs,
    #[serde(rename = "prefer_ipv4")]
    PreferIpv4,
    #[serde(rename = "prefer_ipv6")]
    PreferIpv6,
    #[serde(rename = "ipv4_only")]
    Ipv4Only,
    #[serde(rename = "ipv6_only")]
    Ipv6Only,
}

/// `domain_resolver` / `default_domain_resolver`: a server tag, or an object
/// (sing-box `DomainResolveOptions`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DomainResolveOptions {
    pub server: String,
    pub strategy: DomainStrategy,
    pub disable_cache: bool,
    pub timeout: Duration,
    pub rewrite_ttl: Option<u32>,
}

impl<'de> Deserialize<'de> for DomainResolveOptions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Object {
            server: String,
            #[serde(default)]
            strategy: DomainStrategy,
            #[serde(default)]
            disable_cache: bool,
            #[serde(default)]
            timeout: Duration,
            #[serde(default)]
            rewrite_ttl: Option<u32>,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Tag(String),
            Object(Object),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Tag(server) => Ok(DomainResolveOptions { server, ..Default::default() }),
            Raw::Object(object) => {
                if object.server.is_empty() {
                    return Err(de::Error::custom("empty domain_resolver.server"));
                }
                Ok(DomainResolveOptions {
                    server: object.server,
                    strategy: object.strategy,
                    disable_cache: object.disable_cache,
                    timeout: object.timeout,
                    rewrite_ttl: object.rewrite_ttl,
                })
            }
        }
    }
}

/// A DNS query type, by name (`A`, `AAAA`, ...) or number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryType(pub u16);

impl QueryType {
    pub fn from_name(name: &str) -> Option<u16> {
        Some(match name.to_ascii_uppercase().as_str() {
            "A" => 1,
            "NS" => 2,
            "CNAME" => 5,
            "SOA" => 6,
            "PTR" => 12,
            "MX" => 15,
            "TXT" => 16,
            "AAAA" => 28,
            "SRV" => 33,
            "NAPTR" => 35,
            "DS" => 43,
            "RRSIG" => 46,
            "DNSKEY" => 48,
            "SVCB" => 64,
            "HTTPS" => 65,
            "CAA" => 257,
            "ANY" => 255,
            _ => return None,
        })
    }
}

impl<'de> Deserialize<'de> for QueryType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u16),
            Name(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Number(number) => Ok(QueryType(number)),
            Raw::Name(name) => QueryType::from_name(&name)
                .map(QueryType)
                .ok_or_else(|| de::Error::custom(format!("unknown DNS query type {name:?}"))),
        }
    }
}

/// An authentication user (sing-box `auth.User`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub username: String,
    pub password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(Duration::parse("300ms").unwrap().0, StdDuration::from_millis(300));
        assert_eq!(Duration::parse("1h30m").unwrap().0, StdDuration::from_secs(5400));
        assert_eq!(Duration::parse("1.5s").unwrap().0, StdDuration::from_millis(1500));
        assert!(Duration::parse("5x").is_err());
        assert!(Duration::parse("s").is_err());
    }

    #[test]
    fn udp_timeout() {
        let seconds: UdpTimeout = serde_json::from_str("30").unwrap();
        assert_eq!(seconds.0 .0, StdDuration::from_secs(30));
        let text: UdpTimeout = serde_json::from_str("\"5m\"").unwrap();
        assert_eq!(text.0 .0, StdDuration::from_secs(300));
        assert!(serde_json::from_str::<UdpTimeout>("-1").is_err());
    }

    #[test]
    fn listable() {
        let one: Listable<String> = serde_json::from_str("\"a\"").unwrap();
        let many: Listable<String> = serde_json::from_str("[\"a\",\"b\"]").unwrap();
        assert_eq!(one.0, vec!["a"]);
        assert_eq!(many.0, vec!["a", "b"]);
    }

    #[test]
    fn domain_resolver() {
        let tag: DomainResolveOptions = serde_json::from_str("\"local\"").unwrap();
        assert_eq!(tag.server, "local");
        let object: DomainResolveOptions =
            serde_json::from_str(r#"{"server":"google","strategy":"ipv4_only"}"#).unwrap();
        assert_eq!(object.strategy, DomainStrategy::Ipv4Only);
        assert!(serde_json::from_str::<DomainResolveOptions>(r#"{"server":""}"#).is_err());
    }

    #[test]
    fn query_types() {
        let types: Listable<QueryType> = serde_json::from_str(r#"["A", 28, "https"]"#).unwrap();
        assert_eq!(types.0, vec![QueryType(1), QueryType(28), QueryType(65)]);
    }
}
