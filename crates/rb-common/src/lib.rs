//! Shared data structures ported from sing-box's dependencies:
//! the succinct domain set and its matchers (`sing/common/domain`), the IP
//! set (`go4.org/netipx`), variable-length binary helpers
//! (`sing/common/varbin`) and a JSON writer that formats like Go's
//! `encoding/json` encoder with `SetIndent("", "  ")`.

pub mod domain;
pub mod gojson;
pub mod ipset;
pub mod varbin;
