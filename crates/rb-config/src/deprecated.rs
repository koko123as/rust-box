//! Deprecation notes, mirroring sing-box `experimental/deprecated`: a
//! deprecated feature that still works is reported once, as a warning.

use std::collections::HashSet;
use std::sync::Mutex;

/// `deprecated.Note`.
#[derive(Debug, Clone, Copy)]
pub struct Note {
    pub name: &'static str,
    pub description: &'static str,
    pub deprecated_version: &'static str,
    pub scheduled_version: &'static str,
    pub migration_link: &'static str,
}

impl Note {
    /// `Note.MessageWithLink`.
    pub fn message_with_link(&self) -> String {
        if self.migration_link.is_empty() {
            format!(
                "{} is deprecated in sing-box {} and will be removed in sing-box {}.",
                self.description, self.deprecated_version, self.scheduled_version
            )
        } else {
            format!(
                "{} is deprecated in sing-box {} and will be removed in sing-box {}, checkout documentation for migration: {}",
                self.description, self.deprecated_version, self.scheduled_version, self.migration_link
            )
        }
    }
}

pub const LEGACY_RULE_SET_DOWNLOAD_DETOUR: Note = Note {
    name: "legacy-rule-set-download-detour",
    description: "legacy `download_detour` remote rule-set option",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "",
};

pub const RULE_SET_IP_CIDR_ACCEPT_EMPTY: Note = Note {
    name: "dns-rule-rule-set-ip-cidr-accept-empty",
    description: "Legacy `rule_set_ip_cidr_accept_empty` DNS rule item",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-address-filter-fields-to-response-matching",
};

pub const LEGACY_DNS_ADDRESS_FILTER: Note = Note {
    name: "legacy-dns-address-filter",
    description: "Legacy Address Filter Fields in DNS rules",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-address-filter-fields-to-response-matching",
};

pub const LEGACY_DNS_RULE_STRATEGY: Note = Note {
    name: "legacy-dns-rule-strategy",
    description: "Legacy `strategy` DNS rule action option",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "https://sing-box.sagernet.org/migration/#migrate-dns-rule-action-strategy-to-rule-items",
};

pub const IMPLICIT_DEFAULT_HTTP_CLIENT: Note = Note {
    name: "implicit-default-http-client",
    description: "implicit default HTTP client using default outbound for remote rule-sets",
    deprecated_version: "1.14.0",
    scheduled_version: "1.16.0",
    migration_link: "",
};

static REPORTED: Mutex<Option<HashSet<&'static str>>> = Mutex::new(None);

/// `deprecated.Report` with the stderr manager: one warning per feature.
pub fn report(note: Note) {
    let mut reported = REPORTED.lock().unwrap();
    if reported.get_or_insert_with(HashSet::new).insert(note.name) {
        tracing::warn!("{}", note.message_with_link());
    }
}
