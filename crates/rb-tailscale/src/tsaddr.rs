//! Tailscale-specific address classification from the fork pinned by sing-box v1.14.4.
//!
//! This module currently ports only `IsTailscaleIP` and `IsTailscaleIPv4`; address
//! translation, route helpers, and endpoint behavior remain out of scope.

use std::net::IpAddr;

const CGNAT_START: u32 = u32::from_be_bytes([100, 64, 0, 0]);
const CGNAT_END: u32 = u32::from_be_bytes([100, 127, 255, 255]);
const CHROMEOS_VM_START: u32 = u32::from_be_bytes([100, 115, 92, 0]);
const CHROMEOS_VM_END: u32 = u32::from_be_bytes([100, 115, 93, 255]);
const TAILSCALE_ULA_PREFIX: [u16; 3] = [0xfd7a, 0x115c, 0xa1e0];

/// Reports whether an address belongs to a range Tailscale assigns from.
///
/// IPv4-mapped IPv6 addresses are unmapped before classification, matching the
/// pinned fork's `netip.Addr.Unmap` behavior.
pub fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => is_tailscale_ipv4(ip),
        IpAddr::V6(ipv6) => match ipv6.to_ipv4_mapped() {
            Some(ipv4) => is_tailscale_ipv4(IpAddr::V4(ipv4)),
            None => is_tailscale_ipv6_ula(ipv6),
        },
    }
}

/// Reports whether a native IPv4 address is in Tailscale's assignable CGNAT range.
///
/// The ChromeOS VM range `100.115.92.0/23` is excluded. An IPv4-mapped IPv6 input
/// returns false, matching the pinned fork's `IsTailscaleIPv4` behavior.
pub fn is_tailscale_ipv4(ip: IpAddr) -> bool {
    let IpAddr::V4(ipv4) = ip else {
        return false;
    };
    let address = u32::from(ipv4);
    (CGNAT_START..=CGNAT_END).contains(&address) && !(CHROMEOS_VM_START..=CHROMEOS_VM_END).contains(&address)
}

fn is_tailscale_ipv6_ula(ipv6: std::net::Ipv6Addr) -> bool {
    ipv6.segments()[..3] == TAILSCALE_ULA_PREFIX
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{is_tailscale_ip, is_tailscale_ipv4};

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test address must be valid")
    }

    #[test]
    fn ipv4_cgnat_boundaries_match_pinned_go_oracle() {
        for (address, expected) in [
            ("100.63.255.255", false),
            ("100.64.0.0", true),
            ("100.64.0.1", true),
            ("100.127.255.255", true),
            ("100.128.0.0", false),
        ] {
            let address = ip(address);
            assert_eq!(is_tailscale_ipv4(address), expected, "IPv4 predicate for {address}");
            assert_eq!(is_tailscale_ip(address), expected, "general predicate for {address}");
        }
    }

    #[test]
    fn chromeos_vm_subrange_is_excluded_with_inclusive_boundaries() {
        for (address, expected) in
            [("100.115.91.255", true), ("100.115.92.0", false), ("100.115.93.255", false), ("100.115.94.0", true)]
        {
            let address = ip(address);
            assert_eq!(is_tailscale_ipv4(address), expected, "IPv4 predicate for {address}");
            assert_eq!(is_tailscale_ip(address), expected, "general predicate for {address}");
        }
    }

    #[test]
    fn ipv6_ula_prefix_boundaries_match_pinned_go_oracle() {
        for (address, expected) in [
            ("fd7a:115c:a1df:ffff::1", false),
            ("fd7a:115c:a1e0::", true),
            ("fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff", true),
            ("fd7a:115c:a1e1::", false),
            ("2001:db8::1", false),
        ] {
            let address = ip(address);
            assert_eq!(is_tailscale_ip(address), expected, "general predicate for {address}");
            assert!(!is_tailscale_ipv4(address), "IPv4 predicate for {address}");
        }
    }

    #[test]
    fn mapped_ipv6_is_unmapped_only_by_general_predicate() {
        let mapped_tailscale = ip("::ffff:100.64.0.1");
        assert!(is_tailscale_ip(mapped_tailscale));
        assert!(!is_tailscale_ipv4(mapped_tailscale));

        let mapped_chromeos = ip("::ffff:100.115.92.0");
        assert!(!is_tailscale_ip(mapped_chromeos));
        assert!(!is_tailscale_ipv4(mapped_chromeos));

        let mapped_outside = ip("::ffff:100.128.0.1");
        assert!(!is_tailscale_ip(mapped_outside));
        assert!(!is_tailscale_ipv4(mapped_outside));
    }
}
