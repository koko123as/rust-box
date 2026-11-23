//! Tailscale-specific address classification from the fork pinned by sing-box v1.14.4.
//!
//! This module ports `IsTailscaleIP`, `IsTailscaleIPv4`, `Tailscale4To6`, and
//! `Tailscale6to4`. Other route helpers and endpoint behavior remain out of scope.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const CGNAT_START: u32 = u32::from_be_bytes([100, 64, 0, 0]);
const CGNAT_END: u32 = u32::from_be_bytes([100, 127, 255, 255]);
const CHROMEOS_VM_START: u32 = u32::from_be_bytes([100, 115, 92, 0]);
const CHROMEOS_VM_END: u32 = u32::from_be_bytes([100, 115, 93, 255]);
const TAILSCALE_ULA_PREFIX: [u16; 3] = [0xfd7a, 0x115c, 0xa1e0];
const TAILSCALE_4TO6_PREFIX: [u8; 13] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0xab, 0x12, 0x48, 0x43, 0xcd, 0x96, 0x62];

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

/// Returns the IPv6 address mapped from a native Tailscale IPv4 address.
///
/// Unlike [`is_tailscale_ip`], this follows the pinned fork's native-v4-only
/// input check: IPv4-mapped IPv6 and non-assignable IPv4 addresses return `None`.
pub fn tailscale4_to6(ip: IpAddr) -> Option<Ipv6Addr> {
    let IpAddr::V4(ipv4) = ip else {
        return None;
    };
    if !is_tailscale_ipv4(IpAddr::V4(ipv4)) {
        return None;
    }
    let octets = ipv4.octets();
    let mut mapped = [0; 16];
    mapped[..13].copy_from_slice(&TAILSCALE_4TO6_PREFIX);
    mapped[13..].copy_from_slice(&octets[1..]);
    Some(Ipv6Addr::from(mapped))
}

/// Returns the IPv4 encoding of an address in the Tailscale 4-to-6 `/104` range.
///
/// This intentionally checks only the `/104` prefix, like the pinned fork; the
/// resulting IPv4 address is not revalidated against the assignable IPv4 range.
pub fn tailscale6_to4(ip: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(ipv6) = ip else {
        return None;
    };
    let octets = ipv6.octets();
    if octets[..13] != TAILSCALE_4TO6_PREFIX {
        return None;
    }
    Some(Ipv4Addr::new(100, octets[13], octets[14], octets[15]))
}

fn is_tailscale_ipv6_ula(ipv6: Ipv6Addr) -> bool {
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
    fn address_translations_match_pinned_go_oracle() {
        for (input, expected) in [
            ("100.64.0.1", Some("fd7a:115c:a1e0:ab12:4843:cd96:6240:1")),
            ("100.115.92.1", None),
            ("100.115.94.1", Some("fd7a:115c:a1e0:ab12:4843:cd96:6273:5e01")),
            ("100.127.255.255", Some("fd7a:115c:a1e0:ab12:4843:cd96:627f:ffff")),
            ("192.0.2.1", None),
            ("::ffff:100.64.0.1", None),
        ] {
            let expected = expected.map(|value| value.parse::<std::net::Ipv6Addr>().unwrap());
            assert_eq!(super::tailscale4_to6(ip(input)), expected, "4-to-6 mapping for {input}");
        }

        for (input, expected) in [
            ("fd7a:115c:a1e0:ab12:4843:cd96:6200:0", Some("100.0.0.0")),
            ("fd7a:115c:a1e0:ab12:4843:cd96:6273:5e01", Some("100.115.94.1")),
            ("fd7a:115c:a1e0:ab12:4843:cd96:62ff:ffff", Some("100.255.255.255")),
            ("fd7a:115c:a1e0:ab12:4843:cd97:0:1", None),
            ("2001:db8::1", None),
            ("100.64.0.1", None),
        ] {
            let expected = expected.map(|value| value.parse::<std::net::Ipv4Addr>().unwrap());
            assert_eq!(super::tailscale6_to4(ip(input)), expected, "6-to-4 mapping for {input}");
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
