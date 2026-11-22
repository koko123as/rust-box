//! The default interface (sing-tun `DefaultInterfaceMonitor`): the one the
//! platform reported, else the interface of the lowest-metric default route
//! in the kernel's main table, leaving out this process's TUN interfaces.

use std::io;
use std::os::fd::RawFd;
use std::sync::RwLock;

use crate::{my_interfaces, InterfaceUpdateListener};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultInterface {
    pub name: String,
    pub index: i32,
}

/// What the platform last reported (see [`PlatformListener`]).
static PLATFORM_DEFAULT: RwLock<Option<DefaultInterface>> = RwLock::new(None);

/// Keeps the default interface the platform reports.
pub struct PlatformListener;

impl InterfaceUpdateListener for PlatformListener {
    fn update_default_interface(&self, name: &str, index: i32, _is_expensive: bool, _is_constrained: bool) {
        *PLATFORM_DEFAULT.write().unwrap() =
            (!name.is_empty()).then(|| DefaultInterface { name: name.to_string(), index });
    }
}

/// The current default interface for IPv4 or IPv6 destinations.
pub fn default_interface(ipv6: bool) -> Option<DefaultInterface> {
    if let Some(reported) = PLATFORM_DEFAULT.read().unwrap().clone() {
        return Some(reported);
    }
    let mine = my_interfaces();
    let name = if ipv6 {
        std::fs::read_to_string("/proc/net/ipv6_route").ok().and_then(|table| default_route_v6(&table, &mine))
    } else {
        std::fs::read_to_string("/proc/net/route").ok().and_then(|table| default_route_v4(&table, &mine))
    }
    .or_else(|| {
        // An IPv6 destination with only an IPv4 default route (or the
        // reverse) still leaves through that interface.
        let other = if ipv6 { "/proc/net/route" } else { "/proc/net/ipv6_route" };
        let table = std::fs::read_to_string(other).ok()?;
        if ipv6 {
            default_route_v4(&table, &mine)
        } else {
            default_route_v6(&table, &mine)
        }
    })?;
    let index = interface_index(&name);
    Some(DefaultInterface { name, index })
}

fn interface_index(name: &str) -> i32 {
    let Ok(name) = std::ffi::CString::new(name) else { return 0 };
    // SAFETY: a valid NUL-terminated string.
    unsafe { libc::if_nametoindex(name.as_ptr()) as i32 }
}

/// The interface of the lowest-metric default route in `/proc/net/route`.
pub fn default_route_v4(table: &str, excluded: &[String]) -> Option<String> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 {
                return None;
            }
            let flags = u32::from_str_radix(fields[3], 16).ok()?;
            let metric: u32 = fields[6].parse().ok()?;
            (fields[1] == "00000000" && fields[7] == "00000000" && flags & 1 != 0).then(|| (metric, fields[0]))
        })
        .filter(|(_, name)| *name != "lo" && !excluded.iter().any(|mine| mine == name))
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, name)| name.to_string())
}

/// The interface of the lowest-metric default route in `/proc/net/ipv6_route`.
pub fn default_route_v6(table: &str, excluded: &[String]) -> Option<String> {
    const RTF_REJECT: u32 = 0x0200;
    table
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return None;
            }
            let metric = u32::from_str_radix(fields[5], 16).ok()?;
            let flags = u32::from_str_radix(fields[8], 16).ok()?;
            let default = fields[0].chars().all(|c| c == '0') && fields[1] == "00";
            (default && flags & RTF_REJECT == 0 && flags & 1 != 0).then(|| (metric, fields[9]))
        })
        .filter(|(_, name)| *name != "lo" && !excluded.iter().any(|mine| mine == name))
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, name)| name.to_string())
}

/// `SO_BINDTODEVICE` (sing `control.BindToInterface`).
pub fn bind_to_interface(fd: RawFd, name: &str) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: the name is a byte slice of the given length.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr().cast(),
                name.len() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (fd, name);
        Err(io::Error::new(io::ErrorKind::Unsupported, "`auto_detect_interface` is not supported by rust-box yet"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_routes_from_proc() {
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\
            wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
            eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(default_route_v4(route, &["tun0".into()]), Some("eth0".into()));
        assert_eq!(default_route_v4(route, &[]), Some("tun0".into()));
        let route6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n\
            00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n\
            20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n";
        assert_eq!(default_route_v6(route6, &[]), Some("eth0".into()));
        assert_eq!(default_route_v6(route6, &["eth0".into()]), None);
    }

    #[test]
    fn platform_reported_default_wins() {
        PlatformListener.update_default_interface("rmnet0", 7, false, false);
        assert_eq!(default_interface(false), Some(DefaultInterface { name: "rmnet0".into(), index: 7 }));
        PlatformListener.update_default_interface("", 0, false, false);
        assert_ne!(default_interface(false).map(|it| it.name), Some("rmnet0".into()));
    }
}
