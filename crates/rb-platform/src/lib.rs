//! The platform interface (sing-box `adapter.PlatformInterface`, as the
//! graphical clients implement it through `experimental/libbox`), and the
//! process-wide network state the `tun` inbound and the dialers share.
//!
//! An embedding app (the Android client around `VpnService`) registers its
//! [`PlatformInterface`] with [`set_platform`] before it builds the box.
//! The `tun` inbound then asks it to open the TUN device instead of opening
//! one itself, outbound sockets are protected from the VPN through
//! [`PlatformInterface::auto_detect_interface_control`] (with
//! `route.auto_detect_interface`), and the platform reports the default
//! interface through an [`InterfaceUpdateListener`].
//!
//! Without a platform, the default interface is read from the kernel's
//! main routing table (Linux), and `route.auto_detect_interface` binds
//! outbound sockets to it.

pub mod monitor;

use std::io;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::{Arc, RwLock};

pub use monitor::{default_interface, DefaultInterface, PlatformListener};

/// An IP prefix (`172.19.0.1/30`): the address and its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub address: IpAddr,
    pub len: u8,
}

impl Prefix {
    pub fn new(address: IpAddr, len: u8) -> Self {
        Prefix { address, len }
    }

    /// Whether `address` is inside the prefix.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(prefix), IpAddr::V4(address)) => {
                let bits = u32::from(self.len.min(32));
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                u32::from(prefix) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(prefix), IpAddr::V6(address)) => {
                let bits = u32::from(self.len.min(128));
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                u128::from(prefix) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }

    /// The prefix with the host bits cleared (Go `netip.Prefix.Masked`).
    pub fn masked(&self) -> Prefix {
        match self.address {
            IpAddr::V4(address) => {
                let bits = u32::from(self.len.min(32));
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                Prefix::new(IpAddr::V4((u32::from(address) & mask).into()), self.len)
            }
            IpAddr::V6(address) => {
                let bits = u32::from(self.len.min(128));
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                Prefix::new(IpAddr::V6((u128::from(address) & mask).into()), self.len)
            }
        }
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.len)
    }
}

/// `platform.http_proxy` of the `tun` inbound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpProxy {
    pub server: String,
    pub server_port: u16,
    pub bypass_domain: Vec<String>,
    pub match_domain: Vec<String>,
}

/// What the platform needs to open the TUN device (libbox `TunOptions`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunOptions {
    pub name: String,
    pub mtu: u32,
    pub inet4_address: Vec<Prefix>,
    pub inet6_address: Vec<Prefix>,
    /// `disabled`, `native` or `hijack`.
    pub dns_mode: String,
    /// The DNS servers the platform should announce (the hijacked ones).
    pub dns_server_address: Vec<IpAddr>,
    pub auto_route: bool,
    pub strict_route: bool,
    pub inet4_route_address: Vec<Prefix>,
    pub inet6_route_address: Vec<Prefix>,
    pub inet4_route_exclude_address: Vec<Prefix>,
    pub inet6_route_exclude_address: Vec<Prefix>,
    /// The routes to add (the route addresses less the excluded ones).
    pub inet4_route_range: Vec<Prefix>,
    pub inet6_route_range: Vec<Prefix>,
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,
    pub http_proxy: Option<HttpProxy>,
}

/// A network interface as the platform reports it (libbox `NetworkInterface`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkInterface {
    pub index: i32,
    pub mtu: i32,
    pub name: String,
    pub addresses: Vec<Prefix>,
    /// `wifi`, `cellular`, `ethernet` or `other`.
    pub kind: String,
    pub dns_servers: Vec<IpAddr>,
    pub metered: bool,
}

/// Receives default interface changes from the platform (libbox
/// `InterfaceUpdateListener`).
pub trait InterfaceUpdateListener: Send + Sync {
    /// The default interface is now `name` (index `index`); an empty name
    /// means there is none.
    fn update_default_interface(&self, name: &str, index: i32, is_expensive: bool, is_constrained: bool);
}

/// What an embedding app provides (sing-box `adapter.PlatformInterface`,
/// the parts rust-box uses).
pub trait PlatformInterface: Send + Sync {
    /// Opens the TUN device (`VpnService.Builder.establish()`) and returns
    /// its file descriptor, which rust-box then owns.
    fn open_tun(&self, options: &TunOptions) -> io::Result<RawFd>;

    /// Whether outbound sockets go through [`auto_detect_interface_control`]
    /// (`VpnService.protect`) with `route.auto_detect_interface`.
    ///
    /// [`auto_detect_interface_control`]: PlatformInterface::auto_detect_interface_control
    fn use_platform_auto_detect_interface_control(&self) -> bool {
        true
    }

    /// Keeps an outbound socket out of the VPN (`VpnService.protect(fd)`).
    fn auto_detect_interface_control(&self, fd: RawFd) -> io::Result<()>;

    /// Starts reporting the default interface to `listener`.
    fn start_default_interface_monitor(&self, listener: Arc<dyn InterfaceUpdateListener>) -> io::Result<()>;

    fn close_default_interface_monitor(&self, listener: &Arc<dyn InterfaceUpdateListener>) -> io::Result<()> {
        let _ = listener;
        Ok(())
    }

    /// The network interfaces (Android hides them from apps).
    fn get_interfaces(&self) -> io::Result<Vec<NetworkInterface>>;

    /// iOS/macOS Network Extension; always false on Android.
    fn under_network_extension(&self) -> bool {
        false
    }

    fn include_all_networks(&self) -> bool {
        false
    }

    /// Flushes the platform's DNS cache.
    fn clear_dns_cache(&self) {}

    /// Tells the platform the TUN interface's name, so it is not taken for
    /// the default interface.
    fn register_my_interface(&self, name: &str) {
        let _ = name;
    }
}

static PLATFORM: RwLock<Option<Arc<dyn PlatformInterface>>> = RwLock::new(None);

/// Registers the platform interface (or removes it with `None`).
pub fn set_platform(platform: Option<Arc<dyn PlatformInterface>>) {
    *PLATFORM.write().unwrap() = platform;
}

/// The registered platform interface.
pub fn platform() -> Option<Arc<dyn PlatformInterface>> {
    PLATFORM.read().unwrap().clone()
}

/// The TUN interfaces this process runs and their addresses (sing-tun
/// `DefaultInterfaceMonitor.MyInterfaces`).
static MY_INTERFACES: RwLock<Vec<(String, Vec<Prefix>)>> = RwLock::new(Vec::new());

/// Records a TUN interface this process runs.
pub fn register_my_interface(name: &str, addresses: Vec<Prefix>) {
    let mut interfaces = MY_INTERFACES.write().unwrap();
    interfaces.retain(|(existing, _)| existing != name);
    interfaces.push((name.to_string(), addresses));
    drop(interfaces);
    if let Some(platform) = platform() {
        platform.register_my_interface(name);
    }
}

pub fn unregister_my_interface(name: &str) {
    MY_INTERFACES.write().unwrap().retain(|(existing, _)| existing != name);
}

/// The names of the TUN interfaces this process runs.
pub fn my_interfaces() -> Vec<String> {
    MY_INTERFACES.read().unwrap().iter().map(|(name, _)| name.clone()).collect()
}

/// Whether a connection to `address` would loop back into one of this
/// process's TUN interfaces (sing-box `direct` `isMyLoopbackAddress`): it
/// is inside a TUN address range without being the TUN address itself.
pub fn is_my_loopback_address(address: IpAddr) -> bool {
    let address = match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        address => address,
    };
    MY_INTERFACES.read().unwrap().iter().flat_map(|(_, prefixes)| prefixes.iter()).any(|prefix| {
        if !cfg!(target_os = "macos") && prefix.address == address {
            return false;
        }
        prefix.contains(address)
    })
}

/// `route.auto_detect_interface` for one outbound socket (sing-box
/// `NetworkManager.AutoDetectInterfaceFunc`): the platform protects it, or
/// else it is bound to the default interface.
pub fn auto_detect_interface_control(fd: RawFd, ipv6: bool) -> io::Result<()> {
    if let Some(platform) = platform() {
        if platform.use_platform_auto_detect_interface_control() {
            return platform.auto_detect_interface_control(fd);
        }
    }
    let interface = default_interface(ipv6).ok_or_else(|| io::Error::other("no available network interface"))?;
    monitor::bind_to_interface(fd, &interface.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        let prefix = Prefix::new("172.19.0.1".parse().unwrap(), 30);
        assert!(prefix.contains("172.19.0.2".parse().unwrap()));
        assert!(!prefix.contains("172.19.0.4".parse().unwrap()));
        assert_eq!(prefix.masked().to_string(), "172.19.0.0/30");
        let prefix = Prefix::new("fdfe:dcba:9876::1".parse().unwrap(), 126);
        assert!(prefix.contains("fdfe:dcba:9876::3".parse().unwrap()));
        assert!(!prefix.contains("fdfe:dcba:9876::4".parse().unwrap()));
        assert!(Prefix::new("0.0.0.0".parse().unwrap(), 0).contains("8.8.8.8".parse().unwrap()));
        assert!(!prefix.contains("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn loopback_to_my_interfaces() {
        register_my_interface(
            "rbtest-loop",
            vec![Prefix::new("172.31.0.1".parse().unwrap(), 30), Prefix::new("fdfe:aaaa::1".parse().unwrap(), 126)],
        );
        assert!(my_interfaces().contains(&"rbtest-loop".to_string()));
        // Inside the range but not the address itself (sing-box, not macOS).
        assert!(is_my_loopback_address("172.31.0.2".parse().unwrap()));
        assert!(is_my_loopback_address("::ffff:172.31.0.2".parse().unwrap()));
        assert!(!is_my_loopback_address("172.31.0.1".parse().unwrap()));
        assert!(!is_my_loopback_address("172.31.0.5".parse().unwrap()));
        assert!(is_my_loopback_address("fdfe:aaaa::2".parse().unwrap()));
        unregister_my_interface("rbtest-loop");
        assert!(!is_my_loopback_address("172.31.0.2".parse().unwrap()));
    }

    struct FakePlatform(std::sync::Mutex<Vec<RawFd>>);

    impl PlatformInterface for FakePlatform {
        fn open_tun(&self, _options: &TunOptions) -> io::Result<RawFd> {
            Err(io::ErrorKind::Unsupported.into())
        }
        fn auto_detect_interface_control(&self, fd: RawFd) -> io::Result<()> {
            self.0.lock().unwrap().push(fd);
            Ok(())
        }
        fn start_default_interface_monitor(&self, _listener: Arc<dyn InterfaceUpdateListener>) -> io::Result<()> {
            Ok(())
        }
        fn get_interfaces(&self) -> io::Result<Vec<NetworkInterface>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn platform_protects_sockets() {
        let fake = Arc::new(FakePlatform(Default::default()));
        set_platform(Some(fake.clone()));
        auto_detect_interface_control(42, false).unwrap();
        set_platform(None);
        assert_eq!(*fake.0.lock().unwrap(), vec![42]);
        assert!(platform().is_none());
    }
}
