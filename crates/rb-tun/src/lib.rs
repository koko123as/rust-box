//! The `tun` inbound on Linux and Android (sing-box `protocol/tun`, with
//! sing-tun's Linux device and `auto_route`).
//!
//! Without a platform interface rust-box opens the TUN device itself,
//! assigns its addresses and MTU over rtnetlink, and with `auto_route`
//! installs the same routes and policy rules sing-tun does. With a platform
//! interface (the Android client's `VpnService`) the platform opens the
//! device from [`rb_platform::TunOptions`] and rust-box only reads and
//! writes it. Packets run through rust-box's user-space stack
//! (`rb-netstack`), whose flows are pre-matched against the route rules
//! and then handed to the router like any inbound connection.

pub mod device;
pub mod netlink;
pub mod rules;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{
    ConnectionRouter, DnsResolver, InboundContext, LookupOptions, Network, PacketConn, RouteError, Socksaddr,
};
use rb_config::tun::{TunInbound as TunOptions, UdpNatBehavior};
use rb_netstack::{Handler, NatBehavior, Stack, StackOptions, TcpConn, UdpReply, UdpSession, Verdict};
use rb_platform::Prefix;
use rb_route::{PreMatch, Router};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use device::Device;
use rules::RouteOptions;

/// sing-box `C.UDPTimeout`.
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(300);

/// The TUN interface name to use (sing-tun `CalculateInterfaceName`): the
/// first `tunN` after the highest one that exists.
pub fn calculate_interface_name(existing: &[String]) -> String {
    let mut index = 0;
    for name in existing {
        if let Some(number) = name.strip_prefix("tun").and_then(|rest| rest.parse::<i16>().ok()) {
            if i32::from(number) >= index {
                index = i32::from(number) + 1;
            }
        }
    }
    format!("tun{index}")
}

fn existing_interfaces() -> Vec<String> {
    std::fs::read_dir("/sys/class/net")
        .map(|entries| entries.filter_map(|entry| entry.ok()?.file_name().into_string().ok()).collect())
        .unwrap_or_default()
}

use rules::next_address;

/// The DNS addresses a TUN hijacks (sing-tun `Inet4DNSAddress` and
/// `Inet6DNSAddress`, as `protocol/tun` takes them when `dns_address` is
/// empty): the address after the first one of each family.
pub fn dns_hijack_addresses(inet4: &[Prefix], inet6: &[Prefix]) -> Result<Vec<IpAddr>, String> {
    let mut addresses = Vec::new();
    if let Some(first) = inet4.first() {
        match next_address(first) {
            Some(next) => addresses.push(next),
            None if inet6.first().and_then(next_address).is_some() => {}
            None => {
                return Err(format!(
                    "no IPv4 server configured and no usable next address in {} for DNS",
                    inet6.first().map(Prefix::to_string).unwrap_or_default()
                ))
            }
        }
    }
    if let Some(first) = inet6.first() {
        match next_address(first) {
            Some(next) => addresses.push(next),
            None if inet4.first().and_then(next_address).is_some() => {}
            None => return Err(format!("no IPv6 server configured and no usable next address in {first} for DNS")),
        }
    }
    Ok(addresses)
}

fn nat(behavior: UdpNatBehavior) -> NatBehavior {
    match behavior {
        UdpNatBehavior::EndpointIndependent => NatBehavior::EndpointIndependent,
        UdpNatBehavior::AddressDependent => NatBehavior::AddressDependent,
        UdpNatBehavior::AddressAndPortDependent => NatBehavior::AddressAndPortDependent,
    }
}

fn prefix(prefix: &rb_config::IpPrefix) -> Prefix {
    Prefix::new(prefix.address, prefix.prefix_len)
}

/// The DNS mode with its default (sing-tun `DNSModeOrDefault`).
fn dns_mode(options: &TunOptions) -> &str {
    match options.dns_mode.as_str() {
        "" if options.auto_route => "hijack",
        "" => "disabled",
        mode => mode,
    }
}

/// What the stack's flows go to.
struct FlowHandler {
    tag: String,
    router: Arc<Router>,
    dns: Arc<dyn DnsResolver>,
    dns_hijack: Vec<IpAddr>,
    udp_timeout: Duration,
}

impl FlowHandler {
    fn log_prefix(&self) -> String {
        format!("inbound/tun[{}]", self.tag)
    }

    fn context(&self, network: Network, source: SocketAddr, destination: SocketAddr) -> InboundContext {
        let mut context = InboundContext::new(&self.tag, "tun", network, source, destination.into());
        context.origin_destination = Some(destination);
        if network == Network::Udp {
            context.inbound_udp_timeout = Some(self.udp_timeout);
        }
        if self.dns_hijack.contains(&destination.ip()) {
            context.protocol = Some("dns".into());
        }
        context
    }
}

#[async_trait]
impl Handler for FlowHandler {
    async fn judge(
        &self,
        network: rb_netstack::Network,
        source: SocketAddr,
        destination: SocketAddr,
        first_packet: &[u8],
    ) -> Verdict {
        let network = match network {
            rb_netstack::Network::Tcp => Network::Tcp,
            rb_netstack::Network::Udp => Network::Udp,
            // rust-box's rules have no `icmp` network: pings are answered.
            rb_netstack::Network::Icmp => return Verdict::Accept,
        };
        if self.dns_hijack.contains(&destination.ip()) {
            return if network == Network::Udp { Verdict::HijackDns } else { Verdict::Accept };
        }
        let context = InboundContext::new(&self.tag, "tun", network, source, destination.into());
        match self.router.pre_match(context, first_packet).await {
            PreMatch::Continue | PreMatch::Bypass => Verdict::Accept,
            PreMatch::Reject => Verdict::Reject,
            PreMatch::Drop => Verdict::Drop,
            PreMatch::HijackDns => Verdict::HijackDns,
        }
    }

    fn new_tcp(&self, conn: TcpConn) {
        let (source, destination) = (conn.source(), conn.destination());
        let context = self.context(Network::Tcp, source, destination);
        let (router, prefix) = (self.router.clone(), self.log_prefix());
        if context.protocol.as_deref() == Some("dns") {
            info!("{prefix}: inbound DNS connection from {source}");
        } else {
            info!("{prefix}: inbound connection from {source}");
            info!("{prefix}: inbound connection to {destination}");
        }
        tokio::spawn(async move {
            match router.route_connection(context, Box::new(conn)).await {
                Ok(()) | Err(RouteError::Rejected) => {}
                Err(error) => warn!("{prefix}: {source}: {error}"),
            }
        });
    }

    fn new_udp(&self, session: UdpSession, destination: SocketAddr) {
        let source = session.source();
        let context = self.context(Network::Udp, source, destination);
        let (router, prefix) = (self.router.clone(), self.log_prefix());
        if context.protocol.as_deref() == Some("dns") {
            info!("{prefix}: inbound DNS packet connection from {source}");
        } else {
            info!("{prefix}: inbound packet connection from {source}");
            info!("{prefix}: inbound packet connection to {destination}");
        }
        let conn = Arc::new(SessionConn { session, first_destination: destination });
        tokio::spawn(async move {
            match router.route_packet_connection(context, conn).await {
                Ok(()) | Err(RouteError::Rejected) => {}
                Err(error) => warn!("{prefix}: {source}: {error}"),
            }
        });
    }

    fn dns_packet(&self, payload: Vec<u8>, source: SocketAddr, destination: SocketAddr, reply: UdpReply) {
        let context = self.context(Network::Udp, source, destination);
        let (dns, prefix) = (self.dns.clone(), self.log_prefix());
        info!("{prefix}: inbound DNS packet from {source}");
        tokio::spawn(async move {
            match dns.exchange(&payload, &LookupOptions::for_context(&context)).await {
                Ok(Some(answer)) => {
                    if let Err(error) = reply.send(&answer, destination) {
                        debug!("{prefix}: write DNS response: {error}");
                    }
                }
                Ok(None) => {}
                Err(error) => warn!("{prefix}: process DNS packet: {error}"),
            }
        });
    }
}

/// A stack UDP session as the router's packet connection.
struct SessionConn {
    session: UdpSession,
    first_destination: SocketAddr,
}

#[async_trait]
impl PacketConn for SessionConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (length, destination) = self.session.recv(buffer).await?;
        Ok((length, destination.into()))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        // A reply reported as from a domain came from the session's first
        // destination (the address the client sent to).
        let from = match address.ip() {
            Some(ip) => SocketAddr::new(ip, address.port),
            None => self.first_destination,
        };
        self.session.send(data, from)
    }
}

/// What a started TUN keeps until it closes.
struct Running {
    _stack: Stack,
    tasks: Vec<JoinHandle<()>>,
    name: String,
    /// Set when rust-box configured the interface (no platform).
    system: Option<SystemSetup>,
}

/// The routes, rules and addresses rust-box added (to remove on close).
struct SystemSetup {
    index: u32,
    addresses: Vec<Prefix>,
    route_options: RouteOptions,
    routes: Vec<Prefix>,
    rules: Vec<rules::Rule>,
    resolved: bool,
}

/// The `tun` inbound.
pub struct TunInbound {
    tag: String,
    options: TunOptions,
    router: Arc<Router>,
    dns: Arc<dyn DnsResolver>,
    running: Mutex<Option<Running>>,
}

impl TunInbound {
    pub fn new(
        options: &TunOptions,
        tag: String,
        router: Arc<Router>,
        dns: Arc<dyn DnsResolver>,
    ) -> Result<Self, String> {
        if !cfg!(any(target_os = "linux", target_os = "android")) {
            return Err("`tun` is not supported by rust-box on this platform".into());
        }
        options.uid_ranges()?;
        Ok(TunInbound { tag, options: options.clone(), router, dns, running: Mutex::new(None) })
    }

    /// The MTU with its default (sing-box: 9000 on Android, else 65535).
    pub fn mtu(&self) -> u32 {
        match self.options.mtu {
            0 if cfg!(target_os = "android") => 9000,
            0 => 65535,
            mtu => mtu,
        }
    }

    /// The interface name once started.
    pub fn interface_name(&self) -> Option<String> {
        self.running.lock().unwrap().as_ref().map(|running| running.name.clone())
    }

    fn route_options(&self, name: &str) -> Result<RouteOptions, String> {
        let options = &self.options;
        let (include_uid, exclude_uid) = options.uid_ranges()?;
        let split = |list: &rb_config::Listable<rb_config::IpPrefix>, v4: bool| -> Vec<Prefix> {
            list.iter().filter(|it| it.address.is_ipv4() == v4).map(prefix).collect()
        };
        Ok(RouteOptions {
            name: name.to_string(),
            inet4_address: split(&options.address, true),
            inet6_address: split(&options.address, false),
            auto_route: options.auto_route,
            strict_route: options.strict_route,
            table_index: match options.iproute2_table_index {
                0 if options.auto_route => rules::DEFAULT_TABLE_INDEX,
                index => index,
            },
            rule_index: match options.iproute2_rule_index {
                0 => rules::DEFAULT_RULE_INDEX,
                index => index,
            },
            inet4_route_address: split(&options.route_address, true),
            inet6_route_address: split(&options.route_address, false),
            inet4_route_exclude_address: split(&options.route_exclude_address, true),
            inet6_route_exclude_address: split(&options.route_exclude_address, false),
            include_interface: options.include_interface.0.clone(),
            exclude_interface: options.exclude_interface.0.clone(),
            include_uid: include_uid.iter().map(|range| (range.start, range.end)).collect(),
            exclude_uid: exclude_uid.iter().map(|range| (range.start, range.end)).collect(),
            android_vpn: None,
        })
    }

    fn platform_options(&self, name: &str, route: &RouteOptions, dns: &[IpAddr]) -> rb_platform::TunOptions {
        let ranges = rules::route_ranges(route);
        rb_platform::TunOptions {
            name: name.to_string(),
            mtu: self.mtu(),
            inet4_address: route.inet4_address.clone(),
            inet6_address: route.inet6_address.clone(),
            dns_mode: dns_mode(&self.options).to_string(),
            dns_server_address: dns.to_vec(),
            auto_route: route.auto_route,
            strict_route: route.strict_route,
            inet4_route_address: route.inet4_route_address.clone(),
            inet6_route_address: route.inet6_route_address.clone(),
            inet4_route_exclude_address: route.inet4_route_exclude_address.clone(),
            inet6_route_exclude_address: route.inet6_route_exclude_address.clone(),
            inet4_route_range: ranges.iter().filter(|it| it.address.is_ipv4()).copied().collect(),
            inet6_route_range: ranges.iter().filter(|it| it.address.is_ipv6()).copied().collect(),
            include_package: self.options.include_package.0.clone(),
            exclude_package: self.options.exclude_package.0.clone(),
            http_proxy: self.options.platform.as_ref().and_then(|platform| platform.http_proxy.as_ref()).and_then(
                |proxy| {
                    proxy.enabled.then(|| rb_platform::HttpProxy {
                        server: proxy.server.clone(),
                        server_port: proxy.server_port,
                        bypass_domain: proxy.bypass_domain.0.clone(),
                        match_domain: proxy.match_domain.0.clone(),
                    })
                },
            ),
        }
    }

    /// Opens and configures the device the way sing-tun's Linux `New` and
    /// `Start` do.
    fn open_system(&self, name: &str, mut route: RouteOptions) -> io::Result<(Device, SystemSetup)> {
        let device = Device::open(name)?;
        let index = netlink::interface_index(name)?;
        let mut netlink = netlink::Netlink::open()?;
        let addresses: Vec<Prefix> = route.inet4_address.iter().chain(&route.inet6_address).copied().collect();
        let mut setup = SystemSetup {
            index,
            addresses: Vec::new(),
            route_options: route.clone(),
            routes: Vec::new(),
            rules: Vec::new(),
            resolved: false,
        };
        // configure: without permission for the MTU, sing-tun leaves the
        // interface as it is.
        match netlink.request(&netlink::link_message(index, Some(self.mtu()), false)) {
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => return Ok((device, setup)),
            Err(error) => return Err(io::Error::new(error.kind(), format!("set mtu: {error}"))),
            Ok(()) => {}
        }
        for address in &addresses {
            match netlink.request(&netlink::address_message(index, *address, true)) {
                Ok(()) => setup.addresses.push(*address),
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
                Err(error) => return Err(io::Error::new(error.kind(), format!("add address {address}: {error}"))),
            }
        }
        // start
        netlink
            .request(&netlink::link_message(index, None, true))
            .map_err(|error| io::Error::new(error.kind(), format!("set tun up: {error}")))?;
        let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"), "2");
        if route.table_index == 0 {
            // A random table above 255 (sing-tun picks one with no routes).
            route.table_index = 256 + i64::from(rand_u32() % (0x7fff_ffff - 256));
            setup.route_options.table_index = route.table_index;
        }
        for (position, destination) in rules::routes(&route).into_iter().enumerate() {
            let gateway = rules::gateway(&route, &destination);
            let message = netlink::route_message(index, destination, gateway, route.table_index, true);
            if let Err(error) = netlink.request(&message) {
                remove_system(&mut netlink, &setup);
                return Err(io::Error::new(error.kind(), format!("set routes: add route {position}: {error}")));
            }
            setup.routes.push(destination);
        }
        unset_rules(&mut netlink, &route)
            .map_err(|error| io::Error::new(error.kind(), format!("cleanup rules: {error}")))?;
        let next_index6 = next_index6(&mut netlink);
        let rules = rules::rules(&route, next_index6);
        for (position, rule) in rules.iter().enumerate() {
            if let Err(error) = netlink.request(&netlink::rule_message(rule, true)) {
                setup.rules = rules.clone();
                remove_system(&mut netlink, &setup);
                return Err(io::Error::new(
                    error.kind(),
                    format!("set rules: add rule {position}/{}: {error}", rules.len()),
                ));
            }
        }
        setup.rules = rules;
        if dns_mode(&self.options) != "disabled" {
            setup.resolved = set_resolved(name, &self.dns_servers(&route));
        }
        Ok((device, setup))
    }

    /// The DNS servers the system is told about: `dns_address`, else the
    /// hijacked addresses.
    fn dns_servers(&self, route: &RouteOptions) -> Vec<IpAddr> {
        if !self.options.dns_address.is_empty() {
            return self.options.dns_address.0.clone();
        }
        dns_hijack_addresses(&route.inet4_address, &route.inet6_address).unwrap_or_default()
    }
}

fn rand_u32() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher
        .write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    hasher.finish() as u32
}

/// sing-tun `nextIndex6`: just below the lowest IPv6 rule above the
/// redirect rules.
fn next_index6(netlink: &mut netlink::Netlink) -> i64 {
    const REDIRECT_ROUTE_RULE_PRIORITY: i64 = 32767 - 1;
    let Ok(rules) = netlink.list_rules() else { return -1 };
    let mut min = 0;
    for rule in rules.iter().filter(|rule| rule.family == rules::AF_INET6) {
        let priority = i64::from(rule.priority);
        if priority > REDIRECT_ROUTE_RULE_PRIORITY && (min == 0 || priority < min) {
            min = priority;
        }
    }
    (min - 1).max(REDIRECT_ROUTE_RULE_PRIORITY + 1)
}

/// sing-tun `unsetRules`: removes every rule in the TUN's priority range.
fn unset_rules(netlink: &mut netlink::Netlink, route: &RouteOptions) -> io::Result<()> {
    if !route.auto_route && !route.inet6_address.is_empty() && route.table_index != 0 {
        let mut rule = rules::Rule::new(rules::AF_INET6, -1);
        rule.oif = route.name.clone();
        rule.table = route.table_index;
        match netlink.request(&netlink::rule_message(&rule, false)) {
            Err(error) if error.raw_os_error() != Some(libc::ENOENT) => {
                return Err(io::Error::new(error.kind(), format!("unset rule6: {error}")))
            }
            _ => {}
        }
    }
    if route.auto_route {
        let (start, end) = (route.rule_index, route.rule_index + 10);
        for listed in netlink.list_rules()? {
            let priority = i64::from(listed.priority);
            if priority >= start && priority <= end {
                let rule = rules::Rule::new(listed.family, priority);
                netlink.request(&netlink::rule_message(&rule, false)).map_err(|error| {
                    io::Error::new(error.kind(), format!("unset rule {priority} for {}: {error}", listed.family))
                })?;
            }
        }
    }
    Ok(())
}

fn remove_system(netlink: &mut netlink::Netlink, setup: &SystemSetup) {
    for destination in &setup.routes {
        let gateway = rules::gateway(&setup.route_options, destination);
        let message =
            netlink::route_message(setup.index, *destination, gateway, setup.route_options.table_index, false);
        let _ = netlink.request(&message);
    }
    let _ = unset_rules(netlink, &setup.route_options);
}

/// sing-tun `setSearchDomainForSystemdResolved`: `resolvectl` makes the
/// TUN the default DNS route, when it is installed.
fn set_resolved(name: &str, servers: &[IpAddr]) -> bool {
    let Some(resolvectl) = find_executable("resolvectl") else { return false };
    let (name, servers) = (name.to_string(), servers.to_vec());
    std::thread::spawn(move || {
        let run = |args: Vec<String>| {
            let _ = std::process::Command::new(&resolvectl).args(args).output();
        };
        run(vec!["domain".into(), name.clone(), "~.".into()]);
        run(vec!["default-route".into(), name.clone(), "true".into()]);
        let mut dns = vec!["dns".into(), name];
        dns.extend(servers.iter().map(IpAddr::to_string));
        run(dns);
    });
    true
}

fn find_executable(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| std::path::Path::new(dir).join(name))
        .find(|path| path.is_file())
}

#[async_trait]
impl rb_adapter::Inbound for TunInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "tun"
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn start(self: Arc<Self>) -> io::Result<()> {
        let options = &self.options;
        // As in sing-box, an unknown stack fails at start, not at `check`.
        if !matches!(options.stack.as_str(), "" | "system" | "gvisor" | "mixed") {
            return Err(io::Error::other(format!("unknown stack: {}", options.stack)));
        }
        let platform = rb_platform::platform();
        if cfg!(target_os = "android")
            && platform.is_none()
            && (!options.include_package.is_empty()
                || !options.exclude_package.is_empty()
                || !options.include_android_user.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "`include_package`, `exclude_package` and `include_android_user` are not supported by rust-box yet \
                 without a platform interface",
            ));
        }
        let name = if options.interface_name.is_empty() {
            calculate_interface_name(&existing_interfaces())
        } else {
            options.interface_name.clone()
        };
        let route = self.route_options(&name).map_err(io::Error::other)?;
        let dns_hijack = if dns_mode(options) != "disabled" && options.dns_address.is_empty() {
            dns_hijack_addresses(&route.inet4_address, &route.inet6_address).map_err(io::Error::other)?
        } else {
            Vec::new()
        };
        let (device, system) = match &platform {
            Some(platform) => {
                let platform_options = self.platform_options(&name, &route, &self.dns_servers(&route));
                let fd = platform
                    .open_tun(&platform_options)
                    .map_err(|error| io::Error::new(error.kind(), format!("configure tun interface: {error}")))?;
                (Device::from_fd(fd)?, None)
            }
            None => {
                let (device, setup) = self
                    .open_system(&name, route.clone())
                    .map_err(|error| io::Error::new(error.kind(), format!("configure tun interface: {error}")))?;
                (device, Some(setup))
            }
        };
        let name = device.name().unwrap_or(name);
        rb_platform::register_my_interface(
            &name,
            route.inet4_address.iter().chain(&route.inet6_address).copied().collect(),
        );
        let handler = Arc::new(FlowHandler {
            tag: self.tag.clone(),
            router: self.router.clone(),
            dns: self.dns.clone(),
            dns_hijack,
            udp_timeout: if options.udp_timeout.0 .0.is_zero() {
                DEFAULT_UDP_TIMEOUT
            } else {
                options.udp_timeout.0 .0
            },
        });
        let stack_options = StackOptions {
            mtu: self.mtu() as usize,
            udp_mapping: nat(options.udp_mapping),
            udp_filtering: nat(options.udp_filtering),
            udp_nat_max: options.udp_nat_max as usize,
            interface_addresses: route.inet4_address.iter().chain(&route.inet6_address).map(|it| it.address).collect(),
            source_addresses: Vec::new(),
            strict_source_addresses: false,
        };
        let (output_tx, mut output) = mpsc::channel::<Vec<u8>>(rb_netstack::QUEUE_PACKETS);
        let stack = Stack::new(stack_options, handler, output_tx);
        let input = stack.input();
        let device = Arc::new(device);
        let mtu = self.mtu() as usize;
        let reader = {
            let device = device.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; mtu.max(1500) + 64];
                loop {
                    match device.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(length) => {
                            if input.send(buffer[..length].to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => {
                            debug!("tun read: {error}");
                            break;
                        }
                    }
                }
            })
        };
        let writer = tokio::spawn(async move {
            while let Some(packet) = output.recv().await {
                if let Err(error) = device.write(&packet).await {
                    debug!("tun write: {error}");
                }
            }
        });
        info!("inbound/tun[{}]: started at {name}", self.tag);
        *self.running.lock().unwrap() = Some(Running { _stack: stack, tasks: vec![reader, writer], name, system });
        Ok(())
    }

    async fn close(&self) {
        let Some(running) = self.running.lock().unwrap().take() else { return };
        for task in &running.tasks {
            task.abort();
        }
        rb_platform::unregister_my_interface(&running.name);
        if let Some(setup) = &running.system {
            if setup.resolved {
                if let Some(resolvectl) = find_executable("resolvectl") {
                    let _ = std::process::Command::new(resolvectl).args(["revert", &running.name]).output();
                }
            }
            if let Ok(mut netlink) = netlink::Netlink::open() {
                for address in &setup.addresses {
                    let _ = netlink.request(&netlink::address_message(setup.index, *address, false));
                }
                remove_system(&mut netlink, setup);
            }
        }
    }
}

#[cfg(test)]
mod tests;
