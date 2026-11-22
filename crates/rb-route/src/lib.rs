//! The router, mirroring sing-box `route/route.go` (`matchRule`,
//! `RouteConnectionEx`, `RoutePacketConnectionEx`), `route/conn.go`
//! (`ConnectionManager.NewConnection`, `NewPacketConnection`) and
//! `route/dns.go` (`hijack-dns`).

pub mod describe;
pub mod nat;
pub mod sniff;

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{
    Attachment, BoxStream, CachedPacketConn, ConnectionRouter, ConnectionTracker, DnsResolver, HistoryStorage, Host,
    InboundContext, InboundRegistry, Interrupt, InterruptPacketConn, InterruptStream, LookupOptions, Network, Outbound,
    PacketConn, PrefixedStream, RouteError, RoutedConnection, SharedPacketConn, Socksaddr, MAX_PACKET_SIZE,
};
use rb_config::{RejectMethod, RouteActionOptions, RouteOptions, RuleAction};
use rb_dialer::tls_fragment::TlsFragmentStream;
use rb_rule::{compile, compile_route_match, ClashMode, Compiled, Context as RuleContext, Metadata, RuleSets};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;
use tracing::{debug, info};

use sniff::{Sniffed, Verdict, PACKET_SNIFFERS, STREAM_SNIFFERS};

/// sing-box `C.ReadPayloadTimeout`, the default sniff timeout.
pub const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
/// sing-box `C.DNSTimeout`: a hijacked DNS session ends after this long idle.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(10);
/// sing-box `C.UDPTimeout`, the default inbound `udp_timeout`.
pub const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(300);
/// Most packets read while sniffing one UDP session (a QUIC ClientHello
/// split over Initial packets needs a few).
const MAX_SNIFF_PACKETS: usize = 8;

/// sing-box `C.ProtocolTimeouts`: UDP timeouts of sniffed protocols.
pub fn protocol_timeout(protocol: &str) -> Option<Duration> {
    match protocol {
        "dns" | "ntp" | "stun" => Some(Duration::from_secs(10)),
        "quic" | "dtls" => Some(Duration::from_secs(30)),
        _ => None,
    }
}

/// sing-box `C.PortProtocols`: the protocol a UDP port implies when nothing
/// was sniffed.
pub fn port_protocol(port: u16) -> Option<&'static str> {
    match port {
        53 => Some("dns"),
        123 => Some("ntp"),
        443 => Some("quic"),
        3478 => Some("stun"),
        _ => None,
    }
}

/// The idle timeout of a routed UDP session: the route's `udp_timeout`,
/// else the sniffed (or port) protocol's, never longer than the inbound's.
pub fn udp_timeout(context: &InboundContext) -> Option<Duration> {
    let route = context.udp_timeout.or_else(|| {
        let protocol = context.protocol.as_deref().or_else(|| port_protocol(context.destination.port))?;
        protocol_timeout(protocol)
    });
    match (route, context.inbound_udp_timeout) {
        (Some(route), Some(inbound)) => Some(route.min(inbound)),
        (route, inbound) => route.or(inbound),
    }
}

pub struct Router {
    rules: Vec<Compiled<RuleAction>>,
    outbounds: HashMap<String, Arc<dyn Outbound>>,
    final_outbound: String,
    dns: Arc<dyn DnsResolver>,
    inbounds: Arc<InboundRegistry>,
    management: OnceLock<Management>,
}

/// What the box adds to the router once its management parts exist
/// (sing-box `Router.AppendTracker` and the URL test history storage).
pub struct Management {
    pub trackers: Vec<Arc<dyn ConnectionTracker>>,
    pub history: Arc<HistoryStorage>,
}

#[derive(Debug)]
pub struct RouterError(pub String);

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RouterError {}

/// What matching the rules decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Route(String),
    Reject(RejectMethod),
    HijackDns,
}

/// What sniffing reads from while the rules are matched.
pub enum Input<'a> {
    /// A TCP connection; sniffing puts the bytes it read back in front.
    Stream(&'a mut Option<BoxStream>),
    /// A UDP session; packets read while sniffing are collected in `cached`
    /// and replayed in front of the connection afterwards.
    Packet { conn: &'a SharedPacketConn, cached: &'a mut Vec<(Vec<u8>, Socksaddr)> },
}

/// Applies the route options of a matched `route`, `route-options` or
/// `bypass` action (sing-box `Router.matchRule`).
fn apply_route_options(context: &mut InboundContext, options: &RouteActionOptions) {
    let override_address = (!options.override_address.is_empty()).then_some(&options.override_address);
    if (override_address.is_some() || options.override_port > 0) && context.route_original_destination.is_none() {
        context.route_original_destination = Some(context.destination.clone());
    }
    if let Some(address) = override_address {
        context.destination_addresses.clear();
        let host = Socksaddr::from_host_port(address, 0).host;
        context.destination = Socksaddr::new(host, context.destination.port);
    }
    if options.override_port > 0 {
        context.destination.port = options.override_port;
    }
    if options.fallback_delay != 0 {
        // Nanoseconds: sing-box converts the uint32 with time.Duration().
        context.fallback_delay = Some(Duration::from_nanos(u64::from(options.fallback_delay)));
    }
    if options.udp_disable_domain_unmapping {
        context.udp_disable_domain_unmapping = true;
    }
    if options.udp_connect {
        context.udp_connect = true;
    }
    if !options.udp_timeout.0.is_zero() {
        context.udp_timeout = Some(options.udp_timeout.0);
    }
    if options.tls_fragment {
        context.tls_fragment = true;
        context.tls_fragment_fallback_delay =
            (!options.tls_fragment_fallback_delay.0.is_zero()).then_some(options.tls_fragment_fallback_delay.0);
    }
    if options.tls_record_fragment {
        context.tls_record_fragment = true;
    }
}

/// The sniffers of a `sniff` action that apply to this kind of connection,
/// in the action's order (all of them when the action names none).
fn sniffer_names<'a>(configured: &'a [String], available: &[&'static str]) -> Vec<&'a str> {
    if configured.is_empty() {
        available.to_vec()
    } else {
        configured.iter().map(String::as_str).filter(|name| available.contains(name)).collect()
    }
}

impl Router {
    /// `outbounds` in configuration order; the first one is the default when
    /// `route.final` is empty (sing-box `outbound.Manager`).
    /// `inbounds` is the handle the inbound `detour` looks inbounds up in;
    /// it is filled once the inbounds are built.
    pub fn new(
        options: &RouteOptions,
        outbounds: Vec<Arc<dyn Outbound>>,
        dns: Arc<dyn DnsResolver>,
        inbounds: Arc<InboundRegistry>,
        rule_sets: &RuleSets,
    ) -> Result<Self, RouterError> {
        Self::with_clash_mode(options, outbounds, dns, inbounds, rule_sets, None)
    }

    /// [`Router::new`] with the Clash mode that `clash_mode` items read.
    pub fn with_clash_mode(
        options: &RouteOptions,
        outbounds: Vec<Arc<dyn Outbound>>,
        dns: Arc<dyn DnsResolver>,
        inbounds: Arc<InboundRegistry>,
        rule_sets: &RuleSets,
        clash_mode: Option<Arc<ClashMode>>,
    ) -> Result<Self, RouterError> {
        let final_outbound = if !options.r#final.is_empty() {
            options.r#final.clone()
        } else {
            outbounds
                .first()
                .map(|outbound| outbound.tag().to_string())
                .ok_or_else(|| RouterError("no outbounds".into()))?
        };
        let rules = options
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                let context = RuleContext { clash_mode: clash_mode.clone(), ..RuleContext::new(rule_sets) };
                compile(rule, &|options| compile_route_match(options, &context))
                    .map_err(|error| RouterError(format!("route.rules[{index}]: {error}")))
            })
            .collect::<Result<_, _>>()?;
        let outbounds = outbounds.into_iter().map(|outbound| (outbound.tag().to_string(), outbound)).collect();
        Ok(Router { rules, outbounds, final_outbound, dns, inbounds, management: OnceLock::new() })
    }

    /// Adds the connection trackers and the URL test history; later calls
    /// are ignored.
    pub fn set_management(&self, management: Management) {
        let _ = self.management.set(management);
    }

    /// The outbound connections go to when no rule routes them.
    pub fn default_outbound(&self) -> &str {
        &self.final_outbound
    }

    /// The rules as the Clash API lists them: type (`default` or
    /// `logical`), the rule (`Rule.String()`) and its action.
    pub fn rule_descriptions(&self) -> Vec<(&'static str, String, String)> {
        self.rules
            .iter()
            .map(|rule| {
                let kind = match rule.matcher {
                    rb_rule::Matcher::Default(_) => "default",
                    rb_rule::Matcher::Logical(_) => "logical",
                };
                let action = rule.action().map(describe::describe_action).unwrap_or_default();
                (kind, rule.matcher.to_string(), action)
            })
            .collect()
    }

    fn describe_rule(&self, index: Option<usize>) -> Option<String> {
        let rule = &self.rules[index?];
        let action = rule.action().map(describe::describe_action).unwrap_or_default();
        Some(format!("{} => {action}", rule.matcher))
    }

    /// Matches the rules for a TCP connection (see [`Router::decide_input`]).
    pub async fn decide(
        &self,
        context: &mut InboundContext,
        client: &mut Option<BoxStream>,
    ) -> Result<Decision, RouteError> {
        self.decide_input(context, Input::Stream(client)).await
    }

    /// Walks the rules: `sniff`, `resolve` and `route-options` add to the
    /// context and go on; `route`, `reject` and `hijack-dns` end the walk
    /// (sing-box `Router.matchRule`).
    pub async fn decide_input(&self, context: &mut InboundContext, input: Input<'_>) -> Result<Decision, RouteError> {
        Ok(self.decide_rule(context, input).await?.0)
    }

    /// [`Router::decide_input`] with the index of the rule that decided
    /// (`None` for the final outbound).
    async fn decide_rule(
        &self,
        context: &mut InboundContext,
        mut input: Input<'_>,
    ) -> Result<(Decision, Option<usize>), RouteError> {
        self.reverse_fakeip(context)?;
        let mut last_sniffers: Option<&[String]> = None;
        for (index, rule) in self.rules.iter().enumerate() {
            let matched = {
                let mut metadata = metadata(context);
                rule.matches(&mut metadata)
            };
            if !matched {
                continue;
            }
            let Some(action) = rule.action() else { continue };
            match action {
                RuleAction::Route { outbound, options } => {
                    debug!(rule = index, outbound, "match");
                    apply_route_options(context, options);
                    return Ok((Decision::Route(outbound.clone()), Some(index)));
                }
                RuleAction::RouteOptions(options) => {
                    debug!(rule = index, "match: route-options");
                    apply_route_options(context, options);
                }
                // Without an outbound, bypass only matters to TUN pre-matching.
                RuleAction::Bypass { outbound, .. } if outbound.is_empty() => {
                    debug!(rule = index, "match: bypass without outbound, skipped");
                }
                RuleAction::Bypass { outbound, options } => {
                    debug!(rule = index, outbound, "match: bypass");
                    apply_route_options(context, options);
                    return Ok((Decision::Route(outbound.clone()), Some(index)));
                }
                RuleAction::Reject(reject) => {
                    debug!(rule = index, "match: reject");
                    return Ok((Decision::Reject(reject.method), Some(index)));
                }
                RuleAction::HijackDns => {
                    debug!(rule = index, "match: hijack-dns");
                    return Ok((Decision::HijackDns, Some(index)));
                }
                RuleAction::Sniff { sniffer, timeout } => {
                    if context.protocol.is_some() {
                        debug!(rule = index, "duplicate sniff skipped");
                        continue;
                    }
                    if sniff::skip_port(context.destination.port) {
                        debug!(rule = index, "sniff skipped due to port considered as server-first");
                        continue;
                    }
                    // A sniff that already failed with the same sniffers is not repeated.
                    if last_sniffers == Some(sniffer.as_slice()) {
                        continue;
                    }
                    last_sniffers = Some(sniffer.as_slice());
                    let timeout = if timeout.0.is_zero() { DEFAULT_SNIFF_TIMEOUT } else { timeout.0 };
                    let found = match &mut input {
                        Input::Stream(client) => {
                            let names = sniffer_names(sniffer, STREAM_SNIFFERS);
                            match client.take() {
                                Some(stream) if !names.is_empty() => {
                                    let (stream, found) = sniff_stream(stream, &names, timeout).await;
                                    **client = Some(stream);
                                    found
                                }
                                stream => {
                                    **client = stream;
                                    None
                                }
                            }
                        }
                        Input::Packet { conn, cached } => {
                            let names = sniffer_names(sniffer, PACKET_SNIFFERS);
                            if names.is_empty() {
                                None
                            } else {
                                sniff_packets(conn, cached, &names, timeout).await.map_err(RouteError::Io)?
                            }
                        }
                    };
                    if let Some(found) = found {
                        debug!(rule = index, protocol = found.protocol, domain = ?found.domain, "sniffed");
                        context.protocol = Some(found.protocol.to_string());
                        context.sniff_host = found.domain;
                    }
                }
                RuleAction::Resolve { server, strategy, disable_cache } => {
                    let Some(domain) = context.destination.domain().map(str::to_string) else { continue };
                    let options = LookupOptions {
                        server: (!server.is_empty()).then(|| server.clone()),
                        strategy: *strategy,
                        disable_cache: *disable_cache,
                        ..LookupOptions::for_context(context)
                    };
                    let addresses = self.dns.lookup(&domain, &options).await.map_err(RouteError::Resolve)?;
                    debug!(rule = index, domain, ?addresses, "resolved");
                    context.destination_addresses = addresses;
                }
            }
        }
        Ok((Decision::Route(self.final_outbound.clone()), None))
    }

    /// The inbound a connection's `detour` names (sing-box
    /// `Router.RouteConnectionEx`): unknown inbounds and a detour back to
    /// the inbound that handed the connection over are errors.
    fn detour_inbound(
        &self,
        context: &InboundContext,
        detour: &str,
    ) -> Result<Arc<dyn rb_adapter::Inbound>, RouteError> {
        let error = |message: String| RouteError::Io(io::Error::other(message));
        if context.last_inbound.as_deref() == Some(detour) {
            return Err(error(format!("routing loop on detour: {detour}")));
        }
        self.inbounds.get(detour).ok_or_else(|| error(format!("inbound detour not found: {detour}")))
    }

    /// The outbound a tag names, then what each group in it selects for
    /// the network (sing-box `resolveOutbound`).
    fn resolve_chain(&self, tag: &str, network: Network) -> Result<Vec<Arc<dyn Outbound>>, RouteError> {
        let outbound = self.outbounds.get(tag).ok_or_else(|| {
            RouteError::Dial(io::Error::new(io::ErrorKind::NotFound, format!("outbound not found: {tag}")))
        })?;
        let unsupported = |tag: &str| {
            RouteError::Dial(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{} is not supported by outbound: {tag}", network.as_str().to_uppercase()),
            ))
        };
        let mut chain = vec![outbound.clone()];
        loop {
            let last = chain.last().unwrap().clone();
            let Some(group) = last.group() else { break };
            let selected = group.selected(network).ok_or_else(|| unsupported(last.tag()))?;
            if chain.len() > 64 {
                return Err(unsupported(last.tag()));
            }
            chain.push(selected);
        }
        let last = chain.last().unwrap();
        if !last.networks().contains(&network) {
            return Err(unsupported(last.tag()));
        }
        Ok(chain)
    }

    /// What the trackers and groups need of a routed connection: its
    /// interrupt and route, or `None` when nothing watches it.
    fn routed<'a>(
        &self,
        context: &'a InboundContext,
        rule: Option<usize>,
        chain: &[Arc<dyn Outbound>],
    ) -> Option<(RoutedConnection<'a>, Vec<Attachment>)> {
        let trackers = self.management.get().map(|management| management.trackers.as_slice()).unwrap_or_default();
        let groups: Vec<_> = chain.iter().filter_map(|outbound| outbound.group()).collect();
        if trackers.is_empty() && groups.is_empty() {
            return None;
        }
        let interrupt = Interrupt::new(true);
        let attachments = groups.iter().map(|group| group.attach(interrupt.clone())).collect();
        let routed = RoutedConnection {
            context,
            rule: if trackers.is_empty() { None } else { self.describe_rule(rule) },
            chain: chain.iter().map(|outbound| (outbound.tag().to_string(), outbound.kind())).collect(),
            interrupt,
        };
        Some((routed, attachments))
    }

    fn trackers(&self) -> &[Arc<dyn ConnectionTracker>] {
        self.management.get().map(|management| management.trackers.as_slice()).unwrap_or_default()
    }

    /// `ConnectionManager.deleteURLTestHistory`: a failed dial through a URL
    /// test group drops the outbound's last result.
    fn delete_url_test_history(&self, chain: &[Arc<dyn Outbound>]) {
        if chain.iter().any(|outbound| outbound.group().is_some_and(|group| group.is_url_test())) {
            if let Some(management) = self.management.get() {
                management.history.delete(chain.last().unwrap().tag());
            }
        }
    }

    /// Restores a FakeIP destination to its DNS name before route matching.
    fn reverse_fakeip(&self, context: &mut InboundContext) -> Result<(), RouteError> {
        let Some(address) = context.destination.ip() else { return Ok(()) };
        let Some(domain) = self.dns.reverse_lookup(address).map_err(RouteError::Resolve)? else { return Ok(()) };
        let port = context.destination.port;
        context.destination = Socksaddr::new(Host::Domain(domain), port);
        context.fake_ip_original_destination.get_or_insert_with(|| Socksaddr::new(Host::Ip(address), port));
        Ok(())
    }

    /// Answers DNS over TCP on a hijacked connection (sing-box
    /// `hijackDNSStream`): length-prefixed queries, one after another.
    async fn hijack_dns_stream(&self, context: &InboundContext, mut client: BoxStream) -> io::Result<()> {
        let options = LookupOptions::for_context(context);
        loop {
            let length = match tokio::time::timeout(DNS_TIMEOUT, client.read_u16()).await {
                Ok(Ok(length)) => length as usize,
                Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Ok(Err(error)) => return Err(error),
                Err(_) => return Ok(()),
            };
            let mut query = vec![0u8; length];
            tokio::time::timeout(DNS_TIMEOUT, client.read_exact(&mut query))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))??;
            let Some(response) = self.dns.exchange(&query, &options).await? else { continue };
            let mut frame = Vec::with_capacity(response.len() + 2);
            frame.extend_from_slice(&(response.len() as u16).to_be_bytes());
            frame.extend_from_slice(&response);
            client.write_all(&frame).await?;
        }
    }

    /// Answers DNS queries on a hijacked UDP session (sing-box
    /// `NewDNSPacketConnection`): every packet is a query, answered from
    /// the address it was sent to. Queries are answered concurrently; the
    /// session ends after [`DNS_TIMEOUT`] idle.
    async fn hijack_dns_packets(&self, context: &InboundContext, client: SharedPacketConn) -> io::Result<()> {
        let options = LookupOptions::for_context(context);
        let timeout = context.inbound_udp_timeout.map_or(DNS_TIMEOUT, |inbound| inbound.min(DNS_TIMEOUT));
        let activity = Arc::new(Activity::new());
        let mut answers = tokio::task::JoinSet::new();
        let mut buffer = vec![0u8; MAX_PACKET_SIZE];
        loop {
            tokio::select! {
                read = client.read_packet(&mut buffer) => {
                    let (length, destination) = read?;
                    activity.touch();
                    let query = buffer[..length].to_vec();
                    let (dns, client, options, activity) = (self.dns.clone(), client.clone(), options.clone(), activity.clone());
                    answers.spawn(async move {
                        if let Some(response) = dns.exchange(&query, &options).await? {
                            client.write_packet(&response, &destination).await?;
                            activity.touch();
                        }
                        Ok::<(), io::Error>(())
                    });
                }
                Some(answered) = answers.join_next() => {
                    if let Ok(Err(error)) = answered {
                        return Err(error);
                    }
                }
                _ = activity.idle(Some(timeout)) => return Ok(()),
            }
        }
    }
}

/// Redirects packets for `original` to `destination` and reports replies
/// from `destination` as `original` (sing `bufio.DestinationNATPacketConn`).
struct DestinationNat {
    inner: SharedPacketConn,
    destination: Socksaddr,
    original: Socksaddr,
}

#[async_trait]
impl PacketConn for DestinationNat {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (length, source) = self.inner.read_packet(buffer).await?;
        Ok((length, if source == self.destination { self.original.clone() } else { source }))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let address = if *address == self.original { &self.destination } else { address };
        self.inner.write_packet(data, address).await
    }
}

/// When a session last moved a packet, for its idle timeout (sing-box
/// `canceler.PacketConn`).
struct Activity {
    start: Instant,
    last: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Activity { start: Instant::now(), last: AtomicU64::new(0) }
    }

    fn touch(&self) {
        self.last.store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// Completes once nothing moved for `timeout`; never without one.
    async fn idle(&self, timeout: Option<Duration>) {
        let Some(timeout) = timeout else { return std::future::pending().await };
        loop {
            let deadline = self.start + Duration::from_millis(self.last.load(Ordering::Relaxed)) + timeout;
            if deadline <= Instant::now() {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// Copies packets from `from` to `to` until one side fails, and returns why.
async fn copy_packets(from: &SharedPacketConn, to: &SharedPacketConn, activity: &Activity) -> io::Error {
    let mut buffer = vec![0u8; MAX_PACKET_SIZE];
    loop {
        let (length, address) = match from.read_packet(&mut buffer).await {
            Ok(read) => read,
            Err(error) => return error,
        };
        activity.touch();
        if let Err(error) = to.write_packet(&buffer[..length], &address).await {
            return error;
        }
    }
}

/// Relays a UDP session in both directions until either side fails or it
/// is idle for `timeout` (sing-box `packetConnectionCopy` under a canceler).
pub async fn relay_packets(client: SharedPacketConn, remote: SharedPacketConn, timeout: Option<Duration>) {
    let activity = Activity::new();
    tokio::select! {
        error = copy_packets(&client, &remote, &activity) => debug!(%error, "packet connection upload closed"),
        error = copy_packets(&remote, &client, &activity) => debug!(%error, "packet connection download closed"),
        _ = activity.idle(timeout) => debug!("packet connection timed out"),
    }
}

fn metadata(context: &InboundContext) -> Metadata<'_> {
    Metadata {
        inbound: &context.inbound,
        network: Some(context.network.as_str()),
        user: context.user.as_deref(),
        protocol: context.protocol.as_deref(),
        domain: context.domain(),
        source: Some(context.source),
        destination_ip: context.destination.ip(),
        destination_addresses: &context.destination_addresses,
        destination_port: Some(context.destination.port),
        ..Default::default()
    }
}

/// Reads the client's first bytes until a sniffer decides or the timeout
/// passes, and gives the stream back with those bytes in front.
async fn sniff_stream(mut stream: BoxStream, names: &[&str], timeout: Duration) -> (BoxStream, Option<Sniffed>) {
    let mut buffer = Vec::with_capacity(4096);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut found = None;
    let mut chunk = [0u8; 4096];
    while buffer.len() < 16 * 1024 {
        let read = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(read)) => read,
        };
        buffer.extend_from_slice(&chunk[..read]);
        let mut need_more = false;
        for name in names {
            match sniff::sniff(name, &buffer) {
                Verdict::Found(sniffed) => {
                    found = Some(sniffed);
                    break;
                }
                Verdict::NeedMore => need_more = true,
                Verdict::NotThis => {}
            }
        }
        if found.is_some() || !need_more {
            break;
        }
    }
    (Box::new(PrefixedStream::new(buffer, stream)), found)
}

/// Reads packets until a packet sniffer decides, the timeout passes between
/// two packets, or [`MAX_SNIFF_PACKETS`] were read. Packets are kept in
/// `cached` (sing-box `actionSniff` for packet connections).
async fn sniff_packets(
    conn: &SharedPacketConn,
    cached: &mut Vec<(Vec<u8>, Socksaddr)>,
    names: &[&str],
    timeout: Duration,
) -> io::Result<Option<Sniffed>> {
    // Index of the first packet of a QUIC ClientHello split over packets.
    let mut quic_from: Option<usize> = None;
    let mut index = 0;
    loop {
        if index == cached.len() {
            if cached.len() >= MAX_SNIFF_PACKETS {
                break;
            }
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];
            match tokio::time::timeout(timeout, conn.read_packet(&mut buffer)).await {
                Err(_) => break,
                Ok(Err(error)) => return Err(error),
                Ok(Ok((length, address))) => {
                    buffer.truncate(length);
                    cached.push((buffer, address));
                }
            }
        }
        index += 1;
        if let Some(from) = quic_from {
            let packets: Vec<&[u8]> = cached[from..index].iter().map(|(data, _)| data.as_slice()).collect();
            match sniff::quic(&packets) {
                Verdict::Found(found) => return Ok(Some(found)),
                Verdict::NeedMore => continue,
                // sing-box has already marked the session as QUIC by now.
                Verdict::NotThis => return Ok(Some(Sniffed { protocol: "quic", domain: None })),
            }
        }
        let packet = &cached[index - 1].0;
        let mut need_more = false;
        for name in names {
            match sniff::sniff_packet(name, packet) {
                Verdict::Found(found) => return Ok(Some(found)),
                Verdict::NeedMore => need_more = true,
                Verdict::NotThis => {}
            }
        }
        if !need_more {
            return Ok(None);
        }
        debug!("attempt to sniff fragmented QUIC client hello");
        quic_from = Some(index - 1);
    }
    Ok(quic_from.map(|_| Sniffed { protocol: "quic", domain: None }))
}

#[async_trait]
impl ConnectionRouter for Router {
    async fn route_connection(&self, mut context: InboundContext, client: BoxStream) -> Result<(), RouteError> {
        if let Some(detour) = context.inbound_detour.take() {
            let inbound = self.detour_inbound(&context, &detour)?;
            context.last_inbound = Some(std::mem::replace(&mut context.inbound, detour));
            return inbound.new_connection(context, client).await.map_err(RouteError::Io);
        }
        let mut client = Some(client);
        let (decision, rule) = self.decide_rule(&mut context, Input::Stream(&mut client)).await?;
        let mut client = client.expect("client stream is always given back");
        let tag = match decision {
            Decision::Route(tag) => tag,
            Decision::Reject(_) => {
                info!(inbound = %context.inbound, destination = %context.destination, "rejected");
                return Err(RouteError::Rejected);
            }
            Decision::HijackDns => {
                if let Err(error) = self.hijack_dns_stream(&context, client).await {
                    debug!(%error, "hijacked DNS connection closed");
                }
                return Ok(());
            }
        };
        let chain = self.resolve_chain(&tag, Network::Tcp)?;
        let outbound = chain.last().unwrap().clone();
        let mut _attachments = Vec::new();
        if let Some((routed, attachments)) = self.routed(&context, rule, &chain) {
            _attachments = attachments;
            client = Box::new(InterruptStream::new(client, routed.interrupt.clone()));
            for tracker in self.trackers() {
                client = tracker.routed_connection(&routed, client);
            }
        }
        info!(
            "outbound/{}[{}]: outbound connection to {}",
            outbound.kind(),
            outbound.tag(),
            context
                .sniff_host
                .as_ref()
                .map(|host| format!("{host}:{}", context.destination.port))
                .unwrap_or_else(|| context.destination.to_string())
        );
        let mut remote = match outbound.dial_tcp(&context).await {
            Ok(remote) => remote,
            Err(error) => {
                self.delete_url_test_history(&chain);
                return Err(RouteError::Dial(error));
            }
        };
        if context.tls_fragment || context.tls_record_fragment {
            remote = Box::new(TlsFragmentStream::new(
                remote,
                context.tls_fragment,
                context.tls_record_fragment,
                context.tls_fragment_fallback_delay,
            ));
        }
        match tokio::io::copy_bidirectional(&mut client, &mut remote).await {
            Ok((up, down)) => debug!(destination = %context.destination, up, down, "connection closed"),
            Err(error) => debug!(destination = %context.destination, %error, "connection closed"),
        }
        Ok(())
    }

    async fn route_packet_connection(
        &self,
        mut context: InboundContext,
        client: SharedPacketConn,
    ) -> Result<(), RouteError> {
        if let Some(detour) = context.inbound_detour.take() {
            let inbound = self.detour_inbound(&context, &detour)?;
            context.last_inbound = Some(std::mem::replace(&mut context.inbound, detour));
            return inbound.new_packet_connection(context, client).await.map_err(RouteError::Io);
        }
        context.network = Network::Udp;
        let mut cached = Vec::new();
        let (decision, rule) =
            self.decide_rule(&mut context, Input::Packet { conn: &client, cached: &mut cached }).await?;
        let mut client: SharedPacketConn =
            if cached.is_empty() { client } else { Arc::new(CachedPacketConn::new(cached, client)) };
        let tag = match decision {
            Decision::Route(tag) => tag,
            Decision::Reject(_) => {
                info!(inbound = %context.inbound, destination = %context.destination, "packet connection rejected");
                return Err(RouteError::Rejected);
            }
            Decision::HijackDns => {
                if let Err(error) = self.hijack_dns_packets(&context, client).await {
                    debug!(%error, "hijacked DNS packet connection closed");
                }
                return Ok(());
            }
        };
        let chain = self.resolve_chain(&tag, Network::Udp)?;
        let outbound = chain.last().unwrap().clone();
        let mut _attachments = Vec::new();
        if let Some((routed, attachments)) = self.routed(&context, rule, &chain) {
            _attachments = attachments;
            client = Arc::new(InterruptPacketConn::new(client, routed.interrupt.clone()));
            for tracker in self.trackers() {
                client = tracker.routed_packet_connection(&routed, client);
            }
        }
        info!(
            "outbound/{}[{}]: outbound packet connection to {}",
            outbound.kind(),
            outbound.tag(),
            context
                .sniff_host
                .as_ref()
                .map(|host| format!("{host}:{}", context.destination.port))
                .unwrap_or_else(|| context.destination.to_string())
        );
        let mut remote = match outbound.listen_packet(&context).await {
            Ok(remote) => remote,
            Err(error) => {
                self.delete_url_test_history(&chain);
                return Err(RouteError::Dial(error));
            }
        };
        // With override_address/override_port, packets the client sends to
        // the original destination go to the new one and replies come back
        // from the original (sing `bufio.NewDestinationNATPacketConn`).
        if let Some(original) = &context.route_original_destination {
            if *original != context.destination {
                remote = Arc::new(DestinationNat {
                    inner: remote,
                    destination: context.destination.clone(),
                    original: original.clone(),
                });
            }
        }
        relay_packets(client, remote, udp_timeout(&context)).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
