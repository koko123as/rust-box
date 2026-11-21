//! DNS, mirroring sing-box `dns/`: transports (`dns/transport/{udp,tcp}`,
//! `dns/transport/local`), the DNS router with its rules (`dns/router.go`)
//! and the response cache (`dns/client.go`). The router has sing-box's two
//! rule modes: the legacy mode (address filter fields and rule `strategy`,
//! where a rule's address limit is checked against the response and the
//! walk goes on when it fails) and the default mode.

mod transport;

mod mode;

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record};
use rb_adapter::{apply_strategy, DnsResolver, LookupOptions, OutboundRegistry, Socksaddr};
use rb_config::{DnsOptions, DnsRule, DnsRuleAction, DnsServer, DomainStrategy, RejectMethod};
use rb_dialer::{DialerEnv, NetworkDefaults};
use rb_rule::{compile, compile_dns_match, Compiled, Context as RuleContext, Metadata, RuleSetMetadata, RuleSets};

pub use transport::{
    Answer, DohTransport, DoqTransport, DotTransport, FakeIpTransport, H3Transport, HostsTransport, Transport, QTYPE_A,
    QTYPE_AAAA,
};

/// sing-box `C.DNSTimeout`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// sing-box default `cache_capacity`.
const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// (server tag, domain, query type)
type CacheKey = (String, String, u16);

struct Cache {
    entries: HashMap<CacheKey, CacheEntry>,
    capacity: usize,
    disable_expire: bool,
}

struct CacheEntry {
    addresses: Vec<IpAddr>,
    ttl: u32,
    expires: Option<Instant>,
}

impl Cache {
    /// The cached addresses and their remaining TTL.
    fn get(&mut self, key: &CacheKey) -> Option<Answer> {
        let entry = self.entries.get(key)?;
        let ttl = match entry.expires {
            Some(expires) => {
                let now = Instant::now();
                if expires <= now {
                    self.entries.remove(key);
                    return None;
                }
                (expires - now).as_secs().max(1) as u32
            }
            None => entry.ttl,
        };
        Some(Answer { addresses: entry.addresses.clone(), ttl })
    }

    fn put(&mut self, key: CacheKey, addresses: Vec<IpAddr>, ttl: u32) {
        if ttl == 0 && !self.disable_expire {
            return;
        }
        if self.entries.len() >= self.capacity {
            let now = Instant::now();
            self.entries.retain(|_, entry| entry.expires.is_none_or(|expires| expires > now));
            if self.entries.len() >= self.capacity {
                if let Some(victim) = self.entries.keys().next().cloned() {
                    self.entries.remove(&victim);
                }
            }
        }
        let expires = (!self.disable_expire).then(|| Instant::now() + Duration::from_secs(u64::from(ttl)));
        self.entries.insert(key, CacheEntry { addresses, ttl, expires });
    }
}

/// Where the DNS rules send one query.
enum Selection {
    Server { server: String, strategy: DomainStrategy, disable_cache: bool },
    Reject(RejectMethod),
}

/// The compiled rules and the mode they run in.
struct DnsRules {
    rules: Vec<Compiled<DnsRuleAction>>,
    legacy: bool,
}

#[derive(Default)]
struct RulesState {
    started: bool,
    closing: bool,
    legacy: bool,
}

/// The DNS router (sing-box `dns.Router` + `dns.Client`).
pub struct DnsRouter {
    servers: HashMap<String, Arc<Transport>>,
    raw_rules: Vec<DnsRule>,
    rules: RwLock<Arc<DnsRules>>,
    state: Mutex<RulesState>,
    final_server: String,
    strategy: DomainStrategy,
    timeout: Duration,
    cache: Option<Mutex<Cache>>,
}

#[derive(Default)]
struct DnsResolverHandle {
    router: RwLock<Option<Weak<DnsRouter>>>,
}

impl DnsResolverHandle {
    fn router(&self) -> io::Result<Arc<DnsRouter>> {
        self.router
            .read()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "DNS router is not initialized"))
    }
}

#[async_trait]
impl DnsResolver for DnsResolverHandle {
    async fn lookup(&self, domain: &str, options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
        self.router()?.lookup(domain, options).await
    }

    async fn exchange(&self, query: &[u8], options: &LookupOptions) -> io::Result<Option<Vec<u8>>> {
        self.router()?.exchange(query, options).await
    }

    fn reverse_lookup(&self, address: IpAddr) -> io::Result<Option<String>> {
        self.router()?.reverse_lookup(address)
    }
}

#[derive(Debug)]
pub struct DnsError(pub String);

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DnsError {}

fn rejected(domain: &str) -> io::Error {
    io::Error::other(format!("{domain}: response rejected"))
}

/// sing-box `isAddressQuery`.
fn is_address_query(query_type: u16) -> bool {
    query_type == QTYPE_A || query_type == QTYPE_AAAA || query_type == QTYPE_HTTPS
}

const QTYPE_HTTPS: u16 = 65;
const QTYPE_SVCB: u16 = 64;

fn ip_version_of(query_type: u16) -> Option<u8> {
    match query_type {
        QTYPE_A => Some(4),
        QTYPE_AAAA => Some(6),
        _ => None,
    }
}

fn strategy_allows(strategy: DomainStrategy, query_type: u16) -> bool {
    !((strategy == DomainStrategy::Ipv4Only && query_type == QTYPE_AAAA)
        || (strategy == DomainStrategy::Ipv6Only && query_type == QTYPE_A))
}

impl DnsRouter {
    /// `defaults` are the route-level dial defaults and `outbounds` the
    /// handle a server's `detour` dials through (filled once the outbounds
    /// are built). The rules are checked against the rule-sets as they are
    /// now (sing-box `Router.Initialize`) and built again by
    /// [`DnsRouter::start`] once the rule-sets are loaded.
    pub fn new(
        options: &DnsOptions,
        defaults: &NetworkDefaults,
        outbounds: &Arc<OutboundRegistry>,
        rule_sets: &RuleSets,
        certificates: &Arc<rb_certificate::Store>,
    ) -> Result<Arc<Self>, DnsError> {
        let mut servers = HashMap::new();
        let mut first = None;
        let mut fakeip_count = 0;
        let dns_resolver = Arc::new(DnsResolverHandle::default());
        let dns_resolver_trait: Arc<dyn DnsResolver> = dns_resolver.clone();
        for (index, server) in options.servers.iter().enumerate() {
            let tag = if server.tag().is_empty() { index.to_string() } else { server.tag().to_string() };
            let dialer = |remote: &rb_config::RemoteDnsServer| {
                rb_dialer::new_dialer(&remote.dialer_options(), defaults, outbounds, false)
                    .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))
            };
            let transport = match server {
                DnsServer::Local { .. } => Transport::Local,
                DnsServer::Udp(remote) => {
                    Transport::Udp((remote.server, port_or_default(remote.server_port)).into(), dialer(remote)?)
                }
                DnsServer::Tcp(remote) => {
                    Transport::Tcp((remote.server, port_or_default(remote.server_port)).into(), dialer(remote)?)
                }
                DnsServer::Tls(remote) | DnsServer::Quic(remote) => {
                    let address = Socksaddr::from_host_port(&remote.server, port_or_default_dot(remote.server_port));
                    if remote.server.is_empty() {
                        return Err(DnsError(format!("dns.servers[{index}]: invalid server address: {address}")));
                    }
                    let dial_options = remote.dialer_options();
                    let has_resolver =
                        dial_options.domain_resolver.as_ref().is_some_and(|resolver| !resolver.server.is_empty());
                    if address.domain().is_some() && dial_options.detour.is_empty() && !has_resolver {
                        return Err(DnsError(format!(
                            "dns.servers[{index}]: missing domain resolver for domain server address"
                        )));
                    }
                    let environment = DialerEnv {
                        defaults: defaults.clone(),
                        outbounds: outbounds.clone(),
                        dns: dns_resolver_trait.clone(),
                        // sing-box DNS remote dialers use DirectResolver;
                        // route.default_domain_resolver is deliberately not inherited.
                        default_resolver: None,
                    };
                    let remote_dialer = rb_dialer::new_outbound_dialer(
                        &dial_options,
                        address.domain().is_some(),
                        &environment,
                        &format!(
                            "dns/transport/{}[{tag}]",
                            if matches!(server, DnsServer::Quic(_)) { "quic" } else { "tls" }
                        ),
                    )
                    .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?;
                    let mut tls = remote.tls.clone().unwrap_or_default();
                    // sing-box forces TLS on and leaves ALPN empty by default.
                    tls.enabled = true;
                    if matches!(server, DnsServer::Quic(_)) && tls.alpn.is_empty() {
                        tls.alpn.0 = vec!["doq".into()];
                    }
                    let client = rb_tls::TlsClient::new(&tls, &remote.server, certificates)
                        .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?;
                    if matches!(server, DnsServer::Quic(_)) {
                        Transport::Doq(Arc::new(DoqTransport::new(address, remote_dialer, client)))
                    } else {
                        let tls_dialer = Arc::new(rb_tls::TlsDialer::new(remote_dialer, client));
                        Transport::Dot(Arc::new(DotTransport::new(address, tls_dialer)))
                    }
                }
                DnsServer::Https(remote) => {
                    let address = Socksaddr::from_host_port(&remote.server, port_or_default_https(remote.server_port));
                    if remote.server.is_empty() {
                        return Err(DnsError(format!("dns.servers[{index}]: invalid server address: {address}")));
                    }
                    let dial_options = remote.dialer_options();
                    let has_resolver =
                        dial_options.domain_resolver.as_ref().is_some_and(|resolver| !resolver.server.is_empty());
                    if address.domain().is_some() && dial_options.detour.is_empty() && !has_resolver {
                        return Err(DnsError(format!(
                            "dns.servers[{index}]: missing domain resolver for domain server address"
                        )));
                    }
                    let environment = DialerEnv {
                        defaults: defaults.clone(),
                        outbounds: outbounds.clone(),
                        dns: dns_resolver_trait.clone(),
                        default_resolver: None,
                    };
                    let remote_dialer = rb_dialer::new_outbound_dialer(
                        &dial_options,
                        address.domain().is_some(),
                        &environment,
                        &format!("dns/transport/https[{tag}]"),
                    )
                    .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?;
                    let mut tls = remote.tls.clone().unwrap_or_default();
                    tls.enabled = true;
                    if tls.alpn.is_empty() {
                        tls.alpn.0 = vec!["h2".into(), "http/1.1".into()];
                    }
                    let client = rb_tls::TlsClient::new(&tls, &remote.server, certificates)
                        .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?;
                    let doh = DohTransport::new(
                        address,
                        remote_dialer,
                        client,
                        remote.server_port,
                        &remote.path,
                        &remote.headers,
                    )
                    .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?;
                    Transport::Doh(Arc::new(doh))
                }
                DnsServer::Http3(remote) => {
                    let address = Socksaddr::from_host_port(&remote.server, port_or_default_https(remote.server_port));
                    if remote.server.is_empty() {
                        return Err(DnsError(format!("dns.servers[{index}]: invalid server address: {address}")));
                    }
                    let dial_options = remote.dialer_options();
                    let has_resolver =
                        dial_options.domain_resolver.as_ref().is_some_and(|resolver| !resolver.server.is_empty());
                    if address.domain().is_some() && dial_options.detour.is_empty() && !has_resolver {
                        return Err(DnsError(format!(
                            "dns.servers[{index}]: missing domain resolver for domain server address"
                        )));
                    }
                    let environment = DialerEnv {
                        defaults: defaults.clone(),
                        outbounds: outbounds.clone(),
                        dns: dns_resolver_trait.clone(),
                        default_resolver: None,
                    };
                    let remote_dialer = rb_dialer::new_outbound_dialer(
                        &dial_options,
                        address.domain().is_some(),
                        &environment,
                        &format!("dns/transport/http3[{tag}]"),
                    )
                    .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?;
                    let mut tls = remote.tls.clone().unwrap_or_default();
                    tls.enabled = true;
                    tls.alpn.0 = vec!["h3".into()];
                    let client = rb_tls::TlsClient::new(&tls, &remote.server, certificates)
                        .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?;
                    let h3 = H3Transport::new(
                        address,
                        remote_dialer,
                        client,
                        remote.server_port,
                        &remote.path,
                        &remote.headers,
                    )
                    .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?;
                    Transport::H3(Arc::new(h3))
                }
                DnsServer::Hosts(hosts) => {
                    Transport::hosts(hosts).map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?
                }
                DnsServer::FakeIp(fakeip) => {
                    fakeip_count += 1;
                    if fakeip_count > 1 {
                        return Err(DnsError("multiple fakeip server are not supported".into()));
                    }
                    Transport::FakeIp(Arc::new(
                        FakeIpTransport::new(fakeip)
                            .map_err(|error| DnsError(format!("dns.servers[{index}]: {error}")))?,
                    ))
                }
            };
            first.get_or_insert_with(|| tag.clone());
            servers.insert(tag, Arc::new(transport));
        }
        // Without servers sing-box uses the local resolver.
        let final_server = if !options.r#final.is_empty() {
            options.r#final.clone()
        } else if let Some(first) = first {
            first
        } else {
            servers.insert("local".into(), Arc::new(Transport::Local));
            "local".into()
        };
        if servers.get(&final_server).is_some_and(|server| matches!(server.as_ref(), Transport::FakeIp(_))) {
            return Err(DnsError("default server cannot be fakeip".into()));
        }
        let timeout = if options.timeout.0.is_zero() { DEFAULT_TIMEOUT } else { options.timeout.0 };
        let cache = (!options.disable_cache).then(|| {
            Mutex::new(Cache {
                entries: HashMap::new(),
                capacity: if options.cache_capacity == 0 {
                    DEFAULT_CACHE_CAPACITY
                } else {
                    options.cache_capacity as usize
                },
                disable_expire: options.disable_expire,
            })
        });
        let router = Arc::new(DnsRouter {
            servers,
            raw_rules: options.rules.clone(),
            rules: RwLock::new(Arc::new(DnsRules { rules: Vec::new(), legacy: false })),
            state: Mutex::new(RulesState::default()),
            final_server,
            strategy: options.strategy,
            timeout,
            cache,
        });
        *dns_resolver.router.write().unwrap() = Some(Arc::downgrade(&router));
        let (rules, _) = router.build_rules(rule_sets)?;
        *router.rules.write().unwrap() = Arc::new(rules);
        Ok(router)
    }

    /// `Router.buildRules`.
    fn build_rules(&self, rule_sets: &RuleSets) -> Result<(DnsRules, mode::ModeFlags), DnsError> {
        let lookup = mode::MetadataLookup { rule_sets, overrides: HashMap::new() };
        let (legacy, flags) = mode::resolve_legacy_mode(&self.raw_rules, &lookup).map_err(DnsError)?;
        if !legacy {
            mode::validate_disabled_rules(&self.raw_rules, &lookup).map_err(DnsError)?;
        }
        let context = RuleContext { rule_sets, legacy_dns_mode: legacy, network_manager: true };
        let rules = self
            .raw_rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                compile(rule, &|options| compile_dns_match(options, &context))
                    .map_err(|error| DnsError(format!("parse dns rule[{index}]: {error}")))
            })
            .collect::<Result<_, _>>()?;
        Ok((DnsRules { rules, legacy }, flags))
    }

    /// Builds the rules with the loaded rule-sets (sing-box `Router.Start`).
    pub fn start(&self, rule_sets: &RuleSets) -> Result<(), DnsError> {
        let (rules, flags) = self.build_rules(rule_sets)?;
        let legacy = rules.legacy;
        if legacy && rules.rules.iter().any(|rule| rule.matcher.with_address_limit()) {
            rb_config::deprecated::report(rb_config::deprecated::LEGACY_DNS_ADDRESS_FILTER);
        }
        if legacy && flags.needed_from_strategy {
            rb_config::deprecated::report(rb_config::deprecated::LEGACY_DNS_RULE_STRATEGY);
        }
        *self.rules.write().unwrap() = Arc::new(rules);
        let mut state = self.state.lock().unwrap();
        state.started = true;
        state.legacy = legacy;
        Ok(())
    }

    /// Stops accepting rule-set updates (sing-box marks the router closing).
    pub fn close(&self) {
        self.state.lock().unwrap().closing = true;
    }

    /// `DNSRouter.LookupReverseMapping`, including FakeIP store lookups.
    /// An address inside the configured FakeIP range without a record is an
    /// error rather than an ordinary unmapped address.
    pub fn reverse_lookup(&self, address: IpAddr) -> io::Result<Option<String>> {
        for server in self.servers.values() {
            if let Transport::FakeIp(fakeip) = server.as_ref() {
                if fakeip.contains(address) {
                    return fakeip.lookup(address).map(Some).ok_or_else(|| {
                        io::Error::other("missing fakeip record, try enable `experimental.cache_file`")
                    });
                }
            }
        }
        Ok(None)
    }

    /// Whether the rules run in sing-box's legacy DNS mode.
    pub fn legacy_mode(&self) -> bool {
        self.rules.read().unwrap().legacy
    }

    /// `ValidateRuleSetMetadataUpdate`: whether a rule-set may change to
    /// content with `metadata`.
    pub fn validate_rule_set_update(
        &self,
        rule_sets: &RuleSets,
        tag: &str,
        metadata: &RuleSetMetadata,
    ) -> Result<(), String> {
        let (started, legacy, closing) = {
            let state = self.state.lock().unwrap();
            (state.started, state.legacy, state.closing)
        };
        if closing {
            return Ok(());
        }
        let lookup = mode::MetadataLookup { rule_sets, overrides: HashMap::from([(tag.to_string(), *metadata)]) };
        mode::validate_update(&self.raw_rules, &lookup, started, legacy)
    }

    /// `Router.matchDNS`: the first rule that routes or rejects, from
    /// `start`, and its index.
    fn match_rules(
        &self,
        rules: &DnsRules,
        metadata: &mut Metadata,
        start: usize,
        address_query: bool,
        options: &LookupOptions,
    ) -> (Selection, Option<usize>) {
        if let Some(server) = &options.server {
            return (
                Selection::Server {
                    server: server.clone(),
                    strategy: options.strategy,
                    disable_cache: options.disable_cache,
                },
                None,
            );
        }
        for (index, rule) in rules.rules.iter().enumerate().skip(start) {
            let matched = if rules.legacy {
                if rule.matcher.with_address_limit() && !address_query {
                    continue;
                }
                metadata.reset_rule_cache();
                metadata.destination_address_match_from_response = false;
                rule.matcher.legacy_pre_match(metadata)
            } else {
                metadata.reset_rule_cache();
                rule.matches(metadata)
            };
            if !matched {
                continue;
            }
            match rule.action() {
                Some(DnsRuleAction::Route { server, strategy, disable_cache }) => {
                    tracing::debug!(domain = metadata.domain, rule = index, server, "dns: match");
                    let strategy = if *strategy != DomainStrategy::AsIs { *strategy } else { options.strategy };
                    return (
                        Selection::Server {
                            server: server.clone(),
                            strategy,
                            disable_cache: *disable_cache || options.disable_cache,
                        },
                        Some(index),
                    );
                }
                Some(DnsRuleAction::Reject(reject)) => {
                    tracing::debug!(domain = metadata.domain, rule = index, "dns: reject");
                    return (Selection::Reject(reject.method), Some(index));
                }
                None => {}
            }
        }
        (
            Selection::Server {
                server: self.final_server.clone(),
                strategy: options.strategy,
                disable_cache: options.disable_cache,
            },
            None,
        )
    }

    fn transport(&self, server: &str) -> io::Result<&Arc<Transport>> {
        self.servers
            .get(server)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("DNS server not found: {server}")))
    }

    /// Asks `server` for the A or AAAA records of `domain`, through the cache.
    async fn query_server(
        &self,
        server: &str,
        disable_cache: bool,
        domain: &str,
        query_type: u16,
        options: &LookupOptions,
    ) -> io::Result<Answer> {
        let transport = self.transport(server)?;
        let key = (server.to_string(), domain.to_string(), query_type);
        if !disable_cache {
            if let Some(cache) = &self.cache {
                if let Some(answer) = cache.lock().unwrap().get(&key) {
                    return Ok(answer);
                }
            }
        }
        let timeout = options.timeout.unwrap_or(self.timeout);
        let mut answer = tokio::time::timeout(timeout, transport.query(domain, query_type, timeout))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{domain}: DNS query timed out")))??;
        if let Some(ttl) = options.rewrite_ttl {
            if !answer.addresses.is_empty() {
                answer.ttl = ttl;
            }
        }
        if !disable_cache {
            if let Some(cache) = &self.cache {
                cache.lock().unwrap().put(key, answer.addresses.clone(), answer.ttl);
            }
        }
        Ok(answer)
    }

    fn base_metadata<'a>(domain: &'a str, options: &'a LookupOptions) -> Metadata<'a> {
        Metadata {
            inbound: options.inbound.as_deref().unwrap_or(""),
            network: options.network.map(|network| network.as_str()),
            user: options.user.as_deref(),
            source: options.source,
            domain: Some(domain),
            ..Default::default()
        }
    }

    /// One lookup type in the default mode (`lookupWithRulesType`).
    async fn lookup_type(
        &self,
        rules: &DnsRules,
        domain: &str,
        query_type: u16,
        options: &LookupOptions,
    ) -> io::Result<Vec<IpAddr>> {
        let selection = {
            let mut metadata = Self::base_metadata(domain, options);
            metadata.query_type = Some(query_type);
            metadata.ip_version = ip_version_of(query_type);
            self.match_rules(rules, &mut metadata, 0, true, options).0
        };
        match selection {
            Selection::Reject(method) => Err(reject_error(domain, method)),
            Selection::Server { server, strategy, disable_cache } => {
                if !strategy_allows(strategy, query_type) {
                    return Ok(Vec::new());
                }
                let answer = self.query_server(&server, disable_cache, domain, query_type, options).await?;
                Ok(answer.addresses)
            }
        }
    }

    /// A and AAAA lookups against one server, each response checked
    /// against the rule's address limit (`Client.Lookup` with a response
    /// checker).
    #[allow(clippy::too_many_arguments)]
    async fn lookup_server(
        &self,
        rules: &DnsRules,
        check: Option<(usize, &Metadata<'_>)>,
        server: &str,
        disable_cache: bool,
        domain: &str,
        strategy: DomainStrategy,
        options: &LookupOptions,
    ) -> io::Result<Vec<IpAddr>> {
        let query = |query_type: u16| async move {
            let answer = self.query_server(server, disable_cache, domain, query_type, options).await?;
            if let Some((index, metadata)) = check {
                if !rules.rules[index].matcher.match_address_limit(metadata, &answer.addresses) {
                    return Err(rejected(domain));
                }
            }
            Ok(answer.addresses)
        };
        let (a, aaaa) = match strategy {
            DomainStrategy::Ipv4Only => (Some(query(QTYPE_A).await), None),
            DomainStrategy::Ipv6Only => (None, Some(query(QTYPE_AAAA).await)),
            _ => {
                let (a, aaaa) = tokio::join!(query(QTYPE_A), query(QTYPE_AAAA));
                (Some(a), Some(aaaa))
            }
        };
        combine(domain, a, aaaa, strategy)
    }

    async fn lookup_legacy(&self, rules: &DnsRules, domain: &str, options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
        let mut start = 0;
        loop {
            let mut metadata = Self::base_metadata(domain, options);
            let (selection, index) = self.match_rules(rules, &mut metadata, start, true, options);
            let (server, strategy, disable_cache) = match selection {
                Selection::Reject(method) => return Err(reject_error(domain, method)),
                Selection::Server { server, strategy, disable_cache } => (server, strategy, disable_cache),
            };
            let strategy = if strategy != DomainStrategy::AsIs { strategy } else { self.strategy };
            let check = index.filter(|index| rules.rules[*index].matcher.with_address_limit());
            let metadata = Self::base_metadata(domain, options);
            let result = self
                .lookup_server(
                    rules,
                    check.map(|index| (index, &metadata)),
                    &server,
                    disable_cache,
                    domain,
                    strategy,
                    options,
                )
                .await;
            match (check, result) {
                (Some(index), Err(error)) => {
                    tracing::debug!(domain, %error, "dns: lookup failed, trying the next rule");
                    start = index + 1;
                }
                (_, result) => return result,
            }
        }
    }

    /// Answers one query message (sing-box `dns.Router.Exchange`).
    ///
    /// A and AAAA questions go through the same path as lookups (rules,
    /// strategy, cache) and the answer is built from the addresses; other
    /// types are forwarded as they are to the selected `udp`/`tcp` server.
    async fn exchange_message(&self, request: &Message, options: &LookupOptions) -> io::Result<Option<Vec<u8>>> {
        if request.queries().len() != 1 {
            return response(request, ResponseCode::FormErr, Vec::new()).map(Some);
        }
        let question = request.queries()[0].clone();
        let domain = question.name().to_ascii().trim_end_matches('.').to_ascii_lowercase();
        let query_type = u16::from(question.query_type());
        // isResolverDiscoveryQuery: an empty answer for `_dns.` SVCB.
        if query_type == QTYPE_SVCB && domain.len() > 4 && domain[..5].eq_ignore_ascii_case("_dns.") {
            return response(request, ResponseCode::NoError, Vec::new()).map(Some);
        }
        let rules = self.rules.read().unwrap().clone();
        let mut start = 0;
        loop {
            let mut metadata = Self::base_metadata(&domain, options);
            metadata.query_type = Some(query_type);
            metadata.ip_version = ip_version_of(query_type);
            let (selection, index) =
                self.match_rules(&rules, &mut metadata, start, is_address_query(query_type), options);
            let (server, strategy, disable_cache) = match selection {
                Selection::Server { server, strategy, disable_cache } => (server, strategy, disable_cache),
                Selection::Reject(RejectMethod::Drop) => return Ok(None),
                Selection::Reject(_) => return response(request, ResponseCode::Refused, Vec::new()).map(Some),
            };
            let check = index.filter(|index| rules.legacy && rules.rules[*index].matcher.with_address_limit());
            let (result, addresses) = self
                .exchange_with_server(
                    request,
                    &question,
                    &domain,
                    query_type,
                    &server,
                    strategy,
                    disable_cache,
                    options,
                )
                .await?;
            if let Some(index) = check {
                if !rules.rules[index].matcher.match_address_limit(&metadata, &addresses) {
                    tracing::debug!(domain, "dns: response rejected, trying the next rule");
                    start = index + 1;
                    continue;
                }
            }
            return Ok(result);
        }
    }

    /// Exchanges `request` with one server, returning the response and the
    /// addresses of a successful one (for the address limit).
    #[allow(clippy::too_many_arguments)]
    async fn exchange_with_server(
        &self,
        request: &Message,
        question: &hickory_proto::op::Query,
        domain: &str,
        query_type: u16,
        server: &str,
        strategy: DomainStrategy,
        disable_cache: bool,
        options: &LookupOptions,
    ) -> io::Result<(Option<Vec<u8>>, Vec<IpAddr>)> {
        if query_type == QTYPE_A || query_type == QTYPE_AAAA {
            let strategy = if strategy != DomainStrategy::AsIs { strategy } else { self.strategy };
            // A strategy that rules this type out answers with no records.
            if !strategy_allows(strategy, query_type) {
                return Ok((Some(response(request, ResponseCode::NoError, Vec::new())?), Vec::new()));
            }
            return match self.query_server(server, disable_cache, domain, query_type, options).await {
                Ok(answer) => {
                    let records = answer
                        .addresses
                        .iter()
                        .filter_map(|address| match address {
                            IpAddr::V4(ip) if query_type == QTYPE_A => Some(RData::A((*ip).into())),
                            IpAddr::V6(ip) if query_type == QTYPE_AAAA => Some(RData::AAAA((*ip).into())),
                            _ => None,
                        })
                        .map(|data| Record::from_rdata(question.name().clone(), answer.ttl, data))
                        .collect();
                    Ok((Some(response(request, ResponseCode::NoError, records)?), answer.addresses))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    Ok((Some(response(request, ResponseCode::NXDomain, Vec::new())?), Vec::new()))
                }
                Err(error) => {
                    tracing::debug!(domain, %error, "dns: exchange failed");
                    Ok((Some(response(request, ResponseCode::ServFail, Vec::new())?), Vec::new()))
                }
            };
        }
        let transport = self.transport(server)?;
        let timeout = options.timeout.unwrap_or(self.timeout);
        let raw = request.to_vec().map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        match tokio::time::timeout(timeout, transport.exchange(&raw, timeout)).await {
            Ok(Ok(Some(answer))) => {
                let addresses = response_addresses(&answer);
                Ok((Some(answer), addresses))
            }
            // The local resolver only knows addresses.
            Ok(Ok(None)) => Ok((Some(response(request, ResponseCode::NotImp, Vec::new())?), Vec::new())),
            Ok(Err(error)) => {
                tracing::debug!(domain, %error, "dns: exchange failed");
                Ok((Some(response(request, ResponseCode::ServFail, Vec::new())?), Vec::new()))
            }
            Err(_) => Ok((Some(response(request, ResponseCode::ServFail, Vec::new())?), Vec::new())),
        }
    }
}

/// `DNSResponseAddresses`: the A and AAAA answers of a successful response.
fn response_addresses(message: &[u8]) -> Vec<IpAddr> {
    let Ok(message) = Message::from_vec(message) else { return Vec::new() };
    if message.response_code() != ResponseCode::NoError {
        return Vec::new();
    }
    message
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        })
        .collect()
}

fn reject_error(domain: &str, method: RejectMethod) -> io::Error {
    let kind = if method == RejectMethod::Drop { io::ErrorKind::TimedOut } else { io::ErrorKind::ConnectionRefused };
    io::Error::new(kind, format!("{domain}: rejected by DNS rule"))
}

/// The A and AAAA results of a lookup: an error only when both gave no
/// address, IPv6 first with `prefer_ipv6` (`sortAddresses`).
fn combine(
    domain: &str,
    a: Option<io::Result<Vec<IpAddr>>>,
    aaaa: Option<io::Result<Vec<IpAddr>>>,
    strategy: DomainStrategy,
) -> io::Result<Vec<IpAddr>> {
    let mut last_error = None;
    let mut take = |result: Option<io::Result<Vec<IpAddr>>>| match result {
        Some(Ok(addresses)) => addresses,
        Some(Err(error)) => {
            last_error = Some(error);
            Vec::new()
        }
        None => Vec::new(),
    };
    let v4 = take(a);
    let v6 = take(aaaa);
    if v4.is_empty() && v6.is_empty() {
        return Err(
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{domain}: no addresses")))
        );
    }
    let mut addresses = if strategy == DomainStrategy::PreferIpv6 { [v6, v4].concat() } else { [v4, v6].concat() };
    addresses = apply_strategy(addresses, strategy);
    Ok(addresses)
}

/// A response to `request` with `code` and `answers`.
fn response(request: &Message, code: ResponseCode, answers: Vec<Record>) -> io::Result<Vec<u8>> {
    let mut message = Message::new();
    message
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(request.op_code())
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(code);
    message.add_queries(request.queries().to_vec());
    message.add_answers(answers);
    message.to_vec().map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn port_or_default(port: u16) -> u16 {
    if port == 0 {
        53
    } else {
        port
    }
}

fn port_or_default_dot(port: u16) -> u16 {
    if port == 0 {
        853
    } else {
        port
    }
}

fn port_or_default_https(port: u16) -> u16 {
    if port == 0 {
        443
    } else {
        port
    }
}

#[async_trait]
impl DnsResolver for DnsRouter {
    async fn lookup(&self, domain: &str, options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = domain.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let rules = self.rules.read().unwrap().clone();
        let strategy = if options.strategy != DomainStrategy::AsIs { options.strategy } else { self.strategy };
        if let Some(server) = &options.server {
            return self.lookup_server(&rules, None, server, options.disable_cache, &domain, strategy, options).await;
        }
        if rules.legacy {
            return self.lookup_legacy(&rules, &domain, options).await;
        }
        let (a, aaaa) = match strategy {
            DomainStrategy::Ipv4Only => (Some(self.lookup_type(&rules, &domain, QTYPE_A, options).await), None),
            DomainStrategy::Ipv6Only => (None, Some(self.lookup_type(&rules, &domain, QTYPE_AAAA, options).await)),
            _ => {
                let (a, aaaa) = tokio::join!(
                    self.lookup_type(&rules, &domain, QTYPE_A, options),
                    self.lookup_type(&rules, &domain, QTYPE_AAAA, options)
                );
                (Some(a), Some(aaaa))
            }
        };
        combine(&domain, a, aaaa, strategy)
    }

    async fn exchange(&self, query: &[u8], options: &LookupOptions) -> io::Result<Option<Vec<u8>>> {
        let request =
            Message::from_vec(query).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        if request.message_type() != MessageType::Query {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a DNS query"));
        }
        self.exchange_message(&request, options).await
    }

    fn reverse_lookup(&self, address: IpAddr) -> io::Result<Option<String>> {
        DnsRouter::reverse_lookup(self, address)
    }
}

#[cfg(test)]
mod tests;
