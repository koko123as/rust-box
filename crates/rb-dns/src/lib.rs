//! DNS, mirroring sing-box `dns/`: transports (`dns/transport/{udp,tcp}`,
//! `dns/transport/local`), the DNS router with its rules (`dns/router.go`)
//! and the response cache (`dns/client.go`).

mod transport;

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, Record};
use rb_adapter::{apply_strategy, DnsResolver, LookupOptions, OutboundRegistry};
use rb_config::{DnsOptions, DnsRuleAction, DnsServer, DomainStrategy, RejectMethod};
use rb_dialer::NetworkDefaults;
use rb_rule::{compile, compile_dns_match, Compiled, Metadata};

pub use transport::{Answer, Transport, QTYPE_A, QTYPE_AAAA};

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

/// The DNS router (sing-box `dns.Router` + `dns.Client`).
pub struct DnsRouter {
    servers: HashMap<String, Arc<Transport>>,
    rules: Vec<Compiled<DnsRuleAction>>,
    final_server: String,
    strategy: DomainStrategy,
    timeout: Duration,
    cache: Option<Mutex<Cache>>,
}

#[derive(Debug)]
pub struct DnsError(pub String);

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DnsError {}

impl DnsRouter {
    /// `defaults` are the route-level dial defaults and `outbounds` the
    /// handle a server's `detour` dials through (filled once the outbounds
    /// are built).
    pub fn new(
        options: &DnsOptions,
        defaults: &NetworkDefaults,
        outbounds: &Arc<OutboundRegistry>,
    ) -> Result<Self, DnsError> {
        let mut servers = HashMap::new();
        let mut first = None;
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
        let rules = options
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                compile(rule, &compile_dns_match).map_err(|error| DnsError(format!("dns.rules[{index}]: {error}")))
            })
            .collect::<Result<_, _>>()?;
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
        Ok(DnsRouter { servers, rules, final_server, strategy: options.strategy, timeout, cache })
    }

    /// Picks the server for one query: the first matching rule's, else
    /// `dns.final` (sing-box `Router.matchDNS`).
    fn select(&self, domain: &str, query_type: u16, options: &LookupOptions) -> Selection {
        if let Some(server) = &options.server {
            return Selection::Server {
                server: server.clone(),
                strategy: options.strategy,
                disable_cache: options.disable_cache,
            };
        }
        let metadata = Metadata {
            inbound: options.inbound.as_deref().unwrap_or(""),
            network: options.network.map(|network| network.as_str()),
            user: options.user.as_deref(),
            source: options.source,
            domain: Some(domain),
            query_type: Some(query_type),
            ..Default::default()
        };
        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.matches(&metadata) {
                continue;
            }
            match rule.action() {
                Some(DnsRuleAction::Route { server, strategy, disable_cache }) => {
                    tracing::debug!(domain, rule = index, server, "dns: match");
                    let strategy = if *strategy != DomainStrategy::AsIs { *strategy } else { options.strategy };
                    return Selection::Server {
                        server: server.clone(),
                        strategy,
                        disable_cache: *disable_cache || options.disable_cache,
                    };
                }
                Some(DnsRuleAction::Reject(reject)) => {
                    tracing::debug!(domain, rule = index, "dns: reject");
                    return Selection::Reject(reject.method);
                }
                None => {}
            }
        }
        Selection::Server {
            server: self.final_server.clone(),
            strategy: options.strategy,
            disable_cache: options.disable_cache,
        }
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

    async fn query(
        &self,
        domain: &str,
        query_type: u16,
        options: &LookupOptions,
    ) -> io::Result<(Vec<IpAddr>, DomainStrategy)> {
        let (server, strategy, disable_cache) = match self.select(domain, query_type, options) {
            Selection::Server { server, strategy, disable_cache } => (server, strategy, disable_cache),
            Selection::Reject(method) => {
                let kind = if method == RejectMethod::Drop {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::ConnectionRefused
                };
                return Err(io::Error::new(kind, format!("{domain}: rejected by DNS rule")));
            }
        };
        let strategy = if strategy != DomainStrategy::AsIs { strategy } else { self.strategy };
        let answer = self.query_server(&server, disable_cache, domain, query_type, options).await?;
        Ok((answer.addresses, strategy))
    }

    /// Answers one query message (sing-box `dns.Router.Exchange`).
    ///
    /// A and AAAA questions go through the same path as lookups (rules,
    /// strategy, cache) and the answer is built from the addresses; other
    /// types are forwarded as they are to the selected `udp`/`tcp` server.
    async fn exchange_message(&self, request: &Message, options: &LookupOptions) -> io::Result<Option<Vec<u8>>> {
        let Some(question) = request.queries().first().cloned() else {
            return response(request, ResponseCode::FormErr, Vec::new()).map(Some);
        };
        let domain = question.name().to_ascii().trim_end_matches('.').to_ascii_lowercase();
        let query_type = u16::from(question.query_type());
        let (server, strategy, disable_cache) = match self.select(&domain, query_type, options) {
            Selection::Server { server, strategy, disable_cache } => (server, strategy, disable_cache),
            Selection::Reject(RejectMethod::Drop) => return Ok(None),
            Selection::Reject(_) => return response(request, ResponseCode::Refused, Vec::new()).map(Some),
        };
        if query_type == QTYPE_A || query_type == QTYPE_AAAA {
            let strategy = if strategy != DomainStrategy::AsIs { strategy } else { self.strategy };
            // A strategy that rules this type out answers with no records.
            if (strategy == DomainStrategy::Ipv4Only && query_type == QTYPE_AAAA)
                || (strategy == DomainStrategy::Ipv6Only && query_type == QTYPE_A)
            {
                return response(request, ResponseCode::NoError, Vec::new()).map(Some);
            }
            return match self.query_server(&server, disable_cache, &domain, query_type, options).await {
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
                    response(request, ResponseCode::NoError, records).map(Some)
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    response(request, ResponseCode::NXDomain, Vec::new()).map(Some)
                }
                Err(error) => {
                    tracing::debug!(domain, %error, "dns: exchange failed");
                    response(request, ResponseCode::ServFail, Vec::new()).map(Some)
                }
            };
        }
        let transport = self.transport(&server)?;
        let timeout = options.timeout.unwrap_or(self.timeout);
        let raw = request.to_vec().map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        match tokio::time::timeout(timeout, transport.exchange(&raw, timeout)).await {
            Ok(Ok(Some(answer))) => Ok(Some(answer)),
            // The local resolver only knows addresses.
            Ok(Ok(None)) => response(request, ResponseCode::NotImp, Vec::new()).map(Some),
            Ok(Err(error)) => {
                tracing::debug!(domain, %error, "dns: exchange failed");
                response(request, ResponseCode::ServFail, Vec::new()).map(Some)
            }
            Err(_) => response(request, ResponseCode::ServFail, Vec::new()).map(Some),
        }
    }
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

#[async_trait]
impl DnsResolver for DnsRouter {
    async fn lookup(&self, domain: &str, options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = domain.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        // The strategy that decides which types to ask for is the lookup's,
        // else the default one; a rule's own strategy then filters the answer.
        let wanted = if options.strategy != DomainStrategy::AsIs { options.strategy } else { self.strategy };
        let (a, aaaa) = match wanted {
            DomainStrategy::Ipv4Only => (Some(self.query(&domain, QTYPE_A, options).await), None),
            DomainStrategy::Ipv6Only => (None, Some(self.query(&domain, QTYPE_AAAA, options).await)),
            _ => {
                let (a, aaaa) =
                    tokio::join!(self.query(&domain, QTYPE_A, options), self.query(&domain, QTYPE_AAAA, options));
                (Some(a), Some(aaaa))
            }
        };
        let mut addresses = Vec::new();
        let mut strategy = wanted;
        let mut last_error = None;
        for result in [a, aaaa].into_iter().flatten() {
            match result {
                Ok((found, rule_strategy)) => {
                    addresses.extend(found);
                    if rule_strategy != DomainStrategy::AsIs {
                        strategy = rule_strategy;
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }
        let addresses = apply_strategy(addresses, strategy);
        if addresses.is_empty() {
            return Err(last_error
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{domain}: no addresses"))));
        }
        Ok(addresses)
    }

    async fn exchange(&self, query: &[u8], options: &LookupOptions) -> io::Result<Option<Vec<u8>>> {
        let request =
            Message::from_vec(query).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        if request.message_type() != MessageType::Query {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a DNS query"));
        }
        self.exchange_message(&request, options).await
    }
}

#[cfg(test)]
mod tests;
