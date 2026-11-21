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
use rb_adapter::{apply_strategy, DnsResolver, LookupOptions};
use rb_config::{DnsOptions, DnsRuleAction, DnsServer, DomainStrategy, RejectMethod};
use rb_rule::{compile, compile_dns_match, Compiled, Metadata};

pub use transport::{Answer, Transport, QTYPE_A, QTYPE_AAAA};

/// sing-box `C.DNSTimeout`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// sing-box default `cache_capacity`.
const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// (server tag, domain, query type)
type CacheKey = (String, String, u16);

struct Cache {
    entries: HashMap<CacheKey, (Vec<IpAddr>, Option<Instant>)>,
    capacity: usize,
    disable_expire: bool,
}

impl Cache {
    fn get(&mut self, key: &CacheKey) -> Option<Vec<IpAddr>> {
        let (addresses, expires) = self.entries.get(key)?;
        if let Some(expires) = expires {
            if *expires <= Instant::now() {
                self.entries.remove(key);
                return None;
            }
        }
        Some(addresses.clone())
    }

    fn put(&mut self, key: CacheKey, addresses: Vec<IpAddr>, ttl: u32) {
        if ttl == 0 && !self.disable_expire {
            return;
        }
        if self.entries.len() >= self.capacity {
            let now = Instant::now();
            self.entries.retain(|_, (_, expires)| expires.is_none_or(|expires| expires > now));
            if self.entries.len() >= self.capacity {
                if let Some(victim) = self.entries.keys().next().cloned() {
                    self.entries.remove(&victim);
                }
            }
        }
        let expires = (!self.disable_expire).then(|| Instant::now() + Duration::from_secs(u64::from(ttl)));
        self.entries.insert(key, (addresses, expires));
    }
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
    pub fn new(options: &DnsOptions) -> Result<Self, DnsError> {
        let mut servers = HashMap::new();
        let mut first = None;
        for (index, server) in options.servers.iter().enumerate() {
            let tag = if server.tag().is_empty() { index.to_string() } else { server.tag().to_string() };
            let transport = match server {
                DnsServer::Local { .. } => Transport::Local,
                DnsServer::Udp(remote) => Transport::Udp((remote.server, port_or_default(remote.server_port)).into()),
                DnsServer::Tcp(remote) => Transport::Tcp((remote.server, port_or_default(remote.server_port)).into()),
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
    fn select(
        &self,
        domain: &str,
        query_type: u16,
        options: &LookupOptions,
    ) -> io::Result<(String, DomainStrategy, bool)> {
        if let Some(server) = &options.server {
            return Ok((server.clone(), options.strategy, options.disable_cache));
        }
        let metadata = Metadata {
            inbound: options.inbound.as_deref().unwrap_or(""),
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
                    return Ok((server.clone(), strategy, *disable_cache || options.disable_cache));
                }
                Some(DnsRuleAction::Reject(reject)) => {
                    tracing::debug!(domain, rule = index, "dns: reject");
                    let kind = if reject.method == RejectMethod::Drop {
                        io::ErrorKind::TimedOut
                    } else {
                        io::ErrorKind::ConnectionRefused
                    };
                    return Err(io::Error::new(kind, format!("{domain}: rejected by DNS rule")));
                }
                None => {}
            }
        }
        Ok((self.final_server.clone(), options.strategy, options.disable_cache))
    }

    async fn query(
        &self,
        domain: &str,
        query_type: u16,
        options: &LookupOptions,
    ) -> io::Result<(Vec<IpAddr>, DomainStrategy)> {
        let (server, strategy, disable_cache) = self.select(domain, query_type, options)?;
        let transport = self
            .servers
            .get(&server)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("DNS server not found: {server}")))?;
        let strategy = if strategy != DomainStrategy::AsIs { strategy } else { self.strategy };
        let key = (server.clone(), domain.to_string(), query_type);
        if !disable_cache {
            if let Some(cache) = &self.cache {
                if let Some(addresses) = cache.lock().unwrap().get(&key) {
                    return Ok((addresses, strategy));
                }
            }
        }
        let timeout = options.timeout.unwrap_or(self.timeout);
        let answer = tokio::time::timeout(timeout, transport.query(domain, query_type, timeout))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{domain}: DNS query timed out")))??;
        if !disable_cache {
            if let Some(cache) = &self.cache {
                cache.lock().unwrap().put(key, answer.addresses.clone(), answer.ttl);
            }
        }
        Ok((answer.addresses, strategy))
    }
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
}

#[cfg(test)]
mod tests;
