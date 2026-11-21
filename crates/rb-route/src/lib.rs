//! The router, mirroring sing-box `route/route.go` (`matchRule`,
//! `RouteConnectionEx`) and `route/conn.go` (`ConnectionManager`).

pub mod sniff;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{
    BoxStream, ConnectionRouter, DnsResolver, InboundContext, LookupOptions, Outbound, PrefixedStream, RouteError,
};
use rb_config::{RejectMethod, RouteOptions, RuleAction};
use rb_rule::{compile, compile_route_match, Compiled, Metadata};
use tokio::io::AsyncReadExt;
use tracing::{debug, info};

use sniff::{Sniffed, Verdict, SNIFFERS};

/// sing-box `C.ReadPayloadTimeout`, the default sniff timeout.
pub const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(300);

pub struct Router {
    rules: Vec<Compiled<RuleAction>>,
    outbounds: HashMap<String, Arc<dyn Outbound>>,
    final_outbound: String,
    dns: Arc<dyn DnsResolver>,
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
}

impl Router {
    /// `outbounds` in configuration order; the first one is the default when
    /// `route.final` is empty (sing-box `outbound.Manager`).
    pub fn new(
        options: &RouteOptions,
        outbounds: Vec<Arc<dyn Outbound>>,
        dns: Arc<dyn DnsResolver>,
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
                compile(rule, &compile_route_match)
                    .map_err(|error| RouterError(format!("route.rules[{index}]: {error}")))
            })
            .collect::<Result<_, _>>()?;
        let outbounds = outbounds.into_iter().map(|outbound| (outbound.tag().to_string(), outbound)).collect();
        Ok(Router { rules, outbounds, final_outbound, dns })
    }

    /// Walks the rules: `sniff` and `resolve` add to the context and go on,
    /// `route` and `reject` end the walk (sing-box `Router.matchRule`).
    pub async fn decide(
        &self,
        context: &mut InboundContext,
        client: &mut Option<BoxStream>,
    ) -> Result<Decision, RouteError> {
        let mut sniffed = false;
        for (index, rule) in self.rules.iter().enumerate() {
            let matched = {
                let metadata = metadata(context);
                rule.matches(&metadata)
            };
            if !matched {
                continue;
            }
            let Some(action) = rule.action() else { continue };
            match action {
                RuleAction::Route { outbound } => {
                    debug!(rule = index, outbound, "match");
                    return Ok(Decision::Route(outbound.clone()));
                }
                RuleAction::Reject(reject) => {
                    debug!(rule = index, "match: reject");
                    return Ok(Decision::Reject(reject.method));
                }
                RuleAction::Sniff { sniffer, timeout } => {
                    if sniffed {
                        continue;
                    }
                    sniffed = true;
                    if let Some(stream) = client.take() {
                        let timeout = if timeout.0.is_zero() { DEFAULT_SNIFF_TIMEOUT } else { timeout.0 };
                        let (stream, found) = sniff_stream(stream, sniffer, timeout).await;
                        *client = Some(stream);
                        if let Some(found) = found {
                            debug!(rule = index, protocol = found.protocol, domain = ?found.domain, "sniffed");
                            context.protocol = Some(found.protocol.to_string());
                            context.sniff_host = found.domain;
                        }
                    }
                }
                RuleAction::Resolve { server, strategy, disable_cache } => {
                    let Some(domain) = context.destination.domain().map(str::to_string) else { continue };
                    let options = LookupOptions {
                        server: (!server.is_empty()).then(|| server.clone()),
                        strategy: *strategy,
                        disable_cache: *disable_cache,
                        inbound: Some(context.inbound.clone()),
                        ..Default::default()
                    };
                    let addresses = self.dns.lookup(&domain, &options).await.map_err(RouteError::Resolve)?;
                    debug!(rule = index, domain, ?addresses, "resolved");
                    context.destination_addresses = addresses;
                }
            }
        }
        Ok(Decision::Route(self.final_outbound.clone()))
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
        query_type: None,
    }
}

/// Reads the client's first bytes until a sniffer decides or the timeout
/// passes, and gives the stream back with those bytes in front.
async fn sniff_stream(mut stream: BoxStream, sniffers: &[String], timeout: Duration) -> (BoxStream, Option<Sniffed>) {
    let names: Vec<&str> = if sniffers.is_empty() {
        SNIFFERS.to_vec()
    } else {
        sniffers.iter().map(String::as_str).filter(|name| SNIFFERS.contains(name)).collect()
    };
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
        for name in &names {
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

#[async_trait]
impl ConnectionRouter for Router {
    async fn route_connection(&self, mut context: InboundContext, client: BoxStream) -> Result<(), RouteError> {
        let mut client = Some(client);
        let decision = self.decide(&mut context, &mut client).await?;
        let mut client = client.expect("client stream is always given back");
        let tag = match decision {
            Decision::Route(tag) => tag,
            Decision::Reject(_) => {
                info!(inbound = %context.inbound, destination = %context.destination, "rejected");
                return Err(RouteError::Rejected);
            }
        };
        let outbound = self.outbounds.get(&tag).ok_or_else(|| {
            RouteError::Dial(io::Error::new(io::ErrorKind::NotFound, format!("outbound not found: {tag}")))
        })?;
        info!(
            "outbound/{}[{}]: outbound connection to {}",
            outbound.kind(),
            tag,
            context
                .sniff_host
                .as_ref()
                .map(|host| format!("{host}:{}", context.destination.port))
                .unwrap_or_else(|| context.destination.to_string())
        );
        let mut remote = outbound.dial_tcp(&context).await.map_err(RouteError::Dial)?;
        match tokio::io::copy_bidirectional(&mut client, &mut remote).await {
            Ok((up, down)) => debug!(destination = %context.destination, up, down, "connection closed"),
            Err(error) => debug!(destination = %context.destination, %error, "connection closed"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
