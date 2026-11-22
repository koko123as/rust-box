//! Pre-matching (sing-box `Router.PreMatch`): what the `tun` inbound asks
//! about a new flow before its stack accepts it, so that `reject`, `drop`
//! and `hijack-dns` act on the first packet, as sing-tun's `JudgeFlow`.
//!
//! The walk stops at the first rule whose action needs the connection
//! itself; rust-box has no flow outbounds (WireGuard-like endpoints that
//! take raw packets), so a `route` match always continues to normal routing.

use rb_adapter::{InboundContext, LookupOptions, Network};
use rb_config::{RejectMethod, RuleAction};
use tracing::debug;

use crate::{apply_route_options, metadata, sniff, sniffer_names, Router, PACKET_SNIFFERS};

/// The result of pre-matching (sing-box `adapter.PreMatchAction`, without
/// the flow actions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreMatch {
    /// Accept the flow and route it as usual.
    Continue,
    /// Refuse it (a reset, an ICMP unreachable).
    Reject,
    /// Drop it silently.
    Drop,
    /// Answer the UDP packet as a DNS query.
    HijackDns,
    /// `bypass` matched; without `auto_redirect` this routes it as usual.
    Bypass,
}

impl Router {
    /// Pre-matches a new TUN flow. `first_packet` is the first UDP payload
    /// (empty for TCP).
    pub async fn pre_match(&self, mut context: InboundContext, first_packet: &[u8]) -> PreMatch {
        let packet_destination = context.destination.clone();
        if self.reverse_fakeip(&mut context).is_err() {
            return PreMatch::Continue;
        }
        let mut last_sniffers: Option<&[String]> = None;
        for (index, rule) in self.rules.iter().enumerate() {
            let matched = {
                let mut metadata = metadata(&context);
                rule.matches(&mut metadata)
            };
            if !matched {
                continue;
            }
            let Some(action) = rule.action() else { continue };
            debug!(rule = index, "pre-match");
            match action {
                RuleAction::Sniff { sniffer, .. } => {
                    if context.network != Network::Udp || first_packet.is_empty() {
                        return PreMatch::Continue;
                    }
                    if sniff::skip_port(context.destination.port) || context.protocol.is_some() {
                        continue;
                    }
                    let names = sniffer_names(sniffer, PACKET_SNIFFERS);
                    if names.is_empty() || last_sniffers == Some(sniffer.as_slice()) {
                        continue;
                    }
                    last_sniffers = Some(sniffer.as_slice());
                    let mut need_more = false;
                    let mut found = None;
                    for name in names {
                        match sniff::sniff_packet(name, first_packet) {
                            sniff::Verdict::Found(sniffed) => {
                                found = Some(sniffed);
                                break;
                            }
                            sniff::Verdict::NeedMore => need_more = true,
                            sniff::Verdict::NotThis => {}
                        }
                    }
                    match found {
                        Some(sniffed) => {
                            context.protocol = Some(sniffed.protocol.to_string());
                            context.sniff_host = sniffed.domain;
                        }
                        None if need_more => return PreMatch::Continue,
                        None => {}
                    }
                }
                RuleAction::RouteOptions(options) => apply_route_options(&mut context, options),
                RuleAction::Route { .. } => return PreMatch::Continue,
                RuleAction::Bypass { options, .. } => {
                    apply_route_options(&mut context, options);
                    if context.destination.domain().is_some() || context.destination != packet_destination {
                        return PreMatch::Continue;
                    }
                    return PreMatch::Bypass;
                }
                RuleAction::Reject(reject) => {
                    return if reject.method == RejectMethod::Drop { PreMatch::Drop } else { PreMatch::Reject };
                }
                RuleAction::HijackDns => {
                    return if context.network == Network::Udp { PreMatch::HijackDns } else { PreMatch::Continue };
                }
                RuleAction::Resolve { server, strategy, disable_cache } => {
                    let Some(domain) = context.destination.domain().map(str::to_string) else { continue };
                    let options = LookupOptions {
                        server: (!server.is_empty()).then(|| server.clone()),
                        strategy: *strategy,
                        disable_cache: *disable_cache,
                        ..LookupOptions::for_context(&context)
                    };
                    match self.dns.lookup(&domain, &options).await {
                        Ok(addresses) => context.destination_addresses = addresses,
                        Err(error) => {
                            debug!(rule = index, %error, "pre-match: resolve failed");
                            return PreMatch::Reject;
                        }
                    }
                }
            }
        }
        PreMatch::Continue
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    use async_trait::async_trait;
    use rb_adapter::{BoxStream, DnsResolver, InboundContext, LookupOptions, Network, Outbound};
    use rb_config::RouteOptions;

    use super::PreMatch;
    use crate::Router;

    struct Fake;

    #[async_trait]
    impl Outbound for Fake {
        fn tag(&self) -> &str {
            "direct"
        }
        fn kind(&self) -> &'static str {
            "direct"
        }
        async fn dial_tcp(&self, _context: &InboundContext) -> io::Result<BoxStream> {
            Err(io::Error::other("fake"))
        }
    }

    #[async_trait]
    impl DnsResolver for Fake {
        async fn lookup(&self, domain: &str, _options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
            if domain == "fail.test" {
                return Err(io::Error::other("no such host"));
            }
            Ok(vec!["10.0.0.7".parse().unwrap()])
        }
    }

    fn router(rules: &str) -> Router {
        let options: RouteOptions = serde_json::from_str(&format!(r#"{{"rules":{rules}}}"#)).unwrap();
        Router::new(
            &options,
            vec![Arc::new(Fake)],
            Arc::new(Fake),
            rb_adapter::InboundRegistry::new(),
            &Default::default(),
        )
        .unwrap()
    }

    fn context(network: Network, destination: &str) -> InboundContext {
        let destination: SocketAddr = destination.parse().unwrap();
        InboundContext::new("tun-in", "tun", network, "172.19.0.1:40000".parse().unwrap(), destination.into())
    }

    #[tokio::test]
    async fn actions() {
        let router = router(
            r#"[{"port":1,"action":"reject"},{"port":2,"action":"reject","method":"drop"},
                {"port":53,"action":"hijack-dns"},{"port":3,"action":"bypass"},
                {"port":4,"action":"route-options","override_port":5},{"port":4,"action":"bypass"},
                {"port":6,"action":"route","outbound":"direct"},{"port":6,"action":"reject"},
                {"port":7,"action":"sniff"},{"port":7,"protocol":"dns","action":"reject"}]"#,
        );
        let check = |network, destination: &'static str, expected| {
            let router = &router;
            async move {
                assert_eq!(router.pre_match(context(network, destination), &[]).await, expected, "{destination}");
            }
        };
        check(Network::Tcp, "1.1.1.1:1", PreMatch::Reject).await;
        check(Network::Udp, "1.1.1.1:2", PreMatch::Drop).await;
        check(Network::Udp, "1.1.1.1:53", PreMatch::HijackDns).await;
        // hijack-dns only pre-matches UDP.
        check(Network::Tcp, "1.1.1.1:53", PreMatch::Continue).await;
        check(Network::Tcp, "1.1.1.1:3", PreMatch::Bypass).await;
        // A bypass after the destination changed goes on to routing.
        check(Network::Tcp, "1.1.1.1:4", PreMatch::Continue).await;
        check(Network::Tcp, "1.1.1.1:6", PreMatch::Continue).await;
        check(Network::Tcp, "1.1.1.1:8", PreMatch::Continue).await;
        // TCP sniffing needs the connection: the pre-match stops there.
        check(Network::Tcp, "1.1.1.1:7", PreMatch::Continue).await;
        // A UDP first packet is sniffed.
        let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        assert_eq!(router.pre_match(context(Network::Udp, "1.1.1.1:7"), &query).await, PreMatch::Reject);
        assert_eq!(router.pre_match(context(Network::Udp, "1.1.1.1:7"), b"nothing").await, PreMatch::Continue);
    }

    #[tokio::test]
    async fn resolve_failure_rejects() {
        let router = router(r#"[{"action":"resolve"},{"ip_cidr":"10.0.0.7/32","action":"reject"}]"#);
        let mut ok = context(Network::Tcp, "1.1.1.1:80");
        ok.destination = rb_adapter::Socksaddr::from_host_port("ok.test", 80);
        assert_eq!(router.pre_match(ok, &[]).await, PreMatch::Reject);
        let mut fail = context(Network::Tcp, "1.1.1.1:80");
        fail.destination = rb_adapter::Socksaddr::from_host_port("fail.test", 80);
        assert_eq!(router.pre_match(fail, &[]).await, PreMatch::Reject);
        let router = router_plain();
        assert_eq!(router.pre_match(context(Network::Udp, "8.8.8.8:443"), b"x").await, PreMatch::Continue);
    }

    fn router_plain() -> Router {
        router("[]")
    }
}
