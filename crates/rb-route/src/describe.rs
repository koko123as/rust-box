//! Route actions as sing-box prints them (`RuleAction.String()`), for the
//! Clash API's rule and connection lists.

use std::time::Duration;

use rb_config::{DomainStrategy, NetworkStrategy, RejectMethod, RouteActionOptions, RuleAction};

/// Go's `time.Duration.String`.
pub fn go_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos == 0 {
        return "0s".into();
    }
    // Fractions are printed without trailing zeros.
    fn fraction(value: u128, digits: u32) -> String {
        let unit = 10u128.pow(digits);
        let (whole, rest) = (value / unit, value % unit);
        if rest == 0 {
            return whole.to_string();
        }
        let rest = format!("{rest:0width$}", width = digits as usize);
        format!("{whole}.{}", rest.trim_end_matches('0'))
    }
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return format!("{}µs", fraction(nanos, 3));
    }
    if nanos < 1_000_000_000 {
        return format!("{}ms", fraction(nanos, 6));
    }
    let mut out = String::new();
    let total_seconds = nanos / 1_000_000_000;
    let hours = total_seconds / 3600;
    let minutes = (total_seconds / 60) % 60;
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if hours > 0 || minutes > 0 {
        out.push_str(&format!("{minutes}m"));
    }
    let seconds = nanos % 60_000_000_000;
    out.push_str(&format!("{}s", fraction(seconds, 9)));
    out
}

fn strategy_name(strategy: DomainStrategy) -> &'static str {
    match strategy {
        DomainStrategy::AsIs => "",
        DomainStrategy::PreferIpv4 => "prefer_ipv4",
        DomainStrategy::PreferIpv6 => "prefer_ipv6",
        DomainStrategy::Ipv4Only => "ipv4_only",
        DomainStrategy::Ipv6Only => "ipv6_only",
    }
}

/// `RuleActionRouteOptions.Descriptions`.
fn route_option_descriptions(options: &RouteActionOptions) -> Vec<String> {
    let mut descriptions = Vec::new();
    if !options.override_address.is_empty() {
        descriptions.push(format!("override-address={}", options.override_address));
    }
    if options.override_port > 0 {
        descriptions.push(format!("override-port={}", options.override_port));
    }
    if let Some(strategy) = options.network_strategy {
        let name = match strategy {
            NetworkStrategy::Default => "default",
            NetworkStrategy::Hybrid => "hybrid",
            NetworkStrategy::Fallback => "fallback",
        };
        descriptions.push(format!("network-strategy={name}"));
    }
    if options.fallback_delay > 0 {
        descriptions
            .push(format!("fallback-delay={}", go_duration(Duration::from_nanos(options.fallback_delay.into()))));
    }
    if options.udp_disable_domain_unmapping {
        descriptions.push("udp-disable-domain-unmapping".into());
    }
    if options.udp_connect {
        descriptions.push("udp-connect".into());
    }
    if !options.udp_timeout.0.is_zero() {
        descriptions.push("udp-timeout".into());
    }
    if options.tls_fragment {
        descriptions.push("tls-fragment".into());
    }
    if !options.tls_fragment_fallback_delay.0.is_zero() {
        descriptions
            .push(format!("tls-fragment-fallback-delay={}", go_duration(options.tls_fragment_fallback_delay.0)));
    }
    if options.tls_record_fragment {
        descriptions.push("tls-record-fragment".into());
    }
    descriptions
}

/// `RuleAction.String()` of a route rule's action.
pub fn describe_action(action: &RuleAction) -> String {
    match action {
        RuleAction::Route { outbound, options } => {
            let mut descriptions = vec![outbound.clone()];
            descriptions.extend(route_option_descriptions(options));
            format!("route({})", descriptions.join(","))
        }
        RuleAction::Bypass { outbound, options } => {
            if outbound.is_empty() {
                return "bypass()".into();
            }
            let mut descriptions = vec![outbound.clone()];
            descriptions.extend(route_option_descriptions(options));
            format!("bypass({})", descriptions.join(","))
        }
        RuleAction::RouteOptions(options) => format!("route-options({})", route_option_descriptions(options).join(",")),
        RuleAction::Reject(reject) => match reject.method {
            RejectMethod::Default => "reject".into(),
            RejectMethod::Drop => "reject(drop)".into(),
        },
        RuleAction::HijackDns => "hijack-dns".into(),
        RuleAction::Sniff { sniffer, timeout } => match (sniffer.is_empty(), timeout.0.is_zero()) {
            (true, true) => "sniff".into(),
            (false, true) => format!("sniff({})", sniffer.join(",")),
            (true, false) => format!("sniff({})", go_duration(timeout.0)),
            (false, false) => format!("sniff({},{})", sniffer.join(","), go_duration(timeout.0)),
        },
        RuleAction::Resolve { server, strategy, disable_cache } => {
            let mut options = Vec::new();
            if !server.is_empty() {
                options.push(server.clone());
            }
            if *strategy != DomainStrategy::AsIs {
                options.push(strategy_name(*strategy).to_string());
            }
            if *disable_cache {
                options.push("disable_cache".into());
            }
            if options.is_empty() {
                "resolve".into()
            } else {
                format!("resolve({})", options.join(","))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_durations() {
        for (duration, text) in [
            (Duration::ZERO, "0s"),
            (Duration::from_nanos(15), "15ns"),
            (Duration::from_nanos(1500), "1.5µs"),
            (Duration::from_millis(300), "300ms"),
            (Duration::from_micros(1_500), "1.5ms"),
            (Duration::from_secs(5), "5s"),
            (Duration::from_millis(1_500), "1.5s"),
            (Duration::from_secs(90), "1m30s"),
            (Duration::from_secs(3600), "1h0m0s"),
            (Duration::from_secs(3723), "1h2m3s"),
        ] {
            assert_eq!(go_duration(duration), text);
        }
    }
}
