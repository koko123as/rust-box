//! The routes of sing-box `experimental/clashapi` (chi router, CORS,
//! secret authentication) and their handlers.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rb_adapter::{real_tag, HistoryStorage, LookupOptions, Network, Outbound, OutboundRegistry, UrlTestHistory};
use rb_cachefile::CacheFile;
use rb_certificate::Store;
use rb_config::ClashApiOptions;
use rb_dns::DnsRouter;
use rb_group::{url_test, url_test_outbounds, Selector, UrlTest};
use rb_route::Router;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::watch;
use tracing::{error, info};

use crate::http::{self, Request, Response};
use crate::log::{self as clash_log, format_level, parse_level, LEVEL_DEBUG, LEVEL_ERROR, LEVEL_TRACE};
use crate::mode::ModeManager;
use crate::traffic::TrafficManager;
use crate::util::go_json;
use crate::{ui, ApiParts};

/// sing-box `C.DNSTimeout`.
const DNS_TIMEOUT: Duration = Duration::from_secs(10);

/// The parsed `access_control_allow_origin` list (`cors.New`).
struct Cors {
    all: bool,
    exact: Vec<String>,
    wildcards: Vec<(String, String)>,
    private_network: bool,
}

const ALLOWED_METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const ALLOWED_HEADERS: [&str; 3] = ["Content-Type", "Authorization", "Origin"];

/// `http.CanonicalHeaderKey`.
fn canonical(header: &str) -> String {
    let mut upper = true;
    header
        .chars()
        .map(|character| {
            let out = if upper { character.to_ascii_uppercase() } else { character.to_ascii_lowercase() };
            upper = character == '-';
            out
        })
        .collect()
}

/// `parseHeaderList`.
fn parse_header_list(list: &str) -> Vec<String> {
    let mut headers = Vec::new();
    let mut current = String::new();
    let mut upper = true;
    let bytes = list.as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        if byte.is_ascii_lowercase() {
            current.push(if upper { byte.to_ascii_uppercase() } else { byte } as char);
        } else if byte.is_ascii_uppercase() {
            current.push(if upper { byte } else { byte.to_ascii_lowercase() } as char);
        } else if byte == b'-' || byte == b'_' || byte == b'.' || byte.is_ascii_digit() {
            current.push(byte as char);
        }
        if byte == b' ' || byte == b',' || index == bytes.len() - 1 {
            if !current.is_empty() {
                headers.push(std::mem::take(&mut current));
                upper = true;
            }
        } else {
            upper = byte == b'-';
        }
    }
    headers
}

impl Cors {
    fn new(origins: &[String], private_network: bool) -> Self {
        let origins: Vec<String> = if origins.is_empty() { vec!["*".into()] } else { origins.to_vec() };
        let mut cors = Cors { all: false, exact: Vec::new(), wildcards: Vec::new(), private_network };
        for origin in origins {
            let origin = origin.to_lowercase();
            if origin == "*" {
                cors.all = true;
                cors.exact.clear();
                cors.wildcards.clear();
                break;
            } else if let Some(index) = origin.find('*') {
                cors.wildcards.push((origin[..index].to_string(), origin[index + 1..].to_string()));
            } else {
                cors.exact.push(origin);
            }
        }
        cors
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        if self.all {
            return true;
        }
        let origin = origin.to_lowercase();
        self.exact.contains(&origin)
            || self.wildcards.iter().any(|(prefix, suffix)| {
                origin.len() >= prefix.len() + suffix.len() && origin.starts_with(prefix) && origin.ends_with(suffix)
            })
    }

    fn method_allowed(method: &str) -> bool {
        let method = method.to_uppercase();
        method == "OPTIONS" || ALLOWED_METHODS.contains(&method.as_str())
    }

    fn allow_origin(&self, origin: &str) -> String {
        if self.all {
            "*".into()
        } else {
            origin.to_string()
        }
    }

    /// `handlePreflight`.
    fn preflight(&self, request: &Request) -> Response {
        let mut response = Response::new(200);
        response.add("Vary", "Origin");
        response.add("Vary", "Access-Control-Request-Method");
        response.add("Vary", "Access-Control-Request-Headers");
        let origin = request.header("Origin");
        if origin.is_empty() || !self.origin_allowed(origin) {
            return response;
        }
        let method = request.header("Access-Control-Request-Method");
        if !Self::method_allowed(method) {
            return response;
        }
        let headers = parse_header_list(request.header("Access-Control-Request-Headers"));
        if !headers.iter().all(|header| ALLOWED_HEADERS.contains(&canonical(header).as_str())) {
            return response;
        }
        response.set("Access-Control-Allow-Origin", self.allow_origin(origin));
        response.set("Access-Control-Allow-Methods", method.to_uppercase());
        if !headers.is_empty() {
            response.set("Access-Control-Allow-Headers", headers.join(", "));
        }
        if request.header("Access-Control-Request-Private-Network") == "true" && self.private_network {
            response.set("Access-Control-Allow-Private-Network", "true");
        }
        response.set("Access-Control-Max-Age", "300");
        response
    }

    /// `handleActualRequest`: the headers added to the response.
    fn actual(&self, request: &Request) -> Vec<(String, String)> {
        let mut headers = vec![("Vary".to_string(), "Origin".to_string())];
        let origin = request.header("Origin");
        if !origin.is_empty() && self.origin_allowed(origin) && Self::method_allowed(&request.method) {
            headers.push(("Access-Control-Allow-Origin".into(), self.allow_origin(origin)));
        }
        headers
    }
}

/// The routes, by pattern; `{}` is one path segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Hello,
    Logs,
    Traffic,
    Version,
    Configs,
    Proxies,
    Proxy,
    ProxyDelay,
    Rules,
    Connections,
    Connection,
    ProxyProviders,
    ProxyProvider,
    ProxyProviderHealthcheck,
    RuleProviders,
    RuleProvider,
    Script,
    ProfileTracing,
    FlushFakeIp,
    FlushDns,
    DnsQuery,
    Memory,
    Groups,
    Group,
    GroupDelay,
    UpgradeUi,
}

impl Route {
    fn methods(self) -> &'static [&'static str] {
        match self {
            Route::Configs => &["GET", "PUT", "PATCH"],
            Route::Proxy => &["GET", "PUT"],
            Route::Connections => &["GET", "DELETE"],
            Route::Connection => &["DELETE"],
            Route::ProxyProvider | Route::RuleProvider => &["GET", "PUT"],
            Route::Script => &["POST", "PATCH"],
            Route::FlushFakeIp | Route::FlushDns | Route::UpgradeUi => &["POST"],
            _ => &["GET"],
        }
    }
}

/// Matches a path (split into escaped segments) to a route and its
/// parameter (still escaped).
fn match_route(segments: &[&str]) -> Option<(Route, Option<String>)> {
    let param = |value: &str| Some(value.to_string());
    Some(match segments {
        [] => (Route::Hello, None),
        ["logs"] => (Route::Logs, None),
        ["traffic"] => (Route::Traffic, None),
        ["version"] => (Route::Version, None),
        ["configs"] => (Route::Configs, None),
        ["proxies"] => (Route::Proxies, None),
        ["proxies", name] => (Route::Proxy, param(name)),
        ["proxies", name, "delay"] => (Route::ProxyDelay, param(name)),
        ["rules"] => (Route::Rules, None),
        ["connections"] => (Route::Connections, None),
        ["connections", id] => (Route::Connection, param(id)),
        ["providers", "proxies"] => (Route::ProxyProviders, None),
        ["providers", "proxies", name] => (Route::ProxyProvider, param(name)),
        ["providers", "proxies", name, "healthcheck"] => (Route::ProxyProviderHealthcheck, param(name)),
        ["providers", "rules"] => (Route::RuleProviders, None),
        ["providers", "rules", name] => (Route::RuleProvider, param(name)),
        ["script"] => (Route::Script, None),
        ["profile", "tracing"] => (Route::ProfileTracing, None),
        ["cache", "fakeip", "flush"] => (Route::FlushFakeIp, None),
        ["cache", "dns", "flush"] => (Route::FlushDns, None),
        ["dns", "query"] => (Route::DnsQuery, None),
        ["memory"] => (Route::Memory, None),
        ["group"] => (Route::Groups, None),
        ["group", name] => (Route::Group, param(name)),
        ["group", name, "delay"] => (Route::GroupDelay, param(name)),
        ["upgrade", "ui"] => (Route::UpgradeUi, None),
        _ => return None,
    })
}

/// A long-lived answer.
pub(crate) enum Stream {
    Traffic,
    Logs(u8),
    Memory,
    Connections(u64),
}

pub(crate) enum Reply {
    Full(Response),
    Stream(Stream, Vec<(String, String)>),
}

fn json_response(status: u16, value: &Value) -> Response {
    Response::new(status).header("Content-Type", "application/json").body(go_json(value))
}

fn error_response(status: u16, message: &str) -> Response {
    json_response(status, &json!({ "message": message }))
}

fn no_content() -> Response {
    Response::new(204)
}

fn not_found() -> Response {
    Response::new(404)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        .body(b"404 page not found\n".to_vec())
}

/// sing-box `C.ProxyDisplayName` (with `block` shown as `Reject`).
fn clash_type(kind: &str) -> &'static str {
    match kind {
        "block" => "Reject",
        "tun" => "TUN",
        "redirect" => "Redirect",
        "tproxy" => "TProxy",
        "direct" => "Direct",
        "dns" => "DNS",
        "socks" => "SOCKS",
        "http" => "HTTP",
        "mixed" => "Mixed",
        "shadowsocks" => "Shadowsocks",
        "vmess" => "VMess",
        "trojan" => "Trojan",
        "vless" => "VLESS",
        "selector" => "Selector",
        "urltest" => "URLTest",
        _ => "Unknown",
    }
}

fn history_json(history: &UrlTestHistory) -> Value {
    json!({ "time": crate::util::rfc3339_nano(history.time), "delay": history.delay })
}

/// Memory in use: the resident set (Go reports its heap and stacks).
pub(crate) fn inuse_memory() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(resident) = statm.split_whitespace().nth(1).and_then(|pages| pages.parse::<u64>().ok()) {
                // SAFETY: `sysconf` has no preconditions.
                let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                return resident * page.max(0) as u64;
            }
        }
    }
    0
}

pub(crate) struct State {
    pub(crate) options: ClashApiOptions,
    cors: Cors,
    pub(crate) router: Arc<Router>,
    pub(crate) dns: Arc<DnsRouter>,
    /// In configuration order.
    pub(crate) outbounds: Vec<Arc<dyn Outbound>>,
    pub(crate) registry: Arc<OutboundRegistry>,
    pub(crate) traffic: TrafficManager,
    pub(crate) history: Arc<HistoryStorage>,
    pub(crate) mode: Arc<ModeManager>,
    pub(crate) cache_file: Option<Arc<CacheFile>>,
    pub(crate) store: Arc<Store>,
    pub(crate) log_level: u8,
    pub(crate) version: String,
    pub(crate) external_ui: Option<PathBuf>,
    pub(crate) closing: watch::Receiver<bool>,
}

impl State {
    pub(crate) fn new(parts: ApiParts, closing: watch::Receiver<bool>) -> Self {
        let cors =
            Cors::new(&parts.options.access_control_allow_origin.0, parts.options.access_control_allow_private_network);
        let external_ui = if parts.options.external_ui.is_empty() {
            None
        } else {
            Some(PathBuf::from(crate::expand_env(&parts.options.external_ui)))
        };
        State {
            options: parts.options,
            cors,
            router: parts.router,
            dns: parts.dns,
            outbounds: parts.outbounds,
            registry: parts.registry,
            traffic: parts.traffic,
            history: parts.history,
            mode: parts.mode,
            cache_file: parts.cache_file,
            store: parts.store,
            log_level: parts.log_level,
            version: parts.version,
            external_ui,
            closing,
        }
    }

    fn outbound(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.iter().find(|outbound| outbound.tag() == tag).cloned()
    }

    fn authenticated(&self, request: &Request) -> bool {
        let secret = &self.options.secret;
        if secret.is_empty() {
            return true;
        }
        if request.is_websocket() {
            let token = request.query_get("token");
            if !token.is_empty() {
                return token == *secret;
            }
        }
        let header = request.header("Authorization");
        match header.split_once(' ') {
            Some((bearer, token)) => bearer == "Bearer" && token == secret,
            None => false,
        }
    }

    /// `proxyInfo`.
    fn proxy_info(&self, outbound: &Arc<dyn Outbound>) -> Value {
        let mut info = Map::new();
        info.insert("type".into(), json!(clash_type(outbound.kind())));
        info.insert("name".into(), json!(outbound.tag()));
        info.insert("udp".into(), json!(outbound.networks().contains(&Network::Udp)));
        let history: Vec<Value> =
            self.history.load(&real_tag(outbound, Network::Tcp)).iter().map(history_json).collect();
        info.insert("history".into(), Value::Array(history));
        if let Some(group) = outbound.group() {
            let now = group.selected(Network::Tcp).map(|selected| selected.tag().to_string()).unwrap_or_default();
            info.insert("now".into(), json!(now));
            info.insert("all".into(), json!(group.all()));
        }
        Value::Object(info)
    }

    pub(crate) async fn handle(&self, request: &Request) -> Reply {
        if request.method == "OPTIONS" && !request.header("Access-Control-Request-Method").is_empty() {
            return Reply::Full(self.cors.preflight(request).header("Content-Length", "0"));
        }
        let cors = self.cors.actual(request);
        let reply = self.route(request, &cors).await;
        match reply {
            Reply::Full(mut response) => {
                for (name, value) in cors {
                    if name == "Vary" {
                        response.add(&name, value);
                    } else {
                        response.set(&name, value);
                    }
                }
                Reply::Full(response)
            }
            stream => stream,
        }
    }

    async fn route(&self, request: &Request, cors: &[(String, String)]) -> Reply {
        let path = request.path.as_str();
        if let Some(root) = &self.external_ui {
            if path == "/ui" {
                return Reply::Full(Response::new(301).header("Location", "/ui/"));
            }
            if let Some(rest) = path.strip_prefix("/ui/") {
                return Reply::Full(match request.method.as_str() {
                    "GET" | "HEAD" => ui::serve(root, rest),
                    _ => Response::new(405).header("Allow", "GET, HEAD"),
                });
            }
        }
        let trimmed = path.trim_start_matches('/');
        let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
        let segments: Vec<&str> = if trimmed.is_empty() { Vec::new() } else { trimmed.split('/').collect() };
        let Some((route, param)) = match_route(&segments) else { return Reply::Full(not_found()) };
        let method = if request.method == "HEAD" { "GET" } else { request.method.as_str() };
        if !route.methods().contains(&method) {
            return Reply::Full(Response::new(405).header("Allow", route.methods().join(", ")));
        }
        if !self.authenticated(request) {
            return Reply::Full(error_response(401, "Unauthorized"));
        }
        let param = param.map(|param| crate::util::unescape(&param, false).unwrap_or(param));
        let _ = cors;
        match route {
            Route::Hello => Reply::Full(self.hello(request)),
            Route::Logs => match parse_level(&{
                let level = request.query_get("level");
                if level.is_empty() {
                    "info".to_string()
                } else {
                    level
                }
            }) {
                Some(level) => Reply::Stream(Stream::Logs(level), Vec::new()),
                None => Reply::Full(error_response(400, "Body invalid")),
            },
            Route::Traffic => Reply::Stream(Stream::Traffic, Vec::new()),
            Route::Memory => Reply::Stream(Stream::Memory, Vec::new()),
            Route::Version => {
                Reply::Full(json_response(200, &json!({ "meta": true, "premium": true, "version": self.version })))
            }
            Route::Configs => Reply::Full(match method {
                "GET" => self.get_configs(),
                "PATCH" => self.patch_configs(request),
                _ => no_content(),
            }),
            Route::Proxies => Reply::Full(self.get_proxies()),
            Route::Proxy | Route::ProxyDelay | Route::Group | Route::GroupDelay => {
                let name = param.unwrap_or_default();
                let Some(outbound) = self.outbound(&name) else {
                    return Reply::Full(error_response(404, "Resource not found"));
                };
                Reply::Full(match (route, method) {
                    (Route::Proxy, "GET") => {
                        Response::new(200).body(serde_json::to_vec(&self.proxy_info(&outbound)).unwrap_or_default())
                    }
                    (Route::Proxy, _) => self.update_proxy(request, &outbound),
                    (Route::ProxyDelay, _) => self.proxy_delay(request, &outbound).await,
                    (Route::Group, _) => match outbound.group() {
                        Some(_) => json_response(200, &self.proxy_info(&outbound)),
                        None => error_response(404, "Resource not found"),
                    },
                    _ => self.group_delay(request, &outbound).await,
                })
            }
            Route::Rules => Reply::Full(self.get_rules()),
            Route::Connections => {
                if method == "DELETE" {
                    self.traffic.close_all();
                    return Reply::Full(no_content());
                }
                if !request.is_websocket() {
                    return Reply::Full(json_response(200, &self.connections_snapshot()));
                }
                let interval = request.query_get("interval");
                let interval = if interval.is_empty() { Some(1000) } else { interval.parse::<i64>().ok() };
                match interval {
                    Some(interval) => Reply::Stream(Stream::Connections(interval.max(1) as u64), Vec::new()),
                    // sing-box answers after the upgrade, which the client never reads.
                    None => Reply::Full(error_response(400, "Body invalid")),
                }
            }
            Route::Connection => {
                if let Some(connection) = self.traffic.connection(&param.unwrap_or_default()) {
                    connection.close();
                }
                Reply::Full(no_content())
            }
            Route::ProxyProviders => Reply::Full(json_response(200, &json!({ "providers": {} }))),
            Route::RuleProviders => Reply::Full(json_response(200, &json!({ "providers": [] }))),
            Route::ProxyProvider | Route::ProxyProviderHealthcheck | Route::RuleProvider | Route::ProfileTracing => {
                Reply::Full(error_response(404, "Resource not found"))
            }
            Route::Script => Reply::Full(match method {
                "POST" => error_response(400, "not implemented"),
                _ => no_content(),
            }),
            Route::FlushFakeIp => Reply::Full(match &self.cache_file {
                Some(cache_file) => match cache_file.fakeip_reset() {
                    Ok(()) => no_content(),
                    Err(error) => error_response(500, &error.to_string()),
                },
                None => no_content(),
            }),
            Route::FlushDns => {
                self.dns.clear_cache();
                Reply::Full(no_content())
            }
            Route::DnsQuery => Reply::Full(self.query_dns(request).await),
            Route::Groups => {
                let groups: Vec<Value> = self
                    .outbounds
                    .iter()
                    .filter(|outbound| outbound.group().is_some())
                    .map(|outbound| self.proxy_info(outbound))
                    .collect();
                Reply::Full(json_response(200, &json!({ "proxies": groups })))
            }
            Route::UpgradeUi => Reply::Full(self.upgrade_ui().await),
        }
    }

    fn hello(&self, request: &Request) -> Response {
        if self.external_ui.is_none() || request.header("Content-Type") == "application/json" {
            json_response(200, &json!({ "hello": "clash" }))
        } else {
            let body = if request.method == "GET" || request.method == "HEAD" {
                b"<a href=\"/ui/\">Temporary Redirect</a>.\n\n".to_vec()
            } else {
                Vec::new()
            };
            let mut response = Response::new(307).header("Location", "/ui/");
            if !body.is_empty() {
                response.set("Content-Type", "text/html; charset=utf-8");
            }
            response.body(body)
        }
    }

    fn get_configs(&self) -> Response {
        let level = match self.log_level {
            LEVEL_TRACE => LEVEL_DEBUG,
            level if level < LEVEL_ERROR => LEVEL_ERROR,
            level => level,
        };
        json_response(
            200,
            &json!({
                "port": 0,
                "socks-port": 0,
                "redir-port": 0,
                "tproxy-port": 0,
                "mixed-port": 0,
                "allow-lan": false,
                "bind-address": "*",
                "mode": self.mode.mode(),
                "mode-list": self.mode.mode_list(),
                "log-level": format_level(level),
                "ipv6": false,
                "tun": null,
            }),
        )
    }

    fn patch_configs(&self, request: &Request) -> Response {
        let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&request.body) else {
            return error_response(400, "Body invalid");
        };
        let mode = match body.get("mode") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(mode)) => mode.clone(),
            Some(_) => return error_response(400, "Body invalid"),
        };
        if !mode.is_empty() {
            self.mode.set_mode(&mode);
        }
        no_content()
    }

    fn get_proxies(&self) -> Response {
        let outbounds: Vec<&Arc<dyn Outbound>> =
            self.outbounds.iter().filter(|outbound| !outbound.tag().is_empty()).collect();
        let default_tag = self.router.default_outbound().to_string();
        let mut all: Vec<String> = outbounds
            .iter()
            .filter(|outbound| !matches!(outbound.kind(), "direct" | "block" | "dns"))
            .map(|outbound| outbound.tag().to_string())
            .collect();
        // `sort.SliceStable` with "is the default" as the order.
        all.sort_by_key(|tag| *tag != default_tag);
        let mut proxies = Map::new();
        proxies.insert(
            "GLOBAL".into(),
            json!({
                "all": all,
                "history": [],
                "name": "GLOBAL",
                "now": default_tag,
                "type": "Fallback",
                "udp": true,
            }),
        );
        for outbound in outbounds {
            proxies.insert(outbound.tag().to_string(), self.proxy_info(outbound));
        }
        // Written without a content type, which Go sniffs as text.
        Response::new(200).body(serde_json::to_vec(&json!({ "proxies": proxies })).unwrap_or_default())
    }

    fn update_proxy(&self, request: &Request, outbound: &Arc<dyn Outbound>) -> Response {
        let name = match serde_json::from_slice::<Value>(&request.body) {
            Ok(Value::Object(body)) => match body.get("name") {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(name)) => name.clone(),
                Some(_) => return error_response(400, "Body invalid"),
            },
            _ => return error_response(400, "Body invalid"),
        };
        let Some(selector) = outbound.group().and_then(|group| group.as_any().downcast_ref::<Selector>()) else {
            return error_response(400, "Must be a Selector");
        };
        if !selector.select_outbound(&name) {
            return error_response(400, "Selector update error: not found");
        }
        no_content()
    }

    /// `groupContains`.
    fn group_contains(&self, group: &Arc<dyn Outbound>, tag: &str, visited: &mut HashSet<String>) -> bool {
        let Some(members) = group.group().map(|group| group.all()) else { return false };
        for member_tag in members {
            if member_tag == tag {
                return true;
            }
            let Some(member) = self.outbound(&member_tag) else { continue };
            if real_tag(&member, Network::Tcp) == tag {
                return true;
            }
            if member.group().is_none() || visited.contains(&member_tag) {
                continue;
            }
            visited.insert(member_tag);
            if self.group_contains(&member, tag, visited) {
                return true;
            }
        }
        false
    }

    async fn proxy_delay(&self, request: &Request, outbound: &Arc<dyn Outbound>) -> Response {
        let mut link = request.query_get("url");
        if link.starts_with("http://") {
            link.clear();
        }
        let Ok(timeout) = request.query_get("timeout").parse::<i16>() else {
            return error_response(400, "Body invalid");
        };
        let timeout = Duration::from_millis(timeout.max(0) as u64);
        let result = tokio::time::timeout(timeout, url_test(&link, outbound, &self.store)).await;
        let real = real_tag(outbound, Network::Tcp);
        match &result {
            Ok(Ok(delay)) => self.history.store(&real, UrlTestHistory { time: SystemTime::now(), delay: *delay }),
            _ => self.history.delete(&real),
        }
        for group in &self.outbounds {
            let Some(urltest) = group.group().and_then(|group| group.as_any().downcast_ref::<UrlTest>()) else {
                continue;
            };
            let mut visited = HashSet::from([group.tag().to_string()]);
            if self.group_contains(group, &real, &mut visited) {
                urltest.perform_update_check();
            }
        }
        match result {
            Err(_) => error_response(504, "Timeout"),
            Ok(Ok(delay)) if delay != 0 => json_response(200, &json!({ "delay": delay })),
            Ok(_) => error_response(503, "An error occurred in the delay test"),
        }
    }

    async fn group_delay(&self, request: &Request, outbound: &Arc<dyn Outbound>) -> Response {
        let Some(group) = outbound.group() else { return error_response(404, "Resource not found") };
        let mut link = request.query_get("url");
        if link.starts_with("http://") {
            link.clear();
        }
        let Ok(timeout) = request.query_get("timeout").parse::<i32>() else {
            return error_response(400, "Body invalid");
        };
        let timeout = Duration::from_millis(timeout.max(0) as u64);
        let test = async {
            if let Some(urltest) = group.as_any().downcast_ref::<UrlTest>() {
                urltest.url_test().await
            } else {
                let members: Vec<Arc<dyn Outbound>> = group.all().iter().filter_map(|tag| self.outbound(tag)).collect();
                url_test_outbounds(&members, &link, Duration::ZERO, true, &self.history, &self.store).await
            }
        };
        match tokio::time::timeout(timeout, test).await {
            Ok(result) => {
                let mut sorted: Vec<(String, u16)> = result.into_iter().collect();
                sorted.sort();
                let map: Map<String, Value> = sorted.into_iter().map(|(tag, delay)| (tag, json!(delay))).collect();
                json_response(200, &Value::Object(map))
            }
            Err(_) => error_response(504, "context deadline exceeded"),
        }
    }

    fn get_rules(&self) -> Response {
        let rules: Vec<Value> = self
            .router
            .rule_descriptions()
            .into_iter()
            .map(|(kind, payload, proxy)| json!({ "type": kind, "payload": payload, "proxy": proxy }))
            .collect();
        let rules = if rules.is_empty() { Value::Null } else { Value::Array(rules) };
        json_response(200, &json!({ "rules": rules }))
    }

    pub(crate) fn connections_snapshot(&self) -> Value {
        let (upload, download) = self.traffic.total();
        let connections: Vec<Value> = self
            .traffic
            .connections()
            .iter()
            .filter(|metadata| metadata.outbound_type != "dns")
            .map(|metadata| metadata.to_json())
            .collect();
        json!({
            "connections": connections,
            "downloadTotal": download,
            "memory": inuse_memory(),
            "uploadTotal": upload,
        })
    }

    async fn query_dns(&self, request: &Request) -> Response {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        let name = request.query_get("name");
        let mut type_name = request.query_get("type");
        if type_name.is_empty() {
            type_name = "A".into();
        }
        let query_type = match type_name.parse::<RecordType>() {
            Ok(query_type) if query_type.to_string() == type_name && !matches!(query_type, RecordType::Unknown(_)) => {
                query_type
            }
            _ => return error_response(400, "invalid query type"),
        };
        let fqdn = if name.ends_with('.') { name.clone() } else { format!("{name}.") };
        let Ok(domain) = Name::from_ascii(&fqdn) else { return error_response(500, "bad domain name") };
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(Query::query(domain, query_type));
        let Ok(bytes) = message.to_vec() else { return error_response(500, "pack message") };
        let options = LookupOptions::default();
        let exchange =
            tokio::time::timeout(DNS_TIMEOUT, rb_adapter::DnsResolver::exchange(&*self.dns, &bytes, &options));
        let response = match exchange.await {
            Err(_) => return error_response(500, "context deadline exceeded"),
            Ok(Err(error)) => return error_response(500, &error.to_string()),
            Ok(Ok(None)) => return error_response(500, "response rejected"),
            Ok(Ok(Some(response))) => response,
        };
        let Ok(response) = Message::from_vec(&response) else { return error_response(500, "unpack message") };
        let record = |record: &hickory_proto::rr::Record| {
            let data = record.data().to_string();
            json!({
                "TTL": record.ttl(),
                "data": data,
                "name": record.name().to_string(),
                "type": u16::from(record.record_type()),
            })
        };
        let questions: Vec<Value> = response
            .queries()
            .iter()
            .map(|query| {
                json!({
                    "Name": query.name().to_string(),
                    "Qtype": u16::from(query.query_type()),
                    "Qclass": u16::from(query.query_class()),
                })
            })
            .collect();
        let mut body = Map::new();
        body.insert("AD".into(), json!(response.authentic_data()));
        if !response.answers().is_empty() {
            body.insert("Answer".into(), Value::Array(response.answers().iter().map(record).collect()));
        }
        if !response.name_servers().is_empty() {
            body.insert("Authority".into(), Value::Array(response.name_servers().iter().map(record).collect()));
        }
        body.insert("CD".into(), json!(response.checking_disabled()));
        if !response.additionals().is_empty() {
            body.insert("Additional".into(), Value::Array(response.additionals().iter().map(record).collect()));
        }
        body.insert("Question".into(), Value::Array(questions));
        body.insert("RA".into(), json!(response.recursion_available()));
        body.insert("RD".into(), json!(response.recursion_desired()));
        body.insert("Server".into(), json!("internal"));
        body.insert("Status".into(), json!(u16::from(response.response_code())));
        body.insert("TC".into(), json!(response.truncated()));
        // Go sorts map keys.
        let mut sorted: Vec<(String, Value)> = body.into_iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        json_response(200, &Value::Object(sorted.into_iter().collect()))
    }

    async fn upgrade_ui(&self) -> Response {
        let Some(directory) = &self.external_ui else {
            return error_response(404, "external UI not enabled");
        };
        info!("clash-api: upgrading external UI");
        match self.download_ui(directory).await {
            Ok(()) => {
                info!("clash-api: updated external UI");
                json_response(200, &json!({ "status": "ok" }))
            }
            Err(error) => {
                error!("clash-api: upgrade external ui: {error}");
                error_response(500, &error.to_string())
            }
        }
    }

    pub(crate) async fn download_ui(&self, directory: &std::path::Path) -> std::io::Result<()> {
        let detour = if self.options.external_ui_download_detour.is_empty() {
            self.router.default_outbound().to_string()
        } else {
            let detour = self.options.external_ui_download_detour.clone();
            if self.outbound(&detour).is_none() {
                return Err(std::io::Error::other(format!("detour outbound not found: {detour}")));
            }
            detour
        };
        if let Some(outbound) = self.outbound(&detour) {
            info!("clash-api: downloading external ui using outbound/{}[{}]", outbound.kind(), outbound.tag());
        }
        ui::download(directory, &self.options.external_ui_download_url, &self.registry, &detour, &self.store).await
    }

    /// `checkAndDownloadExternalUI`.
    pub(crate) async fn check_external_ui(&self) {
        let Some(directory) = &self.external_ui else { return };
        let empty = match std::fs::read_dir(directory) {
            Ok(mut entries) => entries.next().is_none(),
            Err(_) => {
                let _ = std::fs::create_dir_all(directory);
                true
            }
        };
        if empty {
            if let Err(error) = self.download_ui(directory).await {
                error!("clash-api: download external ui error: {error}");
            }
        }
    }
}

/// Serves one client connection.
pub(crate) async fn serve_connection<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(state: Arc<State>, stream: S) {
    let (read, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    loop {
        let request = match http::read_request(&mut reader).await {
            Ok(request) => request,
            Err(http::ReadError::Closed) => return,
            Err(http::ReadError::Bad(status)) => {
                let text = format!("{status} {}", http::status_text(status));
                let head = format!(
                    "HTTP/1.1 {text}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{text}"
                );
                let _ = writer.write_all(head.as_bytes()).await;
                return;
            }
        };
        match state.handle(&request).await {
            Reply::Full(response) => {
                let head_only = request.method == "HEAD";
                if http::write_response(&mut writer, response, head_only, request.keep_alive).await.is_err()
                    || !request.keep_alive
                {
                    return;
                }
            }
            Reply::Stream(kind, mut headers) => {
                headers.extend(state.cors.actual(&request));
                run_stream(&state, &request, kind, headers, reader, writer).await;
                return;
            }
        }
    }
}

async fn run_stream<R, W>(
    state: &Arc<State>,
    request: &Request,
    kind: Stream,
    headers: Vec<(String, String)>,
    mut reader: BufReader<R>,
    mut writer: W,
) where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin,
{
    let websocket = request.is_websocket();
    let (control, mut control_frames) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let mut peer_closed = tokio::sync::oneshot::channel::<()>();
    if websocket {
        match http::websocket_accept(request, headers) {
            Ok(head) => {
                if writer.write_all(&head).await.is_err() {
                    return;
                }
            }
            Err(response) => {
                let _ = http::write_response(&mut writer, response, false, false).await;
                return;
            }
        }
        let (closed_sender, closed_receiver) = tokio::sync::oneshot::channel::<()>();
        peer_closed.1 = closed_receiver;
        tokio::spawn(async move {
            let _ = http::websocket_drain(&mut reader, control).await;
            let _ = closed_sender.send(());
        });
    } else if http::start_chunked(&mut writer, headers).await.is_err() {
        return;
    }
    let mut closing = state.closing.clone();
    let mut logs = matches!(kind, Stream::Logs(_)).then(clash_log::subscribe);
    let period = match kind {
        Stream::Connections(interval) => Duration::from_millis(interval),
        _ => Duration::from_secs(1),
    };
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    let (mut last_up, mut last_down) = state.traffic.total();
    let mut first_memory = true;
    if matches!(kind, Stream::Connections(_)) {
        let payload = go_json(&state.connections_snapshot());
        if send(&mut writer, websocket, payload).await.is_err() {
            return;
        }
    }
    loop {
        let payload = tokio::select! {
            _ = closing.changed() => return,
            _ = &mut peer_closed.1, if websocket => return,
            frame = control_frames.recv(), if websocket => {
                match frame {
                    Some(frame) => {
                        let close = frame.first() == Some(&0x88);
                        if writer.write_all(&frame).await.is_err() || close {
                            return;
                        }
                        continue;
                    }
                    None => return,
                }
            }
            entry = async { logs.as_mut().unwrap().recv().await }, if logs.is_some() => {
                let Stream::Logs(level) = kind else { return };
                match entry {
                    Ok(entry) if entry.level <= level => {
                        go_json(&json!({ "type": format_level(entry.level), "payload": entry.message }))
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                }
            }
            _ = ticker.tick(), if logs.is_none() => match kind {
                Stream::Traffic => {
                    let (up, down) = state.traffic.total();
                    let payload = go_json(&json!({ "up": up - last_up, "down": down - last_down }));
                    last_up = up;
                    last_down = down;
                    payload
                }
                Stream::Memory => {
                    let inuse = if first_memory { 0 } else { inuse_memory() };
                    first_memory = false;
                    go_json(&json!({ "inuse": inuse, "oslimit": 0 }))
                }
                Stream::Connections(_) => go_json(&state.connections_snapshot()),
                Stream::Logs(_) => continue,
            },
        };
        if send(&mut writer, websocket, payload).await.is_err() {
            return;
        }
    }
}

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, websocket: bool, payload: Vec<u8>) -> std::io::Result<()> {
    if websocket {
        writer.write_all(&http::websocket_frame(0x1, &payload)).await?;
        writer.flush().await
    } else {
        http::write_chunk(writer, &payload).await
    }
}

/// Listens on `external_controller` (`":9090"` meaning every address).
pub(crate) async fn listen(address: &str) -> std::io::Result<tokio::net::TcpListener> {
    if let Some(port) = address.strip_prefix(':') {
        let port: u16 = port.parse().map_err(|_| std::io::Error::other(format!("invalid address {address}")))?;
        let any6 = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
        return match tokio::net::TcpListener::bind(any6).await {
            Ok(listener) => Ok(listener),
            Err(_) => tokio::net::TcpListener::bind(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port))).await,
        };
    }
    tokio::net::TcpListener::bind(address).await
}
