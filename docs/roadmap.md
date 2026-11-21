# Roadmap

Ordered by dependency, following the porting order in the sing-box
architecture analysis (`docs/singbox-architecture.md`, section 11.2). Each
milestone is one pull request with tests; the configuration stays sing-box
v1.14.4 compatible, and a field rust-box does not implement is an error, never
silently ignored.

1. **Core path** (done): config, socks/http/mixed inbounds, direct/block
   outbounds, route rules and actions (route, reject, sniff, resolve), DNS
   (local/udp/tcp, rules, cache).
2. **UDP** (done): SOCKS5 UDP ASSOCIATE in `socks` and `mixed`, UDP in
   `direct` (and `block`), packet-connection routing through the same rules
   (`route/conn.go` `NewPacketConnection`), UDP NAT table, `udp_timeout`
   (inbound field and route option, protocol timeouts), the `route-options`
   action with `udp_connect`, `udp_timeout` and
   `udp_disable_domain_unmapping`, packet sniffers (dns, quic, stun,
   bittorrent, dtls, ntp) and stream sniffers dns and rdp, `hijack-dns` over
   UDP and TCP.
3. **Dial options and outbound plumbing** (done): every dial field
   (`shared/dial`) in a new crate `rb-dialer` — `detour` (DNS servers),
   `bind_interface`, `inet4_bind_address`, `inet6_bind_address`,
   `bind_address_no_port`, `protect_path`, `routing_mark`, `reuse_addr`,
   `netns`, `connect_timeout`, `tcp_fast_open`, `tcp_multi_path`,
   `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval`,
   `udp_fragment`, `domain_resolver` (string and object, with
   `rewrite_ttl`), `fallback_delay` and the deprecated `domain_strategy`;
   `route.default_interface` and `route.default_mark`; happy-eyeballs in
   `direct`; the route options `override_address`, `override_port`,
   `fallback_delay`, `tls_fragment`, `tls_fragment_fallback_delay`,
   `tls_record_fragment` on `route`, `route-options` and `bypass`; the
   listen fields (`shared/listen`) including the inbound `detour`; HTTP
   proxy keep-alive. Dial fields are also accepted on `udp` and `tcp` DNS
   servers.
4. **Rule-sets** (done): inline, local and remote `source`/`binary` (SRS)
   rule-sets (`rb-rule-set`), headless rules, `rule_set` items in route and
   DNS rules, the DNS router's legacy mode and rule-set update validation,
   file watching (`rb-fswatch`), the top-level `certificate` store
   (`rb-certificate`) for HTTPS downloads, and the `rule-set` commands
   (`compile`, `decompile`, `format`, `upgrade`, `merge`, `match`,
   `convert`).
5. **TLS and first encrypted protocols**: rustls client/server, `shadowsocks`
   (AEAD and 2022), `trojan`, `vless`, `vmess`, `socks`/`http` outbounds,
   multiplex (`sing-mux`).
6. **DNS**: DoT, DoH, DoQ/DoH3, `hosts`, `fakeip`, `predefined`, `evaluate`,
   `match_response`.
7. **V2Ray transports and QUIC protocols**: WebSocket, HTTP/2, gRPC,
   HTTPUpgrade; `hysteria2`, `tuic`.
8. **TUN**: Linux and Android TUN, a user-space TCP/IP stack, auto_route, the
   platform interface for Android VpnService.
9. **Management**: Clash API, cache file, selector/urltest groups.
10. **Heavy endpoints** (evaluated separately): WireGuard, Tailscale, naive,
    uTLS/REALITY fingerprints.

## Known differences in milestone 1

- ~~`direct` tries resolved addresses one after another~~: fixed in
  milestone 3 (happy-eyeballs).
- ~~A plain HTTP proxy request is forwarded with `Connection: close`~~:
  fixed in milestone 3 (keep-alive client connections).
- The `local` DNS server uses the system resolver (getaddrinfo), which
  reports no TTL; answers are cached for 10 seconds.
- `reject` with `method: drop` closes the connection like `default`.

## Known differences in milestone 2

- SOCKS5 UDP packets with a non-zero `FRAG` field are dropped (RFC 1928
  allows a server without reassembly to); sing-box ignores the field and
  treats such a packet as whole.
- The `direct` outbound resolves every domain destination of a UDP session
  through DNS and reports replies from each resolved address as the domain
  (unless `udp_disable_domain_unmapping`); sing-box resolves and maps back
  only the session's first destination.
- `hijack-dns`: A and AAAA answers are built from the addresses the DNS
  router returns (rules, strategy and cache as for lookups), so CNAME
  records and the upstream's other sections and EDNS options are not passed
  through; other query types are forwarded as they are to the selected
  `udp`/`tcp` server and not cached, and the `local` server answers them
  with NOTIMP. Responses are not truncated to the client's UDP size
  (sing-box `TruncateDNSMessage`).
- DNS rules see the inbound, source, user and network of a hijacked query,
  not its destination.
- The QUIC sniffer reads the server name only: there is no client
  detection (chromium, firefox, safari, quic-go), so the `client` rule item
  is not supported yet. At most 8 packets are read while sniffing a UDP
  session.
- The UDP NAT table (`rb_route::nat`) has no user yet: the SOCKS5 inbound
  gives each UDP ASSOCIATE its own socket and session, as sing-box does; the
  table is for the inbounds that share a socket (`direct`, `shadowsocks`,
  `tun`). `udp_fragment` was not supported (added in milestone 3).

## Milestone 3: platform support of the dial and listen fields

| Field | Linux | Android | other platforms |
|---|---|---|---|
| `bind_interface` (dial and listen), `route.default_interface` | `SO_BINDTOIFINDEX`, else `SO_BINDTODEVICE` | same | refused (sing-box also supports macOS and Windows) |
| `routing_mark` (dial and listen), `route.default_mark` | `SO_MARK`, needs `CAP_NET_ADMIN` | same | refused (sing-box: Linux only) |
| `bind_address_no_port` | `IP_BIND_ADDRESS_NO_PORT` | same | refused (sing-box: Linux only) |
| `netns` (dial and listen) | `setns` on a helper thread, needs `CAP_SYS_ADMIN` | same | refused (sing-box: Linux only) |
| `tcp_fast_open` (dial) | lazy connect, data in the SYN (`MSG_FASTOPEN`) | same | refused (sing-box also macOS, Windows, FreeBSD) |
| `tcp_fast_open` (listen) | `TCP_FASTOPEN` queue 4096 | same | refused |
| `tcp_multi_path` | `IPPROTO_MPTCP`, plain TCP when the kernel has none | same | plain TCP (as Go) |
| `udp_fragment` | `IP_MTU_DISCOVER` / `IPV6_MTU_DISCOVER` | same | system default |
| `protect_path` | `SCM_RIGHTS` over a Unix socket | same | refused off Unix |
| `reuse_addr` | `SO_REUSEADDR` + `SO_REUSEPORT` | same | `SO_REUSEADDR` |
| `tcp_keep_alive*`, `disable_tcp_keep_alive` | `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, count 9 (Go's default) | same | idle time only |

`network_strategy`, `network_type` and `fallback_network_type` (dial fields),
the `network_strategy` route option and `route.default_network_strategy`,
`default_network_type`, `default_fallback_network_type` and
`default_fallback_delay` only take effect in sing-box's graphical clients,
through their platform interface with `auto_detect_interface`. rust-box has
no platform interface yet (milestone 8) and handles them exactly as sing-box
v1.14.4's command line does (an exception to "never silently ignore"
approved by the user):

- They are parsed and validated (`unknown network strategy`, `unknown
  interface type`) and otherwise have no effect; neither sing-box nor
  rust-box logs anything about them.
- `dialer.NewDefault`: with `bind_interface`, `inet4_bind_address`,
  `inet6_bind_address` or `tcp_fast_open`, a dialer fails with sing-box's
  message "`network_strategy` is conflict with `bind_interface`,
  `inet4_bind_address`, `inet6_bind_address` and `tcp_fast_open`" when
  `network_strategy` is set, or when `network_type` is set with neither
  `fallback_network_type` (an explicit `[]` counts as set, `null` does not)
  nor `fallback_delay` (Go's operator precedence). A dialer with `detour`
  is not checked, as sing-box builds no default dialer for it. rust-box
  reports this when the configuration loads, with the field path.
- `route.NewNetworkManager`: `default_network_strategy` fails with
  "`default_network_strategy` is conflict with `default_interface`" or
  "`auto_detect_interface` is required by `default_network_strategy`".
- The `network_strategy` route option reaches sing-box's default dialer only
  through `direct`'s resolving dialer, which dials IP destinations without
  it (`resolveParallelNetworkDialer.DialParallelInterface`); other outbounds
  do not read it. So it has no effect in either program.

## Known differences in milestone 3

- The platform network fields (`network_strategy` and the others above)
  behave as in sing-box's command line: accepted without effect, with its
  conflict checks (the first version of this milestone rejected them).
- Rejected with their path rather than implemented: the route options
  `tls_spoof` and `tls_spoof_method` (raw-socket injection),
  `domain_resolver.client_subnet`, and the `network_namespaces`
  section (so `netns` takes a name under `/var/run/netns` or a path, not a
  namespace tag).
- `domain_resolver.disable_optimistic_cache` is accepted; rust-box has no
  optimistic cache, so it is always in effect.
- References are checked when the configuration loads: an inbound
  `detour`, a DNS server `detour` (including sing-box's "detour to an empty
  direct outbound makes no sense") and an `inet4_bind_address` /
  `inet6_bind_address` of the wrong family. sing-box reports these on the
  first connection that uses them.
- `listen` now defaults to `127.0.0.1`, as in sing-box's listener code
  (`Listen.Build(127.0.0.1)`); milestones 1 and 2 used `0.0.0.0`.
- Behaviors kept from v1.14.4 on purpose: `tcp_multi_path` only applies to
  the IPv4 dialer (sing-box enables MPTCP on `dialer4` only; listeners use
  it for both families); the route option `fallback_delay` is a plain number
  of nanoseconds (`uint32` cast to `time.Duration`), so `"300ms"` is a type
  error; `tls_fragment` cuts the ClientHello once inside the first label of
  the server name (the label list is cut down by the number of dots) and
  turns `TCP_NODELAY` off afterwards; `udp_fragment` has no effect on the
  `socks`, `http` and `mixed` inbounds, whose UDP sockets sing-box opens
  without it; inbound `detour` hands TCP connections over but a SOCKS5 UDP
  association fails with "inbound detour is not UDP injectable", as these
  inbounds are not UDP-injectable in sing-box either.
- `tcp_fast_open`: a destination port of a server-first protocol (SMTP,
  IMAP, POP3) is connected at once instead of on the first write (sing-box
  achieves the same by writing an empty first packet); when the kernel
  refuses Fast Open the connection falls back to a plain connect.
- `bypass` routes like `route` when it names an outbound and is skipped
  otherwise; its kernel-level meaning for `auto_redirect` pre-matching
  needs a TUN (milestone 8).
- HTTP proxy, plain requests: each request is a routed connection of its
  own and the client connection stays open with `HTTP/1.1` and
  `Proxy-Connection: keep-alive`, as in sing-box. Differences from Go's
  HTTP client underneath sing-box: no `User-Agent` is added when the client
  sent none; header names and order are passed as received instead of
  canonicalized and sorted; an absolute `https://` target is answered with
  502 (sing-box would make the TLS connection itself); a request body the
  upstream did not read to its end closes the client connection (sing-box
  discards up to 256 KiB to keep it open); the `407` realm is `rust-box`.
  As in sing-box, `X-Forwarded-For` replaces the source address (port 0)
  for routing, so `source_*` rules can be steered by the client.
- `protect_path` talks to the protector synchronously on the dialing
  thread, as sing-box's control function does.
- Not ported: sing-box's connection tracking and power reports in the
  default dialer, and the `direct` outbound's check against connecting back
  into a TUN range.

## Known differences in milestone 4

The `rule-set` commands were compared with the real sing-box v1.14.4 binary
(`crates/rust-box/tests/rule_set_cli.rs`, fixtures written by sing-box in
`crates/rust-box/tests/data/rule-set`): the decompressed `.srs` content of
`compile` and `convert`, and the output of `decompile`, `format`, `upgrade`,
`merge` and `match`, are byte-identical. The compressed `.srs` bytes differ,
since Go's and Rust's zlib encoders produce different (equally valid)
streams.

- No cache file (milestone 9): remote rule-sets are downloaded at every
  start instead of being restored from `cache.db`, and rule-sets are not
  reference-counted (a rule-set no rule uses is still loaded and updated).
- The remote `http_client` option and the top-level `http_clients` section
  are rejected as not supported yet; the deprecated `download_detour` is
  honored (with sing-box's deprecation warning).
- `process_*`, `package_name*`, `network_type`, `network_is_expensive`,
  `network_is_constrained`, `wifi_ssid`/`wifi_bssid` and the interface
  address items are parsed, written to and read from SRS, but never match:
  rust-box has no process searcher and no platform interface yet. As in
  sing-box, `rule-set match` leaves the network items out (no network
  manager outside a box).
- The DNS rule actions and items of later milestones (`match_response`,
  `evaluate`, `respond`) are not implemented.
- Empty lists follow sing-box's decoder: `"domain": []` is the same as an
  unset field, and a rule list made only of empty rules (`[{}]`,
  `[{"domain":[]}]`) is no list at all, while an empty rule next to a real
  one fails with "missing conditions".
- Error and log wording: errors are printed as `Error: ...` (anyhow) rather
  than logrus' `FATAL[0000] ...`, and `upgrade` prints a plain
  `INFO[0000] already up-to-date`; Go's JSON decoder messages are mimicked
  for the common cases only.
- `-c` is not a global flag: it is accepted before or after `run`/`check`,
  so that `rule-set merge` can have its own `-c` (in sing-box the
  subcommand flag shadows the persistent one).
