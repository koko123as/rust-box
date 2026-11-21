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
3. **Dial options and outbound plumbing**: `detour`, `bind_interface`,
   `routing_mark`, `tcp_fast_open`, happy-eyeballs (`fallback_delay`), the
   remaining `route-options` fields (`override_address`, `override_port`,
   `network_strategy`, `fallback_delay`, `tls_fragment`, `tls_spoof`, ...),
   `bypass`.
4. **Rule-sets**: inline, local and remote `source`/`binary` (SRS) rule-sets,
   `rule_set` rule items.
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

- `direct` tries resolved addresses one after another; sing-box races them
  with `fallback_delay` (happy-eyeballs).
- A plain HTTP proxy request is forwarded with `Connection: close`, so each
  request uses its own upstream connection; sing-box keeps the client
  connection alive across requests.
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
  `tun`). `udp_fragment` is not supported.
