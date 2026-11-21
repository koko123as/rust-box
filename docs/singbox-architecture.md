# sing-box v1.14.4 架构分析 —— Rust 重写的基础文档

> 分析对象：官方仓库 `github.com/SagerNet/sing-box`，tag **v1.14.4**（commit `c005f35300ce76427dc285481ec5695f5b179cd2`，2026-10-23），本地克隆于 `/workspace/work/sing-box-1.14.4`。
> 方法：静态阅读 + `go list -json`（tags = `release/DEFAULT_BUILD_TAGS` + `with_v2ray_api,with_grpc`）+ 脚本统计；未做任何构建。
> 配套产物：`/workspace/work/rust-box-notes/golist.json`（go list 原始输出）、`/workspace/work/rust-box-notes/internal_import_graph.json`（sing-box 内部包导入图），生成脚本 `/workspace/work/graph.py`。
> 本文所有路径相对于仓库根目录；`sing/...`、`sing-tun/...` 等指 `$HOME/go/pkg/mod/github.com/sagernet/` 下 go.mod 所锁定版本的模块。

---

## 0. 结论速览

- **代码规模**：sing-box 本仓库非测试 Go 代码 **164,620 行**（另有测试 21,745 行）。其中生成代码约 22k 行（`*.pb.go` 15,305 行；`common/certificate/{chrome,mozilla}.go` 内嵌 CA 数据 6,808 行），**手写代码约 142k 行**。
- **真正的重量在外部模块**：协议与网络栈大量在 sagernet 自有模块中——`sing`（32k）、`sing-tun`（34k）、`sing-quic`（13k）、`quic-go` fork（37k）、`sing-openconnect`（35k）、`sing-openvpn`（21k）、`tailscale` fork（254k）、`gvisor` fork（197k）、`wireguard-go` fork（14k）、`metacubex/utls`（34k）、`cronet-go`（14k Go 绑定 + Chromium 二进制）。
- **架构骨架**：`adapter/` 定义全部接口（无实现）；`box.go` 用 **context 服务定位器**（`sing/service`）注册各 Manager；各协议通过 **类型注册表**（`include/registry.go`）注入，JSON 解析靠 context 中的 `OptionsRegistry` 做 type 分派；生命周期是 1.14 新的 **`Scope` + 四阶段 `StartStage`**。
- **数据路径**：Inbound → `adapter.InboundContext` → `route.Router.RouteConnectionEx` → 规则顺序匹配（含 sniff/resolve 动作）→ Outbound（`N.Dialer`）→ `route.ConnectionManager` 双向拷贝（`sing/common/bufio`，Linux splice）。1.14 新增 **L3 Pre-match / Flow 转发**（`Router.PreMatch`、`adapter.FlowOutbound`、`sing-tun` 的 `FlowVerdict`/`Port`）。
- **最高风险**：(1) TUN 栈与 L3 flow（sing-tun + gVisor）；(2) uTLS/REALITY/Chrome-QUIC 指纹拟态；(3) Tailscale、NaiveProxy(cronet)、OpenVPN/OpenConnect 等“依赖巨型外部实现”的协议；(4) 各平台集成（Android/Apple NetworkExtension、auto_redirect nftables、Windows WinDivert）。
- **许可证**：`LICENSE` 为 **GPL-3.0-or-later**，并附加条款 *“no derivative work may use the name or imply association with this application without prior consent”*。Rust 翻译属衍生作品，必须同样以 GPL-3.0-or-later 发布，且**项目名不能使用 sing-box 名称或暗示关联**。

---

## 1. 官方文档要点（docs/，与 https://sing-box.sagernet.org 同源）

### 1.1 配置模型（`docs/configuration/index.md`）

顶层 JSON 结构（v1.14.4 文档原文字段）：

```json
{ "$schema": "...", "log": {}, "dns": {}, "ntp": {}, "certificate": {},
  "certificate_providers": [], "http_clients": [], "network_namespaces": [],
  "endpoints": [], "inbounds": [], "outbounds": [], "route": {},
  "services": [], "experimental": {} }
```

所有数组项均为 `{ "type": "...", "tag": "...", ...类型特定字段 }` 的**带类型标签对象**；共享字段以“Fields 片段”复用：Listen Fields（`shared/listen.md`）、Dial Fields（`shared/dial.md`）、TLS（`shared/tls.md`）、Multiplex（`shared/multiplex.md`）、V2Ray Transport（`shared/v2ray-transport.md`）、UDP over TCP（`shared/udp-over-tcp.md`）、TCP Brutal（`shared/tcp-brutal.md`）、UDP NAT（`shared/udp-nat.md`）、HTTP Client（`shared/http-client.md`）、HTTP/2（`shared/http2.md`）、QUIC（`shared/quic.md`）、Pre-match（`shared/pre-match.md`）、Neighbor（`shared/neighbor.md`）、Wi-Fi state（`shared/wifi-state.md`）、Certificate Provider（`shared/certificate-provider/*`）、DNS-01（`shared/dns01_challenge.md`）。

CLI 层（`cmd/sing-box/cmd.go`、`cmd_run.go`）：`-c` 可多次、`-C` 目录，多份配置经 `badjson.MergeJSON` 合并；`SIGHUP` 触发重载（`cmd_run.go:198`）。JSON 支持注释（`sing/common/json/comment.go`），解析时 `DisallowUnknownFields`（`option/options.go:41`）。

### 1.2 文档配置段 → 代码包映射

| 文档段 | 文档路径 | Option 类型 | 实现包 |
|---|---|---|---|
| `log` | `configuration/log/index.md`（disabled/level/output/timestamp） | `option.LogOptions` | `log/`（`log.New`、`ObservableFactory` 供 Clash API） |
| `dns` | `configuration/dns/index.md`、`dns/server/*`、`dns/rule.md`、`dns/rule_action.md`、`dns/fakeip.md` | `option.DNSOptions`（`option/dns.go`） | `dns/`（Router/Client/TransportManager）、`dns/transport/*`、`route/rule/rule_dns.go` |
| `ntp` | `configuration/ntp/index.md` | `option.NTPOptions` | `sing/common/ntp`，`box.go` 中构造；`common/tls.TimeServiceWrapper` |
| `certificate` | `configuration/certificate/index.md`（store: system/mozilla/chrome/none） | `option.CertificateOptions` | `common/certificate`（含生成的根证书表） |
| `certificate_providers` | `shared/certificate-provider/{acme,cloudflare-origin-ca,tailscale}.md` | 注册表分派 | `adapter/certificate`、`service/acme`、`service/origin_ca`、`protocol/tailscale/certificate_provider.go` |
| `http_clients` | `shared/http-client.md`、`shared/http2.md`、`shared/quic.md` | `option.HTTPClientOptions` | `common/httpclient`（`httpclient.NewManager`） |
| `network_namespaces` | `configuration/network-namespace/{index,default,unshare}.md` | `option.NetworkNamespaces` | `common/netns`、`cmd/sing-box/cmd_netns_holder.go`、`cmd_run_userns_linux.go` |
| `endpoints` | `configuration/endpoint/*` | 注册表分派 | `adapter/endpoint`、`protocol/{wireguard,tailscale,openvpn,openconnect}` |
| `inbounds` | `configuration/inbound/*` | 注册表分派 | `adapter/inbound`、`protocol/*`、`common/listener` |
| `outbounds` | `configuration/outbound/*` | 注册表分派 | `adapter/outbound`、`protocol/*`、`common/dialer` |
| `route` | `configuration/route/{index,rule,rule_action,sniff}.md`、`rule-set/*` | `option.RouteOptions`、`option.Rule` | `route/`、`route/rule/`、`common/sniff`、`common/srs`、`common/process` |
| `services` | `configuration/service/*` | 注册表分派 | `adapter/service`、`service/*`、`protocol/hysteria2/realm*.go` |
| `experimental` | `configuration/experimental/{index,cache-file,clash-api,v2ray-api}.md` | `option.ExperimentalOptions` | `experimental/{cachefile,clashapi,v2rayapi,clashmode}` |

### 1.3 功能面（按文档）

- **Inbound 类型**（`inbound/index.md`）：direct, mixed, socks, http, shadowsocks, vmess, trojan, naive, hysteria, shadowtls, tuic, hysteria2, vless, anytls, snell, tun, redirect, tproxy, cloudflared。
- **Outbound 类型**（`outbound/index.md`）：direct, bridge, block, socks, http, shadowsocks, vmess, trojan, wireguard(已移除), hysteria, vless, shadowtls, tuic, hysteria2, anytls, snell, tor, ssh, dns(已移除), selector, urltest, naive。
- **Endpoint**（`endpoint/index.md`）：wireguard, tailscale, openconnect, openvpn-client, openvpn-server。
- **DNS server**（`dns/server/index.md`）：local, hosts, tcp, udp, tls, quic, https, h3, dhcp, mdns, fakeip, tailscale, openconnect, openvpn, resolved（以及已移除的 legacy）。
- **Service**（`service/index.md`）：api, ccm, derp, hysteria-realm, ocm, resolved, ssm-api, usbip-server, usbip-client。
- **路由规则动作**（`route/rule_action.md`）：route, bypass, reject, hijack-dns, route-options, sniff, resolve；route-options 含 override_address/port、network_strategy、udp_connect/udp_timeout、tls_fragment、tls_record_fragment、tls_spoof 等。
- **DNS 规则动作**（`dns/rule_action.md`）：route, evaluate(1.14), respond(1.14), route-options, reject, predefined。
- **规则条目**（`route/rule.md`）：inbound, ip_version, auth_user, protocol, client, network, domain/suffix/keyword/regex, source_ip_cidr, ip_cidr, ip_is_private, source/port(_range), process_name/path/path_regex, package_name(_regex), user/user_id, clash_mode, network_type/is_expensive/is_constrained, interface_address 系列, wifi_ssid/bssid, preferred_by, source_mac_address/source_hostname(1.14), rule_set, invert, logical(and/or)；`geoip/geosite/source_geoip` 仍在文档中但标注已移除。
- **Rule-set**（`rule-set/index.md`）：inline / local / remote；format source(JSON) / binary(SRS)；1.14 新增 `tag` 可为列表（`{tag}` 占位符）、`initial_path`、`http_client`；`download_detour` 已弃用。
- **Pre-match**（`shared/pre-match.md`）：L3 入站（TUN/WireGuard/Tailscale）在连接建立前用规则预匹配，支持 reject / route（L3 直转：ICMP→direct/bridge/WG/TS；TCP/UDP→bridge/WG/TS）/ sniff（仅 UDP 首包）/ bypass。
- **TUN**（`inbound/tun.md`）：stack = system / gvisor / mixed；auto_route、auto_redirect（nftables）、strict_route、route_(exclude_)address(_set)、include/exclude uid/package/interface/mac、dns_mode(1.14)、netns(1.14)、platform.http_proxy。
- **TLS**（`shared/tls.md`）：入/出站 std TLS、ACME（已弃用内联）、certificate_provider、ECH（stdlib）、REALITY（入/出）、uTLS fingerprint、kernel_tx/rx（kTLS）、fragment/record_fragment、spoof/spoof_method、engine（`windows` Schannel / `apple` Network.framework）、pinned `certificate_public_key_sha256`。
- **Multiplex**（`shared/multiplex.md`）：protocol smux/yamux/h2mux、padding、brutal。**V2Ray transport**：http, ws, quic, grpc, httpupgrade。

### 1.4 构建标签（`docs/installation/build-from-source.md` 与 `release/DEFAULT_BUILD_TAGS`）

`release/DEFAULT_BUILD_TAGS`（Linux/Darwin/Android 默认）：
`with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_naive_outbound,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0`
- `DEFAULT_BUILD_TAGS_WINDOWS` 额外 `with_purego`；`DEFAULT_BUILD_TAGS_OTHERS` 去掉 `with_naive_outbound`。
- 默认关闭：`with_grpc`（标准 gRPC 传输，否则用 `transport/v2raygrpclite`）、`with_v2ray_api`、`with_embedded_tor`。
- 已失效标签以“编译期报错”方式提示：`common/tls/ech_tag_stub.go`（`with_ech` 已并入 stdlib）、`common/tls/reality_stub.go`（`with_reality_server` 已并入 `with_utls`）。

### 1.5 1.12–1.14 变更与弃用（`docs/changelog.md`、`docs/deprecated.md`、`docs/migration.md`）

- **1.12.0**：重构 DNS servers（新 typed server 格式）、domain_resolver、TLS fragment、certificate 选项、Tailscale endpoint + DNS server、AnyTLS、迁移到 stdlib ECH、NTP sniffer、DERP/Resolved/SSM-API service；**GeoIP/Geosite 移除**。
- **1.13.0**：NaiveProxy outbound（cronet）、auto_redirect pre-match、Chrome Root Store、Wi-Fi state(Linux/Windows)、curve preferences/pinned key/mTLS、**kTLS**、**ICMP echo 代理**、interface_address 规则、`preferred_by`、改进 local DNS、TCP keepalive 选项、CCM/OCM service；**移除** legacy 特殊出站（dns/block 出站改用规则动作）、legacy inbound 字段、direct 的 destination override、WireGuard outbound、TUN gso。
- **1.14.0**：OpenVPN client/server、OpenConnect client、Snell、**L3 转发 + bridge outbound**、network namespaces、**sing-box API service（gRPC）+ `api` 命令**、USB/IP、Hysteria Realm + Hysteria2 NAT 穿透、Hysteria2 Chrome QUIC 指纹/BBR/gecko obfs、DNS `evaluate`/响应匹配/并行评估、**修正 rule-set 匹配语义**（仅“单个非 invert default 规则”才做合并匹配，其余按“其它字段”整体匹配）、乐观 DNS 缓存（`optimistic` + `store_dns`）、DNS 超时、mDNS server、`source_mac_address`/`source_hostname`、TUN `dns_mode`、UDP NAT 选项、pre-match sniff、**统一 HTTP client**、统一 HTTP/2/QUIC 参数、ACME 改造为 certificate provider、Cloudflare Origin CA / Tailscale 证书提供者、**TLS spoof**、Windows/Apple TLS 引擎、Tailscale SSH/Taildrop、JSON Schema、要求 Go ≥ 1.25；quic-go v0.61.0、gVisor 20260727.0、Tailscale v1.102.1、uTLS v1.8.7。
- **1.14 弃用、1.16 移除**（`deprecated.md`）：remote rule-set `download_detour`、隐式默认 HTTP client、TLS 内联 ACME、DNS 规则动作 `strategy`、`rule_set_ip_cidr_accept_empty`、`independent_cache`、`store_rdrc`、DNS 规则里的 legacy 地址过滤字段。

### 1.6 文档与代码不一致之处（已核对）

| 位置 | 文档说法 | 代码实际 |
|---|---|---|
| `installation/build-from-source.md` 构建标签表 | 未列出 `with_usbip`、`with_openvpn`、`with_openconnect`、`with_purego`；“Requirements”只写到 1.11（Go 1.23.1） | `release/DEFAULT_BUILD_TAGS` 默认包含前三者；`go.mod` 为 `go 1.25.5`，changelog 1.14.0 写明需 Go 1.25 |
| 同上 `with_quic` 描述 | 说影响 Naive inbound | `protocol/naive` 的 inbound 无条件注册（`include/registry.go`），仅其 QUIC 子包与 outbound 受标签影响（`protocol/naive/outbound.go` 为 `with_naive_outbound`） |
| `with_gvisor` 描述 | 指向 “WireGuard outbound” | WireGuard outbound 已于 1.13 移除，`include/registry.go` `registerStubForRemovedOutbounds` 仅返回错误；实际影响的是 endpoint 的 gVisor 栈（`transport/wireguard/device_stack.go`）及 tailscale |
| `outbound/index.md` | 仍列出 `wireguard`、`dns` 类型 | `option/outbound.go:44` 对 `dns` 直接报错 “removed in 1.13.0”；`protocol/dns` 只被 `route/dns.go`、`service/resolved` 当库用，`RegisterOutbound` 未被调用 |
| `outbound/dns.md` | “will be removed in 1.13.0” | 已移除（见上） |
| `dns/server/index.md` | “empty (default) → Legacy” | `option/dns.go:131` 对 `""`/legacy 直接报错 “removed in 1.14.0” |
| `inbound/tun.md#gso` | “will be removed in 1.12.0” | `deprecated.md` 写“removed in 1.13.0”；代码 `protocol/tun/inbound.go:71` 报错文本为“removed in 1.12.0”；字段 `option/tun.go:57` 仍保留（`schema:"omit"`）。另：内部在存在 L3 FlowOutbound 时会**自动**开启 GSO（`inbound.go:332-348`） |
| `inbound/tun.md#stack` | “gVisor 标签时默认 mixed，否则 system” | `sing-tun/stack.go NewStack`：`IncludeAllNetworks` 时默认 gvisor；开启 GSO 时默认 system |
| `build-from-source.md` `with_embedded_tor` | 列为可选标签（需 CGO） | v1.14.4 全部 .go 中无 `with_embedded_tor` 引用；`protocol/tor/outbound.go` 只通过 bine 启动/控制外部 tor |
| `rule-set/index.md#type` | “`local` 或 `remote`” | 同页与代码还支持 `inline`（`route/rule/rule_set.go`） |
| `service/index.md` | 未列出 `oom-killer` | `include/oom_killer.go` 无条件注册 `oomkiller.RegisterService`，类型常量 `C.TypeOOMKiller = "oom-killer"`，只在 `docs/schema.json` 出现 |
| `route/index.md`、`route/rule.md` | 仍列出 `geoip`/`geosite` 字段（标注 Removed） | `option/route.go` 保留字段，`route/rule/rule_default.go:124-131` 报错；`common/geoip`、`common/geosite` 仅供 CLI（`cmd_geoip*`/`cmd_geosite*`） |

---

## 2. 顶层目录与代码规模

### 2.1 各顶层目录（非测试 .go 行数，脚本：`find <dir> -name '*.go' ! -name '*_test.go' | xargs cat | wc -l`）

| 目录 | 文件 | 行数 | 职责 |
|---|---|---|---|
| `common/` | 192 | 32,030 | 通用库：dialer、listener、tls、sniff、srs、process、certificate、httpclient、ktls、tlsspoof、windivert… |
| `experimental/` | 171 | 26,511 | libbox（移动/桌面绑定）、boxdd（桌面守护进程 main）、clashapi、v2rayapi、cachefile、clashmode、deprecated、locale |
| `protocol/` | 110 | 25,201 | 每种 inbound/outbound/endpoint 的适配层 |
| `daemon/` | 18 | 14,695 | 图形客户端/API 共用的 gRPC 服务（其中 pb 生成 10,801 行） |
| `service/` | 61 | 12,062 | services：api, resolved, ssmapi, derp, acme, origin_ca, ccm, ocm, oomkiller, usbip, powerreport |
| `cmd/` | 118 | 11,989 | `cmd/sing-box` CLI（9,067）与 `cmd/internal` 构建工具（2,922） |
| `route/` | 79 | 10,112 | Router、ConnectionManager、NetworkManager、规则 `route/rule`（5,062） |
| `dns/` | 43 | 9,758 | DNS Router/Client/TransportManager 与 `dns/transport`（6,451） |
| `transport/` | 67 | 8,864 | v2ray 传输、wireguard/openvpn/openconnect 设备、trojan/sip003/simple-obfs |
| `option/` | 63 | 5,915 | 全部配置结构体及 JSON 反序列化 |
| `adapter/` | 49 | 3,262 | 核心接口 + 4 个 Manager/Registry 实现子包 |
| `constant/` | 43 | 1,000 | 类型名、超时、平台常量 |
| `include/` | 33 | 853 | 按 build tag 组装注册表 |
| `log/` | 10 | 835 | 日志工厂/观察者 |
| `schema/` | 4 | 609 | JSON Schema 生成（1.14） |
| 根目录 `*.go` | — | 836 | `box.go`（Box 构造/启动/关闭）、debug |
| `test/` | 1 | 88 | 集成测试的辅助 |
| `docs/`、`clients/`、`release/` | — | — | mkdocs 文档、客户端子模块、发布配置 |
| **合计** | | **164,620** | 测试另 21,745 |

### 2.2 次级目录（行数）

- `common/`：certificate 7,291（6,808 为生成的 CA 表）· tls 4,776 · ktls 1,802 · httpclient 1,780 · dialer 1,736 · networkquality 1,630 · settings 1,499 · sniff 1,098 · windivert 1,093 · tlsspoof 1,076 · process 1,025 · schannel 1,012 · srs 832 · stun 612 · listener 606 · badtls 520 · ja3 479 · tlsfragment 464 · convertor 454 · trafficcontrol 366 · geosite 340 · netns 259 · urltest 175 · badversion 167 · interrupt 142 · mux 139 · proxybridge 118 · 其余 <100。
- `protocol/`：tailscale 6,387 · bridge 4,512 · openvpn 2,591 · openconnect 1,434 · hysteria2 1,233 · naive 896 · shadowsocks 788 · group 719 · tun 640 · vless 490 · vmess 477 · trojan 471 · direct 453 · snell 387 · hysteria 363 · anytls 361 · tuic 350 · wireguard 344 · cloudflare 330 · ssh 313 · dns 287 · shadowtls 256 · socks 239 · redirect 238 · tor 235 · http 196 · mixed 169 · block 42。
- `transport/`：wireguard 1,769 · openvpn 1,104 · openconnect 1,056 · v2raygrpc 936 · v2rayhttp 818 · v2raywebsocket 652 · trojan 645 · v2raygrpclite 463 · v2rayquic 350 · sip003 326 · simple-obfs 303 · v2rayhttpupgrade 284 · v2ray 158。
- `experimental/`：libbox 10,920 · boxdd 10,846 · clashapi 1,814 · v2rayapi 1,089 · cachefile 1,081。
- `service/`：ocm 2,457 · powerreport 1,671 · ccm 1,622 · oomkiller 1,477 · resolved 1,267 · api 924 · ssmapi 879 · origin_ca 617 · derp 517 · acme 417 · usbip 214。

**按功能归并（便于排期）**：核心骨架（adapter+option+constant+log+include+box.go+schema）≈ 13.3k；路由+DNS ≈ 19.9k；协议适配+传输 ≈ 34.1k；common ≈ 25.2k（扣除 CA 数据）；管理/API/客户端（experimental+daemon+service+cmd）≈ 65k（其中 pb 生成 15.3k）。**可见：代理核心本身不大，大头是客户端/平台/管理面。**

### 2.3 外部模块（go.mod 锁定版本，非测试 .go 行数）

| 模块 | 版本 | 行数 | 用途（使用方） |
|---|---|---|---|
| sagernet/sing | v0.9.7-0.20261023115459 | 32,233 | 基础库：`common/{buf,bufio,network,metadata,exceptions,json,domain,udpnat2,uot,ntp,control}`、`service`（服务定位器）、`protocol/{socks,http}` |
| sagernet/sing-tun | v0.9.7-0.20261023115432 | 33,694 | TUN 设备、system/gvisor/mixed 栈、L3 flow、auto_route/auto_redirect、接口监视、`gtcpip`（6.9k，gVisor header 拷贝） |
| sagernet/gvisor | 20260727.0-sing-box-mod.1 | 196,777 | 用户态 TCP/IP 栈（`with_gvisor`） |
| sagernet/quic-go | v0.61.0-sing-box-mod.12 | 36,586 | QUIC/HTTP3 fork（Chrome QUIC 拟态等） |
| sagernet/sing-quic | v0.7.2-… | 12,648 | Hysteria/Hysteria2/TUIC 协议 |
| sagernet/sing-vmess | v0.2.9-… | 4,632 | VMess、VLESS、packetaddr、XUDP |
| sagernet/sing-shadowsocks | v0.2.9-… | 4,249 | SS AEAD / none（`shadowaead`、`shadowimpl`） |
| sagernet/sing-shadowsocks2 | v0.2.2-… | 2,406 | SS 2022 |
| sagernet/sing-shadowtls | v0.2.2-… | 1,313 | ShadowTLS v1/2/3 |
| anytls/sing-anytls | v0.0.11 | 2,464 | AnyTLS |
| sagernet/sing-snell | — | 9,600 | Snell（1.14） |
| sagernet/sing-mux | v0.3.10-… | 2,534 | 多路复用（smux/yamux/h2mux + padding + brutal） |
| sagernet/smux | v1.5.50-mod.1 | 1,835 | smux fork；另 hashicorp/yamux v0.1.2 |
| sagernet/wireguard-go | v0.0.8-… | 13,826 | WireGuard（MIT） |
| sagernet/tailscale | v1.102.1-sing-box-1.14-mod.5 | 254,019 | Tailscale 客户端 fork（tsnet/ipn 等） |
| sagernet/sing-openvpn | v0.1.1-… | 21,318 | OpenVPN 客户端/服务端 |
| sagernet/sing-openconnect | v0.1.1-… | 34,864 | OpenConnect（AnyConnect/GlobalProtect 等）客户端 |
| sagernet/sing-cloudflared | v0.1.4-… | 12,383 | Cloudflare Tunnel inbound |
| sagernet/sing-usbip | — | 12,414 | USB/IP |
| sagernet/cronet-go | — | 14,313 | Chromium 网络栈绑定（Naive outbound），另有约 30 个平台 `lib/*` 预编译库模块 |
| metacubex/utls | v1.8.7 | 34,150 | uTLS（ClientHello 指纹）+ REALITY 所需的底层 |
| miekg/dns | v1.1.72 | 22,325 | DNS 报文 |
| sagernet/bbolt | — | 11,665 | cache.db |
| sagernet/ws | — | 6,298 | WebSocket |
| sagernet/gliderssh | — | 2,535 | Tailscale SSH server |
| sagernet/netlink / nftables | — | 22,758 / 9,270 | Linux 路由、auto_redirect、bridge |
| cretz/bine | v0.2.0 | 7,320 | Tor 控制 |
| golang.org/x/crypto / x/net | v0.54 / v0.57 | 45,077 / 94,634 | ssh、chacha、http2 等 |
| google.golang.org/grpc | v1.79.1 | 119,748 | daemon / API / v2ray_api / `with_grpc` 传输 |
| sagernet/gomobile、asc-go | — | 17,787 / 12,806 | 移动绑定、App Store Connect 工具 |

除 `wireguard-go`（MIT）外，sagernet `sing*` 模块的 LICENSE 均为同一 GPL-3.0-or-later 文本（已抽查 sing、sing-tun、sing-quic、sing-vmess、sing-shadowsocks2、sing-mux、sing-openvpn、sing-openconnect、sing-snell、sing-cloudflared）。

---

## 3. 核心抽象（`adapter/`）

`adapter` 只依赖 `constant`、`log`、`option`、`common/{interrupt,taskmonitor,tlsspoof}`（见 §9），是全仓的“接口层”，fan-in 90。

### 3.1 生命周期（`adapter/lifecycle.go`）—— 1.14 的新模型

```go
type StartStage uint8 // StartStateInitialize, StartStateStart, StartStatePostStart, StartStateStarted
type Lifecycle interface { Start(stage StartStage, scope *Scope) error }
type LifecycleService interface { Name() string; Lifecycle }
type SimpleLifecycle interface { Start() error; Close() error }
```
- **没有 `Close()`**：组件在 `Start` 时向 `*Scope` 注册清理函数（`scope.Add(h.listener.Close)`）。
- `Scope`：持有 `ctx/cancel`、`cleanups []func() error`、`children map[Lifecycle]*Scope`。`Scope.Start(name, component, stage)` 为每个组件**懒建子 Scope**，并把“关闭子 Scope”作为清理项登记到父 Scope；带 `taskmonitor` 超时告警（`C.StartTimeout`/`C.StopTimeout`）。
- `Scope.Close()`：先 `cancel()`，再 **LIFO** 逆序执行清理（`slices.Backward`），过滤 closed/canceled 错误。

### 3.2 Inbound / Outbound / Endpoint

- `adapter/inbound.go`：`Inbound{Lifecycle; Type(); Tag()}`；`TCPInjectableInbound`/`UDPInjectableInbound`（用于 `detour` 注入）；`InboundRegistry`、`InboundManager`。
- `adapter/outbound.go`：`Outbound{Type(); Tag(); Network() []string; Dependencies() []string; N.Dialer}`——**出站本质是 `N.Dialer`**。扩展：`OutboundWithPreferredRoutes`（`preferred_by`）、`OutboundWithMultiplex`、**`FlowOutbound`（1.14：嵌入 `tun.Port` + `PreMatchFlow`，L3 直转）**、`IdleConnectionKeeper`、`Referrer`。
- `adapter/endpoint.go`：`Endpoint = Lifecycle + Outbound`（同时可作入站源）。
- `adapter/experimental.go`：`OutboundGroup`（`Selected(network)`、`AttachConnection`）、`URLTestGroup`、`CacheFile`、`V2RayServer`。

### 3.3 连接元数据 `InboundContext`（`adapter/inbound.go`）

单一大结构体，按值传递、在 context 中以指针挂载（`WithContext/ContextFrom/ExtendContext/OverrideContext`）。字段分组：
- 基础：`Inbound, InboundType, IPVersion, Network, Source, Destination(M.Socksaddr), User, Outbound`
- 路由结果：`RouteRule, RouteOutbound, OutboundChain`
- 嗅探：`Protocol, Domain, Client, SniffContext, SnifferNames, SniffError`
- 路由选项：`InboundDetour, LastInbound, OriginDestination, RouteOriginalDestination, UDPDisableDomainUnmapping, UDPConnect, UDPTimeout, TLSFragment*, TLSRecordFragment, TLSSpoof*, NetworkStrategy, NetworkType, FallbackNetworkType, FallbackDelay`
- 匹配缓存：`DestinationAddresses, DNSResponse, NamedDNSResponses, ProcessInfo, SourceMACAddress, SourceHostname, QueryType, QueryClientSubnet, QueryDNSSEC, FakeIP, PreMatch`，以及 `SourceAddressMatch` 等规则组匹配标志（`ResetRuleCache`）。

### 3.4 Handler 接口（`adapter/handler.go`、`adapter/upstream.go`）

- `ConnectionHandler.NewConnection(ctx, net.Conn, InboundContext, onClose)`；`PacketConnectionHandler.NewPacketConnection(ctx, N.PacketConn, InboundContext, onClose)`。
- 与 sing 的 `N.TCPConnectionHandlerEx.NewConnectionEx(ctx, conn, source, destination, onClose)` / `N.UDPConnectionHandlerEx` 之间由 `adapter/upstream.go` 的适配器桥接：`NewUpstreamHandler`、`NewUpstreamContextHandler`、`NewRouteHandler`、`NewRouteContextHandler`。协议库（sing-vmess 等）只认识 sing 的接口，sing-box 用这些 wrapper 把它们接回 Router。

### 3.5 sing 中的网络原语（`sing/common/network`、`sing/common/metadata`、`sing/common/buf`）

- `N.Dialer{DialContext(ctx, network, M.Socksaddr) (net.Conn, error); ListenPacket(ctx, M.Socksaddr) (net.PacketConn, error)}`（`network/dialer.go`）。
- `N.PacketConn`（`ReadPacket(*buf.Buffer) (M.Socksaddr, error)` / `WritePacket`）、`ExtendedConn`、`ReadWaiter`（`network/direct.go`，零拷贝读）、`CloseHandlerFunc = func(error)` 与 `AppendClose`。
- `M.Socksaddr{Addr netip.Addr; Fqdn string; Port uint16}`：IP 或域名二选一的目的地址。
- `buf.Buffer`：带前置 headroom 的池化缓冲，协议层可就地加/去头。

### 3.6 Router / DNS / 其它 Manager

- `adapter/router.go`：`Router{Lifecycle; ConnectionRouter(Ex); PreMatch(metadata, firstPacket) PreMatchResult; HijackDNSPacket; RuleSet(tag); Rules(); NeedFindProcess(); NeedFindNeighbor(); NeighborResolver(); AppendTracker(ConnectionTracker); ResetNetwork()}`。`PreMatchAction`：Continue/Flow/Reject/Drop/Bypass/HijackDNS；`JudgeFlow()` 把它翻译为 `tun.FlowVerdict`。`ConnectionTracker`（Clash/V2Ray 统计挂钩）。`RuleSet` 接口含引用计数、更新回调、`ExtractIPSet`。
- `adapter/dns.go`：`DNSRouter{Exchange, ExchangeAsync, Lookup, ClearCache, LookupReverseMapping, ResetNetwork}`、`DNSClient`、`DNSQueryOptions`、`DNSTransport{Type, Tag, Dependencies, Reset, Exchange, ExchangeAsync}`、`DNSTransportManager`（含 `FakeIP()`）、`RDRCStore`、`DNSCacheStore`。
- `adapter/fakeip.go`：`FakeIPStore`、`FakeIPStorage`、`FakeIPTransport`。
- `adapter/connections.go`：`ConnectionManager{Count, CloseAll, TrackConn, TrackPacketConn, NewConnection(ctx, dialer, conn, metadata, onClose), NewPacketConnection(...)}`。
- `adapter/network.go`：`NetworkManager`（接口查找、默认接口、auto-detect/protect `control.Func`、auto_redirect mark、`tun.NetworkUpdateMonitor/DefaultInterfaceMonitor/PackageManager`、Wi-Fi 状态、ResetNetwork、FlushSystemDNSCache）。
- `adapter/platform.go`：`PlatformInterface`——移动/桌面宿主的回调面：`OpenInterface`（由宿主打开 TUN fd）、`AutoDetectInterfaceControl(fd)`（Android protect）、接口监视、`FindConnectionOwner`、Wi-Fi、通知、邻居监视、Shell（Tailscale SSH）、`CreateBridge` 等。
- `adapter/service.go`：`Service{Lifecycle; Type; Tag}`、`ServiceRegistry`、`ServiceManager`。
- 其它：`certificate_provider.go`（`CertificateProvider*`）、`http.go`（`HTTPClientManager`、`HTTPStartContext`）、`neighbor.go`、`netns.go`、`security.go`（`CheckSecurityFeature`）、`v2ray.go`（`V2RayServerTransport/ClientTransport`）、`ssm.go`、`tailscale.go`、`openvpn.go`、`openconnect.go`、`usbip.go`、`time.go`。

### 3.7 注册表（`adapter/{inbound,outbound,endpoint,service,certificate}/registry.go`、`dns/transport_registry.go`）

泛型注册：`inbound.Register[Options any](registry, type, func(ctx, router, logger, tag, Options) (adapter.Inbound, error))`。Registry 同时实现两件事：
1. `option.InboundOptionsRegistry.CreateOptions(type) (any, bool)` —— **JSON 反序列化阶段**按 type 生成空 Options 结构体；
2. `adapter.InboundRegistry.Create(...)` —— 构造阶段用 `options any` 调回具体构造器。
`include/registry.go` 把各协议的 `RegisterXxx` 汇总；可选协议在 `include/<feature>.go` / `<feature>_stub.go` 成对实现（见 §7）。

### 3.8 context 服务定位器（`sing/service/context.go`、`registry.go`）

`service.ContextWithDefaultRegistry(ctx)` 在 context 中放一个 `map[类型]实例` 的 Registry；`service.MustRegister[T](ctx, v)` / `service.FromContext[T](ctx)` / `PtrFromContext`。**全仓 90 个文件**通过它取依赖，频次（脚本统计）：`NetworkManager` 38、`DNSRouter` 21、`OutboundManager` 18、`EndpointManager` 14、`PlatformInterface` 12、`CacheFile` 12、`HTTPClientManager` 9、`DNSTransportManager` 9、`pause.Manager` 8、`urltest.HistoryStorage` 7、`Router` 7、`ConnectionManager` 7、`clashmode.Manager` 6、`ServiceManager` 6……这是**隐式耦合**：编译期包依赖图看不到，但运行期几乎所有协议都依赖 Manager 已注册（见 §9.3）。

---

## 4. 启动流程（`box.go`）

### 4.1 配置解析
1. `include.Context(ctx)`（`include/registry.go`）→ `box.Context(...)` 把 6 个 Registry（inbound/outbound/endpoint/dns transport/service/certificate provider）以**两种接口身份**（`option.*OptionsRegistry` 与 `adapter.*Registry`）放入 context。
2. `json.UnmarshalContext(ctx, bytes, &option.Options)`：`option.Inbound.UnmarshalJSONContext`（`option/inbound.go`）先解析 `type/tag`，再 `registry.CreateOptions(type)`，然后 `badjson.UnmarshallExcludedContext` 把其余字段解到具体 Options；同时拦截已移除字段并报迁移提示。`sing/common/json` 是 `encoding/json` 的 context 化 fork（`internal/contextjson`）+ 注释剥离。
3. `badoption.*`（`Listable`、`Duration`、`Addr`、`Prefix`…）提供“单值或数组”、Go duration 字符串等宽松类型。

### 4.2 `box.New(options)`（构造顺序）
1. 校验 6 个 Registry；`pause.WithDefaultManager`；`urltest.NewHistoryStorage`；`log.New` → `MustRegister[log.Factory]`。
2. `certificate.NewStore`（非 system store 或有自定义证书时）、`netns.NewManager`。
3. 构造 Manager 并注册：`endpoint.NewManager` → `inbound.NewManager` → `outbound.NewManager(…, route.final)` → `dns.NewTransportManager(…, dns.final)` → `boxService.NewManager` → `boxCertificate.NewManager`。
4. `dns.NewRouter` → `route.NewConnectionManager` → `route.NewNetworkManager` → `httpclient.NewManager` → `route.NewRouter`，`router.Initialize(rules, rule_set)`。
5. 需要 Clash API / API service / 平台日志时：`trafficcontrol.NewManager`（作为 ConnectionTracker 追加到 router）、`clashmode.NewManager`。`route.NewReferenceManager`。NTP 时注册 `ntp.TimeService` 包装。
6. **按配置创建组件**：DNS servers → `dnsRouter.Initialize(dns.rules)` → endpoints → inbounds → services → outbounds → certificate providers（outbound/endpoint 的 ctx 预挂 `InboundContext{Outbound: tag}`）。
7. 默认回退：`outboundManager.Initialize(direct)`、`dnsTransportManager.Initialize(local)`、`httpClientManager.Initialize(…)`（隐式默认 HTTP client，已弃用）。
8. `platformInterface.Initialize(networkManager)`；cache file、Clash server、V2Ray server、NTP service 作为 `internalService`。

### 4.3 `Box.Start()`（`preStart` + `start`）
- logger 启动 → debug HTTP → internal services `Initialize`；
- **Initialize 阶段**：httpclient, network, dns-transport, dns-router, connection, router, outbound, endpoint, certificate-provider, inbound, service；
- **Start 阶段 (preStart)**：outbound, dns-transport, network, connection, httpclient, router, dns-router；
- （`start`）internal services Start → NTP → **Start 阶段**：endpoint, certificate-provider, inbound, service；
- **PostStart**：outbound, network, dns-transport, dns-router, connection, router, endpoint, certificate-provider, inbound, service → internal services PostStart；
- **Started**：同序 + internal services Started。
- `PreStart()` 单独暴露给 libbox（先起出站/DNS/路由，平台再起 TUN）。
- 出站启动按依赖拓扑：`adapter/outbound/manager.go startOutbounds` 反复扫描，`Dependencies()` 全部已启动才启动；无法推进时 `lintOutbound` 报 “circular outbound dependency” 或 “dependency not found”。Endpoint 经 `EndpointManager.StartEndpoint` 启动。
- 任一步失败调用 `Close()`。

### 4.4 关闭
`Box.Close()` = `scope.Close()`：取消根 context，LIFO 关闭——即**按启动注册的逆序**：最后启动的（service/inbound…）先关，logger 最后关（它最先 `scope.Add`）。

---

## 5. 数据路径

### 5.1 入站接收
- 监听：`common/listener.Listener`（`listener_tcp.go loopTCPIn`、`listener_udp.go`），处理 Listen Fields（bind_interface、routing_mark、netns、TFO、MPTCP、keepalive、detour）。
- 典型协议入站（`protocol/vmess/inbound.go`）：`listener.New(Options{ConnectionHandler: inbound})` → `NewConnection` 中可选 `tls.ServerHandshake` → 可选 `v2ray.NewServerTransport` → `sing-vmess` 的 `vmess.Service` 解析 → 通过 `adapter.NewUpstreamContextHandler(newConnectionEx, newPacketConnectionEx)` 回调 → 填充 `metadata.Inbound/InboundType/User` → `router.RouteConnectionEx`。多路复用入站由 `common/mux.NewRouterWithOptions` 包装 router。
- `detour`：`metadata.InboundDetour` 由 `routeConnection` 转交给另一入站（需 `TCPInjectableInbound`），检测环路。

### 5.2 路由（`route/route.go`）
`routeConnection`：
1. 处理 detour、拒绝已废弃的全局 mux/UoT 魔法地址；TUN 上协议为 DNS 时直接 `hijackDNSStream`。
2. `matchRule()`：`prepareMatchMetadata`（`searchProcessInfo` 进程查找、邻居 MAC/主机名、**FakeIP 反查**把目的地还原为域名、DNS 反向映射 `LookupReverseMapping`、IPVersion）→ **顺序遍历 `r.rules`**：每条先 `ResetRuleCache()` 再 `Match`；命中后应用 route-options（override 地址/端口、网络策略、UDP、TLS fragment/spoof…）；`sniff` 动作调用 `actionSniff` 读取首包（缓冲放入 `buffers`，之后用 `bufio.NewCachedConn` 回放），`resolve` 动作调用 `actionResolve` 做 DNS 解析写入 `DestinationAddresses`；遇到 route/reject/hijack-dns（或带 outbound 的 bypass）为终止动作。
3. 无命中 → `outbound.Default()`；`resolveOutbound` 沿 `OutboundGroup.Selected(network)` 展开得到 `OutboundChain`，检查网络支持。
4. 依次经 `ConnectionTracker.RoutedConnection` 包装（统计）；`registerInterrupt` 让 group 切换时可中断连接。
5. 链尾出站若实现 `adapter.ConnectionHandler`（如 block 等自处理出站）则直接交给它，否则 `ConnectionManager.NewConnection`。

### 5.3 出站与拷贝（`route/conn.go`）
- `NewConnection`：有 `DestinationAddresses` 或目的为 IP 时 `dialer.DialSerialNetwork`（多地址串行/网络策略回退），否则 `outbound.DialContext`（由出站或其 `ResolveDialer` 解析域名）。失败则删除 urltest 历史。
- `N.ReportConnHandshakeSuccess`（如 SOCKS 回复成功）；按需包 `tlsfragment.NewConn`、`tlsspoof.NewConn`。
- `kickWriteHandshake`（处理需要先写的握手，`sniff.Skip` 判断服务端先发协议）→ 两个 goroutine `connectionCopy` → `bufio.CopyWithIncreateBuffer`。
- `sing/common/bufio/copy.go`：`CopyExtended` 利用 `ReadWaiter` 零拷贝、`splice_linux.go` 在两端都是裸 TCP 时走 splice；`vectorised*`、`packet_batch_*`（sendmmsg/recvmmsg、Linux UDP GSO offload）做批量。
- 出站构建：`common/dialer.New(ctx, DialerOptions, remoteIsDomain)` → `DefaultDialer`（绑定接口、mark、netns、TFO、MPTCP、并行接口/网络 `default_parallel_*.go`）或 `DetourDialer`（`detour` 指向另一出站），外包 `ResolveDialer`（`domain_resolver` → `DNSRouter.Lookup`）。协议出站（`protocol/vmess/outbound.go`）：`dialer.New` → 可选 `tls.NewClient/NewDialer` → 可选 `v2ray.NewClientTransport` → 可选 `mux.NewClientWithOptions` → `vmess.NewClient`。

### 5.4 UDP / PacketConn 与 NAT
- `routePacketConnection`（`route/route.go:248`）流程同 TCP，嗅探用 `PeekPacket`/`packetBuffers`；hijack-dns 走 `route/dns.go`（复用 `protocol/dns.NewDNSPacketConnection`）。
- `ConnectionManager.NewPacketConnection`：`ListenPacket` 得到远端 PacketConn；`UDPConnect` 时 `DialContext(udp)` + `bufio.NewUnbindPacketConn`；根据 FakeIP/override 使用 `bufio.NewNATPacketConn` / `NewUnidirectionalNATPacketConn` / `NewDestinationNATPacketConn` 做地址改写，使回包源地址与客户端期待一致（`UDPDisableDomainUnmapping` 控制域名回写）；`packetConnectionCopy` → `bufio.CopyPacket`（含 batch 路径）。
- UDP 会话 NAT 表：普通监听入站用 `sing/common/udpnat2`（`protocol/direct/inbound.go`），L3 入站由 `sing-tun/udp_nat.go` 管理；1.14 的 UDP NAT 选项（`udp_mapping/udp_filtering/udp_nat_max`，`shared/udp-nat.md`）出现在 tun/tproxy/wireguard/openvpn/openconnect 的 option 中。
- UDP over TCP：`common/uot` + `sing/common/uot`。`route/fakeip_conn.go` 处理 FakeIP 的包级改写。

### 5.5 TUN 的接入（`protocol/tun/inbound.go` + sing-tun）
- `NewInbound` 校验/转换选项 → `Start(StartStateStart)`：`tun.NewAutoRedirect`（Linux nftables，`sing-tun/redirect_nftables*.go`）→ `tun.New(tunOptions)` 或 `PlatformInterface.OpenInterface` → `tun.NewStack(stack, StackOptions{Handler: inbound})`。
- `sing-tun/stack.go NewStack`：`system`（`stack_system.go` 1,010 行：利用内核 TCP 栈 + 自身 NAT 改写，监听本地端口回接）、`gvisor`（`stack_gvisor*.go`）、`mixed`（system TCP + gVisor UDP）。
- `tun.Handler` 回调（`sing-tun/tun.go`）：`JudgeFlow(network, src, dst, firstPacket) FlowVerdict`（→ `adapter.JudgeFlow` → `Router.PreMatch`）、`NewDNSPacket`（→ `Router.HijackDNSPacket`）、`NewConnectionEx`/`NewPacketConnectionEx`（→ `RouteConnectionEx`）。
- **L3 flow（1.14）**：`sing-tun/flow*.go`（`flow_dispatch.go` 848 行）在 IP 层直接把包转给实现 `tun.Port` 的出站（bridge、WireGuard、Tailscale），`FlowTracker` 计数；Linux 上有 FlowOutbound 时 TUN 自动启用 GSO。
- WireGuard/OpenVPN/OpenConnect endpoint 同样在 `transport/*/device_stack.go` 内跑一个 gVisor 栈（或 `device_system_stack.go` 系统 TUN）把隧道内 L3 包转成 L4 连接再交给 Router。

---

## 6. 路由与规则

### 6.1 规则结构（`route/rule/`）
- `NewRule`（`rule_default.go`）把 `option.Rule` 编译为 `abstractDefaultRule`（`rule_abstract.go`）：items 按**组**存放（`sourceAddressItems`、`sourcePortItems`、`destinationAddressItems`、`destinationIPCIDRItems`、`destinationPortItems`、其他 `items`），**组内 OR、组间 AND**，再 `invert`；`ruleSetItem` 单独处理。`abstractLogicalRule` 实现 and/or 嵌套。
- 1.14 修正的 rule-set 语义：`evaluateForMerge` / `match_state.go` 的 `ruleGroupMatch` 只在被引用规则集“恰好一条非 invert default 规则”时做合并匹配（`route/rule/rule_set_semantics_test.go`）。
- 条目实现：`rule_item_*.go` 共 40+ 个（domain、domain_keyword、domain_regex、cidr、port(_range)、process_*、package_name(_regex)、user(_id)、wifi_*、network_*、preferred_by、source_mac_address、source_hostname、query_*、response_*、adguard、clash_mode、client、auth_user、rule_set…）。域名匹配使用 `sing/common/domain.Matcher`（succinct trie，修改自 openacid/succinct，`set.go`）。
- 动作：`rule_action.go`：`RuleActionRoute/Bypass/RouteOptions/Reject/HijackDNS/Sniff/Resolve`，DNS 侧 `RuleActionDNSRoute/Evaluate/Respond/DNSRouteOptions/Predefined`。

### 6.2 Rule-set
- `rule_set.go`（工厂，处理 `{tag}` 多标签）、`rule_set_local.go`（文件 + `fswatch` 热重载）、`rule_set_remote.go`（`HTTPClientManager` 下载、`update_interval`、缓存到 `CacheFile.SaveRuleSet`）、`rule_set_updater.go`；`adapter.RuleSetMetadata` 用来告知 DNS/TUN 是否含进程/Wi-Fi/IPCIDR 规则（`DNSRuleSetUpdateValidator` 拒绝不兼容的热更新）。
- SRS 二进制（`common/srs/binary.go`）：魔数 `"SRS"`、1 字节版本（`constant/rule.go`：`RuleSetVersion1..5`，当前 5）、其后 **zlib** 压缩的 varbin 规则流；条目类型码 `ruleItemQueryType…ruleItemPackageNameRegex`、`ruleItemFinal=0xFF`；IP 用 `ip_set.go` 范围序列化，域名直接写 succinct 结构。CLI：`cmd_rule_set_{compile,decompile,convert,merge,match,upgrade,format}`；`common/convertor/adguard` 转 AdGuard 规则。
- GeoIP/Geosite：已移除（§1.6），`common/geoip`（mmdb 读取 38 行）与 `common/geosite`（340 行）仅服务于 CLI 导出/转换。

### 6.3 嗅探（`common/sniff`）
TLS ClientHello、HTTP Host、QUIC ClientHello（含分片重组 `quic.go`、`quic_blacklist.go`）、DNS（UDP/流）、STUN、BitTorrent/uTP、DTLS、SSH、RDP、NTP。接口 `StreamSniffer` / `PacketSniffer`，`PeekStream`/`PeekPacket` 带超时并返回 `ErrNeedMoreData`；`sniff.Skip` 对服务端先发协议的端口跳过。

### 6.4 进程/邻居查找
- `common/process`：Linux `socket_diag_linux.go`（netlink sock_diag）+ procfs；Darwin `searcher_darwin*.go`（sysctl pcblist）；Windows `searcher_windows.go`（iphlpapi，`sing/common/winiphlpapi`）；Android 走 `PlatformInterface.FindConnectionOwner`。`route/process_cache.go` 缓存。
- 邻居：`route/neighbor_resolver_*.go`、`neighbor_table_*.go`（ARP/NDP 表）、`neighbor_resolver_lease.go`（解析 DHCP 租约文件 `dhcp_lease_files`）。

### 6.5 NetworkManager（`route/network.go`，617 行）
默认接口跟踪（`tun.DefaultInterfaceMonitor`）、`auto_detect_interface`、网络策略（`network_strategy`/`network_type`，配合 `common/dialer/default_parallel_*.go`）、Wi-Fi 状态、`network_environment_*.go`（检测网络变化以 ResetNetwork）。

---

## 7. DNS 子系统

### 7.1 组件
- `dns/router.go`（1,775 行）：`Router.Exchange/Lookup` → `matchDNS`/`walkDNSRules`：遍历 DNS 规则，支持 `route`（选择 transport）、**`evaluate`**（异步发起查询得到响应并打 tag，`launchDNSEvaluate`/`settleDNSFutures`，可并行赛跑 `Race()`）、`respond`、`predefined`、`reject`；`match_response` 后的规则用响应字段（rcode/answer/ns/extra）匹配。保留 `exchangeLegacy` 兼容旧地址过滤字段。`recordReverseMapping` 支持 `reverse_mapping`。
- `dns/client.go`（920 行）：缓存（`sing/contrab/freelru`，按 transport 独立或共享）、乐观缓存（过期先返回后台刷新）、`RewriteTTL`、`ClientSubnet`（`extension_edns0_subnet.go`）、截断处理、RDRC（拒绝响应缓存）与持久 DNS 缓存（`CacheFile`）。
- `dns/transport_manager.go`、`transport_registry.go`、`transport_adapter.go`、`transport_dialer.go`（transport 自身用的 dialer/detour）。
- 注意：`dns` 包导入了 `service/powerreport` 与 `route/rule`（规则实现与路由共用）。

### 7.2 Transports（类型 → 实现）
| type | 实现 | 备注 |
|---|---|---|
| udp / tcp | `dns/transport/udp.go`、`tcp.go`、`conn_pool.go`、`multiplexer.go` | 连接复用/多路复用 |
| tls | `dns/transport/tls.go` | DoT |
| https | `dns/transport/https.go`、`https_transport.go` | DoH，走 `common/httpclient` |
| quic / h3 | `dns/transport/quic/{quic,http3}.go` | `with_quic`，sing-quic/quic-go |
| local | `dns/transport/local/`：`local.go`、`local_darwin.go`、`local_resolved_linux.go`（systemd-resolved D-Bus，809 行）、`systemconfig` | 系统解析器 |
| hosts | `dns/transport/hosts/` | hosts 文件 |
| dhcp | `dns/transport/dhcp/dhcp.go` | `with_dhcp` |
| mdns | `dns/transport/mdns/mdns.go` | 1.14 |
| fakeip | `dns/transport/fakeip/{fakeip,store,memory}.go` | 地址池分配，持久化到 CacheFile（`bucketFakeIP`） |
| tailscale | `protocol/tailscale/dns_transport.go` | `with_tailscale` |
| openvpn / openconnect | `protocol/openvpn`、`protocol/openconnect` 的 `RegisterDNSTransport` | 隧道下发的 DNS |
| resolved | `service/resolved/transport.go` | 与 resolved service 联动 |

### 7.3 FakeIP 闭环
`fakeip` transport 为 A/AAAA 分配池内地址 → 连接到达时 `route.prepareMatchMetadata` 用 `FakeIP().Store().Lookup` 还原域名（`metadata.FakeIP=true`）→ UDP 回包由 NAT PacketConn 改写回 fake 地址。L3 pre-match 下 FakeIP 目的必须先 `resolve`（`shared/pre-match.md`）。

---

## 8. 协议清单

注册入口均在 `include/registry.go`；“外部模块”指主要协议实现所在模块；“标签”为门控 build tag（空 = 无条件）。

### 8.1 Inbound
| type | 包 | 外部实现 | 标签 |
|---|---|---|---|
| tun | `protocol/tun` | sing-tun（+gvisor） | gvisor 栈需 `with_gvisor` |
| redirect / tproxy | `protocol/redirect` | sing-tun / 内核 | — |
| direct | `protocol/direct` | sing udpnat2 | — |
| socks / http / mixed | `protocol/{socks,http,mixed}` | `sing/protocol/{socks,http}` | — |
| shadowsocks | `protocol/shadowsocks` | sing-shadowsocks、sing-shadowsocks2 | — |
| snell | `protocol/snell` | sing-snell | — |
| vmess / vless | `protocol/{vmess,vless}` | sing-vmess | — |
| trojan | `protocol/trojan` | 自实现 `transport/trojan`（+smux） | — |
| naive | `protocol/naive`（inbound 无条件；`quic/` 子包 HTTP/3 由 `include/quic.go` 引入，未启用时 `include/quic_stub.go` 给 `ConfigureHTTP3ListenerFunc` 打桩） | x/net http2、quic-go | QUIC 部分 `with_quic` |
| shadowtls | `protocol/shadowtls` | sing-shadowtls | — |
| anytls | `protocol/anytls` | anytls/sing-anytls | — |
| hysteria / tuic / hysteria2 | `protocol/{hysteria,tuic,hysteria2}` | sing-quic + quic-go | `with_quic` |
| cloudflared | `protocol/cloudflare` | sing-cloudflared | `with_cloudflared` |
| shadowsocksr | `include/registry.go` 桩 | — | 报错（1.6 移除） |

### 8.2 Outbound
| type | 包 | 外部实现 | 标签 |
|---|---|---|---|
| direct | `protocol/direct` | — | — |
| bridge (1.14) | `protocol/bridge`（Linux netlink/nftables、Darwin pf、Windows WinDivert） | sing-tun、netlink、nftables、`common/windivert` | 平台：linux/darwin/windows(amd64,386) |
| block | `protocol/block` | — | — |
| selector / urltest | `protocol/group` | `common/urltest` | — |
| socks / http | `protocol/{socks,http}` | sing | — |
| shadowsocks / snell / vmess / vless / trojan / shadowtls / anytls | 同名包 | 同 8.1 | — |
| naive | `protocol/naive/outbound.go` | **cronet-go（Chromium）** | `with_naive_outbound` |
| tor | `protocol/tor` | cretz/bine（控制外部 tor 进程） | —（文档的 `with_embedded_tor` 在代码中无引用，见 §1.6） |
| ssh | `protocol/ssh` | x/crypto/ssh | — |
| hysteria / tuic / hysteria2 | 同名包 | sing-quic | `with_quic` |
| wireguard / shadowsocksr / dns | 桩或报错 | — | 已移除 |

### 8.3 Endpoint
| type | 包 | 外部实现 | 标签 |
|---|---|---|---|
| wireguard | `protocol/wireguard` + `transport/wireguard` | wireguard-go fork + gvisor | `with_wireguard`（栈 `with_gvisor`） |
| tailscale | `protocol/tailscale`（含 `tailssh/`、taildrop、证书提供者、DNS transport） | tailscale fork、gvisor、gliderssh、pkg/sftp | `with_tailscale`（大部分文件再加 `with_gvisor`） |
| openvpn-client / openvpn-server | `protocol/openvpn` + `transport/openvpn` | sing-openvpn + gvisor | `with_openvpn` |
| openconnect | `protocol/openconnect` + `transport/openconnect` | sing-openconnect + gvisor | `with_openconnect` |

### 8.4 Service / Certificate provider
- Service：`api`（`service/api`，暴露 `daemon` gRPC + dashboard）、`resolved`、`ssm-api`、`hysteria-realm`（`with_quic`）、`derp`（`with_tailscale`）、`ccm`（`with_ccm`）、`ocm`（`with_ocm`）、`oom-killer`（无条件）、`usbip-server/client`（`with_usbip`，linux / darwin+cgo / windows）。
- Certificate provider：`acme`（`service/acme`，`with_acme`，基于 caddyserver/certmagic、mholt/acmez、libdns/* DNS-01 提供者）、`tailscale`、`cloudflare-origin-ca`（`service/origin_ca`）。

### 8.5 共享层
- TLS（`common/tls`）：`std_client/std_server`（crypto/tls）、`utls_client.go`（metacubex/utls，`with_utls`）、`reality_client.go`/`reality_server.go`（同 `with_utls`）、`ech*.go`（stdlib ECH + DNS HTTPS 记录查询，因此 `common/tls` 依赖 `dns`）、`ktls.go`→`common/ktls`、`apple_client*.go`（Network.framework，cgo/.m）、`windows_client.go`→`common/schannel`、`acme.go`（内联 ACME，已弃用）、`common/badtls`、`common/tlsfragment`、`common/tlsspoof`（原始套接字伪造 ClientHello）、`common/ja3`。
- V2Ray 传输（`transport/v2ray/transport.go` 按 `C.V2RayTransportType*` 分派）：http（`v2rayhttp`，x/net http2/h2c）、ws（`v2raywebsocket`，sagernet/ws）、quic（`v2rayquic`，`with_quic`）、grpc（`v2raygrpc` 需 `with_grpc`，否则 `v2raygrpclite`）、httpupgrade（`v2rayhttpupgrade`）。
- 多路复用：`common/mux` → sing-mux（smux/yamux/h2mux、padding、`brutal_linux.go` TCP Brutal）。
- SIP003 插件：`transport/sip003` + `transport/simple-obfs`（以及 v2ray-plugin 兼容，借 sing-vmess）。

---

## 9. 实验性与管理面

- **cache file**（`experimental/cachefile`，sagernet/bbolt）：bucket `selected`、`group_expand`、`clash_mode`、`rule_set`、`dns_cache`、`rdrc2`、FakeIP（`fakeip` 前缀）、`cache_id` 命名空间（`default`）。实现 `adapter.CacheFile`（FakeIPStorage + RDRCStore + DNSCacheStore + 选择器记忆）。
- **clash_api**（`experimental/clashapi`，go-chi）：路由 `/logs /traffic /memory /version /configs /proxies /group /rules /connections /providers/{proxies,rules} /script /profile /cache /dns /upgrade /ui`；依赖 `trafficcontrol.Manager`（连接跟踪/流量统计）与 `clashmode.Manager`（`clash_mode` 规则条目）。
- **v2ray_api**（`experimental/v2rayapi`，`with_v2ray_api`）：gRPC StatsService（`stats.pb.go`），作为 ConnectionTracker 计数。
- **daemon**（`daemon/`）：`started_service.proto` 定义 `StartedService`（42 个 RPC：状态/日志订阅、分组选择、URLTest、Clash 模式、连接列表与关闭、网络质量/STUN 测试、Tailscale 状态/Ping/SSH/Taildrop、USB/IP、OpenConnect/OpenVPN 认证挑战、通知）；`managed_service.proto` 定义 `ManagedService`。`service/api` 把它通过监听端口暴露（1.14 “sing-box API service”），CLI `cmd_api_*` 是其客户端。
- **libbox**（`experimental/libbox`，gomobile 绑定，10,920 行）：`CommandServer`/`CommandClient`、`PlatformInterface` 宿主回调桥接、各种 Iterator 类型；导入 `daemon`。**boxdd**（`experimental/boxdd`，package main，`desktop_service.proto`：`DesktopService`、`ApplicationService`）：桌面客户端的系统服务/工作进程。
- 其它：`experimental/clashmode`、`experimental/deprecated`（运行时弃用告警汇总，`deprecated.Report`）、`experimental/locale`；`service/powerreport`（被 `dns`、`common/dialer` 等导入，用于功耗统计）。

---

## 10. 耦合分析（`go list` 生成）

### 10.1 总体
- 144 个内部包、772 条内部导入边，**无循环（Tarjan 无非平凡 SCC）**——Go 本身禁止循环，sing-box 通过 `adapter` 接口层 + context 定位器规避。
- **Fan-in 最高**：`log` 91、`adapter` 90、`option` 86、`constant` 83、`common/dialer` 38、`common/tls` 35、`common/listener` 26、`adapter/outbound` 22、`adapter/inbound` 20、`dns` 19、`adapter/service` 11、`common/uot` 10、`experimental/deprecated` 9、`dns/transport` 8、`service/powerreport` 6、`common/urltest` 5、`transport/v2ray` 5。
- **Fan-out 最高**：`include` 59、根包 `box` 24、`experimental/libbox` 24、`cmd/sing-box` 18、`route` 17、`daemon` 16、`experimental/boxdd` 14、`protocol/tailscale` 14、`protocol/{naive,openvpn,trojan,vless,vmess}` 12、`common/tls` 11、`dns` 11。
- 关键包的内部传递依赖数：`constant` 1、`option` 3、`log` 4、`adapter` 8、`common/srs` 4、`common/dialer` 16、`route/rule` 17、`dns` 24、`common/tls` 28、`dns/transport` 29、`route` 30、`transport/v2ray` 35、`protocol/vmess` 40、根包 45、`include` 115、`libbox` 118。

### 10.2 分层（最长依赖深度）
- L0（叶子，无内部导入，可独立移植）：`common/{badtls,badversion,compatible,geoip,interrupt,iponly,ja3,jni,pipelistener,redir,schannel,stun,taskmonitor,tlsspoof,windivert}`、`common/sniff/internal/qtls`、`constant/goos`、`dns/transport/local/systemconfig`、`experimental/locale`、`schema`、`service/powerreport`、`transport/{simple-obfs,trojan}`、`transport/v2raygrpc/credentials`。
- L1–L4：`constant`、`common/ktls` → `option`、`common/tlsfragment`、`common/networkquality`、`experimental/deprecated` → `log`、`common/srs`、`common/geosite`、`common/convertor/adguard` → `adapter`。
- L5–L7：`adapter/*` 管理器、`common/{certificate,mux,netns,process,sniff,trafficcontrol,uot,urltest,settings}`、`experimental/{cachefile,clashmode}` → `common/listener`、`route/rule`、`protocol/{tun,group,block,bridge}` → `common/dialer`、`experimental/clashapi`、`protocol/redirect`。
- L8–L11：`dns`、简单协议（direct/socks/ssh/tor/snell）、wireguard/openvpn/openconnect 传输 → `common/tls`、fakeip/hosts/mdns → `dns/transport`、`common/httpclient`、`route`、QUIC 协议、v2ray http/grpc → 根包 `box`、dhcp/local/quic DNS、naive、tailscale、openvpn、openconnect、resolved。
- L12–L17：`transport/v2ray`、`daemon` → vmess/vless/trojan/`service/api` → shadowsocks（因 SIP003）→ `include` → `cmd/sing-box`、`libbox` → `boxdd`。

### 10.3 值得注意的依赖
- `adapter` 依赖 `option`（Registry 接口里有 Options 类型）、`common/tlsspoof`（`InboundContext.TLSSpoofMethod`）——接口层并不纯。
- `log` 依赖 `option`；`option` 只依赖 `constant`、`schema`：配置层非常干净，可最先移植。
- `common/tls → dns`（ECH 查询 HTTPS 记录）、`common/dialer → service/powerreport`、`dns → route/rule`：跨子系统的“横向”边。
- `route` 直接导入 `protocol/dns`（作为 DNS 劫持处理库）与 `experimental/clashmode`。
- **隐式耦合（context 定位器）**：`common/dialer` 通过 `service.FromContext[adapter.OutboundManager]`（detour）、`[adapter.NetworkManager]`、`[adapter.DNSRouter]` 取依赖；协议几乎都在构造时取 `NetworkManager`/`DNSRouter`/`OutboundManager`。这些依赖在导入图中只表现为“依赖 adapter”，因此**真实的启动顺序约束只存在于 `box.go` 的构造顺序和 StartStage 中**。Rust 版应把它显式化。

---

## 11. Rust 重写建议

### 11.1 Crate 划分（对应 Go 包）

| Crate | 对应 Go | 说明 |
|---|---|---|
| `xb-core` | `constant`、`adapter`（接口）、`sing/common/{metadata,network,exceptions}` | `Socksaddr`、`InboundContext`、trait：`Inbound/Outbound/Endpoint/Dialer/PacketConn/Router/DnsRouter/DnsTransport/Service/Lifecycle`、`StartStage`、`Scope` |
| `xb-buf` | `sing/common/{buf,bufio}` | 带 headroom 的池化 Buffer、零拷贝 copy、splice、批量 UDP、NAT PacketConn |
| `xb-config` | `option`、`sing/common/json{,badjson,badoption}`、`schema` | serde 模型、注释剥离、多文件合并、迁移错误、JSON Schema（schemars） |
| `xb-log` | `log` | tracing + 可订阅（Clash API） |
| `xb-net` | `common/{dialer,listener,netns,redir,interrupt}`、`route/network*.go`、sing `control` | socket 选项、绑定接口/mark/netns、并行拨号、接口监视 |
| `xb-tls` | `common/{tls,ktls,badtls,tlsfragment,tlsspoof,ja3,certificate}`、`adapter/certificate`、`service/{acme,origin_ca}` | rustls 主干 + 指纹/REALITY 扩展 |
| `xb-rule` | `route/rule`、`common/{srs,sniff,process,geosite,geoip,convertor}`、`sing/common/domain` | 规则编译/匹配、SRS 读写（需二进制兼容）、嗅探、进程查找 |
| `xb-dns` | `dns`、`dns/transport/*` | 客户端缓存、规则路由、各 transport、FakeIP |
| `xb-route` | `route`（Router、ConnectionManager、ReferenceManager） | 规则驱动路由、pre-match、连接拷贝、tracker |
| `xb-transport` | `transport/{v2ray*,sip003,simple-obfs,trojan}`、`common/mux`、sing-mux、smux | ws/h2/grpc/httpupgrade/quic、多路复用 |
| `xb-proto-*` | `protocol/*` + sing-shadowsocks(2)/sing-vmess/sing-shadowtls/sing-anytls/sing-snell/sing-quic | 每协议一 crate 或 feature |
| `xb-tun` | sing-tun | TUN 设备、system/用户态栈、auto_route/auto_redirect、L3 flow |
| `xb-wireguard` / `xb-tailscale` / `xb-openvpn` / `xb-openconnect` | 对应 endpoint | 见 11.4 |
| `xb-experimental` | `experimental/{cachefile,clashapi,v2rayapi,clashmode,deprecated}`、`common/{trafficcontrol,urltest}` | |
| `xb-api` | `daemon`、`service/api` | tonic，复用 `.proto` |
| `xb-ffi` | `experimental/libbox` | uniffi（Kotlin/Swift） |
| `xb`（bin） | `cmd/sing-box`、`box.go`、`include` | CLI + Cargo features 代替 build tags |

（`xb-` 为占位前缀；按 LICENSE 附加条款，名称不得使用 “sing-box” 或暗示关联。）

### 11.2 移植顺序（依赖优先）
1. `xb-core` + `xb-buf` + `xb-config` + `xb-log`（对应 L0–L4；用 `docs/schema.json` 与 `option/` 做配置兼容测试）。
2. `xb-net` + `xb-route`（无规则时直连）+ 入站 `direct/socks/http/mixed`、出站 `direct/block` → 可跑通最小代理。
3. `xb-rule`（含 SRS 兼容、sniff）+ `xb-dns`（udp/tcp/tls/https/local/hosts/fakeip）+ `cache file`。
4. `xb-tls`（std）+ `xb-transport` + 主流协议：shadowsocks(含 2022)、vmess/vless、trojan、shadowtls、anytls、mux。
5. `xb-tun`（Linux system 栈优先）+ redirect/tproxy + auto_route；随后用户态栈与 Android/Apple 平台桥。
6. QUIC 系：hysteria2/tuic/hysteria、DNS quic/h3、v2ray quic。
7. 管理面：clash_api、API service（daemon proto）、v2ray_api。
8. 重型/外部依赖：WireGuard endpoint、uTLS/REALITY、Naive、Tailscale、OpenVPN/OpenConnect、cloudflared、bridge、USB/IP、CCM/OCM。

### 11.3 Go → Rust 映射
- `context.Context`（取消 + 值）→ `tokio_util::sync::CancellationToken` 处理取消；**值部分拆开**：`InboundContext` 作为显式参数（`&mut`/克隆），服务定位器改为显式 `Arc<BoxCtx>`（字段为 `Arc<dyn OutboundManager>` 等）或在构造期注入；必要时用 `OnceLock` 打破构造期环（Router↔OutboundManager）。
- `Scope` + `StartStage` → `async fn start(&self, stage, scope: &Scope)`，`Scope` 内含 `CancellationToken` + `TaskTracker` + LIFO 清理栈（`Vec<Box<dyn FnOnce() -> BoxFuture<Result<()>>>>`）。
- `net.Conn` → `AsyncRead + AsyncWrite + Unpin + Send` 的 `Box<dyn ProxyStream>`；`N.PacketConn` → 自定义 `trait PacketConn { async fn read_packet(&self, &mut Buf) -> Result<Socksaddr>; async fn write_packet(...) }`；`ReadWaiter`/`ExtendedConn` → 拥有型缓冲的读写 trait，避免二次拷贝；`onClose` 回调 → Drop guard 或 `oneshot`。
- goroutine-per-direction 拷贝 → `tokio::io::copy_bidirectional` 的自定义版本（支持缓存回放、统计、Linux `splice`（`tokio-splice` 或手写 `nix::fcntl::splice`））。
- 接口 → trait（`async_trait` 或原生 async fn in trait + `dyn` 兼容包装）；类型断言（`outbound.(adapter.ConnectionHandler)`）→ trait 上的 `fn as_connection_handler(&self) -> Option<&dyn ...>` 等能力方法。
- 泛型注册表 + 两段 JSON 解析 → serde **internally tagged enum**（`#[serde(tag = "type")]`），`#[cfg(feature)]` 控制变体；未启用的特性用带错误信息的占位变体，复现 stub 报错。工厂：`fn build(opts, &BoxCtx) -> Result<Arc<dyn Outbound>>`。
- build tags → Cargo features（`quic`、`gvisor`→`userspace-stack`、`wireguard`、`utls`、`acme`、`clash-api`、`v2ray-api`、`tailscale`、`naive`、`openvpn`、`openconnect`、`cloudflared`、`usbip`…）。
- 依赖库候选：TLS `rustls`/`tokio-rustls`（ECH 客户端已在 rustls 支持中）；kTLS `ktls` crate；DNS 报文 `hickory-proto`；QUIC `quinn`（可插拔拥塞控制，可实现 BBR/Brutal）+ `h3`/`h3-quinn`；HTTP `hyper`/`h2`；WebSocket `tokio-tungstenite`；gRPC `tonic`；HTTP API `axum`；SSH `russh`；Tor `arti-client`（或控制外部 tor）；缓存 `redb`（bbolt 格式不兼容，需迁移或接受新格式）；netlink `rtnetlink`/`netlink-packet-*`；nftables `rustables`/`nftnl`；WinDivert `windivert` crate；TUN 设备 `tun-rs`；用户态 TCP/IP `smoltcp`（或 `netstack-smoltcp`、`ipstack`），WireGuard `boringtun`（或 `gotatun`/`defguard_boringtun`）；mmdb `maxminddb`；SS 加密 `shadowsocks-crypto`/RustCrypto AEAD。可参考的 Rust 代理实现：shadowsocks-rust、leaf、clash-rs、shoes（许可证均需核对与 GPL-3.0 的兼容性，Apache-2.0/MIT 可并入 GPLv3 作品）。

### 11.4 缺口与难点（按风险排序）
1. **TUN 栈与 L3 flow**：`sing-tun` 的 system 栈（内核栈 + NAT 回接）、gVisor 栈、`flow_dispatch.go` 的 L3 直转、GSO/GRO offload（`tun_offload_linux.go`）、auto_redirect（nftables 规则集 `redirect_nftables_rules*.go`）。smoltcp 性能与 TCP 行为（窗口、SACK、拥塞）弱于 gVisor；建议优先实现 system 栈，用户态栈单独评估。（1.15 alpha 已宣布“新 TCP/IP 栈”并去掉 `with_gvisor`，见 §12，说明上游自己也在替换 gVisor。）
2. **TLS 指纹 / REALITY / TLS spoof**：rustls 无法精确复刻 Chrome/Firefox ClientHello（扩展顺序、GREASE、padding、证书压缩、ALPS 等）；REALITY 需要控制 session_id 与密钥派生。选项：`boring`（BoringSSL，可配置接近 Chrome）、维护 rustls fork、或自写 ClientHello 编码器 + rustls 的低层 API。Hysteria2 的 Chrome QUIC 拟态同理需改 quinn 的 Initial 包。
3. **Naive（cronet）**：没有纯 Rust 替代，只能 FFI 链接 Chromium cronet（`cronet-go` 本身就是 FFI/purego 绑定），构建复杂度高。
4. **Tailscale**：上游 fork 25 万行 Go，无成熟 Rust 客户端。现实做法：通过 `libtailscale`（Go 构建的 C 库）FFI，或推迟。DERP service 亦同。
5. **OpenVPN / OpenConnect**：`sing-openvpn` 21k、`sing-openconnect` 35k 行，Rust 生态无成熟等价，需完整移植（含各种认证挑战，见 `adapter/openconnect.go`）。
6. **WireGuard**：boringtun 可用，但需对接用户态栈 + L3 flow（`tun.Port`）。
7. **平台集成**：Android VpnService protect（`AutoDetectInterfaceControl`）、Apple NetworkExtension（`UnderNetworkExtension`、`IncludeAllNetworks`）、`PlatformInterface` 全部回调；进程查找三平台；Windows Schannel/Apple Network.framework TLS 引擎；`bridge` 的 pf/WinDivert/nftables 后端。
8. **DNS 规则引擎语义**：1.14 的 evaluate/respond/并行赛跑 + legacy 地址过滤兼容（`dns/router.go` 1,775 行，有专门的 `router_race_test.go`），以及 rule-set 合并语义修正——必须以 Go 测试用例为准逐一对照。
9. **兼容性资产**：SRS 二进制格式（必须字节级兼容，`common/srs`）、succinct 域名集合序列化（`sing/common/domain/set.go`）、Clash API JSON、daemon proto、cache.db（bbolt）。
10. **弃用路径**：大量“已移除字段→友好报错”（`option/*.go`、`protocol/tun/inbound.go`），Rust 版要决定是否复刻。

### 11.5 许可证
`LICENSE`：GPL-3.0-or-later + “no derivative work may use the name or imply association with this application without prior consent”。逐行翻译/结构性移植属于衍生作品：Rust 项目须采用 GPL-3.0-or-later、保留版权声明，并另起名称。若链接 Apache-2.0/MIT 依赖没有问题；若想以更宽松协议发布，只能 clean-room 实现，而本文档本身即基于源码阅读，不适合作为 clean-room 依据。

---

## 12. 附：与 v1.15.0-alpha.13 的差异（只作参考）

在 `/tmp/ksrc/sing-box`（alpha.13）中顺带观察到：
- 新增目录：`protocol/masque`、`transport/masque`（MASQUE 客户端/服务端）、`transport/http`（HTTP 代理的 HTTP/2、HTTP/3、UDP 支持）、`transport/device`、`common/kernelports`、`common/ipset`、`common/badhttp`；v1.14.4 独有 `cmd/internal/tun_bench`。
- `release/DEFAULT_BUILD_TAGS` 去掉了 `with_gvisor`，代码中不再有 `with_gvisor` 标签；changelog 写“Significantly improve TUN performance with a new TCP/IP stack”。
- changelog 1.15 alpha 其它条目：Android 完整 `auto_redirect`、endpoint `on_demand`、cache file 写缓冲、TLS 完整证书 pinning、Tailcat、`dns_server_address`/`dns_search_domain` 规则条目。
- alpha 非测试代码约 173.8k 行（v1.14.4 为 164.6k）。

建议 Rust 重写以 v1.14.4 的配置面为目标，但 TUN 栈设计可关注 1.15 的新栈方向，避免在 gVisor 语义上投入过多。
