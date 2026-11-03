# Vega

基于 [sing-box](https://github.com/SagerNet/sing-box) 的**精简 fork**，加入了 [Nowhere](https://github.com/NodePassProject/Nowhere)（nw3）协议与运行期用户管理，并配套一个终端面板。

名字取自织女星——与北极星同属亮星，都是「导航」的意象。

最近一次自有模块审核、修复验证与升级注意见 [`AUDIT-2026-11-01.md`](AUDIT-2026-11-01.md)。
本轮订阅修复、北极星功能对照及隐私边界见 [`AUDIT-2026-11-02.md`](AUDIT-2026-11-02.md)。

```
vega/
├── protocol/nowhere/       ← 自有扩展：Nowhere 入站 + 控制端点
├── option/nowhere.go       ← 配置结构
├── panel/                  ← 终端面板（独立 Go module）
├── tools/sbstats/          ← 按用户统计工具（独立 Go module）
├── third_party/nowhere-go/ ← 打补丁的 nowhere 协议库
└── include/registry.go     ← 只加了 1 行注册
```

## 这是一个 thin fork

自有功能集中在新增目录，另有少量上游接入点与统计补丁：

| 类别 | 文件 | 说明 |
|---|---|---|
| **修改上游** | `constant/proxy.go` | +1 行（`TypeNowhere`） |
| | `include/registry.go` | +2 行（import + 注册） |
| | `go.mod` | +1 个依赖 |
| | `experimental/v2rayapi/stats.go` | 热用户统计、并发保护、内核实例标识 |
| | `common/tls/std_server.go` | 证书重载回调与配置发布的竞态保护 |
| | `release/DEFAULT_BUILD_TAGS*` | 默认编入 `with_v2ray_api` |
| | `.github/workflows/{test,lint}.yml` | `main` 分支与独立 module 的回归检查 |
| **新增文件** | `option/nowhere.go`、`protocol/nowhere/*` | 通常减少冲突，仍需核对上游接口 |

### 跟随上游

当前基线是上游的 **`v1.14.4`** tag（commit `c005f35`）。

注意：sing-box 的**默认分支是 `testing`**（开发分支），没有 `main`。跟版本建议直接跟 **tag**：

```sh
git fetch upstream --tags

git rebase v1.15.0        # 换成你要跟的目标版本 tag
# 或者跟开发分支（不推荐用于生产）：
# git rebase upstream/testing
```

升级时检查上表的接入点，尤其是统计服务接口与依赖变更，不要只保留注册行就跳过回归。具体基线见 [`BASELINE.md`](BASELINE.md)。

跟完之后重新编译并跑一遍测试：

```sh
go test -race -tags with_v2ray_api ./protocol/nowhere/... ./experimental/v2rayapi/...
(cd panel && go test -race ./...)
(cd third_party/nowhere-go && go test -race ./...)
(cd tools/sbstats && go test ./... && go vet ./...)
```

### 支持哪些协议

**内核支持 sing-box 的全部协议**（因为它就是 sing-box），另外多了 `nowhere`：

```sh
vega check -c config.json     # 任何合法 sing-box 配置都能跑
```

`panel/` 目前**管理**其中 8 种（`nowhere` / `anytls` / `tuic` / `hysteria2` / `vless` / `vmess` / `trojan` / `shadowsocks`）。VMess/VLESS/Trojan 支持 TCP、WS、gRPC、HTTPUpgrade；REALITY 限 VLESS TCP。其余协议手写配置即可，能力取决于内核编译标签。**不实现 XHTTP，不扩展非 Nowhere 的内核热更新接口，不做 Web UI。**

## 自有扩展

### 1. Nowhere（nw3）入站

```json
{
  "type": "nowhere",
  "tag": "hk-nowhere",
  "listen": "0.0.0.0",
  "listen_port": 8443,
  "users": [
    {"name": "alice", "shared_key": "32位小写十六进制"},
    {"name": "bob",   "shared_key": "..."}
  ],
  "morph": true,
  "control_addr": "127.0.0.1:10087",
  "control_secret": "替换为足够长的随机管理令牌，不要给代理用户",
  "tls": {"enabled": true, "certificate_path": "...", "key_path": "..."}
}
```

`shared_key` 是 **32 位小写十六进制**（16 字节），不是 base64——nw3 的 `ValidateServiceKey` 只接受这个格式。

**多用户**：nw3 的 AuthFrame 不带身份字段，服务端靠**逐个试解密钥**识别用户。开了 Morph 就试 prelude，否则试 AuthFrame 本身（两者都是定长 + 纯校验函数，失败的候选不留副作用）。

### 2. 运行期改用户（不重启）

sing-box 原生没有这个能力——改用户只能改配置再重启，所有人断线一次。

```
POST http://127.0.0.1:10087/users
Authorization: Bearer <control_secret>
{"inbound":"hk-nowhere","users":[{"name":"alice","shared_key":"..."}]}
→ {"ok":true,"updated":["hk-nowhere"],"users":1}
```

- 新连接按新名单认证，**老连接按原样跑完**
- `inbound` 留空表示改全部已注册的 nowhere 入站
- **回环 + Bearer 鉴权**：只绑回环并不安全，代理用户也能通过代理访问回环。必须配置 `control_secret`；未配置地址和令牌时不开放端点，显式指定地址却没给令牌则拒绝启动。
- `users` 必须显式传数组；`[]` 表示清空，漏传或 `null` 不会误清空。用户名和密钥都必须唯一。
- 多个 nowhere 入站**共用一个端点**（第一个启动的负责监听，其余注册进来），不会抢端口
- Nowhere 的 TCP、UDP 都经过 sing-box 路由和用户流量统计；当前入站不支持 QUIC/Egress。

升级已有部署时：面板会在数据库里生成管理令牌，并在下一次 `apply` 时写入内核配置；升级内核、面板和 `sb-stats` 后先执行一次 `apply`，再使用 `user sync`。手写配置需要自行添加 `control_secret`，调用方同步添加 Authorization 头。远端运行期同步使用 SSH + 远端 `curl`，远端需要安装 curl。不要把 `show` 输出的配置或数据库发给代理用户，它们包含凭据。

## 面板

```sh
cd panel
go build -trimpath -o vega-panel .
./vega-panel                      # TUI
./vega-panel apply                # 下发到所有机器并重启
./vega-panel user sync            # 运行期改用户（不重启，仅 nowhere）
./vega-panel collect              # 采集全部机器，逐机报告成功/失败
./vega-panel status               # 全部机器内核运行状态
./vega-panel enforce              # 采集并执行配额/到期，配置变化的机器会重启
./vega-panel enforce --watch --interval 30s  # 持续轮询，Ctrl+C 或 SIGTERM 停止
./vega-panel doctor               # 验证节点参数及本机内核配置，不部署/重启
./vega-panel traffic --hours 24 --json
./vega-panel events --limit 50
./vega-panel selftest --user alice --node hk-vmess  # 显式发起经代理的 HTTP 204 探测
```

五个页面：**概览 / 节点 / 用户 / 流量 / 机器**。按键 `1-5` 切页、`a` 新增、`e` 编辑、`d` 删除、`空格` 启停、`r` 下发全部、`c` 采集全部、`s` 改用户、`x` 采集后执行配额、`u` 刷新全部状态。下发/采集/同步/探测均在后台执行；运行中可切页或退出，重复写操作会被阻止。

### 面板提供的内核原生没有的能力

| 能力 | 说明 |
|---|---|
| 按用户配额 | 三道闸门：停用 / 过期 / 超额；`enforce` 全机采集后摘除，可选择持续轮询 |
| 运行期改用户 | 见上，不重启不断线 |
| 多机编排 | 登记多台机器，`apply` 逐台 scp + 校验 + 原子替换 + 重启 |
| 可观测性 | 全机读取 clash_api，概览汇总已成功机器，机器页逐台显示版本与服务状态；本机直连、远端通过 SSH |

### 节点、订阅与编辑

```sh
vega-panel node add hk-vmess --proto vmess --port 8443 --tls tls \
  --cert /etc/ssl/vega/fullchain.pem --key /etc/ssl/vega/private.key \
  --sni proxy.example.com --transport ws --path /proxy --host proxy.example.com
vega-panel node set hk-vmess --entry-host 'relay.example.com,192.0.2.10' --entry-port 443
vega-panel user add alice --quota 100 --days 30
vega-panel user grant alice hk-vmess
vega-panel user set alice --remark 'updated'  # 仅改显式字段，不改期限或凭据
vega-panel setting set sub_host proxy.example.com
vega-panel setting set sub_base https://sub.example.com
vega-panel setting set sub_title Vega
vega-panel user link alice
vega-panel user qr alice --format singbox
```

`node add` / `user add` 不覆盖已有记录，修改请用 `set`。TUI 节点表单支持证书、REALITY 目标、传输与中转字段，长表单随光标滚动。REALITY 密钥用本机标准库生成；普通 TLS 可填写证书和私钥路径，或留空并提供 SNI 使用面板已签发的证书；实际文件由 `doctor` / `apply` 的内核校验检查。

入口地址优先于 `sub_host`，逗号分隔时展开多个入口；未填入口端口则沿用节点端口。`--entry-sni` 只覆盖客户端 SNI。`--fingerprint` 用于 TCP TLS；Hysteria2 的 QUIC TLS 不使用 uTLS 指纹。新增字段随数据库打开自动迁移，升级前仍应备份。

订阅支持 `/clash`、`/singbox`、`/nowhere`、`/plain`、`/base64`。Clash 会明确跳过 Nowhere、HTTPUpgrade 和无 TLS 的 Trojan 节点；Nowhere 需要本仓库内核或兼容的官方客户端。sing-box 配置带 `127.0.0.1:2080` mixed 入口，节点备注重名与保留名会确定性去重。通用分享 URI 的导入能力因客户端而异，以原生 JSON/YAML 订阅为准。**订阅 URL、分享链接、二维码、`show`、`user show` 输出均是敏感凭据，不要公开。**

sing-box 使用原生 SRS/JSON 规则，不再把 MRS 当作 SRS。`cn_additional` 使用 [YiXuanZX 的同源转换 SRS](https://raw.githubusercontent.com/YiXuanZX/sing-box-geosite/main/rule/cn-additional-list-clash.srs)，已恢复与 Clash 预设对应的 UDP/443 封禁条件：只在不命中国内域名或国内 IP 规则集时拒绝，TCP 不受此规则影响。此策略按端口匹配，不保证所有 UDP/443 都是 QUIC；它是预设策略，不是协议限制。转换仓库每日更新，与原作者可能有同步延迟。sing-box 广告规则直接执行 reject，不能像 Clash 的 AdBlock 组一样临时切到直连。外部规则来源可见于 `panel/internal/sub/rules.go`，需要信任并能访问这些第三方服务；它们会看到下载请求的公网 IP，但请求不包含用户代理密钥。

订阅可以在反代后使用 HTTP，也可以自行提供证书：

```sh
vega-panel serve --tls-cert /etc/ssl/vega/fullchain.pem --tls-key /etc/ssl/vega/private.key --acme-tls :8443
# 自动签发（公网域名和挑战端口必须可达）
vega-panel serve --acme-domain sub.example.com --acme-cache /var/lib/sbx-panel/acme --acme-tls :443
```

TLS 模式由 `--acme-tls` 指定监听地址；明文模式使用 `--listen`。自备证书与 ACME 不能同时启用。反向代理必须隐藏 `/sub/<token>` 访问日志，避免订阅令牌被记录。

### 计费、历史与告警

```sh
vega-panel setting set traffic_rate 1.5
vega-panel setting set quota_reset_day 1
vega-panel setting set alert_webhook https://alerts.example.com/vega
vega-panel alert --test
vega-panel traffic --hours 168 --json
vega-panel events --limit 100 --json
```

- 倍率默认 1，范围 `(0,1000]`，最多六位小数，只计入新采样差额；使用定点整数和小数余量，不重新计算历史账单。小时历史显示**计费流量**，不是网卡原始流量，按采集时间归入小时；保留最近 30 天，不会回填升级前小时数据。
- 月度重置默认关闭，`quota_reset_day=1..28` 启用，`0` 关闭；由 `collect` / `enforce` 触发，按面板进程本地时区。首次启用或更改重置日只建立基线，不立即清账；之后每周期只清一次配额用量，不清原始采样点和小时历史，不启用被手工停用或到期的用户。
- 轮询不是精确账期边界：跨界的未采样增量记到新周期；长期离线无法从累计计数还原真实发生时间。只运行订阅服务不触发重置，持续运营应显式启用 enforce watcher。
- 80% 用量、超额、到期、停用及恢复等状态变化写入事件，重复轮询不刷屏。配置 webhook 后发送 JSON `{text, events}`，包含面板用户名和用量，**不包含代理密码、订阅 token 或共享密钥**。仅配置你信任的接收端，推荐 HTTPS；未配置不发送。发送超时/失败记为 `alert_error`，当前是尽力发送，不提供持久重试或送达保证；失败不阻断计费和配额执行。事件保留 90 天，由采集清理。
- `doctor` 不校验远端主机上的证书和内核，明确输出 SKIP；`selftest` 启动带随机 SOCKS 凭据的临时本地客户端，通过指定用户/节点的第一个入口探测，结束时清理，不重启服务端。它验证连通性与耗时，不验证匿名性、出口 IP 或全部入口；请求会产生实际代理流量。

设置项现在拒绝未知键，避免“保存成功但功能未实现”。支持 `sub_host`、`sub_base`、`sub_title`、`extra_config`、`traffic_rate`、`quota_reset_day`、`alert_webhook`。`setting get` 仍是管理员的原始值读取命令，不要把含 webhook 凭据或 extra_config 的输出公开。

### 配额执行与运维边界

`collect` 只入库，不改认证或中断连接。`enforce` 先采集所有管理机器的用量，再按全局共享配额生成各机器配置；只有配置内容变化时才校验、替换和重启对应机器。**重启会断开那台机器的所有用户连接，不只超额用户**。`user sync` 则不重启，只影响 Nowhere 新认证，已建立连接不受影响。

`enforce --watch` 默认两轮之间等待 30 秒，轮询不重叠，不会默认后台启动或安装系统服务；用量达到上限后的执行延迟还包含采集和部署耗时，不是逐字节硬限额。任一机器采集失败时，本轮保留已成功的采集，但整体跳过部署并报错，避免用不完整用量重新放行用户。机器首次使用请先 `apply`，再启用 enforce。

远端需要 `ssh/scp`、`curl`、`flock`（通常由 util-linux 提供）与 systemd；内核配置目录需要事先存在。本机部署使用系统文件锁，远端用 flock，进程退出自动释放。`.lock` 普通文件会保留，请勿删除或替换锁文件；它不是“遗留占锁”，可以安全复用。同一数据库只运行一个 enforce watcher，手工 apply/修改授权时避免与 watcher 并行。

## 构建

```sh
# 内核（需要 Go 1.26+）
go build -trimpath -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_v2ray_api" \
  -o vega ./cmd/sing-box
```

**`with_v2ray_api` 是必须的**：官方 sing-box 发布版不含它，而按用户统计依赖它。

### 交叉编译注意

`modernc.org/sqlite`（面板用）从 darwin 交叉编译到 linux 时**必须显式指定 `GOAMD64=v1`**，否则产物在 Linux 上一启动就 SIGSEGV：

```sh
(cd panel && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -o ../vega-panel-linux .)
```

统计工具也需要单独构建：`(cd tools/sbstats && go build -o sb-stats .)`。

### Linux 安装（显式执行，不自动启动）

```sh
# 在目标系统上准备好三个二进制，再运行：
sudo sh deploy/install.sh ./vega ./panel/vega-panel ./tools/sbstats/sb-stats
```

配套安装路径使用面板默认的 `/usr/local/bin/sbx`、`sbx-panel`、`sb-stats` 与 `/usr/local/etc/sbx/config.json`；安装 `sbx.service`、`sbx-sub.service`、`sbx-enforce.service`，不覆盖数据库和配置，不启动或启用服务。升级已有部署时先采集、备份并停止相应服务，再替换二进制。

创建节点/用户/授权和订阅设置，完成 `sbx-panel doctor`、`sbx-panel apply` 后，再按需显式执行 `sudo systemctl enable --now sbx sbx-sub sbx-enforce`。默认订阅仅监听回环 HTTP，公网使用前须配置 HTTPS 反代或覆盖订阅服务的 ExecStart 使用证书。安装器支持 `DESTDIR` 暂存打包；`sh deploy/install_test.sh` 验证不会覆盖现有配置/数据库或自动启用服务。继承上游的 `release/local/install.sh` 仍是 sing-box 原路径安装器，不是面板全组件安装器。

面板首次运行会创建数据库父目录，数据库权限设为 `0600`。本机和远端下发都先校验临时配置，再替换；重启失败时恢复旧配置并尝试重启旧服务。流量按稳定机器名及内核实例的累计计数计算差额，流量与采样点一起事务提交，失败重试不会重复计费。重启前请先执行 `collect`，避免丢失尚未采集的内存计数；断电或崩溃仍可能丢失末次采样后尚未入库的流量。不要另用 `sb-stats -reset` 清零正在由面板采集的内核，也不要随意删除重建机器记录来更换计费来源名。

## third_party/nowhere-go

[nowhere-go](https://github.com/ohmycggk/nowhere-go) 的副本，基线是上游 **v3.2.0**（`6a8410c`），本地补丁如下：

| 文件 | 补丁 |
|---|---|
| `morph/morph.go` | `WrapTCPServerMulti` / `MatchedKeyIndex`：多密钥试解 prelude |
| `portal/server.go` | 多用户与热更新、沿用未变密钥的防重放状态、用户/来源上下文、连接关闭清理 |
| `vector/client.go` | Morph/认证/setup 阶段的 context 取消，不改变线上协议 |

同步上游：按 `third_party/nowhere-go/VEGA-PATCHES.md` 合并本地补丁与对应测试，尤其保留 `portal/replay_update_test.go` 的热更新防重放回归。

## 致谢

Vega 站在这些项目的肩膀上：

| 项目 | 我们用到了什么 |
|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) | **整个内核**——协议实现、路由、DNS、出站、规则引擎全部来自它 |
| [nowhere-go](https://github.com/ohmycggk/nowhere-go) | Nowhere 协议的 Go 实现——握手、Morph 伪装、FLOW 与 UoT |
| [Nowhere](https://github.com/NodePassProject/Nowhere) | nw3 协议的规范与 Rust 官方实现 |
| [bubbletea](https://github.com/charmbracelet/bubbletea) / [lipgloss](https://github.com/charmbracelet/lipgloss) | 面板的 TUI 框架 |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | 面板的纯 Go SQLite 驱动 |
| [grpc-go](https://github.com/grpc/grpc-go) | `tools/sbstats` 查 v2ray_api |

完整的版权与许可说明见 [`NOTICE`](NOTICE)。

## 许可

本项目是 sing-box 的衍生作品，整体以 **GNU GPL-3.0** 分发（完整条款见 [`LICENSE`](LICENSE)）。

`LICENSE` 放的是 GPL-3.0 的标准正文（不放自定义声明，这样 GitHub 能正确识别许可类型）；
各方的版权署名与完整致谢在 [`NOTICE`](NOTICE)。

    Vega                Copyright (C) 2026 PPX-LuBing
    sing-box            Copyright (C) 2022 nekohasekai <contact-sagernet@sekai.icu>
    nowhere-go          Copyright (C) 2026 ohmycggk

因为上游是 GPL-3.0，这是**法律上必须**的：衍生作品不能换成更宽松的许可。
## 2026-11-04 审核修复与操作注意

- Nowhere 出站默认 Morph 开启（显式 false 仍可关闭），与入站及固定的官方 nw3 基线一致。UDP 保留来源地址，多目标回包独立接收；Close、context 和 deadline 能终止等待，目标缓存与接收队列均有界。协议线上格式不变。
- TUI 删除只接受明确的 y/Y，Enter 默认取消。新增用户后进入节点勾选授权；用户页按 g 可修改/撤销授权，不默认开放全部节点。保存后按 r 下发，s 只热同步 Nowhere 新连接。
- 列表随光标滚动，支持 PgUp/PgDn/Home/End，按 ? 查看帮助。表单支持光标编辑、Delete、Ctrl+U 和协议/传输枚举选择。长行按显示宽度裁切，机器页窄窗口隐藏内核路径。
- Anywhere AJSON 不会用 SNI 替换客户端接入地址。Nowhere 入口与 SNI 不同时明确跳过并说明原因；请配置证书匹配的接入域名，或使用支持独立 SNI 的客户端格式。
- 统一证书文件由运行中的 sing-box 热加载，续期不再自动重启整个内核。首次安装仍需证书准备好后执行 doctor/apply 并启用服务。文件更新日志不代表已确认内核加载成功；请检查内核的 reload certificate 日志。
- `sbx-panel cert status --check` 在证书缺失、证钥不匹配或 14 天内到期时返回失败。安装器提供但不自动启用 `sbx-cert-check.timer`，配置好托管证书后可显式启用每日检查；它只检查，不重启、不直接发送通知。自定义证书目录/域名需用 systemd override 配置 ExecStart 与环境变量。
- `cert renew` 的默认订阅服务名与安装器一致为 sbx-sub；手工安装使用其他名称时设置 `SBX_PANEL_SUB_SERVICE`。

详细修复范围、回归和未验证事项见 `AUDIT-FIXES-2026-11-04.md`。
