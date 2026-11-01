# Vega

基于 [sing-box](https://github.com/SagerNet/sing-box) 的**精简 fork**，加入了 [Nowhere](https://github.com/NodePassProject/Nowhere)（nw3）协议与运行期用户管理，并配套一个终端面板。

名字取自织女星——与北极星同属亮星，都是「导航」的意象。

最近一次自有模块审核、修复验证与升级注意见 [`AUDIT-2026-11-01.md`](AUDIT-2026-11-01.md)。

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
| | `release/DEFAULT_BUILD_TAGS*` | 默认编入 `with_v2ray_api` |
| | `.github/workflows/{test,lint}.yml` | `main` 分支与独立 module 的回归检查 |
| **新增文件** | `option/nowhere.go`、`protocol/nowhere/*` | 新文件不会冲突 |

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

`panel/` 目前只**管理**其中 6 种（`nowhere` / `anytls` / `hysteria2` / `vless` / `trojan` / `shadowsocks`）——其余协议手写配置即可，内核照样支持。

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
go build -o vega-panel .
./vega-panel                      # TUI
./vega-panel apply                # 下发到所有机器并重启
./vega-panel user sync            # 运行期改用户（不重启，仅 nowhere）
./vega-panel collect              # 采集全部机器，逐机报告成功/失败
./vega-panel status               # 全部机器内核运行状态
./vega-panel enforce              # 采集并执行配额/到期，配置变化的机器会重启
./vega-panel enforce --watch --interval 30s  # 持续轮询，Ctrl+C 或 SIGTERM 停止
```

五个页面：**概览 / 节点 / 用户 / 流量 / 机器**。按键 `1-5` 切页、`a` 新增、`e` 编辑、`d` 删除、`空格` 启停、`r` 下发全部、`c` 采集全部、`s` 改用户、`x` 采集后执行配额、`u` 刷新全部状态。下发/采集/同步/探测均在后台执行；运行中可切页或退出，重复写操作会被阻止。

### 面板提供的内核原生没有的能力

| 能力 | 说明 |
|---|---|
| 按用户配额 | 三道闸门：停用 / 过期 / 超额；`enforce` 全机采集后摘除，可选择持续轮询 |
| 运行期改用户 | 见上，不重启不断线 |
| 多机编排 | 登记多台机器，`apply` 逐台 scp + 校验 + 原子替换 + 重启 |
| 可观测性 | 全机读取 clash_api，概览汇总已成功机器，机器页逐台显示版本与服务状态；本机直连、远端通过 SSH |

### 配额执行与运维边界

`collect` 只入库，不改认证或中断连接。`enforce` 先采集所有管理机器的用量，再按全局共享配额生成各机器配置；只有配置内容变化时才校验、替换和重启对应机器。**重启会断开那台机器的所有用户连接，不只超额用户**。`user sync` 则不重启，只影响 Nowhere 新认证，已建立连接不受影响。

`enforce --watch` 默认两轮之间等待 30 秒，轮询不重叠，不会默认后台启动或安装系统服务；用量达到上限后的执行延迟还包含采集和部署耗时，不是逐字节硬限额。任一机器采集失败时，本轮保留已成功的采集，但整体跳过部署并报错，避免用不完整用量重新放行用户。机器首次使用请先 `apply`，再启用 enforce。

远端需要 `ssh/scp`、`curl`、`flock`（通常由 util-linux 提供）与 systemd；内核配置目录需要事先存在。本机部署使用系统文件锁，远端用 flock，进程退出自动释放。`.lock` 普通文件会保留，请勿删除或替换锁文件；它不是“遗留占锁”，可以安全复用。同一数据库只运行一个 enforce watcher，手工 apply/修改授权时避免与 watcher 并行。

## 构建

```sh
# 内核（需要 Go 1.26+）
go build -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_v2ray_api" \
  -o vega ./cmd/sing-box
```

**`with_v2ray_api` 是必须的**：官方 sing-box 发布版不含它，而按用户统计依赖它。

### 交叉编译注意

`modernc.org/sqlite`（面板用）从 darwin 交叉编译到 linux 时**必须显式指定 `GOAMD64=v1`**，否则产物在 Linux 上一启动就 SIGSEGV：

```sh
(cd panel && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -o ../vega-panel-linux .)
```

统计工具也需要单独构建：`(cd tools/sbstats && go build -o sb-stats .)`。

面板首次运行会创建数据库父目录，数据库权限设为 `0600`。本机和远端下发都先校验临时配置，再替换；重启失败时恢复旧配置并尝试重启旧服务。流量按稳定机器名及内核实例的累计计数计算差额，流量与采样点一起事务提交，失败重试不会重复计费。重启前请先执行 `collect`，避免丢失尚未采集的内存计数；断电或崩溃仍可能丢失末次采样后尚未入库的流量。不要另用 `sb-stats -reset` 清零正在由面板采集的内核，也不要随意删除重建机器记录来更换计费来源名。

## third_party/nowhere-go

[nowhere-go](https://github.com/ohmycggk/nowhere-go) 的副本，基线是上游 **v3.2.0**（`6a8410c`），加了两处补丁：

| 文件 | 补丁 |
|---|---|
| `morph/morph.go` | `WrapTCPServerMulti` / `MatchedKeyIndex`：多密钥试解 prelude |
| `portal/server.go` | 多用户与热更新、沿用未变密钥的防重放状态、用户/来源上下文、连接关闭清理 |

同步上游：合并这两个文件的本地补丁与对应测试，尤其保留 `portal/replay_update_test.go` 的热更新防重放回归。

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

    Vega                Copyright (C) 2026 PPX-LuBing <1711958652@qq.com>
    sing-box            Copyright (C) 2022 nekohasekai <contact-sagernet@sekai.icu>
    nowhere-go          Copyright (C) 2026 ohmycggk

因为上游是 GPL-3.0，这是**法律上必须**的：衍生作品不能换成更宽松的许可。
