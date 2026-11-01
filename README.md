# Vega

基于 [sing-box](https://github.com/SagerNet/sing-box) 的**精简 fork**，加入了 [Nowhere](https://github.com/NodePassProject/Nowhere)（nw3）协议与运行期用户管理，并配套一个终端面板。

名字取自织女星——与北极星同属亮星，都是「导航」的意象。

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

**自有代码只占上游的 0.5%**，上游改动几乎不会冲突：

| 类别 | 文件 | 说明 |
|---|---|---|
| **修改上游** | `constant/proxy.go` | +1 行（`TypeNowhere`） |
| | `include/registry.go` | +2 行（import + 注册） |
| | `go.mod` | +1 个依赖 |
| **新增文件** | `option/nowhere.go`、`protocol/nowhere/*` | 新文件不会冲突 |

### 跟随上游

```sh
git fetch upstream
git rebase upstream/main        # 或 upstream/dev
```

冲突只会出现在上面那 3 个上游文件里，且都是加行——通常一次就能过。唯一需要留意的是 `go.mod`（上游升依赖时会冲突，删掉冲突标记保留两边即可）。

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
  "tls": {"enabled": true, "certificate_path": "...", "key_path": "..."}
}
```

`shared_key` 是 **32 位小写十六进制**（16 字节），不是 base64——nw3 的 `ValidateServiceKey` 只接受这个格式。

**多用户**：nw3 的 AuthFrame 不带身份字段，服务端靠**逐个试解密钥**识别用户。开了 Morph 就试 prelude，否则试 AuthFrame 本身（两者都是定长 + 纯校验函数，失败的候选不留副作用）。

### 2. 运行期改用户（不重启）

sing-box 原生没有这个能力——改用户只能改配置再重启，所有人断线一次。

```
POST http://127.0.0.1:10087/users
{"inbound":"hk-nowhere","users":[{"name":"alice","shared_key":"..."}]}
→ {"ok":true,"updated":["hk-nowhere"],"users":1}
```

- 新连接按新名单认证，**老连接按原样跑完**
- `inbound` 留空表示改全部已注册的 nowhere 入站
- **只绑回环**：这个端点没有鉴权，与内核自己的 clash_api / v2ray_api 同级
- 多个 nowhere 入站**共用一个端点**（第一个启动的负责监听，其余注册进来），不会抢端口

## 面板

```sh
cd panel
go build -o vega-panel .
./vega-panel                      # TUI
./vega-panel apply                # 下发到所有机器并重启
./vega-panel user sync            # 运行期改用户（不重启，仅 nowhere）
./vega-panel status               # 内核运行状态
```

五个页面：**概览 / 节点 / 用户 / 流量 / 机器**。按键 `1-5` 切页、`a` 新增、`e` 编辑、`d` 删除、`空格` 启停、`r` 下发全部、`c` 采集、`s` 改用户、`u` 刷新状态。

### 面板提供的内核原生没有的能力

| 能力 | 说明 |
|---|---|
| 按用户配额 | 三道闸门：停用 / 过期 / 超额，配置生成时自动摘除 |
| 运行期改用户 | 见上，不重启不断线 |
| 多机编排 | 登记多台机器，`apply` 逐台 scp + 校验 + 原子替换 + 重启 |
| 可观测性 | 读 clash_api：版本、内存、活动连接、进程流量、活跃目标 |

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
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -o vega-panel-linux ./panel
```

## third_party/nowhere-go

[nowhere-go](https://github.com/ohmycggk/nowhere-go) 的副本，基线是上游 **v3.2.0**（`6a8410c`），加了两处补丁：

| 文件 | 补丁 |
|---|---|
| `morph/morph.go` | `WrapTCPServerMulti` / `MatchedKeyIndex`：多密钥试解 prelude |
| `portal/server.go` | `Config.Users` 多用户、双路径识别、`UpdateUsers` 运行期换名单、`ContextWithUser` |

同步上游：把新版 nowhere-go 复制过来，重新应用这两处改动（补丁约 265 行）。

## 许可

内核与 nowhere-go 均为 **GPL-3.0**，本项目沿用 GPL-3.0。上游 sing-box 的 README 保留在 `README.sing-box.md`。
