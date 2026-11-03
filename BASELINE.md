# 上游基线

本仓库 fork 自 [SagerNet/sing-box](https://github.com/SagerNet/sing-box)。

| 项 | 值 |
|---|---|
| 上游版本 | `v1.14.4` |
| 上游 commit | `c005f35300ce76427dc285481ec5695f5b179cd2` |
| 上游默认分支 | `testing`（注意**不是** `main`） |
| fork 时间 | 2026-11-01 |

## 改动规模

自有扩展主要位于新增文件；统计会随迭代变化，请用 `git diff --stat v1.14.4 HEAD` 查看当前规模。新增文件通常减少冲突，但上游同名新增或接口变化仍需处理。

| 类别 | 数量 | rebase 影响 |
|---|---|---|
| 修改的上游文件 | **13 个**（截至 2026-11-04） | 可能冲突 |
| 新增文件 | 以 Git diff 为准 | 上游同名新增或接口变化仍可能冲突 |
| 内核自有代码 | `option/nowhere.go` + `protocol/nowhere/`（含出站） | — |
| 面板自有代码 | `panel/`，独立 Go module | — |
| 打补丁的第三方 | `third_party/nowhere-go/`（见下） | — |

### 修改的上游文件（按冲突风险排序）

| 文件 | 改动 | 冲突风险 |
|---|---|---|
| `experimental/v2rayapi/stats.go` | +24 / −6 | **高**——改在函数中间（锁顺序、`RegisterUsers`、实例标识），上游一动这个文件就冲突 |
| `common/tls/std_server.go` | 串行化证书文件重载、保护配置读取与发布 | 中——保留证书与私钥同时替换的竞态回归 |
| `README.md` | +194 / −20 | 中——直接取我们的（`git checkout --ours README.md`） |
| `go.mod` / `go.sum` | +4 | 中——上游升依赖时冲突，删掉冲突标记保留两边 |
| `constant/proxy.go` | +1 | 低——加 `TypeNowhere` 常量 |
| `include/registry.go` | +3 | 低——import + 入站/出站注册各一行 |
| `release/DEFAULT_BUILD_TAGS` | +1 / −1 | 低——加了 `with_v2ray_api` |
| `release/DEFAULT_BUILD_TAGS_OTHERS` | +1 / −1 | 低——同上 |
| `.github/workflows/test.yml` | 新增 job | 低 |
| `.github/workflows/lint.yml` | 小改 | 低 |
| `.gitignore` | 加构建产物规则 | 低 |
| `LICENSE` | 换成 GPL-3.0 标准正文 | 低——上游改许可时才冲突 |

## 升级步骤

```sh
git fetch upstream --tags
git rebase <新版本 tag>
```

解冲突时按上表的顺序处理，`stats.go` 优先看。跟完之后必须验证：

```sh
# 内核扩展
go test -race -tags with_v2ray_api ./protocol/nowhere/... ./experimental/v2rayapi/...

# 面板（独立 module）
(cd panel && go test -race ./...)

# 打补丁的第三方（独立 module）
(cd third_party/nowhere-go && go test -race ./...)

# 统计工具（独立 module）
(cd tools/sbstats && go test ./... && go vet ./...)

# 实际编译（with_v2ray_api 不能少，按用户统计依赖它）
go build -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_v2ray_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0" ./cmd/sing-box
```

## 为什么跟 tag 而不是 testing

`testing` 是上游的开发分支，随时可能引入不兼容改动。落地机跟稳定 tag 更安全。

## third_party/nowhere-go

基线是 [ohmycggk/nowhere-go](https://github.com/ohmycggk/nowhere-go) 的 `v3.3.0`（commit `6b9ec08`）。

补丁集中在三个文件（详见 `third_party/nowhere-go/VEGA-PATCHES.md`）：

| 文件 | 补丁 |
|---|---|
| `morph/morph.go` | `WrapTCPServerMulti` / `MatchedKeyIndex`——多密钥试解 prelude |
| `portal/server.go` | `Config.Users` 多用户、双路径识别、热更新与防重放状态保留、身份/来源上下文、3.3 握手超时适配、连接清理与 TLS Egress 所有权交接 |
| `vector/client.go` | context 取消覆盖 Morph、认证与 setup；Close 取消限速等待；不改报文或协议状态机 |

同步方式：合并新版与这三个文件的本地改动，保留对应测试（`portal/multiuser_test.go`、`portal/replay_update_test.go`、`vector/cancel_test.go`），并运行整个独立 module 的竞态回归。不要因修复适配层而修改官方 wire/auth/Morph 算法。

v3.3.0 的 `UPSTREAM.lock` 另有一处元数据修正：按官方固定提交重算协议源码哈希，未改动 nw2 锁。此次升级与官方 Rust 双向互通记录见 `NOWHERE-UPGRADE-3.3.0.md`。

## 判断改动是否完整

升级后跑一遍这几个「不变量」，它们覆盖了我们对上游的全部依赖：

1. **协议注册生效**：`vega check -c <带 nowhere 入站的配置>` 通过
2. **按用户统计可用**：`vega run` 后 `sb-stats` 能查到 `user>>>` 计数（验证 `with_v2ray_api` 与 `stats.go` 的补丁都在）
3. **热加用户有统计**：`POST /users` 加人后，新用户能连且能查到流量（验证 `RegisterUsers`）
4. **控制端点鉴权**：无令牌返回 401（验证 `control.go`）
5. **默认构建带统计标签**：`go version -m vega | grep with_v2ray_api`
