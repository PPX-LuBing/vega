# 上游基线

本仓库 fork 自 [SagerNet/sing-box](https://github.com/SagerNet/sing-box)。

| 项 | 值 |
|---|---|
| 上游版本 | `v1.14.4` |
| 上游 commit | `c005f35300ce76427dc285481ec5695f5b179cd2` |
| 上游默认分支 | `testing`（注意不是 `main`） |
| fork 时间 | 2026-11-01 |

## 升级步骤

```sh
git fetch upstream --tags
git rebase <新版本 tag>

# 解冲突：重点检查这些接入点，不保证冲突只发生在这里
#   constant/proxy.go     TypeNowhere 常量
#   include/registry.go   import + 注册
#   go.mod                依赖（删掉冲突标记保留两边）
#   experimental/v2rayapi/stats.go 热用户、实例标识与并发保护
#   release/DEFAULT_BUILD_TAGS*  默认启用 v2ray_api
#   .github/workflows/{test,lint}.yml main 与独立 module 回归
#   README.md             直接取我们的（--ours）

# 验证
go test -race -tags with_v2ray_api ./protocol/nowhere/... ./experimental/v2rayapi/...
(cd panel && go test -race ./...)
(cd third_party/nowhere-go && go test -race ./...)
(cd tools/sbstats && go test ./... && go vet ./...)
go build -tags "with_gvisor,with_quic,with_utls,with_acme,with_clash_api,with_v2ray_api" ./cmd/sing-box
```

## 为什么是 tag 而不是 testing

`testing` 是上游的开发分支，随时可能引入不兼容改动。生产落地机跟稳定 tag 更安全。

## third_party/nowhere-go

基线是 [ohmycggk/nowhere-go](https://github.com/ohmycggk/nowhere-go) 的 `v3.2.0`（commit `6a8410c`），
本地补丁集中在 `morph/morph.go`（多密钥）与 `portal/server.go`（多用户、运行期换名单、沿用未变密钥的防重放状态与连接清理）。
同步方式：合并新版与这两个文件的本地改动，保留对应测试，并运行整个独立 module 的竞态回归。
