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

# 解冲突：只有这几个文件会冲突，都是加行
#   constant/proxy.go     TypeNowhere 常量
#   include/registry.go   import + 注册
#   go.mod                依赖（删掉冲突标记保留两边）
#   README.md             直接取我们的（--ours）

# 验证
go build ./protocol/nowhere/ && go test ./protocol/nowhere/
(cd panel && go test ./...)
go build -tags "with_gvisor,with_quic,with_utls,with_acme,with_clash_api,with_v2ray_api" ./cmd/sing-box
```

## 为什么是 tag 而不是 testing

`testing` 是上游的开发分支，随时可能引入不兼容改动。生产落地机跟稳定 tag 更安全。

## third_party/nowhere-go

基线是 [ohmycggk/nowhere-go](https://github.com/ohmycggk/nowhere-go) 的 `v3.2.0`（commit `6a8410c`），
加了两处补丁（`morph/morph.go` 多密钥、`portal/server.go` 多用户与运行期换名单）。
同步方式：复制新版过来，重新应用这两处改动。
