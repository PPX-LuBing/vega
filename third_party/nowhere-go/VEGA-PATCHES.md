# Vega downstream patches

Go implementation baseline: `ohmycggk/nowhere-go v3.4.0`, commit
`b73c5dea85`（3.4.0 tag）(Go 1.21 minimum).
Official wire baseline: `NodePassProject/Nowhere 3.4.0`, commit
`000001c866b0c9fada350c84bdc11702473564a6` (see `UPSTREAM.lock`).

Keep the original copyright/license notices. This is a vendored third-party
implementation, not an independently authored protocol or an official Rust port.

## 相对上游 v3.4.0 的本地改动

| 文件 | 本地改动 | 必需回归 |
| --- | --- | --- |
| `morph/multi_packet.go` | 多密钥 UDP 准入（无新 wire 格式）。3.4.0 起 UDP 带 cipher 分支，写路径改为复用上游 `packetConn.WriteTo`，读路径按 key 现算 AES block | `morph` 全量 + iptables interop |
| `morph/prehello.go` | 扩展级校验：`validClientExtension` / `validServerName`，并把它接进 `clientHelloWellFormed` 的扩展遍历；要求 signature_algorithms 必选、压缩必须为 null | `prehello_validation_test.go`、`FuzzAcceptorAdmission` |
| `portal/server.go` | 多用户（`Users`）、按 key 隔离的 registries、`AcceptEgress`、Egress 按 key 路由 | `portal/multiuser_test.go`、`runtime_multiuser_test.go` |
| `portal/registry.go` | `closed` 状态 + `close()`；`claim` **先查 ctx/deadline 再取 slot**（取消的调用不得消耗 FIFO） | `host_egress_test.go` 的 `TestRegistryCanceledClaimDoesNotConsume` |
| `portal/host_egress.go`、`portal/packet.go` | 主机侧 Egress 与分组工具 | `host_egress_test.go` |
| `vector/client.go` | **无本地改动** —— 3.4.0 的 `auth.Cond` + `used0` 方案已取代我们的 `sessionState` 机制 | `vector/session_test.go`（按新 API 重写） |

## 3.4.0 迁移时删掉的本地机制

- `vector/client.go` 的 `sessionState` / `dialing` / `dialCancel` / `quicSession`：
  换成上游的 `auth sync.Cond` + `opening` + `used0`。语义等价（首个 OpenStream
  必须是 stream 0、取消能广播唤醒），且上游有 `e2e_test.go` 覆盖，代码更简单。
- `vector/cancel_test.go`（依赖已删除的 `newLimitedConn`）：删除，
  改为 `session_test.go` 里按新 API 覆盖同样的失败路径。

## 3.4.0 带来的东西（我们直接受益）

- Morph Cipher 扩展（`CipherChaCha` 默认 / `CipherAES`），协议向量从 28 增到 34
- QUIC 传输内存档位对齐（`memory` 4/16/8 MiB、`balanced` 4/16/16、`throughput` 4/32/32）
- `NOW_QUIC_UDP_QUEUE_BYTES` 字节预算强制、`wire.Reassembler` 并发保护
- egress 拨号超时的孤儿 TCP、SOCKS5 UDP associate 的 map/goroutine 泄漏修复
- `flowio.RelaySize` 缓冲可调、热路径缓冲池化

## Updating

1. 记录确切的 Go 与官方 Rust 上游 commit。协议变更必须显式复核，
   不要凭默认值相同的假设宣称兼容。
2. 合并上游后只重新应用上表里仍然需要的补丁。上游提供了等价实现就删掉本地补丁。
3. 跑 `go test -race -count=1 ./...` 和 `go run ./cmd/nowhere-check -vectors`；
   再单独跑 Vega 的 Nowhere / v2rayapi / 面板测试。
4. 协议版本升级时，两个方向都要跑官方 Rust 互操作（见
   `../../docs-vega/nowhere/CAPABILITIES.md` 的验收范围）。
