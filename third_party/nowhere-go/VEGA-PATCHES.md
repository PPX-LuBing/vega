# Vega downstream patches

Go implementation baseline: `ohmycggk/nowhere-go v3.2.0`, commit `6a8410c`.
Official wire baseline: `NodePassProject/Nowhere 3.2.0`, commit
`00000e23a0a131dd04fd7aec340b8d523a13ae51` (see `UPSTREAM.lock`).

Keep the original copyright/license notices. This is a vendored third-party
implementation, not an independently authored protocol or an official Rust port.

| File | Local change | Required regression |
| --- | --- | --- |
| `morph/morph.go` | Multi-key prelude admission, without a new wire format | Morph vectors/admission tests, Portal multiuser tests |
| `portal/server.go` | User identity, source metadata, user updates, replay-state preservation and cleanup | `portal/multiuser_test.go`, `portal/replay_update_test.go` |
| `vector/client.go` | Cancel TCP during Morph/auth/setup, then transfer ownership; Close also releases rate-limiter waits | `vector/cancel_test.go`, Vega outbound integration tests |

The 2026-11-04 fixes do not change `wire/`, key derivation, ALPN, authentication,
Morph bytes, protocol vectors, or the upstream locks. UDP source addresses,
multi-target reply queues and deadlines belong to Vega's `protocol/nowhere/`
adapter, not the Nowhere wire protocol.

## Updating

1. Select and record exact Go and official Rust upstream commits. Review protocol
   changes explicitly; do not silently claim compatibility with a newer release.
2. Merge upstream and reapply only still-needed patches above. Drop a local fix
   once upstream provides equivalent behavior and its regression passes.
3. Run `go test -race -count=1 ./...` and `go run ./cmd/nowhere-check -vectors`
   here; run Vega's Nowhere/v2rayapi and panel tests separately.
4. For a protocol-version upgrade, run both official Rust Vector -> Vega Portal
   and Vega Vector -> official Rust Portal. Include TCP, UDP, Morph on/off,
   invalid keys, replay rejection, cancellation and reconnects.

Vectors and Go-to-Go loopbacks do not replace official-client interoperability
tests. This patch set retains the pinned 3.2.0 baseline; it does not claim full
3.3.0 support or add QUIC/Egress to the Vega adapter.
