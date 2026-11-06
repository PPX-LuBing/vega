# Nowhere-Go 3.3.0 update

> Historical baseline-upgrade report. The subsequent QUIC/Egress and PreHello
> work supersedes the operational limitations below: see [NOWHERE-CAPABILITIES.md](NOWHERE-CAPABILITIES.md).


Date: 2026-11-04. Branch: `main`. Previous stable Vega commit: `a1e6f11e`.
This continues the existing sing-box + nowhere-go route, not the Rust-core
experiment. No production server was accessed or changed.

## Exact sources

| Component | Previous | Updated |
| --- | --- | --- |
| nowhere-go | v3.2.0 / `6a8410c3cb4c3414cd96809ecf4920cdb74785e4` | v3.3.0 / `6b9ec0879e54d1ee52fe28f4cbffa8631333bc4d` |
| Official Nowhere | 3.2.0 / `00000e23a0a131dd04fd7aec340b8d523a13ae51` | 3.3.0 / `000007b2482b8acf3a609888921fd847cad56c33` |

The Go tag and main resolved to the same commit when checked. The vendored
module now requires Go 1.21, as upstream does; Vega's existing minimum toolchain
is already newer. Copyright and license notices remain intact.

## What changed

Imported all 32 files changed upstream between the tags, including the runtime
package, TLS Egress/FIFO support, UDP Prelude, QUIC flow/session handling,
vectors, CLI and tests. Core framing, ALPN and authentication remain upstream
definitions. No Vega-specific protocol bytes or cipher changes were added.

Kept Vega's multi-key admission, user identity/source metadata, hot user updates,
replay-state preservation and connection cleanup. Kept the Vector cancellation
and rate-limiter cancellation fixes. The previous UDP adapter, TUI and certificate
fixes are unchanged.

Two integration details needed explicit resolution:

- Upstream derives a Portal handshake timeout from its single Shared Key.
  Before multiuser authentication Vega has no selected key, so it uses the
  maximum derived timeout of the current user snapshot, recomputed on updates.
  An explicit `NOW_HANDSHAKE_TIMEOUT` wins. Single-key semantics remain upstream.
- A claimed TLS Egress connection must transfer ownership instead of being
  closed by Vega's TCP cleanup defer. The unchanged upstream Egress echo test
  caught this merge regression; ownership transfer fixes it. Multiuser Egress
  is explicitly rejected rather than allowing cross-user exit sharing.

All upstream-tracked files match v3.3.0 byte-for-byte except the three existing
patched implementation files and `UPSTREAM.lock`. Additional Vega regression
tests and the patch manifest remain separate. See
`third_party/nowhere-go/VEGA-PATCHES.md` for the upgrade contract.

## Source lock correction

The upstream v3.3.0 release retains the old 3.2 protocol source hash, as its
changelog notes. Downloaded the exact official Rust commit and regenerated
only the nw3 lock using upstream's tool:

```sh
# Run from third_party/nowhere-go; OFFICIAL_SOURCE is the pinned Rust checkout.
go run ./internal/upstreamlock/tool.go -upstream "$OFFICIAL_SOURCE" -lock UPSTREAM.lock -write
```

Verified source hash:
`fdd1b17df596d529edee3705246be6aed005083b4792ed71a051cb746feb6b4f`.
The vector tree hash matches upstream v3.3.0. Compared the vector payload with
official `src/tests/protocol/vectors.json`: identical after removing the four
Go export provenance fields. The nw2 lock is untouched.

## Verification

Passed locally on macOS arm64 with Go 1.27.3:

- Vendored library: `go test -race ./... -count=1 -timeout 180s` and `go vet ./...`.
- Independent vendored CLI module: the same tests and vet; CI now includes it.
- Protocol vectors: 83 nw2 + 28 nw3 passed.
- Portal/Vector/runtime focused race tests repeated three times, including
  multiuser timeout overrides/updates, replay preservation and TLS Egress echo.
- Vega Nowhere, v2rayapi and TLS race tests; adapter vet; full-feature local
  core build and Linux amd64 cross-build.
- Panel full race suite and vet with the newly built core, including the
  existing 12 VMess/VLESS/Trojan transport loopbacks.
- Official Rust source built unchanged using `cargo build --locked --release`.
  The opt-in interoperability test passed all four direction/Morph combinations:
  official Rust Vector -> Vega multiuser Portal, and Vega outbound -> official
  Rust Portal, each with Morph off/on. Each case transfers TCP payloads on two
  connections and UDP payloads to two targets, checking response source addresses.
  Tests use generated certificates with explicit trust/pinning, not insecure TLS.

Re-run the official interoperability test from Vega's root:

```sh
TMPDIR=/tmp VEGA_TEST_NOWHERE_RUST="$OFFICIAL_SOURCE/target/release/nowhere" \
  go test -race -tags with_v2ray_api ./protocol/nowhere \
  -run TestOfficialRustInterop -count=1 -v -timeout 120s
```

Without that environment variable, the official test explicitly skips. A short
TMPDIR avoids Unix telemetry socket path limits. It launches only loopback
listeners and terminates its own child processes; it does not run against
production. Invalid-key/replay/cancellation regressions run in the Go suite;
those negative cases were not separately exercised against the Rust process.

## Operational boundary

Protocol compatibility is the target, not identical implementation behavior.
The upstream Go code explicitly documents a remaining Silent PreHello gap in
`third_party/nowhere-go/morph/prehello.go`: after structural validation, Go's
`crypto/tls` can emit TLS alerts for some semantic ClientHello failures, whereas
the corresponding Rust rustls Acceptor rejection can remain silent. The Go
parser is unchanged from upstream. Successful payload interoperability does
not establish identical probing behavior; this upgrade does not resolve or
separately measure that gap.

Vega still exposes the TCP+TLS carrier with TCP/UDP payloads. This update does
not enable QUIC carrier or Egress in the adapter/panel and does not claim full
Nowhere feature parity. The old Egress rejection message now describes the
actual missing routing/accounting integration, not a false QUIC requirement.

No key/URL migration is required by upstream 3.3.0. Existing `NOW_*` environment
settings should be reviewed: upstream now validates runtime settings and invalid
values can fail startup. The default handshake timeout also changes from the
old randomized 4-6 seconds to the upstream key-derived budget.

Not tested here: production deployment, live ACME renewal, Anywhere App UI,
official QUIC/Egress interoperability, all-platform runtime behavior or sustained
load. The Rust experiment branch is retained but is not part of this update.
