# Vega audit fixes - 2026-11-04

Starting revision: `61dce94e6dcfbd49bc8cd91ca260380f3ba871c2`.
Scope: close the reproduced Go Vega defects before branching for a separate
official-Nowhere-based Rust experiment. No production access or deployment.

## Findings and resolution

| Finding | Resolution | Regression evidence |
| --- | --- | --- |
| V01: Nowhere outbound UDP loses source address | Each flow retains its target; replies return that source | Real SOCKS5 -> Vega outbound -> Vega inbound -> UDP echo, including source assertion |
| V02: Enter deletes despite `[y/N]` | Only explicit y/Y confirms; Enter cancels | Both node and user deletion tests |
| V03: Only the first UDP flow is read | Independent readers fan replies into a bounded queue | Silent first target, responding second target; concurrent writes preserve UoT frames |
| V04: UDP waits ignore Close/deadline before first write | Owned context, read/write deadlines, cancellable setup, serialized writes, failed-flow retirement | Close/cancel/read deadline/reset/extension, stalled open/write, bounded eviction, oversized datagrams |
| V05: Outbound Morph defaults differ from inbound | Omitted means enabled; explicit false remains supported | Omitted/true handshake and payload tests; false exercised by integration test |
| V06: AJSON silently replaces relay entry with SNI | Preserve entry host/port; explicitly skip incompatible independent-SNI Nowhere entries | EntrySNI override, differing host, case equivalence, skip reporting |
| V07: Renewal restarts the entire core and drops counters | Remove restart callback; use existing native certificate file reload | Atomic PEM replacement reaches Nowhere TLS callback without restart; callback does not invoke systemctl |
| V08: TUI cannot grant nodes to a new user | Explicit grant selection after creation and via g; atomic replace/revoke | New user starts with zero grants; save/cancel/revoke and transaction rollback tests |
| V09: Lists overflow and hide the selection | Cursor-following viewport, display-cell clipping, compact machine columns | All tabs checked at 80x24, 120x36 and 40x16 |

Related usability fixes: working modal help, cursor-aware form editing,
protocol/TLS/transport choices, TUIC documentation, and explicit saved-but-not-
applied messages. Hidden list actions are blocked while help is open.

## Additional certificate and lifecycle fixes

- Serialize concurrent certificate/key watcher callbacks. Protect TLS config
  snapshot reads and publication, and avoid mutating shared ALPN slices.
- Nowhere installs its ALPN callback on a private config copy; the dynamic
  callback still sees renewed certificates. Race tests cover publication and
  actual file reload.
- Validate certificate/key matching before materialization; status also checks
  the hostname and activation time. A disk fingerprint is not proof of which
  certificate a running listener currently serves.
- `cert status --check` fails for missing/invalid certificates or expiry within
  14 days. `sbx-cert-check.timer` is installed but never enabled automatically.
  It only checks; it does not renew, restart or send external notifications.
- `cert renew` uses the installer's `sbx-sub` service name by default. It remains
  an explicit recovery operation that restarts the subscription service, not
  the proxy core. Actual issuance/renewal still depends on ACME reachability.
- Vector cancellation covers Morph/auth/setup as well as TLS; cancellation
  ownership ends before returning a successful flow. Closing a flow also
  cancels rate-limiter waits. The vendored module keeps its Go 1.20 declaration.

## Compatibility and operational notes

Go library: `ohmycggk/nowhere-go v3.2.0`, commit `6a8410c`.
Official protocol baseline: `NodePassProject/Nowhere 3.2.0`, commit
`00000e23a0a131dd04fd7aec340b8d523a13ae51`.

No edits to the wire format, authentication, key derivation, Morph algorithms,
vectors or upstream locks. Local library patches are enumerated in
`third_party/nowhere-go/VEGA-PATCHES.md`; adapter behavior lives in
`protocol/nowhere/`. This does not assert compatibility with official 3.3.0.

AJSON entries whose entry address differs from their effective SNI are now
explicitly skipped instead of silently connecting elsewhere. Configure an
entry domain that matches the certificate, or use a client format supporting
an independent SNI. This is an intentional behavior change.

New users receive no access until grants are saved. Database edits still need
apply to reach the running core; Nowhere-only hot sync affects new connections.
The certificate timer is opt-in after certificate configuration. Custom paths
and service names require matching environment/systemd overrides.

## Validation

Local environment: macOS arm64, Go 1.27.3. Tests use temporary files, local
loopback sockets and a newly built core; not the production binary/config.

Passed:

```sh
# Repository root
go test -race -tags with_v2ray_api ./protocol/nowhere/... ./experimental/v2rayapi/... ./common/tls -count=3 -timeout 180s
go vet -tags with_v2ray_api ./protocol/nowhere/... ./experimental/v2rayapi/... ./common/tls
go test -race ./route/rule -run TestVegaQUICPolicy -count=1
go build -tags with_clash_api,with_v2ray_api,with_quic,with_utls -o /tmp/vega ./cmd/sing-box
sh deploy/install_test.sh

# panel/
VEGA_TEST_KERNEL=/tmp/vega go test -race ./... -count=1 -timeout 180s
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build .

# third_party/nowhere-go/
go test -race ./... -count=1 -timeout 180s
go vet ./...
go run ./cmd/nowhere-check -vectors
```

The vectors report 83 nw2 + 28 nw3 cases. Panel tests include the 12 existing
VMess/VLESS/Trojan x TCP/WS/gRPC/HTTPUpgrade loopbacks. The Linux amd64 core
also cross-compiles with the same feature tags. Staged installer testing
preserves existing database/configuration and starts/enables no services.
CI now includes the TLS race tests and the explicit protocol-vector check.

## Not claimed complete

- No official Rust Vector/Portal or Anywhere App end-to-end interoperability
  run. Go loopbacks and vectors are necessary, not sufficient, for that claim.
- No live ACME CA renewal, Linux systemd timer execution or production smoke
  test. No full sing-box upstream suite or all-platform runtime matrix here.
- No new complete privacy/credential-leak audit; no guarantee of zero leaks.
- No QUIC carrier/Egress adapter, protocol-version upgrade, Web UI or Rust core
  replacement in this fix set.
- No claim of full PolarisX feature parity or a completed TUI visual redesign.
  Subscription/QR remain CLI features; TUI details/history/alerts, expanded
  selftest, SNI selection, tunnels and structured routing presets remain
  separate product work, not hidden inside this stabilization patch.

The Rust experiment must branch from this tested Go baseline and must not
replace the default binaries, installer or configuration until its own
compatibility and migration acceptance criteria pass.
