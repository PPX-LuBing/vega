# Vega downstream patches

Go implementation baseline: `ohmycggk/nowhere-go v3.3.0`, commit
`6b9ec0879e54d1ee52fe28f4cbffa8631333bc4d` (Go 1.21 minimum).
Official wire baseline: `NodePassProject/Nowhere 3.3.0`, commit
`000007b2482b8acf3a609888921fd847cad56c33` (see `UPSTREAM.lock`).

Keep the original copyright/license notices. This is a vendored third-party
implementation, not an independently authored protocol or an official Rust port.

| File | Local change | Required regression |
| --- | --- | --- |
| `morph/morph.go` | Multi-key prelude admission, without a new wire format | Morph vectors/admission tests, Portal multiuser tests |
| `portal/server.go` | User identity, source metadata, user updates, replay-state preservation, multiuser handshake budget and cleanup/ownership transfer | `portal/multiuser_test.go`, `portal/replay_update_test.go`, `portal/runtime_multiuser_test.go`, upstream `TestTLSEgressEcho` |
| `vector/client.go` | Cancel TCP during Morph/auth/setup, then transfer ownership; Close also releases rate-limiter waits | `vector/cancel_test.go`, Vega outbound integration tests |
| `UPSTREAM.lock` | Recompute the stale upstream protocol source hash against the exact official 3.3.0 commit | Upstream lock generator; upstream vectors compared modulo their four provenance keys |

Vega adds no local changes to `wire/`, key derivation, ALPN, authentication,
Morph bytes or protocol vectors beyond the upstream v3.3.0 update. UDP source addresses,
multi-target reply queues and deadlines belong to Vega's `protocol/nowhere/`
adapter, not the Nowhere wire protocol.

Official Nowhere has one Shared Key per Portal. Before a multiuser connection
authenticates, Vega cannot know which key's derived handshake timeout applies.
It uses the maximum official derived timeout of the current user snapshot;
hot updates recompute it. An explicit `NOW_HANDSHAKE_TIMEOUT` takes precedence.
Single-key behavior is unchanged. Multiuser Egress remains explicitly rejected
to avoid sharing exits across identities without an accounting/routing design.

The TCP cleanup patch transfers ownership of a claimed TLS Egress connection
instead of closing it when registration returns. The upstream TLS Egress test
is kept intact to catch regressions; this does not expose Egress in Vega.

Upstream v3.3.0 retained a 3.2 protocol-source hash, as its changelog notes.
Only `UPSTREAM.lock` (nw3) was regenerated using its own tool against the official
3.3.0 checkout; the nw2 lock is untouched. The corrected source hash is
`fdd1b17df596d529edee3705246be6aed005083b4792ed71a051cb746feb6b4f`.

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
tests. Run Vega's opt-in `TestOfficialRustInterop` with `VEGA_TEST_NOWHERE_RUST`
pointing to an independently built official 3.3.0 binary. It exercises both
directions, TLS TCP/UDP payloads, multi-target UDP sources, Morph on/off and
reconnects. QUIC/Egress are not exposed by the Vega adapter; a library update
does not imply full feature parity. See `../../NOWHERE-UPGRADE-3.3.0.md`.

Retain upstream's documented Silent PreHello limitation (`morph/prehello.go`):
Go crypto/tls may emit alerts on some structurally valid but semantically invalid
ClientHellos that Rust rejects silently in its Acceptor. Do not describe normal
wire interoperability as proof of identical anti-probing behavior.
