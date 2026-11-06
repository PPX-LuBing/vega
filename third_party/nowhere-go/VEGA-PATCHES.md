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
Single-key authentication is unchanged. Multiuser Egress uses a distinct registry
per shared key; Vega routes through its host router before claiming an exit.
Revoking a key closes its standby registrations (including QUIC connections);
existing Vector sessions are not reauthenticated by a hot update.

The TCP cleanup patch transfers ownership of a claimed TLS Egress connection
instead of closing it when registration returns. The upstream TLS Egress test
is kept intact to catch regressions; Vega now exposes routed Egress.

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
directions, TLS/QUIC TCP/UDP payloads, multi-target UDP sources, Morph on/off and
reconnects. `TestOfficialEgressInterop` adds all four carrier combinations in
both directions; `TestOfficialSilentPreHello` compares negative admission,
post-admission TLS responses and replay commit behavior to the Rust executable.
See `../../NOWHERE-CAPABILITIES.md` for configuration and acceptance scope.

## Additional host-integration patches

| Files | Change | Regression |
| --- | --- | --- |
| `morph/prehello.go` | rustls 0.23.46 configuration-independent ClientHello checks before replay commit; strict record framing | `prehello_validation_test.go`, official differential probes, fuzz |
| `morph/multi_packet.go` | Dynamic multi-key UDP masking; validate opaque host-generated CIDs instead of guessing short-header keys; bounded reply map | `multi_packet_test.go`, official QUIC multiuser interop |
| `portal/host_egress.go`, `registry.go`, `packet.go`, `server.go` | Host-routed per-user Egress, cancellation/half-close, bounded registrations, revoked registry cleanup, bounded setup tasks | `host_egress_test.go`, Vega policy/accounting/concurrency tests |
| `egress/client.go` | TLS Morph, immediate Hydra replenishment on FlowStart, bounded setup/flows, cancel idle/active connections | official Egress matrix, host Egress cancellation test |
| `vector/client.go` | Session-scoped auth state, cancellation without holding the client lock during dial, old failures cannot close new sessions, half-close | `session_test.go`, Vega concurrent/half-close tests |
| `dgram/router.go`, Portal/Vector/Egress | Reserve UDP routes before READY; reuse reservations and close readers when router stops | empty/8-byte/8192-byte interop tests |

No local wire fields, authentication algorithms, exporter labels or protocol
vectors were changed. A host-generated QUIC CID is an opaque QUIC routing value,
not an additional Nowhere message. Go TLS and rustls are different engines:
the differential corpus is evidence for covered cases, not a proof of identical
behavior for every malformed input or identical transport fingerprints.
