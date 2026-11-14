# Nowhere carrier and Egress acceptance

Baseline remains nowhere-go v3.3.0 (`6b9ec087`) and official Rust Nowhere
3.3.0 (`000007b2`). This is a sing-box host integration with documented vendor
fixes, not a new protocol or a Rust FFI wrapper. Existing TCP configurations
remain TCP when `carrier` is omitted. No key or on-wire format migration.

## Configuration

- Nowhere inbound: `carrier: "tcp" | "quic" | "both"`; `both` binds TCP and UDP
  on the same `listen_port`. QUIC requires a build with `with_quic`.
- Nowhere outbound and Egress service: `carrier: "tcp" | "quic"`.
- Both carriers require TLS 1.3, ALPN `nw3`, and matching Morph settings. QUIC
  uses v1, streams for TCP and NW3 DATAGRAM fragmentation for UDP, without 0-RTT.
- `egress: true` on an inbound permits exit registrations. It does **not** bypass
  sing-box routing: select a `nowhere-egress` outbound referencing that inbound.
- An exit uses the same shared key as its corresponding Vector user. Registries
  are isolated per key. No matching registered exit means failure, not fallback
  to direct access or another user's exit. A failed selected setup is not retried
  against another exit. Treat an Egress key as a privileged proxy credential.

Portal fragment (certificate paths and keys are placeholders):

```json
{
  "inbounds": [{
    "type": "nowhere", "tag": "portal", "listen": "::", "listen_port": 8446,
    "carrier": "both", "morph": true, "egress": true,
    "users": [{"name": "alice", "shared_key": "0123456789abcdef0123456789abcdef"}],
    "tls": {"enabled": true, "certificate_path": "/etc/vega/cert.pem", "key_path": "/etc/vega/key.pem"}
  }],
  "outbounds": [{"type": "nowhere-egress", "tag": "exit", "portal": "portal"}],
  "route": {"rules": [{"port": [25], "action": "reject"}], "final": "exit"}
}
```

Exit fragment (runs on the exit host, not necessarily the Portal):

```json
{
  "services": [{
    "type": "nowhere-egress", "tag": "remote-exit",
    "server": "portal.example.com", "server_port": 8446,
    "carrier": "quic", "morph": true,
    "shared_key": "0123456789abcdef0123456789abcdef",
    "tls": {"enabled": true, "server_name": "portal.example.com"}
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
```

Exit flows re-enter the exit host's router with the service tag as `inbound`.
The optional service `user` is a **local configured accounting label**, not a
remote authenticated username. Apply destination restrictions on the exit too;
it can reach that host's LAN. The Portal continues to count authenticated user
payload bytes once, using the normal sing-box traffic tracker.

Panel:

```sh
vega-panel node set my-nowhere --nowhere-carrier both --nowhere-egress true
```

The TUI exposes both fields at the end of the node form. Database columns migrate
on open; old rows retain TCP/direct defaults. Back up the database before upgrades.
Panel-generated Egress routing follows management-port protection and custom
`extra_config.route.rules`, so earlier policy rules still take precedence.
Configure active exit services through the existing `extra_config.services`
mechanism using the exit fragment above; no separate service editor was added.

Subscriptions: Vega JSON emits `carrier`; official Vector URLs use `/udp:PORT`
for QUIC; Anywhere AJSON uses the documented `network: "udp"`. A `both` node
advertises TCP by default. Use a QUIC-only node to publish QUIC. Clash still
explicitly skips unsupported Nowhere. Nowhere does not support a uTLS fingerprint;
the panel rejects that combination instead of producing unusable subscriptions.

Hot user removal revokes pending Egress registrations, including a removed
key's QUIC exit connection (and flows using it). Existing Vector sessions are
not reauthenticated; a revoked QUIC Vector may stop working after NAT rebinding
or expiry of its old source-key mapping. For immediate removal of active traffic, use the
existing enforcement/restart path, as with the earlier TCP implementation.

## Alignment and fixes

- Silent PreHello admission checks null compression, required nonempty signature
  algorithms, SNI, known extension encodings, TLS record framing and aligned first
  handshake. Rejected input does not consume the replay counter. Holding a rejected
  connection stops on shutdown. Later cipher/version/ALPN negotiation remains a
  separate TLS phase, where errors must not all be suppressed.
- Multiuser QUIC masks packets using current key snapshots. Opaque, authenticated
  server-generated CIDs recognize short headers and NAT rebinding; a bounded,
  expiring source map selects reply masking. QUIC AEAD and AuthFrame still perform
  authentication. There are no new Nowhere bytes.
- Per-connection pre-authentication QUIC windows, bounded registrations/setup
  tasks, session-scoped authentication state and cancellable dials/streams.
- UDP receive routes exist before READY; empty and fragmented payloads retain
  datagram boundaries. Closing a router wakes packet readers.
- Egress TLS now actually applies Morph and replenishes its Hydra standby pool
  when FlowStart arrives, not after the active flow finishes. In-memory relays
  preserve half-close. Outbound default TLS server name no longer includes a port.

## Reproducible acceptance

Run an independently built, unchanged official 3.3.0 executable:

```sh
TMPDIR=/tmp VEGA_TEST_NOWHERE_RUST=/path/to/official/target/release/nowhere \
  go test -race -tags with_quic,with_v2ray_api ./protocol/nowhere \
  -count=2 -timeout 180s
(cd third_party/nowhere-go && go test -race ./... && go run ./cmd/nowhere-check -vectors)
(cd panel && VEGA_TEST_KERNEL=/path/to/vega go test -race ./... && go vet ./...)
```

The official executable is opt-in; without the environment variable those tests
skip explicitly. Normal CI still runs the Go Egress policy/concurrency tests.

Acceptance covers:

- Eight direct interoperability combinations: both directions, both carriers,
  Morph on/off; reconnects, multi-target UDP, empty/8-byte/8192-byte payloads.
- Sixteen official Egress combinations: Rust Egress to Vega Portal and Vega
  Egress to Rust Portal; all Vector/Egress carrier pairs and Morph on/off.
- Differential malformed-ClientHello probes, a non-silent post-admission TLS
  rejection, rejected-then-repaired prelude reuse and accepted-prelude replay.
- Cross-user exit isolation, revocation, route rejection, user traffic counters,
  sixteen concurrent flows, cancellation, shutdown and TCP half-close.
- Panel schema round-trip, TUI, CLI, all subscription outputs, generated routes,
  existing regression suites, protocol vectors and parser fuzzing.

Limits: this is not proof that Go TLS and rustls have identical fingerprints or
identical behavior for every malformed TLS byte sequence. Production rollout,
public-Internet NAT/migration/MTU behavior, sustained load, live ACME renewal and
Anywhere App UI are not covered by loopback acceptance. No server was changed.

### Observed result (2026-11-04)

- Full Nowhere adapter race suite with official peers: passed twice consecutively.
- No-QUIC build/tests, v2ray statistics and TLS regression suites: passed.
- Vendored library and separate CLI: full race suites and vet passed; 83 nw2 +
  28 nw3 protocol vectors passed unchanged. Admission fuzz: 649,296 executions
  in a ten-second run, no failure.
- Panel: full race suite and vet passed with a rebuilt core; old-schema migration,
  CLI field preservation and generated Egress configuration check passed.
- Core: Linux amd64/arm64 builds passed. Panel: Linux amd64/arm64 and Windows
  amd64 builds passed. Staged installer regression passed without starting services.

This is acceptance of the changed Vega/Nowhere paths and their regression suites,
not a fresh execution of every upstream sing-box platform test. Changes remain
local until separately committed/pushed; these checks do not deploy a release.
