# Net subsystem log

The run record for the mediated network bridge (BPTK-026): the Winsock and
DirectPlay contract served over a consented, allowlisted relay, its delivery
model, its lockstep-determinism support, and the two-instance fixture that is
the acceptance. A reached stage is not a playable claim; implemented is not
passing. The Tier-1 invariant — zero off-allowlist / un-consented connection —
is structural, never weakened.

## Measurement method

Two independent measurements, because the live capability and the surface's own
coverage are different claims:

1. **Surface conformance.** `runConformanceSuite` (lib/conformance.mjs) over the
   net case table (`buildNetConformanceCaseTable`) against the real Winsock
   surface (`createNetConformanceImplementation`, lib/net.mjs). The metric is
   `is_coverage_complete`: every served ws2_32 export carries at least one case.
   This is measurable in-tree today.
2. **Corpus import coverage.** `bptk corpus coverage` (lib/corpus.mjs) tallies a
   staged payload's imported symbol against the served/covered surface drawn
   from `hleExport()`. A ws2_32 import flips from `absent` to `covered` only once
   the net exports are registered into the hle export table. This measurement
   needs a *staged* payload — payloads stay out of git (BPTK-002 / R-003), so it
   reads zero in a fresh worktree until a corpus is acquired locally.

## 2026-09-05 — cycle 0 baseline (at `b09b298`)

- `npm run gate` exit 0 on a clean tree; manifest 40 implemented, 0 passing.
- `bptk corpus coverage`: 0 imported symbol from 9 entry, 0 covered, 0 absent —
  no payload staged in this worktree, so the real-corpus network delta is not
  yet measurable here.
- No `lib/net.mjs` existed: the Winsock/DirectPlay surface was unserved and had
  no conformance machine to compare against.

## 2026-09-05 — cycle 1: the Winsock/DirectPlay contract over a mediated relay

### Implemented (generic; no payload or title branch anywhere)

- **The consent + allowlist gate** (`createTransportPolicy`,
  `authorizeEndpoint`). A dial becomes a link only after consent is granted AND
  the endpoint is on the declared allowlist. Every attempt is counted; an
  off-allowlist or un-consented attempt is refused before any link and tallied,
  so the Tier-1 invariant is a measured `off_allowlist_attempt_count === 0`, not
  a narration.
- **The mediated relay** (`createMediatedRelay`). One in-memory switchboard that
  opens no host socket (`host_socket_opened` is structurally false), models the
  browser WebRTC-data / WebSocket transport, and delivers only between attached,
  authorized endpoints. A seeded `mulberry32` stream drives the unreliable drop
  and reorder decision so two instances agree.
- **The Winsock surface** (`createWinsock`): `WSAStartup`, `socket`, `bind`,
  `connect`, `send`/`recv`, `sendto`/`recvfrom`, `closesocket`,
  `WSAGetLastError`, `WSACleanup`, reproducing the ws2_32 return sentinel
  (`SOCKET_ERROR`, `INVALID_SOCKET`) and the last-error codes (`WSANOTINITIALISED`
  before startup, `WSAEACCES` on an off-allowlist dial, `WSAENOTCONN`,
  `WSAEWOULDBLOCK` on an empty non-blocking recv, `WSAEMSGSIZE` past the datagram
  bound). Reliable+ordered for the stream; unreliable+unordered for the datagram.
- **Reconnect** (`dropLink`/`reconnect`): a transient link loss keeps the relay
  endpoint attached so a reliable frame already queued for the peer survives; the
  stream resumes in sequence with no loss and no re-handshake, bounded by
  `reconnect_count`.
- **The DirectPlay session/lobby stub** (`createDirectPlayLobby`): host advertise,
  `enumSession` lobby enumeration, join with capacity refusal, player list, and a
  player message routed over the guaranteed (reliable+ordered, `DPSEND_GUARANTEED`)
  or non-guaranteed (unreliable+unordered) channel.
- **Lockstep determinism** (`createLockstepEngine`): a turn advances only when
  every player's command for that turn is present, and a rolling SHA-256 digest
  over the ordered (turn, player, command) tuple is equal across instances iff
  the executed command stream was identical — a mismatch is a named desync, never
  tolerated.
- **The two-instance fixture** (`runTwoInstanceFixture`): two guests attach
  through the consented allowlist, host and join a session, exchange an ordered
  (8 reliable) and an unordered (8 datagram) set, run 16 lockstep turns, and the
  report asserts ordered-in-order, unordered-multiset-match, lockstep-synced, and
  `off_allowlist_connection_count === 0` / `unconsented_connection_count === 0`
  with `host_socket_opened === false`.

### Measured

- **Surface conformance: coverage-complete.** 13 case over 11 served ws2_32
  export; `is_coverage_complete === true`, `fail_count === 0`. Delta from cycle 0:
  0 served → 11 served, 0 case → 13 case, no uncovered export.
- **Gate:** `node --test` 178 pass / 0 fail (164 baseline + 14 net); `npm run
  gate` exit 0. Package content 44 → 45 file (lib/net.mjs registered).
- **Corpus import coverage:** unchanged at 0 measured — no payload is staged in
  this worktree, so the real Plink/OpenTTD ws2_32 import delta cannot be measured
  here. The honest next step is to register the ws2_32 exports into the hle
  export table so a staged Plink (a ws2_32 client) flips those imports from
  `absent` to `covered`, and to acquire the payload locally to measure it.

## 2026-09-05 — cycle 2: name-resolution refusal, socket option, byte-order helper

### Implemented (generic; no payload or title branch anywhere)

- **Name-resolution refusal** (`resolveName`) — a Tier-1 legal rail.
  getaddrinfo / gethostbyname resolve ONLY an allowlisted, consented logical
  relay endpoint, and to that endpoint identity itself, never to a routable host
  address. An off-allowlist or un-consented name is refused with
  `WSAHOST_NOT_FOUND` (11001) and no lookup is performed — the resolver reaches
  nothing outside the allowlist, so the guest cannot probe or reach a live host
  by name.
- **Socket option** (`setsockopt`/`getsockopt`): a bounded store honoring only a
  declared, host-neutral option (`SO_REUSEADDR`, `SO_RCVBUF`, `SO_SNDBUF`,
  `SO_BROADCAST`, `TCP_NODELAY`); an unknown option is refused with `WSAEINVAL`,
  never mapped onto host behavior.
- **`ioctlsocket` FIONBIO**: the non-blocking flag, changing only the local
  empty-inbox contract, never reaching a host descriptor; an unknown command is
  refused.
- **Byte-order and address helpers** (`htons`/`htonl`/`ntohs`/`ntohl`,
  `inetAddr`): pure arithmetic with the ws2_32 `INADDR_NONE` sentinel on a
  malformed dotted quad — no host, no descriptor.

### Measured

- **Surface conformance: still coverage-complete.** 23 case over 20 served
  ws2_32 export; `is_coverage_complete === true`, `fail_count === 0`. Delta from
  cycle 1: 11 served → 20 served, 13 case → 23 case, no uncovered export.
- **Gate:** `node --test` 181 pass / 0 fail; `npm run gate` exit 0.
- **Corpus import coverage:** still 0 measured — no payload staged; the hle
  export registration and local corpus acquisition remain the next step.

## 2026-09-05 — cycle 3: latency metric, offline failure, and the BPTK-026 promotion

### Implemented (generic; no payload or title branch anywhere)

- **Latency metric.** The relay carries a declared `hop_latency_ms`, stamps it on
  every delivered frame, and the two-instance fixture reports a
  `round_trip_latency_ms` (2× hop). This completes the deliverable's latency
  metric without any live clock dependency.
- **Offline failure.** The relay can be declared offline (`setOffline`); every
  `deliver` then fails with the ws2_32 `WSAENETDOWN` contract and queues no
  frame — the offline case disclosed with no fallback. The fixture exercises it
  and asserts `is_offline_disclosed`.

### Promotion — BPTK-026 to implemented (red)

Per the 8-file promotion contract, reconciled across the gate:

- `bench/roadmap/spec/bptk-026.json`: `gate` excluded → active, `state` stays
  red; `exclusion_reason` and `active_gate_evidence` rewritten to the honest
  implemented-but-red rationale citing the net conformance suite, the
  two-instance fixture, the name-resolution refusal, and test/policy.test.mjs.
- `bench/roadmap/manifest.json`: BPTK-026 `promotion_state` planned →
  implemented; `count.implemented` 40 → 41 (`passing` stays 0).
- `data/status.json`: regenerated by `script/status.mjs` — count 41 and the new
  manifest content hash.
- `README.md`, `ROADMAP.md`: implemented count 40 → 41; BPTK-026 added to the
  implemented-but-red list and its benchmark row rewritten to the in-process
  contract with the live transport still red.
- `test/cli.test.mjs`: the implemented-count assertion 40 → 41.

### Measured

- **Surface conformance: coverage-complete.** 23 case over 20 served ws2_32
  export; zero uncovered, zero failing.
- **Gate:** `node --test` 183 pass / 0 fail; `npm run gate` exit 0.
- **Manifest:** 41 implemented / 0 passing — passing stays 0 because no real
  benchmark (a full networked game over a live browser transport) passes.

### Honest state

BPTK-026 is **implemented but red** as a live capability. The contract, the
delivery model, reconnect, lockstep, and the fixture are real code proven by the
in-process fixture and the conformance suite. The live acceptance stays red
because no browser WebRTC-data/WebSocket relay, no real consent surface, and no
guest ws2_32 import binding exist yet, and the BPTK-026 prerequisite (BPTK-004
approval, BPTK-021, BPTK-024) remain red. The manifest promotion is not flipped
this cycle; the surface is self-contained and the corpus ledger does not yet
recognize it until the hle export registration lands.
