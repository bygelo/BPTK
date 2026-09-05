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

### Honest state

BPTK-026 is **implemented but red** as a live capability. The contract, the
delivery model, reconnect, lockstep, and the fixture are real code proven by the
in-process fixture and the conformance suite. The live acceptance stays red
because no browser WebRTC-data/WebSocket relay, no real consent surface, and no
guest ws2_32 import binding exist yet, and the BPTK-026 prerequisite (BPTK-004
approval, BPTK-021, BPTK-024) remain red. The manifest promotion is not flipped
this cycle; the surface is self-contained and the corpus ledger does not yet
recognize it until the hle export registration lands.
