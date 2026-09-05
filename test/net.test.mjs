// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The mediated network bridge tests (BPTK-026): the consent + allowlist gate
// refuses an off-allowlist or un-consented dial before any link, the relay
// opens no host socket, the Winsock surface reproduces the ws2_32 return and
// last-error contract, reliable stays ordered while the datagram reorders,
// reconnect preserves a buffered reliable frame, the DirectPlay lobby routes a
// guaranteed vs non-guaranteed message, lockstep agrees on a matching command
// stream and diverges on a mismatched one, the two-instance fixture is
// accepted with zero off-allowlist / un-consented connection, and every served
// export carries a conformance case.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  authorizeEndpoint,
  buildNetConformanceCaseTable,
  createDirectPlayLobby,
  createLockstepEngine,
  createMediatedRelay,
  createNetConformanceImplementation,
  createTransportPolicy,
  createWinsock,
  deliveryChannel,
  htons,
  inetAddr,
  listNetExport,
  netAcceptance,
  ntohs,
  resolveName,
  runTwoInstanceFixture,
  winsockConstant,
  winsockOption,
  wsaError,
} from "../lib/net.mjs";
import { runConformanceSuite } from "../lib/conformance.mjs";

test("the consent and allowlist gate refuses an un-consented and an off-allowlist dial before any link", () => {
  const unconsented = createTransportPolicy({ allowlist: ["relay:a"], is_consented: false });
  const refuseConsent = authorizeEndpoint(unconsented, "relay:a");
  assert.equal(refuseConsent.is_authorized, false);
  assert.equal(refuseConsent.reason, "consent_absent");
  assert.equal(unconsented.unconsented_attempt_count, 1);

  const policy = createTransportPolicy({ allowlist: ["relay:a"], is_consented: true });
  assert.equal(authorizeEndpoint(policy, "relay:evil").is_authorized, false);
  assert.equal(policy.off_allowlist_attempt_count, 1);
  const allow = authorizeEndpoint(policy, "relay:a");
  assert.equal(allow.is_authorized, true);
  assert.equal(policy.authorized_count, 1);
});

test("the relay opens no host socket and refuses attaching an off-allowlist endpoint", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:a"], is_consented: true });
  const relay = createMediatedRelay(policy);
  assert.equal(relay.host_socket_opened, false);
  assert.equal(relay.attach("relay:evil").is_authorized, false);
  assert.equal(relay.is_attached("relay:evil"), false);
  assert.equal(relay.attach("relay:a").is_authorized, true);
  assert.equal(relay.is_attached("relay:a"), true);
});

test("the reliable channel preserves send order and the datagram channel reorders under the seed", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:a", "relay:b"], is_consented: true });
  const relay = createMediatedRelay(policy, { seed: 12345 });
  relay.attach("relay:a");
  relay.attach("relay:b");
  const sent = Array.from({ length: 12 }, (unused, index) => `m${index}`);
  for (const message of sent) relay.deliver("relay:a", "relay:b", deliveryChannel.reliable_ordered, message);
  for (const message of sent) relay.deliver("relay:a", "relay:b", deliveryChannel.unreliable_unordered, message);
  const ordered = relay.drain("relay:b", deliveryChannel.reliable_ordered).map((frame) => frame.byte.toString("utf8"));
  const datagram = relay.drain("relay:b", deliveryChannel.unreliable_unordered).map((frame) => frame.byte.toString("utf8"));
  assert.deepEqual(ordered, sent);
  assert.deepEqual([...datagram].sort(), [...sent].sort());
  assert.notDeepEqual(datagram, sent);
});

test("an unreliable datagram can drop under a lossy seed while the reliable stream never loses", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:a", "relay:b"], is_consented: true });
  const relay = createMediatedRelay(policy, { seed: 3, loss_rate: 0.5 });
  relay.attach("relay:a");
  relay.attach("relay:b");
  for (let index = 0; index < 40; index++) relay.deliver("relay:a", "relay:b", deliveryChannel.unreliable_unordered, `d${index}`);
  for (let index = 0; index < 40; index++) relay.deliver("relay:a", "relay:b", deliveryChannel.reliable_ordered, `r${index}`);
  const datagram = relay.drain("relay:b", deliveryChannel.unreliable_unordered);
  const reliable = relay.drain("relay:b", deliveryChannel.reliable_ordered);
  assert.ok(relay.dropped_count > 0, "the lossy seed drops at least one datagram");
  assert.ok(datagram.length < 40, "a datagram was lost");
  assert.equal(reliable.length, 40, "the reliable stream never loses");
});

test("the Winsock surface reproduces the ws2_32 return and last-error contract", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:a", "relay:b"], is_consented: true });
  const relay = createMediatedRelay(policy);
  const winsock = createWinsock(relay, { endpoint: "relay:a" });

  assert.equal(winsock.socket(2, 1, 6), winsockConstant.SOCKET_ERROR);
  assert.equal(winsock.WSAGetLastError(), wsaError.WSANOTINITIALISED);

  assert.equal(winsock.WSAStartup(), wsaError.WSA_OK);
  const handle = winsock.socket(winsockConstant.AF_INET, winsockConstant.SOCK_STREAM, winsockConstant.IPPROTO_TCP);
  assert.ok(handle > 0);

  assert.equal(winsock.bind(handle, "relay:evil"), winsockConstant.SOCKET_ERROR);
  assert.equal(winsock.WSAGetLastError(), wsaError.WSAEACCES);
  assert.equal(winsock.bind(handle, "relay:a"), wsaError.WSA_OK);

  assert.equal(winsock.send(handle, "x"), winsockConstant.SOCKET_ERROR);
  assert.equal(winsock.WSAGetLastError(), wsaError.WSAENOTCONN);
});

test("a connected Winsock stream sends ordered and recv drains it, empty recv is WSAEWOULDBLOCK", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:a", "relay:b"], is_consented: true });
  const relay = createMediatedRelay(policy);
  const client = createWinsock(relay, { endpoint: "relay:a" });
  const server = createWinsock(relay, { endpoint: "relay:b" });
  client.WSAStartup();
  server.WSAStartup();
  const serverHandle = server.socket(winsockConstant.AF_INET, winsockConstant.SOCK_STREAM, winsockConstant.IPPROTO_TCP);
  server.bind(serverHandle, "relay:b");
  const clientHandle = client.socket(winsockConstant.AF_INET, winsockConstant.SOCK_STREAM, winsockConstant.IPPROTO_TCP);
  client.bind(clientHandle, "relay:a");
  assert.equal(client.connect(clientHandle, "relay:b"), wsaError.WSA_OK);

  assert.equal(client.send(clientHandle, "alpha"), 5);
  assert.equal(client.send(clientHandle, "beta"), 4);
  const received = server.recv(serverHandle);
  assert.equal(received.data.toString("utf8"), "alphabeta");
  const empty = server.recv(serverHandle);
  assert.equal(empty.byte, winsockConstant.SOCKET_ERROR);
  assert.equal(server.WSAGetLastError(), wsaError.WSAEWOULDBLOCK);
});

test("reconnect preserves a reliable frame buffered while the link was down", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:a", "relay:b"], is_consented: true });
  const relay = createMediatedRelay(policy);
  const client = createWinsock(relay, { endpoint: "relay:a" });
  const server = createWinsock(relay, { endpoint: "relay:b" });
  client.WSAStartup();
  server.WSAStartup();
  const serverHandle = server.socket(winsockConstant.AF_INET, winsockConstant.SOCK_STREAM, winsockConstant.IPPROTO_TCP);
  server.bind(serverHandle, "relay:b");
  const clientHandle = client.socket(winsockConstant.AF_INET, winsockConstant.SOCK_STREAM, winsockConstant.IPPROTO_TCP);
  client.bind(clientHandle, "relay:a");
  client.connect(clientHandle, "relay:b");

  client.send(clientHandle, "before");
  assert.equal(client.dropLink(clientHandle), wsaError.WSA_OK);
  assert.equal(client.send(clientHandle, "during"), winsockConstant.SOCKET_ERROR);
  assert.equal(client.WSAGetLastError(), wsaError.WSAENOTCONN);
  assert.equal(client.reconnect(clientHandle), wsaError.WSA_OK);
  client.send(clientHandle, "after");
  const received = server.recv(serverHandle);
  assert.equal(received.data.toString("utf8"), "beforeafter");
});

test("the DirectPlay lobby hosts, enumerates, joins, and routes guaranteed versus non-guaranteed", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:host", "relay:peer"], is_consented: true });
  const relay = createMediatedRelay(policy);
  relay.attach("relay:host");
  const lobby = createDirectPlayLobby();
  const hosted = lobby.host(relay, { session_name: "arena", max_player_count: 4 });
  assert.equal(lobby.enumSession()[0].session_name, "arena");
  const host = lobby.join(hosted.session_id, "host", "relay:host");
  const peer = lobby.join(hosted.session_id, "peer", "relay:peer");
  assert.equal(host.is_joined, true);
  assert.equal(peer.is_joined, true);
  assert.equal(lobby.listPlayer(hosted.session_id).length, 2);

  lobby.sendPlayerMessage(hosted.session_id, host.player_id, peer.player_id, "reliable", { is_guaranteed: true });
  lobby.sendPlayerMessage(hosted.session_id, host.player_id, peer.player_id, "loose", { is_guaranteed: false });
  const guaranteed = lobby.receiveMessage(hosted.session_id, peer.player_id, { is_guaranteed: true });
  const loose = lobby.receiveMessage(hosted.session_id, peer.player_id, { is_guaranteed: false });
  assert.equal(guaranteed[0].byte.toString("utf8"), "reliable");
  assert.equal(loose[0].byte.toString("utf8"), "loose");
});

test("a full session refuses an over-capacity join and never opens the extra endpoint", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:1", "relay:2", "relay:3"], is_consented: true });
  const relay = createMediatedRelay(policy);
  const lobby = createDirectPlayLobby();
  const hosted = lobby.host(relay, { session_name: "duo", max_player_count: 2 });
  lobby.join(hosted.session_id, "one", "relay:1");
  lobby.join(hosted.session_id, "two", "relay:2");
  const overflow = lobby.join(hosted.session_id, "three", "relay:3");
  assert.equal(overflow.is_joined, false);
  assert.equal(overflow.reason, "session_full");
});

test("lockstep agrees on a matching command stream and diverges on a mismatched one", () => {
  const left = createLockstepEngine({ player_id: 1, player_order: [1, 2] });
  const right = createLockstepEngine({ player_id: 2, player_order: [1, 2] });
  for (let turn = 0; turn < 8; turn++) {
    for (const engine of [left, right]) {
      engine.submit(turn, 1, { move: turn });
      engine.submit(turn, 2, { move: turn + 1 });
      assert.equal(engine.tryAdvance(), true);
    }
  }
  assert.equal(left.determinismDigest(), right.determinismDigest());

  const desync = createLockstepEngine({ player_id: 2, player_order: [1, 2] });
  desync.submit(0, 1, { move: 0 });
  desync.submit(0, 2, { move: 99 });
  desync.tryAdvance();
  assert.notEqual(left.determinismDigest(), desync.determinismDigest());
});

test("lockstep stalls until every player's command for the turn is present", () => {
  const engine = createLockstepEngine({ player_id: 1, player_order: [1, 2] });
  engine.submit(0, 1, { move: 0 });
  assert.equal(engine.tryAdvance(), false);
  assert.equal(engine.turn_index(), 0);
  engine.submit(0, 2, { move: 0 });
  assert.equal(engine.tryAdvance(), true);
  assert.equal(engine.turn_index(), 1);
});

test("the two-instance fixture is accepted with zero off-allowlist and un-consented connection", () => {
  const report = runTwoInstanceFixture();
  assert.equal(report.is_ordered_in_order, true);
  assert.equal(report.is_unordered_multiset_match, true);
  assert.equal(report.is_lockstep_synced, true);
  assert.equal(report.off_allowlist_connection_count, 0);
  assert.equal(report.unconsented_connection_count, 0);
  assert.equal(report.host_socket_opened, false);
  assert.equal(report.is_accepted, true);
  assert.equal(report.player.length, 2);
});

test("name resolution refuses an off-allowlist and un-consented name and reaches no host", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:room/peer"], is_consented: true });
  const offAllowlist = resolveName(policy, "matchmaker.example.com");
  assert.equal(offAllowlist.is_resolved, false);
  assert.equal(offAllowlist.reason, "off_allowlist");
  assert.equal(offAllowlist.wsa_error, 11001);
  assert.equal(offAllowlist.endpoint, null);
  assert.equal(policy.off_allowlist_attempt_count, 1);

  const allowlisted = resolveName(policy, "relay:room/peer");
  assert.equal(allowlisted.is_resolved, true);
  assert.equal(allowlisted.endpoint, "relay:room/peer");

  const unconsented = createTransportPolicy({ allowlist: ["relay:room/peer"], is_consented: false });
  assert.equal(resolveName(unconsented, "relay:room/peer").is_resolved, false);
  assert.equal(unconsented.unconsented_attempt_count, 1);
});

test("the byte-order and address helpers are pure and reach no host", () => {
  assert.equal(htons(0x1234), 0x3412);
  assert.equal(ntohs(0x3412), 0x1234);
  assert.equal(inetAddr("127.0.0.1"), 0x7f000001);
  assert.equal(inetAddr("999.1.1.1"), 0xffffffff);
  assert.equal(inetAddr("not-an-address"), 0xffffffff);
});

test("socket option honors a declared name, refuses an unknown one, and toggles FIONBIO", () => {
  const policy = createTransportPolicy({ allowlist: ["relay:a"], is_consented: true });
  const relay = createMediatedRelay(policy);
  const winsock = createWinsock(relay, { endpoint: "relay:a" });
  winsock.WSAStartup();
  const handle = winsock.socket(winsockConstant.AF_INET, winsockConstant.SOCK_DGRAM, winsockConstant.IPPROTO_UDP);
  assert.equal(winsock.setsockopt(handle, winsockOption.TCP_NODELAY, 1), wsaError.WSA_OK);
  assert.equal(winsock.getsockopt(handle, winsockOption.TCP_NODELAY).value, 1);
  assert.equal(winsock.setsockopt(handle, "SO_UNKNOWN", 1), winsockConstant.SOCKET_ERROR);
  assert.equal(winsock.WSAGetLastError(), wsaError.WSAEINVAL);
  assert.equal(winsock.ioctlsocket(handle, "FIONBIO", 1), wsaError.WSA_OK);
  assert.equal(winsock.ioctlsocket(handle, "SIOCATMARK", 0), winsockConstant.SOCKET_ERROR);
});

test("the net conformance suite covers every served export with zero coverage hole", () => {
  const caseTable = buildNetConformanceCaseTable();
  const report = runConformanceSuite(caseTable, createNetConformanceImplementation(), { served_export: listNetExport() });
  assert.equal(report.is_coverage_complete, true, `uncovered: ${report.uncovered_export.join(", ")}`);
  assert.equal(report.fail_count, 0, report.result.filter((entry) => !entry.pass).map((entry) => `${entry.case_id}: ${entry.mismatch.join(";")}`).join(" | "));
});

test("the net acceptance is honestly implemented-but-red about the live capability", () => {
  assert.equal(netAcceptance.item_id, "BPTK-026");
  assert.equal(netAcceptance.state, "implemented_red");
  assert.match(netAcceptance.reason, /no browser WebRTC-data\/WebSocket relay/);
});
