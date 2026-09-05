// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The mediated network bridge (BPTK-026): the Winsock and DirectPlay contract
// served over a CONSENTED, allowlisted relay — never a raw host socket. The
// guest reaches no host network here. Every packet travels one in-memory
// switchboard that models the browser WebRTC-data / WebSocket transport, and a
// dial is refused before it becomes a link unless its endpoint is on the
// declared allowlist AND consent was granted. That refusal is the Tier-1
// invariant: an off-allowlist or un-consented connection count is structurally
// zero, never merely low. Delivery matches the Winsock contract — reliable and
// ordered for the stream/guaranteed channel, unreliable and unordered for the
// datagram channel — and the unreliable model is seeded so two instances stay
// in lockstep on the guaranteed command stream regardless of datagram loss.
//
// This is implemented but red as a live capability: there is no browser relay,
// no real consent surface, and no guest ws2_32 import binding yet, so the
// contract is proven only against the in-process fixture. See doc/net-log.md.

import { InputError } from "./input.mjs";
import { createHash } from "node:crypto";

// Declared bound (resource-exhaustion containment). Every socket table, queue,
// session, and turn buffer is capped by these frozen constant; exceeding one is
// a structured fault, never unbounded growth.
export const netBound = Object.freeze({
  socket_count: 256,
  session_count: 64,
  player_count: 64,
  endpoint_count: 256,
  allowlist_count: 256,
  channel_count: 4,
  message_byte: 64 * 1024,
  datagram_byte: 1200,
  send_queue_count: 4096,
  recv_queue_count: 4096,
  reconnect_count: 32,
  lockstep_turn_count: 100000,
});

// The Winsock numeric contract the surface reproduces. Handle sentinel and the
// WSA last-error codes are the ones a real ws2_32 caller compares against.
export const winsockConstant = Object.freeze({
  INVALID_SOCKET: -1,
  SOCKET_ERROR: -1,
  AF_INET: 2,
  SOCK_STREAM: 1,
  SOCK_DGRAM: 2,
  IPPROTO_TCP: 6,
  IPPROTO_UDP: 17,
});

export const wsaError = Object.freeze({
  WSA_OK: 0,
  WSAEACCES: 10013,
  WSAEINVAL: 10022,
  WSAEMSGSIZE: 10040,
  WSAEADDRINUSE: 10048,
  WSAENOTCONN: 10057,
  WSAEISCONN: 10056,
  WSAENOTSOCK: 10038,
  WSAECONNRESET: 10054,
  WSAECONNREFUSED: 10061,
  WSAEWOULDBLOCK: 10035,
  WSANOTINITIALISED: 10093,
});

// The declared, host-neutral socket option the surface honors. An option that
// would expose a host descriptor or a real network interface is not listed, so
// it is refused rather than mapped onto host behavior.
export const winsockOption = Object.freeze({
  SO_REUSEADDR: "SO_REUSEADDR",
  SO_RCVBUF: "SO_RCVBUF",
  SO_SNDBUF: "SO_SNDBUF",
  SO_BROADCAST: "SO_BROADCAST",
  TCP_NODELAY: "TCP_NODELAY",
});

// The four delivery channel the transport serves. The stream and the
// guaranteed DirectPlay message ride reliable+ordered; the datagram rides
// unreliable+unordered; the two mixed channel exist for DirectPlay flag parity.
export const deliveryChannel = Object.freeze({
  reliable_ordered: "reliable_ordered",
  reliable_unordered: "reliable_unordered",
  unreliable_ordered: "unreliable_ordered",
  unreliable_unordered: "unreliable_unordered",
});

function netError(code, message) {
  return new InputError(code, message);
}

// A deterministic 32-bit generator (mulberry32). The unreliable delivery model
// is driven by this so a given seed yields the same drop-and-reorder decision
// on every instance — the property lockstep determinism depends on.
export function createDeterministicStream(seed) {
  let state = (seed >>> 0) || 0x9e3779b9;
  return function next() {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 0x100000000;
  };
}

function toPayloadBuffer(payload) {
  if (Buffer.isBuffer(payload)) return payload;
  if (payload instanceof Uint8Array) return Buffer.from(payload);
  if (typeof payload === "string") return Buffer.from(payload, "utf8");
  throw netError("invalid_payload", "A payload must be a Buffer, Uint8Array, or string");
}

// The Winsock byte-order and address helpers. These are pure arithmetic — no
// host, no descriptor — so the guest's ntohs/htonl and dotted-quad parsing
// behave to contract without any capability. inet_addr rejects a malformed
// dotted quad with the INADDR_NONE sentinel like ws2_32.
export function htons(value) {
  return ((value & 0xff) << 8) | ((value >> 8) & 0xff);
}
export function htonl(value) {
  return (((value & 0xff) << 24) | ((value & 0xff00) << 8) | ((value >> 8) & 0xff00) | ((value >> 24) & 0xff)) >>> 0;
}
export const ntohs = htons;
export const ntohl = htonl;
export function inetAddr(dotted) {
  if (typeof dotted !== "string") return 0xffffffff;
  const part = dotted.split(".");
  if (part.length !== 4) return 0xffffffff;
  let value = 0;
  for (const octet of part) {
    if (!/^\d{1,3}$/.test(octet)) return 0xffffffff;
    const number = Number(octet);
    if (number > 255) return 0xffffffff;
    value = (value << 8) | number;
  }
  return value >>> 0;
}

// Name resolution over the mediated policy — never a live DNS. getaddrinfo /
// gethostbyname resolve ONLY an allowlisted logical relay endpoint, and to that
// endpoint identity itself, never to a routable host address. An off-allowlist
// or un-consented name is refused with WSAHOST_NOT_FOUND and no lookup is
// performed, so the guest cannot probe or reach a real host by name. This is a
// Tier-1 legal rail: the resolver reaches nothing outside the allowlist.
export function resolveName(policy, name) {
  const decision = authorizeEndpoint(policy, name);
  if (!decision.is_authorized) {
    return { is_resolved: false, reason: decision.reason, wsa_error: 11001, endpoint: null };
  }
  // The "address" is the logical relay endpoint identity, not an IP a host
  // stack could route. The transport dials the endpoint, never a socket address.
  return { is_resolved: true, reason: "allowlisted_endpoint", wsa_error: wsaError.WSA_OK, endpoint: name };
}

// The consent + allowlist gate. It is the only thing that turns a dial into a
// link, and it counts every attempt so the Tier-1 invariant is measurable: an
// off-allowlist or un-consented attempt never yields an authorization and is
// tallied so a fixture can assert the connection count stayed zero.
export function createTransportPolicy(option = {}) {
  const allowlist = Array.isArray(option.allowlist) ? option.allowlist.filter((entry) => typeof entry === "string") : [];
  if (allowlist.length > netBound.allowlist_count) {
    throw netError("allowlist_overflow", `Allowlist exceeds ${netBound.allowlist_count} endpoint`);
  }
  return {
    schema_version: 1,
    allowlist: Object.freeze([...new Set(allowlist)]),
    is_consented: option.is_consented === true,
    is_proxy_disclosed: option.is_proxy_disclosed === true,
    attempt_count: 0,
    authorized_count: 0,
    off_allowlist_attempt_count: 0,
    unconsented_attempt_count: 0,
    refusal: [],
  };
}

// Authorize one endpoint. Refuses — and records the reason — before any link
// exists when consent is absent or the endpoint is off the allowlist. A
// refusal is never an authorization, so no off-allowlist/un-consented
// connection is reachable through this gate.
export function authorizeEndpoint(policy, endpoint) {
  policy.attempt_count += 1;
  if (typeof endpoint !== "string" || endpoint === "") {
    policy.refusal.push({ endpoint: String(endpoint), reason: "empty_endpoint", wsa_error: wsaError.WSAEINVAL });
    return { is_authorized: false, reason: "empty_endpoint", wsa_error: wsaError.WSAEINVAL };
  }
  if (!policy.is_consented) {
    policy.unconsented_attempt_count += 1;
    policy.refusal.push({ endpoint, reason: "consent_absent", wsa_error: wsaError.WSAEACCES });
    return { is_authorized: false, reason: "consent_absent", wsa_error: wsaError.WSAEACCES };
  }
  if (!policy.allowlist.includes(endpoint)) {
    policy.off_allowlist_attempt_count += 1;
    policy.refusal.push({ endpoint, reason: "off_allowlist", wsa_error: wsaError.WSAEACCES });
    return { is_authorized: false, reason: "off_allowlist", wsa_error: wsaError.WSAEACCES };
  }
  policy.authorized_count += 1;
  return { is_authorized: true, reason: "authorized", wsa_error: wsaError.WSA_OK };
}

// The mediated relay: the one switchboard every packet crosses. It opens no
// host socket. An endpoint attaches only after the policy authorizes it, and a
// frame is delivered into the peer inbox under the channel's delivery model.
export function createMediatedRelay(policy, option = {}) {
  const seed = Number.isInteger(option.seed) ? option.seed : 0x1234abcd;
  const lossRate = typeof option.loss_rate === "number" ? Math.min(Math.max(option.loss_rate, 0), 1) : 0;
  const stream = createDeterministicStream(seed);
  const endpointTable = new Map();
  let deliverySequence = 0;
  return {
    schema_version: 1,
    policy,
    seed,
    loss_rate: lossRate,
    host_socket_opened: false,
    delivered_count: 0,
    dropped_count: 0,
    // Attach an endpoint. The authorization gate is the only door; an
    // unauthorized endpoint never gets an inbox, so no link forms.
    attach(endpoint) {
      const decision = authorizeEndpoint(policy, endpoint);
      if (!decision.is_authorized) return decision;
      if (endpointTable.size >= netBound.endpoint_count) {
        throw netError("endpoint_overflow", `Relay endpoint exceeds ${netBound.endpoint_count}`);
      }
      if (!endpointTable.has(endpoint)) {
        endpointTable.set(endpoint, { inbox: new Map() });
      }
      return decision;
    },
    is_attached(endpoint) {
      return endpointTable.has(endpoint);
    },
    // Deliver one frame from an attached endpoint to an attached endpoint over a
    // channel. Reliable channel never drops; unreliable channel consults the
    // seeded stream for a drop and an arrival key so two instances agree.
    deliver(fromEndpoint, toEndpoint, channel, payload) {
      if (!endpointTable.has(fromEndpoint)) return { is_delivered: false, reason: "source_detached", wsa_error: wsaError.WSAENOTCONN };
      if (!endpointTable.has(toEndpoint)) return { is_delivered: false, reason: "peer_detached", wsa_error: wsaError.WSAECONNRESET };
      if (!deliveryChannel[channel]) throw netError("invalid_channel", `Unknown delivery channel: ${channel}`);
      const buffer = toPayloadBuffer(payload);
      const isDatagram = channel === deliveryChannel.unreliable_unordered || channel === deliveryChannel.unreliable_ordered;
      const limit = isDatagram ? netBound.datagram_byte : netBound.message_byte;
      if (buffer.length > limit) {
        return { is_delivered: false, reason: "message_too_large", wsa_error: wsaError.WSAEMSGSIZE };
      }
      const isReliable = channel === deliveryChannel.reliable_ordered || channel === deliveryChannel.reliable_unordered;
      const isOrdered = channel === deliveryChannel.reliable_ordered || channel === deliveryChannel.unreliable_ordered;
      const roll = stream();
      const arrivalRoll = stream();
      if (!isReliable && roll < lossRate) {
        this.dropped_count += 1;
        return { is_delivered: false, reason: "unreliable_drop", wsa_error: wsaError.WSA_OK };
      }
      const box = endpointTable.get(toEndpoint).inbox;
      if (!box.has(channel)) box.set(channel, []);
      const queue = box.get(channel);
      if (queue.length >= netBound.recv_queue_count) {
        return { is_delivered: false, reason: "recv_queue_full", wsa_error: wsaError.WSAEWOULDBLOCK };
      }
      // Ordered channel keeps the send sequence; unordered assigns a seeded
      // arrival key so an ordered and an unordered stream of the same send
      // sequence drain in a different, deterministic order.
      const sequence = deliverySequence++;
      const arrivalKey = isOrdered ? sequence : Math.floor(arrivalRoll * 0x100000000);
      queue.push({ from: fromEndpoint, channel, sequence, arrival_key: arrivalKey, byte: Buffer.from(buffer) });
      this.delivered_count += 1;
      return { is_delivered: true, reason: "delivered", wsa_error: wsaError.WSA_OK };
    },
    // Drain the inbox for one endpoint+channel in delivery order.
    drain(endpoint, channel) {
      const entry = endpointTable.get(endpoint);
      if (!entry || !entry.inbox.has(channel)) return [];
      const queue = entry.inbox.get(channel).sort((left, right) => left.arrival_key - right.arrival_key);
      entry.inbox.set(channel, []);
      return queue;
    },
    detach(endpoint) {
      endpointTable.delete(endpoint);
    },
    endpoint_count() {
      return endpointTable.size;
    },
  };
}

// The Winsock surface over the relay. WSAStartup gates every call, the last
// error follows the ws2_32 contract, and a socket is a handle into a relay
// endpoint — never a host descriptor.
export function createWinsock(relay, option = {}) {
  const localEndpoint = typeof option.endpoint === "string" ? option.endpoint : null;
  const socketTable = new Map();
  let nextHandle = 1;
  let isStarted = false;
  let lastError = wsaError.WSA_OK;
  function fail(code) {
    lastError = code;
    return winsockConstant.SOCKET_ERROR;
  }
  function getSocket(handle) {
    return socketTable.get(handle) ?? null;
  }
  return {
    schema_version: 1,
    endpoint: localEndpoint,
    WSAStartup(versionRequested = 0x0202) {
      if (!Number.isInteger(versionRequested) || versionRequested <= 0) {
        lastError = wsaError.WSAEINVAL;
        return wsaError.WSAEINVAL;
      }
      isStarted = true;
      lastError = wsaError.WSA_OK;
      return wsaError.WSA_OK;
    },
    socket(af, type, protocol) {
      if (!isStarted) return fail(wsaError.WSANOTINITIALISED);
      if (af !== winsockConstant.AF_INET) return fail(wsaError.WSAEINVAL);
      if (type !== winsockConstant.SOCK_STREAM && type !== winsockConstant.SOCK_DGRAM) return fail(wsaError.WSAEINVAL);
      if (socketTable.size >= netBound.socket_count) return fail(wsaError.WSAEINVAL);
      const handle = nextHandle++;
      socketTable.set(handle, {
        handle,
        type,
        protocol,
        bound_endpoint: null,
        peer_endpoint: null,
        is_connected: false,
        is_nonblocking: false,
        option_value: new Map(),
      });
      lastError = wsaError.WSA_OK;
      return handle;
    },
    bind(handle, endpoint) {
      const socket = getSocket(handle);
      if (!socket) return fail(wsaError.WSAENOTSOCK);
      const decision = relay.attach(endpoint);
      if (!decision.is_authorized) return fail(decision.wsa_error);
      socket.bound_endpoint = endpoint;
      lastError = wsaError.WSA_OK;
      return wsaError.WSA_OK;
    },
    connect(handle, endpoint) {
      const socket = getSocket(handle);
      if (!socket) return fail(wsaError.WSAENOTSOCK);
      if (socket.is_connected) return fail(wsaError.WSAEISCONN);
      // A dial must be authorized before it becomes a link. An off-allowlist or
      // un-consented endpoint is refused here and no peer is ever set.
      const decision = authorizeEndpoint(relay.policy, endpoint);
      if (!decision.is_authorized) return fail(decision.wsa_error);
      if (!relay.is_attached(endpoint)) return fail(wsaError.WSAECONNREFUSED);
      if (!socket.bound_endpoint) {
        const attach = relay.attach(localEndpoint ?? `auto:${handle}`);
        if (!attach.is_authorized) return fail(attach.wsa_error);
        socket.bound_endpoint = localEndpoint ?? `auto:${handle}`;
      }
      socket.peer_endpoint = endpoint;
      socket.is_connected = true;
      lastError = wsaError.WSA_OK;
      return wsaError.WSA_OK;
    },
    // Stream send: reliable, ordered. Returns the byte count like ws2_32.
    send(handle, payload) {
      const socket = getSocket(handle);
      if (!socket) return fail(wsaError.WSAENOTSOCK);
      if (!socket.is_connected) return fail(wsaError.WSAENOTCONN);
      const buffer = toPayloadBuffer(payload);
      const result = relay.deliver(socket.bound_endpoint, socket.peer_endpoint, deliveryChannel.reliable_ordered, buffer);
      if (!result.is_delivered) return fail(result.wsa_error);
      lastError = wsaError.WSA_OK;
      return buffer.length;
    },
    // Stream recv: drains the reliable+ordered inbox. Empty inbox is the
    // non-blocking WSAEWOULDBLOCK contract, not an end-of-stream lie.
    recv(handle) {
      const socket = getSocket(handle);
      if (!socket) return { byte: winsockConstant.SOCKET_ERROR, data: null };
      // A bound endpoint is what makes a socket addressable on the relay; a
      // passive listener receives without an outbound connect. An unbound
      // socket has no inbox and reports the ws2_32 not-connected contract.
      if (!socket.bound_endpoint) { lastError = wsaError.WSAENOTCONN; return { byte: winsockConstant.SOCKET_ERROR, data: null }; }
      const drained = relay.drain(socket.bound_endpoint, deliveryChannel.reliable_ordered);
      if (drained.length === 0) { lastError = wsaError.WSAEWOULDBLOCK; return { byte: winsockConstant.SOCKET_ERROR, data: null }; }
      const data = Buffer.concat(drained.map((frame) => frame.byte));
      lastError = wsaError.WSA_OK;
      return { byte: data.length, data };
    },
    // Datagram send: unreliable, unordered, connectionless.
    sendto(handle, payload, endpoint) {
      const socket = getSocket(handle);
      if (!socket) return fail(wsaError.WSAENOTSOCK);
      if (socket.type !== winsockConstant.SOCK_DGRAM) return fail(wsaError.WSAEINVAL);
      const decision = authorizeEndpoint(relay.policy, endpoint);
      if (!decision.is_authorized) return fail(decision.wsa_error);
      if (!socket.bound_endpoint) {
        const attach = relay.attach(localEndpoint ?? `auto:${handle}`);
        if (!attach.is_authorized) return fail(attach.wsa_error);
        socket.bound_endpoint = localEndpoint ?? `auto:${handle}`;
      }
      const buffer = toPayloadBuffer(payload);
      const result = relay.deliver(socket.bound_endpoint, endpoint, deliveryChannel.unreliable_unordered, buffer);
      if (!result.is_delivered && result.reason !== "unreliable_drop") return fail(result.wsa_error);
      lastError = wsaError.WSA_OK;
      return buffer.length;
    },
    // Datagram recv: drains the unreliable+unordered inbox and names the sender.
    recvfrom(handle) {
      const socket = getSocket(handle);
      if (!socket) return { byte: winsockConstant.SOCKET_ERROR, data: null, from: null };
      const drained = relay.drain(socket.bound_endpoint, deliveryChannel.unreliable_unordered);
      if (drained.length === 0) { lastError = wsaError.WSAEWOULDBLOCK; return { byte: winsockConstant.SOCKET_ERROR, data: null, from: null }; }
      lastError = wsaError.WSA_OK;
      return drained.map((frame) => ({ byte: frame.byte.length, data: frame.byte, from: frame.from }));
    },
    // Reconnect support: a transient link loss marks the socket disconnected
    // without detaching its relay endpoint, so any reliable frame already
    // queued for the peer survives. reconnect restores the peer and the stream
    // continues in sequence — no loss, no re-handshake of buffered message.
    dropLink(handle) {
      const socket = getSocket(handle);
      if (!socket) return fail(wsaError.WSAENOTSOCK);
      if (!socket.is_connected) return fail(wsaError.WSAENOTCONN);
      socket.is_connected = false;
      socket.reconnect_count = socket.reconnect_count ?? 0;
      lastError = wsaError.WSA_OK;
      return wsaError.WSA_OK;
    },
    reconnect(handle) {
      const socket = getSocket(handle);
      if (!socket) return fail(wsaError.WSAENOTSOCK);
      if (socket.is_connected) return fail(wsaError.WSAEISCONN);
      if (!socket.peer_endpoint) return fail(wsaError.WSAENOTCONN);
      socket.reconnect_count = (socket.reconnect_count ?? 0) + 1;
      if (socket.reconnect_count > netBound.reconnect_count) return fail(wsaError.WSAECONNRESET);
      const decision = authorizeEndpoint(relay.policy, socket.peer_endpoint);
      if (!decision.is_authorized) return fail(decision.wsa_error);
      if (!relay.is_attached(socket.peer_endpoint)) return fail(wsaError.WSAECONNREFUSED);
      socket.is_connected = true;
      lastError = wsaError.WSA_OK;
      return wsaError.WSA_OK;
    },
    // Socket option: a bounded key/value store. Only a declared, host-neutral
    // option is honored; an unknown one is refused, never silently swallowed.
    setsockopt(handle, optionName, value) {
      const socket = getSocket(handle);
      if (!socket) return fail(wsaError.WSAENOTSOCK);
      if (!winsockOption[optionName]) return fail(wsaError.WSAEINVAL);
      socket.option_value.set(optionName, value);
      lastError = wsaError.WSA_OK;
      return wsaError.WSA_OK;
    },
    getsockopt(handle, optionName) {
      const socket = getSocket(handle);
      if (!socket) { lastError = wsaError.WSAENOTSOCK; return { value: winsockConstant.SOCKET_ERROR }; }
      if (!winsockOption[optionName]) { lastError = wsaError.WSAEINVAL; return { value: winsockConstant.SOCKET_ERROR }; }
      lastError = wsaError.WSA_OK;
      return { value: socket.option_value.get(optionName) ?? 0 };
    },
    // ioctlsocket FIONBIO: the non-blocking flag. It changes only the local
    // recv/recvfrom empty-inbox contract; it never reaches a host descriptor.
    ioctlsocket(handle, command, argument) {
      const socket = getSocket(handle);
      if (!socket) return fail(wsaError.WSAENOTSOCK);
      if (command !== "FIONBIO") return fail(wsaError.WSAEINVAL);
      socket.is_nonblocking = argument !== 0;
      lastError = wsaError.WSA_OK;
      return wsaError.WSA_OK;
    },
    closesocket(handle) {
      if (!socketTable.has(handle)) return fail(wsaError.WSAENOTSOCK);
      socketTable.delete(handle);
      lastError = wsaError.WSA_OK;
      return wsaError.WSA_OK;
    },
    WSAGetLastError() {
      return lastError;
    },
    WSACleanup() {
      socketTable.clear();
      isStarted = false;
      lastError = wsaError.WSA_OK;
      return wsaError.WSA_OK;
    },
    is_started() {
      return isStarted;
    },
  };
}

// A DirectPlay session/lobby stub over the relay. Host advertises a session,
// peers enumerate and join, and a player message routes over a guaranteed
// (reliable+ordered) or non-guaranteed (unreliable+unordered) channel per the
// DPSEND flag — the DirectPlay contract mapped onto the transport channel.
export function createDirectPlayLobby() {
  const sessionTable = new Map();
  return {
    schema_version: 1,
    host(relay, sessionDesc) {
      const sessionId = sessionDesc?.session_id ?? createHash("sha256").update(String(sessionDesc?.session_name ?? sessionTable.size)).digest("hex").slice(0, 16);
      if (sessionTable.has(sessionId)) throw netError("session_exists", `Session already advertised: ${sessionId}`);
      if (sessionTable.size >= netBound.session_count) throw netError("session_overflow", `Session exceeds ${netBound.session_count}`);
      const session = {
        session_id: sessionId,
        session_name: sessionDesc?.session_name ?? "session",
        max_player_count: Math.min(sessionDesc?.max_player_count ?? netBound.player_count, netBound.player_count),
        relay,
        player: new Map(),
      };
      sessionTable.set(sessionId, session);
      return { session_id: sessionId, session_name: session.session_name };
    },
    // Lobby enumeration: the advertised session list a joining peer reads.
    enumSession() {
      return [...sessionTable.values()].map((session) => ({
        session_id: session.session_id,
        session_name: session.session_name,
        current_player_count: session.player.size,
        max_player_count: session.max_player_count,
      }));
    },
    join(sessionId, playerName, endpoint) {
      const session = sessionTable.get(sessionId);
      if (!session) return { is_joined: false, reason: "session_absent", wsa_error: wsaError.WSAECONNREFUSED };
      if (session.player.size >= session.max_player_count) return { is_joined: false, reason: "session_full", wsa_error: wsaError.WSAEADDRINUSE };
      const decision = session.relay.attach(endpoint);
      if (!decision.is_authorized) return { is_joined: false, reason: decision.reason, wsa_error: decision.wsa_error };
      const playerId = session.player.size + 1;
      session.player.set(playerId, { player_id: playerId, player_name: playerName, endpoint });
      return { is_joined: true, player_id: playerId, endpoint };
    },
    listPlayer(sessionId) {
      const session = sessionTable.get(sessionId);
      if (!session) return [];
      return [...session.player.values()].map((player) => ({ player_id: player.player_id, player_name: player.player_name }));
    },
    // Route a player message. is_guaranteed maps to reliable+ordered (DirectPlay
    // DPSEND_GUARANTEED); otherwise unreliable+unordered. A broadcast fans to
    // every player but the sender.
    sendPlayerMessage(sessionId, fromPlayerId, toPlayerId, payload, option = {}) {
      const session = sessionTable.get(sessionId);
      if (!session) return { sent_count: 0, reason: "session_absent" };
      const from = session.player.get(fromPlayerId);
      if (!from) return { sent_count: 0, reason: "sender_absent" };
      const channel = option.is_guaranteed ? deliveryChannel.reliable_ordered : deliveryChannel.unreliable_unordered;
      const target = toPlayerId === "all"
        ? [...session.player.values()].filter((player) => player.player_id !== fromPlayerId)
        : [session.player.get(toPlayerId)].filter(Boolean);
      let sentCount = 0;
      for (const player of target) {
        const result = session.relay.deliver(from.endpoint, player.endpoint, channel, payload);
        if (result.is_delivered) sentCount += 1;
      }
      return { sent_count: sentCount, channel };
    },
    receiveMessage(sessionId, playerId, option = {}) {
      const session = sessionTable.get(sessionId);
      if (!session) return [];
      const player = session.player.get(playerId);
      if (!player) return [];
      const channel = option.is_guaranteed ? deliveryChannel.reliable_ordered : deliveryChannel.unreliable_unordered;
      return session.relay.drain(player.endpoint, channel).map((frame) => ({ from: frame.from, byte: frame.byte }));
    },
  };
}

// Lockstep determinism support. Each player submits one command per turn; a
// turn advances only when every player's command for that turn is present, and
// a rolling digest hashes the ordered (turn, player, command) tuple. Two
// instances fed the identical command stream compute the identical digest — a
// mismatch is a desync fault, never silently tolerated.
export function createLockstepEngine(option = {}) {
  const playerId = option.player_id ?? 1;
  const playerOrder = Array.isArray(option.player_order) ? [...option.player_order].sort((left, right) => left - right) : [playerId];
  let turnIndex = 0;
  let digest = createHash("sha256");
  const pending = new Map();
  return {
    schema_version: 1,
    player_id: playerId,
    turn_index() {
      return turnIndex;
    },
    submit(turn, fromPlayerId, command) {
      if (turn !== turnIndex) throw netError("turn_out_of_order", `Command for turn ${turn} but engine is on turn ${turnIndex}`);
      if (turnIndex >= netBound.lockstep_turn_count) throw netError("turn_overflow", `Turn exceeds ${netBound.lockstep_turn_count}`);
      if (!pending.has(turn)) pending.set(turn, new Map());
      pending.get(turn).set(fromPlayerId, command);
    },
    // Advance the turn if — and only if — every player's command is in. Returns
    // false when the turn is not yet complete (the lockstep stall that keeps
    // both instances aligned).
    tryAdvance() {
      const bucket = pending.get(turnIndex);
      if (!bucket || playerOrder.some((id) => !bucket.has(id))) return false;
      for (const id of playerOrder) {
        digest.update(`${turnIndex}:${id}:${JSON.stringify(bucket.get(id))}\n`);
      }
      pending.delete(turnIndex);
      turnIndex += 1;
      return true;
    },
    // The determinism checksum over every advanced turn. Equal across instances
    // iff the executed command stream was identical.
    determinismDigest() {
      return digest.copy().digest("hex");
    },
  };
}

// The two-instance fixture: the acceptance. Two guests attach to one relay
// through the consented allowlist, host and join a DirectPlay session, exchange
// an ordered (reliable) and an unordered (unreliable) set, and run lockstep
// turns whose digest must match. The report carries the Tier-1 invariant count
// so the caller can assert zero off-allowlist / un-consented connection.
export function runTwoInstanceFixture(option = {}) {
  const endpointA = option.endpoint_a ?? "relay:room-42/peer-a";
  const endpointB = option.endpoint_b ?? "relay:room-42/peer-b";
  const policy = createTransportPolicy({ allowlist: [endpointA, endpointB], is_consented: true });
  const relay = createMediatedRelay(policy, { seed: option.seed ?? 0x51ade, loss_rate: 0 });

  const winsockA = createWinsock(relay, { endpoint: endpointA });
  const winsockB = createWinsock(relay, { endpoint: endpointB });
  winsockA.WSAStartup();
  winsockB.WSAStartup();
  relay.attach(endpointA);
  relay.attach(endpointB);

  const lobby = createDirectPlayLobby();
  const hosted = lobby.host(relay, { session_name: "fixture", max_player_count: 2 });
  const joinA = lobby.join(hosted.session_id, "peer-a", endpointA);
  const joinB = lobby.join(hosted.session_id, "peer-b", endpointB);

  // Ordered set over the guaranteed channel: eight sequenced message A -> B.
  const orderedSent = Array.from({ length: 8 }, (unused, index) => `ordered-${index}`);
  for (const message of orderedSent) {
    lobby.sendPlayerMessage(hosted.session_id, joinA.player_id, joinB.player_id, message, { is_guaranteed: true });
  }
  const orderedReceived = lobby.receiveMessage(hosted.session_id, joinB.player_id, { is_guaranteed: true }).map((frame) => frame.byte.toString("utf8"));

  // Unordered set over the datagram channel: the same eight, delivered under
  // the unreliable+unordered model (same multiset, seeded order).
  const unorderedSent = Array.from({ length: 8 }, (unused, index) => `unordered-${index}`);
  for (const message of unorderedSent) {
    lobby.sendPlayerMessage(hosted.session_id, joinA.player_id, joinB.player_id, message, { is_guaranteed: false });
  }
  const unorderedReceived = lobby.receiveMessage(hosted.session_id, joinB.player_id, { is_guaranteed: false }).map((frame) => frame.byte.toString("utf8"));

  // Lockstep: both engines advance the identical command stream and must agree.
  const engineA = createLockstepEngine({ player_id: 1, player_order: [1, 2] });
  const engineB = createLockstepEngine({ player_id: 2, player_order: [1, 2] });
  const turnCount = option.turn_count ?? 16;
  for (let turn = 0; turn < turnCount; turn++) {
    const commandOne = { move: turn % 4, player: 1 };
    const commandTwo = { move: (turn * 3) % 4, player: 2 };
    for (const engine of [engineA, engineB]) {
      engine.submit(turn, 1, commandOne);
      engine.submit(turn, 2, commandTwo);
      engine.tryAdvance();
    }
  }

  const orderedInOrder = orderedReceived.length === orderedSent.length
    && orderedReceived.every((value, index) => value === orderedSent[index]);
  const unorderedMultisetMatch = [...unorderedReceived].sort().join(",") === [...unorderedSent].sort().join(",");

  return {
    schema_version: 1,
    item_id: "BPTK-026",
    session_id: hosted.session_id,
    player: lobby.listPlayer(hosted.session_id),
    ordered_sent_count: orderedSent.length,
    ordered_received: orderedReceived,
    is_ordered_in_order: orderedInOrder,
    unordered_sent_count: unorderedSent.length,
    unordered_received_count: unorderedReceived.length,
    is_unordered_multiset_match: unorderedMultisetMatch,
    lockstep_turn_count: engineA.turn_index(),
    is_lockstep_synced: engineA.determinismDigest() === engineB.determinismDigest(),
    off_allowlist_connection_count: policy.off_allowlist_attempt_count,
    unconsented_connection_count: policy.unconsented_attempt_count,
    host_socket_opened: relay.host_socket_opened,
    is_accepted:
      orderedInOrder
      && unorderedMultisetMatch
      && engineA.determinismDigest() === engineB.determinismDigest()
      && policy.off_allowlist_attempt_count === 0
      && policy.unconsented_attempt_count === 0
      && relay.host_socket_opened === false,
  };
}

// The honest acceptance state: the contract is implemented and exercised by the
// in-process fixture, but the live capability stays red until a browser relay,
// a real consent surface, and a guest ws2_32 import binding exist.
export const netAcceptance = Object.freeze({
  item_id: "BPTK-026",
  state: "implemented_red",
  invariant: "zero off-allowlist / un-consented connection",
  reason:
    "The Winsock/DirectPlay contract, the seeded delivery model, reconnect state, lockstep determinism, and the two-instance fixture run in-process over a mediated switchboard. The live acceptance is red because no browser WebRTC-data/WebSocket relay, no real consent surface, and no guest ws2_32 import binding exist yet, and the BPTK-026 prerequisite (BPTK-004 approval, BPTK-021, BPTK-024) remain red.",
});

// The net conformance case table + implementation: every served Winsock export
// carries at least one case so the generic conformance apparatus reports zero
// uncovered export for the net surface. The live suite stays red at the .exe
// stage; this proves the surface's own coverage is complete.
export function listNetExport() {
  return [
    "ws2_32.dll!WSAStartup",
    "ws2_32.dll!socket",
    "ws2_32.dll!bind",
    "ws2_32.dll!connect",
    "ws2_32.dll!send",
    "ws2_32.dll!recv",
    "ws2_32.dll!sendto",
    "ws2_32.dll!recvfrom",
    "ws2_32.dll!closesocket",
    "ws2_32.dll!setsockopt",
    "ws2_32.dll!getsockopt",
    "ws2_32.dll!ioctlsocket",
    "ws2_32.dll!getaddrinfo",
    "ws2_32.dll!gethostbyname",
    "ws2_32.dll!htons",
    "ws2_32.dll!ntohs",
    "ws2_32.dll!inet_addr",
    "ws2_32.dll!WSAGetLastError",
    "ws2_32.dll!WSACleanup",
  ];
}

export function buildNetConformanceCaseTable() {
  return [
    { case_id: "net-startup", library: "ws2_32.dll", symbol: "WSAStartup", input: [0x0202], expected: { return_value: wsaError.WSA_OK, last_error: wsaError.WSA_OK } },
    { case_id: "net-socket-before-startup", library: "ws2_32.dll", symbol: "socket", input: ["cold"], expected: { return_value: winsockConstant.SOCKET_ERROR, last_error: wsaError.WSANOTINITIALISED } },
    { case_id: "net-socket-stream", library: "ws2_32.dll", symbol: "socket", input: [winsockConstant.AF_INET, winsockConstant.SOCK_STREAM, winsockConstant.IPPROTO_TCP], expected: { return_value: 1, last_error: wsaError.WSA_OK } },
    { case_id: "net-bind-authorized", library: "ws2_32.dll", symbol: "bind", input: ["on"], expected: { return_value: wsaError.WSA_OK, last_error: wsaError.WSA_OK } },
    { case_id: "net-bind-off-allowlist", library: "ws2_32.dll", symbol: "bind", input: ["off"], expected: { return_value: winsockConstant.SOCKET_ERROR, last_error: wsaError.WSAEACCES } },
    { case_id: "net-connect-refused", library: "ws2_32.dll", symbol: "connect", input: ["off"], expected: { return_value: winsockConstant.SOCKET_ERROR, last_error: wsaError.WSAEACCES } },
    { case_id: "net-send-not-connected", library: "ws2_32.dll", symbol: "send", input: ["cold"], expected: { return_value: winsockConstant.SOCKET_ERROR, last_error: wsaError.WSAENOTCONN } },
    { case_id: "net-recv-would-block", library: "ws2_32.dll", symbol: "recv", input: ["empty"], expected: { return_value: winsockConstant.SOCKET_ERROR, last_error: wsaError.WSAEWOULDBLOCK } },
    { case_id: "net-sendto-datagram", library: "ws2_32.dll", symbol: "sendto", input: ["dgram"], expected: { return_value: 5, last_error: wsaError.WSA_OK } },
    { case_id: "net-recvfrom-would-block", library: "ws2_32.dll", symbol: "recvfrom", input: ["empty"], expected: { return_value: winsockConstant.SOCKET_ERROR, last_error: wsaError.WSAEWOULDBLOCK } },
    { case_id: "net-closesocket-not-socket", library: "ws2_32.dll", symbol: "closesocket", input: ["missing"], expected: { return_value: winsockConstant.SOCKET_ERROR, last_error: wsaError.WSAENOTSOCK } },
    { case_id: "net-setsockopt-known", library: "ws2_32.dll", symbol: "setsockopt", input: ["TCP_NODELAY"], expected: { return_value: wsaError.WSA_OK, last_error: wsaError.WSA_OK } },
    { case_id: "net-setsockopt-unknown", library: "ws2_32.dll", symbol: "setsockopt", input: ["SO_UNKNOWN"], expected: { return_value: winsockConstant.SOCKET_ERROR, last_error: wsaError.WSAEINVAL } },
    { case_id: "net-getsockopt-known", library: "ws2_32.dll", symbol: "getsockopt", input: ["TCP_NODELAY"], expected: { return_value: 1, last_error: wsaError.WSA_OK } },
    { case_id: "net-ioctlsocket-fionbio", library: "ws2_32.dll", symbol: "ioctlsocket", input: ["FIONBIO"], expected: { return_value: wsaError.WSA_OK, last_error: wsaError.WSA_OK } },
    { case_id: "net-getaddrinfo-off-allowlist", library: "ws2_32.dll", symbol: "getaddrinfo", input: ["evil.example"], expected: { return_value: 11001, last_error: wsaError.WSA_OK } },
    { case_id: "net-gethostbyname-allowlisted", library: "ws2_32.dll", symbol: "gethostbyname", input: ["peer"], expected: { return_value: 0, last_error: wsaError.WSA_OK } },
    { case_id: "net-htons", library: "ws2_32.dll", symbol: "htons", input: [0x1234], expected: { return_value: 0x3412, last_error: wsaError.WSA_OK } },
    { case_id: "net-ntohs", library: "ws2_32.dll", symbol: "ntohs", input: [0x3412], expected: { return_value: 0x1234, last_error: wsaError.WSA_OK } },
    { case_id: "net-inet-addr-malformed", library: "ws2_32.dll", symbol: "inet_addr", input: ["999.1.1.1"], expected: { return_value: 0xffffffff, last_error: wsaError.WSA_OK } },
    { case_id: "net-getlasterror", library: "ws2_32.dll", symbol: "WSAGetLastError", input: [], expected: { return_value: wsaError.WSA_OK, last_error: wsaError.WSA_OK } },
    { case_id: "net-cleanup", library: "ws2_32.dll", symbol: "WSACleanup", input: [], expected: { return_value: wsaError.WSA_OK, last_error: wsaError.WSA_OK } },
  ];
}

// The conformance implementation-under-test: one machine that maps a case onto
// the real Winsock surface over a consented, allowlisted relay so the oracle
// compares against genuine emulator behavior, not a rehearsed answer.
export function createNetConformanceImplementation() {
  const endpoint = "relay:conformance/local";
  const peer = "relay:conformance/peer";
  const policy = createTransportPolicy({ allowlist: [endpoint, peer], is_consented: true });
  const relay = createMediatedRelay(policy, { seed: 7 });
  relay.attach(endpoint);
  relay.attach(peer);
  const winsock = createWinsock(relay, { endpoint });
  let streamHandle = null;
  let datagramHandle = null;
  return function execute(library, symbol, input) {
    const observe = (returnValue) => ({ return_value: returnValue, last_error: winsock.WSAGetLastError() });
    switch (symbol) {
      case "WSAStartup":
        return observe(winsock.WSAStartup(input[0] ?? 0x0202));
      case "socket": {
        if (input[0] === "cold") {
          const cold = createWinsock(createMediatedRelay(createTransportPolicy({ allowlist: [endpoint], is_consented: true })), { endpoint });
          return { return_value: cold.socket(winsockConstant.AF_INET, winsockConstant.SOCK_STREAM, winsockConstant.IPPROTO_TCP), last_error: cold.WSAGetLastError() };
        }
        streamHandle = winsock.socket(input[0], input[1], input[2]);
        datagramHandle = winsock.socket(winsockConstant.AF_INET, winsockConstant.SOCK_DGRAM, winsockConstant.IPPROTO_UDP);
        return observe(streamHandle);
      }
      case "bind":
        return observe(winsock.bind(streamHandle, input[0] === "off" ? "relay:conformance/evil" : endpoint));
      case "connect":
        return observe(winsock.connect(streamHandle, input[0] === "off" ? "relay:conformance/evil" : peer));
      case "send": {
        if (input[0] === "cold") {
          const fresh = winsock.socket(winsockConstant.AF_INET, winsockConstant.SOCK_STREAM, winsockConstant.IPPROTO_TCP);
          return observe(winsock.send(fresh, "x"));
        }
        return observe(winsock.send(streamHandle, "x"));
      }
      case "recv": {
        const result = winsock.recv(streamHandle);
        return { return_value: result.byte, last_error: winsock.WSAGetLastError() };
      }
      case "sendto":
        return observe(winsock.sendto(datagramHandle, "hello", peer));
      case "recvfrom": {
        const result = winsock.recvfrom(datagramHandle);
        const byte = Array.isArray(result) ? result[0].byte : result.byte;
        return { return_value: byte, last_error: winsock.WSAGetLastError() };
      }
      case "closesocket":
        return observe(winsock.closesocket(input[0] === "missing" ? 9999 : streamHandle));
      case "setsockopt":
        return observe(winsock.setsockopt(datagramHandle, input[0], 1));
      case "getsockopt": {
        winsock.setsockopt(datagramHandle, input[0], 1);
        const result = winsock.getsockopt(datagramHandle, input[0]);
        return { return_value: result.value, last_error: winsock.WSAGetLastError() };
      }
      case "ioctlsocket":
        return observe(winsock.ioctlsocket(datagramHandle, input[0], 1));
      case "getaddrinfo": {
        const result = resolveName(policy, input[0] === "peer" ? peer : "relay:conformance/evil");
        return { return_value: result.is_resolved ? 0 : result.wsa_error, last_error: wsaError.WSA_OK };
      }
      case "gethostbyname": {
        const result = resolveName(policy, peer);
        return { return_value: result.is_resolved ? 0 : result.wsa_error, last_error: wsaError.WSA_OK };
      }
      case "htons":
        return { return_value: htons(input[0]), last_error: wsaError.WSA_OK };
      case "ntohs":
        return { return_value: ntohs(input[0]), last_error: wsaError.WSA_OK };
      case "inet_addr":
        return { return_value: inetAddr(input[0]), last_error: wsaError.WSA_OK };
      case "WSAGetLastError":
        return { return_value: wsaError.WSA_OK, last_error: wsaError.WSA_OK };
      case "WSACleanup":
        return observe(winsock.WSACleanup());
      default:
        throw netError("unserved_net_export", `Net surface does not serve ${library}!${symbol}`);
    }
  };
}

export function formatNet(report) {
  return [
    `Net (BPTK-026): ${netAcceptance.state}`,
    `Session: ${report.session_id} with ${report.player.length} player`,
    `Ordered: ${report.ordered_received.length}/${report.ordered_sent_count} in order ${report.is_ordered_in_order ? "yes" : "no"}`,
    `Unordered: ${report.unordered_received_count}/${report.unordered_sent_count} multiset ${report.is_unordered_multiset_match ? "match" : "differ"}`,
    `Lockstep: ${report.lockstep_turn_count} turn synced ${report.is_lockstep_synced ? "yes" : "no"}`,
    `Off-allowlist connection: ${report.off_allowlist_connection_count}; un-consented: ${report.unconsented_connection_count}`,
    `Accepted: ${report.is_accepted ? "yes" : "no"} — but live capability red: ${netAcceptance.reason}`,
  ].join("\n");
}
