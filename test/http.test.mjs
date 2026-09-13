// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Generic WinHTTP-style HLE (leftover sidecar IAT): session handles exist,
// dials refuse, CAPI hashes are real, certificate chains are not found, and
// no title branch appears.

import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import {
  bcryptStatus,
  capiAlg,
  capiHashParam,
  capiStatus,
  createHttpSubsystem,
  decodeCryptString,
  httpAcceptance,
  winHttpError,
} from "../lib/http.mjs";
import { createConformanceMachine, resolveHleExport } from "../lib/hle.mjs";
import { isSystemLibrary } from "../lib/sidecar.mjs";

function invoke(guest, library, symbol, argument) {
  return guest.invokeExport(guest.lookupExport(library, symbol), argument);
}

test("WinHTTP opens a session then refuses the unconsented send", () => {
  const http = createHttpSubsystem();
  const session = http.WinHttpOpen("BPTK");
  assert.notEqual(session, 0);
  const connection = http.WinHttpConnect(session, "example.test", 443);
  assert.notEqual(connection, 0);
  const request = http.WinHttpOpenRequest(connection, "GET", "/");
  assert.notEqual(request, 0);
  assert.equal(http.WinHttpSendRequest(request), 0);
  assert.equal(http.getLastError(), winHttpError.name_not_resolved);
  assert.equal(http.WinHttpReceiveResponse(request), 0);
  assert.equal(http.getLastError(), winHttpError.cannot_connect);
  assert.equal(http.WinHttpCloseHandle(request), 1);
  assert.equal(http.WinHttpCloseHandle(0), 0);
  assert.equal(http.getLastError(), winHttpError.invalid_handle);
});

test("CAPI hashes SHA-1 and refuses TLS key import", () => {
  const http = createHttpSubsystem();
  const provider = http.CryptAcquireContext();
  const hash = http.CryptCreateHash(provider, capiAlg.sha1);
  assert.equal(http.CryptHashData(hash, Buffer.from("abc")), 1);
  const result = http.CryptGetHashParam(hash, capiHashParam.hashval);
  assert.equal(result.byte.toString("hex"), createHash("sha1").update("abc").digest("hex"));
  assert.equal(http.CryptImportKey(), 0);
  assert.equal(http.getLastError(), capiStatus.nte_not_supported);
  assert.equal(http.CryptEncrypt(), 0);
  assert.equal(http.CryptDestroyHash(hash), 1);
  assert.equal(http.CryptReleaseContext(provider), 1);
});

test("crypt32 stores are empty and BCryptGenRandom is deterministic", () => {
  const http = createHttpSubsystem({ prng_seed: 1 });
  const store = http.CertOpenStore();
  assert.notEqual(store, 0);
  assert.equal(http.CertEnumCertificatesInStore(), 0);
  assert.equal(http.getLastError(), capiStatus.crypt_e_not_found);
  assert.equal(http.CertGetCertificateChain(), 0);
  assert.equal(http.CertCloseStore(store), 1);
  const first = http.BCryptGenRandom(8, 1);
  const second = http.BCryptGenRandom(8, 1);
  assert.equal(first.status, bcryptStatus.success);
  assert.deepEqual(first.byte, second.byte);
  assert.equal(http.if_nametoindex("eth0"), 0);
});

test("CryptStringToBinary decodes hex and base64", () => {
  assert.deepEqual(decodeCryptString("4142", 4), Buffer.from("AB"));
  assert.deepEqual(decodeCryptString("QUI=", 1), Buffer.from("AB"));
  assert.equal(decodeCryptString("zz", 4), null);
});

test("leftover libcurl sidecar IAT symbols bind as generic HLE", () => {
  const leftover = [
    ["ws2_32.dll", "getaddrinfo"],
    ["ws2_32.dll", "freeaddrinfo"],
    ["ws2_32.dll", "WSAIoctl"],
    ["ws2_32.dll", null, 1],
    ["ws2_32.dll", null, 13],
    ["ws2_32.dll", null, 151],
    ["ws2_32.dll", null, 112],
    ["bcrypt.dll", "BCryptGenRandom"],
    ["advapi32.dll", "CryptAcquireContextW"],
    ["crypt32.dll", "CertOpenStore"],
    ["iphlpapi.dll", "if_nametoindex"],
    ["winhttp.dll", "WinHttpOpen"],
  ];
  for (const [library, symbol, ordinal] of leftover) {
    assert.ok(resolveHleExport(library, symbol, ordinal), `${library}!${symbol ?? `#${ordinal}`} must bind`);
  }
  assert.equal(isSystemLibrary("bcrypt.dll"), true);
  assert.equal(isSystemLibrary("winhttp.dll"), true);
  assert.equal(isSystemLibrary("zlib1.dll"), false, "zlib stays a sidecar PE, not HLE");
});

test("guest WinHTTP and CAPI rows match the subsystem", () => {
  const { guest, memory } = createConformanceMachine();
  const session = invoke(guest, "winhttp.dll", "WinHttpOpen", [0, 0, 0, 0, 0]);
  assert.equal(session, 0x00090000);
  assert.equal(invoke(guest, "winhttp.dll", "WinHttpSendRequest", [0]), 0);
  assert.equal(guest.getLastError(), 6);
  const dest = guest.layout.arena_base + 0x40;
  assert.equal(invoke(guest, "bcrypt.dll", "BCryptGenRandom", [0, dest, 4, 2]), 0);
  assert.notEqual(memory.readMemory(dest, 4), 0);
});

test("the http acceptance stays implemented-red and names no title", () => {
  assert.equal(httpAcceptance.state, "implemented_red");
  assert.doesNotMatch(httpAcceptance.reason, /SuperTux|OpenTTD|title/i);
});
