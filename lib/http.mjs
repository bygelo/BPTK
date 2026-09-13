// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Generic Win32 / WinHTTP-style HLE for leftover sidecar IAT (BPTK-010 / 099).
// A packaged libcurl (or any WinHTTP/CAPI caller) gets a session and handle
// table, deny-by-default name resolution, real MD5/SHA hashes, and a
// deterministic PRNG. TLS keys, certificate chains, and host sockets do not
// exist — same posture as the empty SSPI table. No title branch. zlib is not
// stubbed: a package-local zlib1.dll stays a sidecar PE.

import { createHash } from "node:crypto";
import { InputError } from "./input.mjs";

export const httpBound = Object.freeze({
  session_count: 32,
  connection_count: 64,
  request_count: 64,
  provider_count: 16,
  hash_count: 64,
  store_count: 16,
  header_byte: 4096,
});

export const winHttpError = Object.freeze({
  success: 0,
  invalid_handle: 6,
  invalid_parameter: 87,
  name_not_resolved: 12007,
  cannot_connect: 12029,
  connection_error: 12030,
});

export const capiStatus = Object.freeze({
  ok: 0,
  nte_bad_uid: 0x80090001,
  nte_bad_hash: 0x80090002,
  nte_bad_algid: 0x80090008,
  nte_bad_flags: 0x80090009,
  nte_not_supported: 0x80090029,
  crypt_e_not_found: 0x80092004,
  crypt_e_no_match: 0x80092009,
});

export const bcryptStatus = Object.freeze({
  success: 0,
  invalid_handle: 0xc0000008,
  invalid_parameter: 0xc000000d,
});

export const capiAlg = Object.freeze({
  md5: 0x00008003,
  sha1: 0x00008004,
  sha256: 0x0000800c,
});

export const capiHashParam = Object.freeze({
  algid: 1,
  hashval: 2,
  hashsize: 4,
});

const firstSession = 0x00090000;
const firstConnection = 0x00091000;
const firstRequest = 0x00092000;
const firstProvider = 0x00093000;
const firstHash = 0x00094000;
const firstStore = 0x00095000;

function httpError(code, message) {
  return new InputError(code, message);
}

function hashName(algid) {
  if (algid === capiAlg.md5) return "md5";
  if (algid === capiAlg.sha1) return "sha1";
  if (algid === capiAlg.sha256) return "sha256";
  return null;
}

function fillPrng(size, seed) {
  const block = Buffer.alloc(size);
  let state = (seed >>> 0) || 0x4250544b;
  for (let index = 0; index < size; index += 1) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    block[index] = state >>> 24;
  }
  return block;
}

// One guest's WinHTTP session table plus the CAPI/CNG/crypt32 handles a
// libcurl-class sidecar imports. Every dial is refused; hash and PRNG are real.
export function createHttpSubsystem(option = {}) {
  const sessionTable = new Map();
  const connectionTable = new Map();
  const requestTable = new Map();
  const providerTable = new Map();
  const hashTable = new Map();
  const storeTable = new Map();
  let nextSession = firstSession;
  let nextConnection = firstConnection;
  let nextRequest = firstRequest;
  let nextProvider = firstProvider;
  let nextHash = firstHash;
  let nextStore = firstStore;
  let lastError = winHttpError.success;
  const prngSeed = option.prng_seed ?? 0x4250544b;

  function fail(code) {
    lastError = code >>> 0;
    return 0;
  }

  return {
    schema_version: 1,
    getLastError() {
      return lastError;
    },
    setLastError(code) {
      lastError = code >>> 0;
    },

    // --- WinHTTP session / request (deny-by-default) ---------------------------
    WinHttpOpen(agent) {
      if (sessionTable.size >= httpBound.session_count) return fail(winHttpError.invalid_parameter);
      const handle = nextSession++;
      sessionTable.set(handle, { handle, kind: "session", agent: typeof agent === "string" ? agent : "", timeout_ms: 0 });
      lastError = winHttpError.success;
      return handle;
    },
    WinHttpConnect(session, server, port) {
      if (!sessionTable.has(session >>> 0)) return fail(winHttpError.invalid_handle);
      if (typeof server !== "string" || server === "") return fail(winHttpError.invalid_parameter);
      if (connectionTable.size >= httpBound.connection_count) return fail(winHttpError.invalid_parameter);
      const handle = nextConnection++;
      connectionTable.set(handle, { handle, kind: "connection", session: session >>> 0, server, port: port & 0xffff });
      lastError = winHttpError.success;
      return handle;
    },
    WinHttpOpenRequest(connection, verb, objectPath) {
      if (!connectionTable.has(connection >>> 0)) return fail(winHttpError.invalid_handle);
      if (requestTable.size >= httpBound.request_count) return fail(winHttpError.invalid_parameter);
      const handle = nextRequest++;
      requestTable.set(handle, {
        handle,
        kind: "request",
        connection: connection >>> 0,
        verb: typeof verb === "string" && verb !== "" ? verb : "GET",
        object_path: typeof objectPath === "string" ? objectPath : "/",
        is_sent: false,
      });
      lastError = winHttpError.success;
      return handle;
    },
    WinHttpSendRequest(request) {
      const entry = requestTable.get(request >>> 0);
      if (!entry) return fail(winHttpError.invalid_handle);
      entry.is_sent = true;
      lastError = winHttpError.name_not_resolved;
      return 0;
    },
    WinHttpReceiveResponse(request) {
      const entry = requestTable.get(request >>> 0);
      if (!entry) return fail(winHttpError.invalid_handle);
      lastError = entry.is_sent ? winHttpError.cannot_connect : winHttpError.invalid_parameter;
      return 0;
    },
    WinHttpReadData(request) {
      if (!requestTable.has(request >>> 0)) return fail(winHttpError.invalid_handle);
      lastError = winHttpError.connection_error;
      return 0;
    },
    WinHttpSetTimeouts(session, resolveMs, connectMs, sendMs, receiveMs) {
      const entry = sessionTable.get(session >>> 0);
      if (!entry) return fail(winHttpError.invalid_handle);
      entry.timeout_ms = Math.max(resolveMs, connectMs, sendMs, receiveMs) | 0;
      lastError = winHttpError.success;
      return 1;
    },
    WinHttpCloseHandle(handle) {
      const id = handle >>> 0;
      if (sessionTable.delete(id) || connectionTable.delete(id) || requestTable.delete(id)) {
        lastError = winHttpError.success;
        return 1;
      }
      return fail(winHttpError.invalid_handle);
    },

    // --- CAPI: provider + hash exist; keys/TLS do not --------------------------
    CryptAcquireContext() {
      if (providerTable.size >= httpBound.provider_count) {
        lastError = capiStatus.nte_not_supported;
        return 0;
      }
      const handle = nextProvider++;
      providerTable.set(handle, { handle, kind: "provider" });
      lastError = capiStatus.ok;
      return handle;
    },
    CryptReleaseContext(provider) {
      if (!providerTable.delete(provider >>> 0)) {
        lastError = capiStatus.nte_bad_uid;
        return 0;
      }
      lastError = capiStatus.ok;
      return 1;
    },
    CryptCreateHash(provider, algid) {
      if (!providerTable.has(provider >>> 0)) {
        lastError = capiStatus.nte_bad_uid;
        return 0;
      }
      const name = hashName(algid >>> 0);
      if (name === null) {
        lastError = capiStatus.nte_bad_algid;
        return 0;
      }
      if (hashTable.size >= httpBound.hash_count) {
        lastError = capiStatus.nte_not_supported;
        return 0;
      }
      const handle = nextHash++;
      hashTable.set(handle, { handle, kind: "hash", algid: algid >>> 0, digest: createHash(name) });
      lastError = capiStatus.ok;
      return handle;
    },
    CryptHashData(hash, data) {
      const entry = hashTable.get(hash >>> 0);
      if (!entry) {
        lastError = capiStatus.nte_bad_hash;
        return 0;
      }
      entry.digest.update(data);
      lastError = capiStatus.ok;
      return 1;
    },
    CryptGetHashParam(hash, param) {
      const entry = hashTable.get(hash >>> 0);
      if (!entry) {
        lastError = capiStatus.nte_bad_hash;
        return null;
      }
      if (param === capiHashParam.algid) {
        lastError = capiStatus.ok;
        return { dword: entry.algid, byte: null };
      }
      const digest = entry.digest.copy().digest();
      if (param === capiHashParam.hashsize) {
        lastError = capiStatus.ok;
        return { dword: digest.length, byte: null };
      }
      if (param === capiHashParam.hashval) {
        lastError = capiStatus.ok;
        return { dword: digest.length, byte: digest };
      }
      lastError = capiStatus.nte_bad_flags;
      return null;
    },
    CryptDestroyHash(hash) {
      if (!hashTable.delete(hash >>> 0)) {
        lastError = capiStatus.nte_bad_hash;
        return 0;
      }
      lastError = capiStatus.ok;
      return 1;
    },
    CryptEncrypt() {
      lastError = capiStatus.nte_not_supported;
      return 0;
    },
    CryptImportKey() {
      lastError = capiStatus.nte_not_supported;
      return 0;
    },
    CryptDestroyKey() {
      lastError = capiStatus.nte_not_supported;
      return 0;
    },

    // --- CNG preferred RNG (deterministic; no host CSPRNG) ---------------------
    BCryptGenRandom(size, seed) {
      if (!Number.isInteger(size) || size < 0) return { status: bcryptStatus.invalid_parameter, byte: null };
      return { status: bcryptStatus.success, byte: fillPrng(size, seed ?? prngSeed) };
    },

    // --- crypt32: empty store; no chain, no PFX --------------------------------
    CertOpenStore() {
      if (storeTable.size >= httpBound.store_count) {
        lastError = capiStatus.crypt_e_not_found;
        return 0;
      }
      const handle = nextStore++;
      storeTable.set(handle, { handle, kind: "store" });
      lastError = capiStatus.ok;
      return handle;
    },
    CertCloseStore(store) {
      if (!storeTable.delete(store >>> 0)) {
        lastError = capiStatus.crypt_e_not_found;
        return 0;
      }
      lastError = capiStatus.ok;
      return 1;
    },
    CertEnumCertificatesInStore() {
      lastError = capiStatus.crypt_e_not_found;
      return 0;
    },
    CertFindCertificateInStore() {
      lastError = capiStatus.crypt_e_not_found;
      return 0;
    },
    CertFreeCertificateContext() {
      lastError = capiStatus.ok;
      return 1;
    },
    CertFreeCTLContext() {
      lastError = capiStatus.ok;
      return 1;
    },
    CertFreeCRLContext() {
      lastError = capiStatus.ok;
      return 1;
    },
    CertAddCertificateContextToStore() {
      lastError = capiStatus.crypt_e_no_match;
      return 0;
    },
    CertCreateCertificateChainEngine() {
      lastError = capiStatus.ok;
      return 0x00096001;
    },
    CertFreeCertificateChainEngine() {
      lastError = capiStatus.ok;
      return 1;
    },
    CertGetCertificateChain() {
      lastError = capiStatus.crypt_e_not_found;
      return 0;
    },
    CertFreeCertificateChain() {
      lastError = capiStatus.ok;
      return 1;
    },
    CertFindExtension() {
      lastError = capiStatus.crypt_e_not_found;
      return 0;
    },
    CertGetNameStringW() {
      lastError = capiStatus.ok;
      return 1;
    },
    CryptQueryObject() {
      lastError = capiStatus.crypt_e_no_match;
      return 0;
    },
    PFXImportCertStore() {
      lastError = capiStatus.crypt_e_no_match;
      return 0;
    },
    CryptDecodeObjectEx() {
      lastError = capiStatus.crypt_e_no_match;
      return 0;
    },

    // --- iphlpapi: no host interface -------------------------------------------
    if_nametoindex(name) {
      if (typeof name !== "string" || name === "") {
        lastError = winHttpError.invalid_parameter;
        return 0;
      }
      lastError = winHttpError.success;
      return 0;
    },
  };
}

export function decodeCryptString(text, flag) {
  if (typeof text !== "string") throw httpError("invalid_crypt_string", "CryptStringToBinary needs a string");
  const trimmed = text.replace(/\s+/g, "");
  if (flag === 4) {
    if (!/^[0-9a-fA-F]*$/.test(trimmed) || trimmed.length % 2 !== 0) return null;
    return Buffer.from(trimmed, "hex");
  }
  if (flag === 0 || flag === 1) {
    const body = flag === 0 ? trimmed.replace(/^-----BEGIN[^-]*-----/, "").replace(/-----END[^-]*-----$/, "") : trimmed;
    try {
      return Buffer.from(body, "base64");
    } catch {
      return null;
    }
  }
  return null;
}

export const httpAcceptance = Object.freeze({
  item_id: "BPTK-010",
  state: "implemented_red",
  reason:
    "WinHTTP-style session handles, CAPI hashes, and CNG PRNG are served. Dial, TLS keys, and certificate chains stay refused (deny-by-default). No host socket. Not a playable network client.",
});
