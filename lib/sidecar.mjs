// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Package-local PE module mapping (the BottleShip-class loader slice).
// A title that imports sdl2.dll / zlib1.dll / msvcp140.dll is not asking
// for a kernel32 stub: those byte live next to the executable. This module
// maps each such DLL at a non-overlapping base, binds the guest IAT to the
// real export VA, and recursively maps that DLL's own non-system imports.
// System libraries stay on the Win32 HLE. Package-local exports win over an
// HLE row so a shipped ucrt `_initterm` is the real walker. Each sidecar
// DllMain is invoked with DLL_PROCESS_ATTACH before the main TLS/entry
// phases (dependency first). Sidecar TLS callbacks are not a separate phase.

import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { mapPe32ForRuntime } from "./pe.mjs";
import { listWin32HleExport, resolveHleExport, hleImportBindAddress } from "./hle.mjs";
import { applyLeftoverSidecarIat } from "./openal32.mjs";

const maxSidecarCount = 48;
const sidecarAlign = 0x01000000;
const sidecarBaseFirst = 0x28000000;

const systemLibrary = new Set([
  "kernel32.dll",
  "user32.dll",
  "gdi32.dll",
  "ntdll.dll",
  "advapi32.dll",
  "ws2_32.dll",
  "ole32.dll",
  "oleaut32.dll",
  "comctl32.dll",
  "comdlg32.dll",
  "shell32.dll",
  "shlwapi.dll",
  "imm32.dll",
  "winmm.dll",
  "version.dll",
  "secur32.dll",
  "sspicli.dll",
  "setupapi.dll",
  "usp10.dll",
  "msvcrt.dll",
  "opengl32.dll",
]);

export function isSystemLibrary(library) {
  const lib = String(library ?? "").toLowerCase();
  return systemLibrary.has(lib) || lib.startsWith("api-ms-win-");
}

export function resolveSidecarPath(executablePath, library) {
  if (typeof executablePath !== "string" || typeof library !== "string") return null;
  if (isSystemLibrary(library)) return null;
  const dir = dirname(executablePath);
  const leaf = library.split(/[\\/]/).pop();
  if (!leaf) return null;
  const exact = join(dir, leaf);
  let listing;
  try {
    listing = readdirSync(dir);
  } catch {
    return existsSync(exact) ? exact : null;
  }
  const wanted = leaf.toLowerCase();
  const match = listing.find((name) => name.toLowerCase() === wanted);
  return match === undefined ? null : join(dir, match);
}

function chooseSidecarBase(occupied, sizeByte) {
  const aligned = Math.ceil(Math.max(sizeByte, 1) / sidecarAlign) * sidecarAlign;
  for (let base = sidecarBaseFirst; base < 0x60000000; base += sidecarAlign) {
    const end = base + aligned;
    if (!occupied.some((range) => base < range.end && range.start < end)) return base;
  }
  return null;
}

function thunkMap(layout) {
  return new Map(listWin32HleExport().map((entry, index) => [`${entry.library}!${entry.symbol}`, layout.thunk_base + index * 4]));
}

function parseForwarder(forwarder) {
  if (typeof forwarder !== "string" || !forwarder.includes(".")) return null;
  const dot = forwarder.lastIndexOf(".");
  let library = forwarder.slice(0, dot);
  const symbol = forwarder.slice(dot + 1);
  if (!library.toLowerCase().endsWith(".dll")) library = `${library}.dll`;
  return { library: library.toLowerCase(), symbol };
}

function sidecarAlias(library) {
  const lib = String(library ?? "").toLowerCase();
  if (/^api-ms-win-crt-[a-z0-9-]+\.dll$/.test(lib)) return ["ucrtbase.dll", "msvcrt.dll"];
  return [];
}

export function bindSidecarModules({ executablePath, import: importEntry, layout }) {
  const thunkBySymbol = thunkMap(layout);
  const loaded = new Map();
  const occupied = [];
  const refusal = [];
  try {
    const main = mapPe32ForRuntime(executablePath, null, null);
    occupied.push({
      start: main.report.load_base,
      end: main.report.load_base + main.report.image_size_byte,
    });
  } catch {
    // The caller already mapped the main image; a second probe failure
    // must not hide the sidecar bind of whatever still sits next to it.
  }
  if (Number.isSafeInteger(layout?.stack_base) && Number.isSafeInteger(layout?.stack_end)) {
    occupied.push({ start: layout.stack_base, end: layout.stack_end });
  }
  if (Number.isSafeInteger(layout?.block_base)) {
    occupied.push({ start: layout.block_base, end: 0x100000000 });
  }

  function resolveOne(library, symbol, ordinal, depth = 0) {
    if (depth > 8) return undefined;
    // A package-local DLL is the 1:1 image. Prefer it over an HLE row so
    // ucrt `_initterm` actually walks constructors and SDL runs its own code.
    // System libraries never map here, so kernel32 stays on the thunk page.
    for (const name of [library, ...sidecarAlias(library)]) {
      const module = ensureModule(name);
      if (module === null) continue;
      const exported = symbol != null
        ? module.exportByName.get(symbol)
        : module.exportByOrdinal.get(ordinal);
      if (exported === undefined) continue;
      if (exported.is_forwarder) {
        const target = parseForwarder(exported.forwarder);
        if (target === null) continue;
        return resolveOne(target.library, target.symbol, null, depth + 1);
      }
      return (module.load_base + exported.rva) >>> 0;
    }
    const hle = resolveHleExport(library, symbol, ordinal);
    if (hle) {
      const thunk = thunkBySymbol.get(`${hle.library}!${hle.symbol}`);
      return hleImportBindAddress(layout, hle, thunk);
    }
    return undefined;
  }

  function ensureModule(library) {
    const lib = String(library ?? "").toLowerCase();
    if (loaded.has(lib)) return loaded.get(lib);
    if (isSystemLibrary(lib)) return null;
    if (loaded.size >= maxSidecarCount) {
      refusal.push(`sidecar_count_limit: ${lib}`);
      return null;
    }
    const path = resolveSidecarPath(executablePath, library);
    if (path === null) return null;
    let probe;
    try {
      probe = mapPe32ForRuntime(path, null, null);
    } catch (error) {
      refusal.push(`${lib}: ${error.message}`);
      loaded.set(lib, null);
      return null;
    }
    const base = chooseSidecarBase(occupied, probe.report.image_size_byte);
    if (base === null) {
      refusal.push(`sidecar_address_exhausted: ${lib}`);
      loaded.set(lib, null);
      return null;
    }
    occupied.push({ start: base, end: base + Math.ceil(probe.report.image_size_byte / sidecarAlign) * sidecarAlign });
    let mapped = probe;
    if (probe.report.load_base !== base) {
      try {
        mapped = mapPe32ForRuntime(path, base, null);
      } catch (error) {
        refusal.push(`${lib}: ${error.message}`);
        loaded.set(lib, null);
        return null;
      }
    }
    const entry = {
      library: lib,
      path,
      mapped,
      load_base: mapped.report.load_base,
      exportByName: new Map((mapped.report.export ?? []).map((row) => [row.symbol, row])),
      exportByOrdinal: new Map((mapped.report.export ?? []).map((row) => [row.ordinal, row])),
    };
    loaded.set(lib, entry);
    return entry;
  }

  for (const currentImport of importEntry ?? []) {
    ensureModule(currentImport.library);
    for (const alias of sidecarAlias(currentImport.library)) ensureModule(alias);
  }
  let growing = true;
  while (growing) {
    growing = false;
    for (const module of [...loaded.values()]) {
      if (module === null) continue;
      for (const currentImport of module.mapped.report.import ?? []) {
        if (loaded.has(currentImport.library.toLowerCase())) continue;
        if (ensureModule(currentImport.library)) growing = true;
      }
    }
  }

  function catalogFor(importList) {
    const catalog = [];
    const unserved = [];
    for (const currentImport of importList ?? []) {
      const address = resolveOne(currentImport.library, currentImport.symbol, currentImport.ordinal);
      if (address === undefined) {
        unserved.push(`${currentImport.library}!${currentImport.symbol ?? `#${currentImport.ordinal}`}`);
        continue;
      }
      catalog.push({
        library: currentImport.library,
        symbol: currentImport.symbol,
        ordinal: currentImport.ordinal,
        address,
      });
    }
    return { catalog, unserved };
  }

  const main = catalogFor(importEntry);
  const sidecar = [];
  for (const module of loaded.values()) {
    if (module === null) continue;
    const bound = catalogFor(module.mapped.report.import);
    let remapped = module.mapped;
    try {
      remapped = mapPe32ForRuntime(module.path, module.load_base, bound.catalog);
    } catch (error) {
      refusal.push(`${module.library} bind: ${error.message}`);
    }
    const leftover = applyLeftoverSidecarIat({
      image: remapped.image,
      section: remapped.section,
      load_base: remapped.report.load_base,
      import_entry: remapped.report.import,
      unserved: bound.unserved,
    });
    sidecar.push({
      name: module.library,
      path: module.path,
      load_base: remapped.report.load_base,
      entry_rva: remapped.report.entry_rva ?? 0,
      entry_address: remapped.report.entry_address ?? 0,
      tls_callback: remapped.report.tls_callback ?? [],
      image: leftover.image,
      section: leftover.section,
      export_count: remapped.report.export_count ?? 0,
      export: remapped.report.export ?? [],
      import_count: remapped.report.import_count ?? 0,
      unserved: leftover.unserved,
      leftover_served: leftover.leftover_served,
    });
  }

  const tally = new Map();
  for (const key of main.unserved) {
    const library = key.split("!")[0];
    tally.set(library, (tally.get(library) ?? 0) + 1);
  }
  return {
    schema_version: 1,
    is_fully_served: main.unserved.length === 0,
    served_count: main.catalog.length,
    unserved_count: main.unserved.length,
    unserved_library: [...tally.entries()].sort((left, right) => right[1] - left[1]).map(([library, count]) => `${library} (${count})`),
    unserved_sample: main.unserved.slice(0, 24),
    unserved_entry: main.unserved,
    import_catalog: main.catalog,
    sidecar,
    sidecar_count: sidecar.length,
    reserved_range: occupied,
    refusal,
    layout,
  };
}
