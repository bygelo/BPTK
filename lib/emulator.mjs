// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The pre-Win32 emulator lane (GS-049). Without this boundary DOS and Win16
// titles are refused at the front door forever. This surface classifies an
// input by its executable header alone — DOS (plain MZ), Win16 (NE), and the
// LE/LX family (Win9x VxD and DOS extenders) are admitted to the sandboxed
// emulator lane; a Win32 PE32/PE32+ image is refused so the emulator lane can
// never swallow a binary-lane title. Admission declares a sandbox confinement
// contract, but no emulator is embedded and nothing runs, so the lane's
// terminal state stays blocked and honest.

import { closeSync, openSync, readSync } from "node:fs";
import { resolve } from "node:path";

const headerReadByte = 4096;

// The sandbox confinement contract the emulator lane declares for every
// admitted input: no host reach of any kind, bounded memory and instruction
// budget, and no persistence. It is a contract, not a running sandbox — the
// emulator that would honor it is not embedded yet.
const sandboxConfinement = Object.freeze({
  host_filesystem: false,
  host_network: false,
  host_process: false,
  host_clipboard: false,
  host_device: false,
  memory_byte_cap: 16 * 1024 * 1024,
  instruction_budget: 2_000_000_000,
  is_persisted: false,
});

// Reads a bounded head of the input without executing or fully loading it.
function readHeader(path) {
  const buffer = Buffer.alloc(headerReadByte);
  let handle;
  try {
    handle = openSync(path, "r");
  } catch {
    return Buffer.alloc(0);
  }
  try {
    const read = readSync(handle, buffer, 0, headerReadByte, 0);
    return buffer.subarray(0, read);
  } catch {
    return Buffer.alloc(0);
  } finally {
    closeSync(handle);
  }
}

// Classifies an executable image by header signature alone. The new-header
// signature at e_lfanew separates the eras: PE is Win32, NE is Win16, LE/LX is
// the Win9x VxD / DOS-extender family, and a plain MZ with no valid new header
// is DOS-era. The mapping is data, never a per-title branch.
export function classifyExecutableEra(prefix) {
  if (prefix.length < 2 || prefix[0] !== 0x4d || prefix[1] !== 0x5a) {
    return { kind: "not_executable", era: null, evidence: "no MZ signature" };
  }
  if (prefix.length < 0x40) {
    return { kind: "dos", era: "dos", evidence: "MZ header with no new-executable table" };
  }
  const newOffset = prefix.readUInt32LE(0x3c);
  if (newOffset === 0 || newOffset + 2 > prefix.length) {
    return { kind: "dos", era: "dos", evidence: "MZ header with no new-executable table" };
  }
  const signature = prefix.toString("ascii", newOffset, newOffset + 2);
  if (signature === "PE" && newOffset + 4 <= prefix.length && prefix[newOffset + 2] === 0 && prefix[newOffset + 3] === 0) {
    return { kind: "pe", era: "win32", evidence: "PE\\0\\0 new-executable signature" };
  }
  if (signature === "NE") {
    return { kind: "ne_win16", era: "win16", evidence: "NE new-executable signature" };
  }
  if (signature === "LE" || signature === "LX") {
    return { kind: "le_extended", era: "win9x_or_extender", evidence: `${signature} linear-executable signature` };
  }
  return { kind: "dos", era: "dos", evidence: "MZ header with an unrecognized new-executable signature" };
}

const admissibleEra = Object.freeze(new Set(["dos", "ne_win16", "le_extended"]));

// The lane boundary: an admitted pre-Win32 image carries the sandbox
// confinement contract but stays blocked (no emulator embedded); a Win32 PE
// image is refused so it stays in the binary lane; anything else is not an
// executable this lane serves.
export function admitEmulatorLane(input) {
  const path = resolve(input);
  const classification = classifyExecutableEra(readHeader(path));
  if (classification.kind === "pe") {
    return {
      schema_version: 1,
      command: "emulator admit",
      input_path: path,
      era: classification.era,
      lane: "binary",
      is_admitted: false,
      state: "refused",
      sandbox: null,
      is_emulator_embedded: false,
      is_executed: false,
      reason: ["A PE32 or PE32+ Win32 image belongs to the binary lane, not the pre-Win32 emulator lane"],
    };
  }
  if (!admissibleEra.has(classification.kind)) {
    return {
      schema_version: 1,
      command: "emulator admit",
      input_path: path,
      era: classification.era,
      lane: "no_lane",
      is_admitted: false,
      state: "refused",
      sandbox: null,
      is_emulator_embedded: false,
      is_executed: false,
      reason: [`The input is not a pre-Win32 executable: ${classification.evidence}`],
    };
  }
  return {
    schema_version: 1,
    command: "emulator admit",
    input_path: path,
    era: classification.era,
    lane: "emulator_legacy",
    is_admitted: true,
    state: "blocked",
    sandbox: sandboxConfinement,
    is_emulator_embedded: false,
    is_executed: false,
    reason: [
      `Admitted to the sandboxed emulator lane by ${classification.evidence}`,
      "No emulator core is embedded, so the input is confined by contract but never run",
    ],
  };
}

export function formatEmulatorLane(report) {
  const line = [
    `Input: ${report.input_path}`,
    `Era: ${report.era ?? "unknown"}`,
    `Lane: ${report.lane}`,
    `Admitted: ${report.is_admitted ? "yes" : "no"}`,
    `State: ${report.state}`,
  ];
  if (report.sandbox) {
    line.push(`Sandbox: host reach denied; memory<=${report.sandbox.memory_byte_cap} byte; not persisted`);
  }
  for (const reason of report.reason) line.push(`Reason: ${reason}`);
  line.push(`Emulator embedded: ${report.is_emulator_embedded ? "yes" : "no"}`);
  return line.join("\n");
}
