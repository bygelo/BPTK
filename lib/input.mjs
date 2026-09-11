// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { lstatSync, openSync, closeSync, readSync, readdirSync } from "node:fs";
import { basename, relative, resolve, sep } from "node:path";

const defaultLimit = Object.freeze({
  entry_count: 4096,
  depth_count: 8,
  // Same ceiling as the corpus download bound: a lawful game archive
  // (SuperTux win32 portable is 307 MiB) is not a bomb, and the extraction
  // output bound still caps what unpacking may emit.
  file_size_byte: 512 * 1024 * 1024,
  prefix_size_byte: 1024 * 1024,
});

export class InputError extends Error {
  constructor(input_code, message) {
    super(message);
    this.name = "InputError";
    this.input_code = input_code;
  }
}

function assertInside(rootPath, candidatePath) {
  const pathPart = relative(rootPath, candidatePath);
  if (pathPart === "" || (!pathPart.startsWith(`..${sep}`) && pathPart !== "..")) {
    return;
  }
  throw new InputError("path_escape", `Path escapes the inspected root: ${candidatePath}`);
}

export function readPrefix(inputPath, sizeByte = defaultLimit.prefix_size_byte) {
  const descriptor = openSync(inputPath, "r");
  try {
    const value = Buffer.alloc(sizeByte);
    const readByte = readSync(descriptor, value, 0, sizeByte, 0);
    return value.subarray(0, readByte);
  } finally {
    closeSync(descriptor);
  }
}

function walkDirectory(rootPath, limit) {
  const entry = [];
  let totalSizeByte = 0;

  function walk(currentPath, depthCount) {
    if (depthCount > limit.depth_count) {
      throw new InputError("depth_limit", `Directory depth exceeds ${limit.depth_count}`);
    }
    const name = readdirSync(currentPath, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    for (const currentName of name) {
      if (entry.length >= limit.entry_count) {
        throw new InputError("entry_limit", `Directory entry count exceeds ${limit.entry_count}`);
      }
      const currentPathValue = resolve(currentPath, currentName.name);
      assertInside(rootPath, currentPathValue);
      const stat = lstatSync(currentPathValue);
      const pathPart = relative(rootPath, currentPathValue);
      if (stat.isSymbolicLink()) {
        entry.push({ path: pathPart, type: "symlink", size_byte: 0 });
        continue;
      }
      if (stat.isDirectory()) {
        entry.push({ path: pathPart, type: "directory", size_byte: 0 });
        walk(currentPathValue, depthCount + 1);
        continue;
      }
      if (stat.isFile()) {
        if (stat.size > limit.file_size_byte) {
          throw new InputError("file_size_limit", `${pathPart} exceeds ${limit.file_size_byte} byte`);
        }
        totalSizeByte += stat.size;
        entry.push({ path: pathPart, type: "file", size_byte: stat.size });
      }
    }
  }

  walk(rootPath, 0);
  return { entry, total_size_byte: totalSizeByte };
}

export function inspectPath(input, option = {}) {
  if (typeof input !== "string" || input.trim() === "") {
    throw new InputError("missing_input", "A local input path is required");
  }
  const limit = { ...defaultLimit, ...option };
  const inputPath = resolve(input);
  let stat;
  try {
    stat = lstatSync(inputPath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new InputError("not_found", `Input does not exist: ${inputPath}`);
    }
    throw error;
  }
  if (stat.isSymbolicLink()) {
    throw new InputError("symlink_input", `Symbolic-link input is not followed: ${inputPath}`);
  }
  if (stat.isDirectory()) {
    const directory = walkDirectory(inputPath, limit);
    return {
      input_path: inputPath,
      input_name: basename(inputPath),
      type: "directory",
      size_byte: directory.total_size_byte,
      entry: directory.entry,
      prefix: Buffer.alloc(0),
    };
  }
  if (!stat.isFile()) {
    throw new InputError("unsupported_file_type", `Input is not a regular file or directory: ${inputPath}`);
  }
  if (stat.size > limit.file_size_byte) {
    throw new InputError("file_size_limit", `Input exceeds ${limit.file_size_byte} byte`);
  }
  return {
    input_path: inputPath,
    input_name: basename(inputPath),
    type: "file",
    size_byte: stat.size,
    entry: [],
    prefix: readPrefix(inputPath, Math.min(limit.prefix_size_byte, Math.max(stat.size, 1))),
  };
}

export function formatInputError(error) {
  if (error instanceof InputError) {
    return { error_code: error.input_code, message: error.message };
  }
  return { error_code: "input_failure", message: error instanceof Error ? error.message : String(error) };
}

// ---------------------------------------------------------------------------
// Game controller input (BPTK-097): a generic XInput/DirectInput gamepad model
// driven by injected browser Gamepad-API state, never a host device. A slot is
// disconnected until a state is injected, so the default honestly reports no
// controller rather than fabricating one. The state fields follow the XInput
// contract; the mixer/window layer never branches on a title identity.
// ---------------------------------------------------------------------------

export const gamepadBound = Object.freeze({
  slot_count: 4,
  thumb_min: -32768,
  thumb_max: 32767,
  trigger_max: 255,
  motor_max: 65535,
});

export const xinputError = Object.freeze({
  ERROR_SUCCESS: 0,
  ERROR_DEVICE_NOT_CONNECTED: 1167,
});

// The XINPUT_CAPABILITIES gamepad subtype and the full digital button mask a
// standard controller reports.
export const gamepadCapability = Object.freeze({
  type_gamepad: 1,
  subtype_gamepad: 1,
  supported_buttons: 0xf3ff, // DPAD, START/BACK, thumbs, shoulders, A/B/X/Y
});

function neutralGamepad() {
  return { buttons: 0, left_trigger: 0, right_trigger: 0, thumb_lx: 0, thumb_ly: 0, thumb_rx: 0, thumb_ry: 0 };
}

function clampField(value, min, max) {
  const number = Number.isFinite(value) ? Math.round(value) : 0;
  return number < min ? min : number > max ? max : number;
}

export function createGamepadSubsystem() {
  const slot = [];
  for (let index = 0; index < gamepadBound.slot_count; index += 1) {
    slot.push({ connected: false, packet_number: 0, state: neutralGamepad(), vibration: { left_motor: 0, right_motor: 0 } });
  }
  const inRange = (index) => Number.isInteger(index) && index >= 0 && index < gamepadBound.slot_count;

  return {
    slot_count: gamepadBound.slot_count,
    // Inject a controller state (the browser Gamepad bridge feeds this). A new
    // state increments the packet number only when a field actually changes,
    // matching the XInput packet-number contract.
    injectGamepad(index, state = {}) {
      if (!inRange(index)) return false;
      const entry = slot[index];
      const next = {
        buttons: (state.buttons ?? 0) & 0xffff,
        left_trigger: clampField(state.left_trigger ?? 0, 0, gamepadBound.trigger_max),
        right_trigger: clampField(state.right_trigger ?? 0, 0, gamepadBound.trigger_max),
        thumb_lx: clampField(state.thumb_lx ?? 0, gamepadBound.thumb_min, gamepadBound.thumb_max),
        thumb_ly: clampField(state.thumb_ly ?? 0, gamepadBound.thumb_min, gamepadBound.thumb_max),
        thumb_rx: clampField(state.thumb_rx ?? 0, gamepadBound.thumb_min, gamepadBound.thumb_max),
        thumb_ry: clampField(state.thumb_ry ?? 0, gamepadBound.thumb_min, gamepadBound.thumb_max),
      };
      const changed = !entry.connected || JSON.stringify(entry.state) !== JSON.stringify(next);
      entry.connected = true;
      entry.state = next;
      if (changed) entry.packet_number = (entry.packet_number + 1) >>> 0;
      return true;
    },
    disconnectGamepad(index) {
      if (!inRange(index)) return false;
      slot[index].connected = false;
      slot[index].state = neutralGamepad();
      return true;
    },
    getState(index) {
      if (!inRange(index) || !slot[index].connected) return { connected: false };
      return { connected: true, packet_number: slot[index].packet_number, state: { ...slot[index].state } };
    },
    setVibration(index, leftMotor, rightMotor) {
      if (!inRange(index) || !slot[index].connected) return false;
      slot[index].vibration = { left_motor: clampField(leftMotor, 0, gamepadBound.motor_max), right_motor: clampField(rightMotor, 0, gamepadBound.motor_max) };
      return true;
    },
    getVibration(index) {
      if (!inRange(index) || !slot[index].connected) return null;
      return { ...slot[index].vibration };
    },
    getCapabilities(index) {
      if (!inRange(index) || !slot[index].connected) return null;
      return { type: gamepadCapability.type_gamepad, subtype: gamepadCapability.subtype_gamepad, buttons: gamepadCapability.supported_buttons };
    },
  };
}
