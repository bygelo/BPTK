// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { lstatSync, openSync, closeSync, readSync, readdirSync } from "node:fs";
import { basename, relative, resolve, sep } from "node:path";

const defaultLimit = Object.freeze({
  entry_count: 4096,
  depth_count: 8,
  file_size_byte: 64 * 1024 * 1024,
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
