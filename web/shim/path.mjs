// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// A pure POSIX-style path shim for the node:path surface the runtime imports
// (basename, extname, resolve, relative, sep, dirname; join for completeness).
// No filesystem is touched; resolve anchors on a virtual "/" root so a browser
// build stays deterministic. Semantics match node:path.posix for the inputs the
// runtime forms (package/executable names, not general path arithmetic).

export const sep = "/";
export const delimiter = ":";

function splitSegment(path) {
  return path.split("/").filter((segment) => segment.length > 0);
}

function normalizeArray(parts, allowAboveRoot) {
  const out = [];
  for (const part of parts) {
    if (part === "." || part === "") continue;
    if (part === "..") {
      if (out.length > 0 && out[out.length - 1] !== "..") out.pop();
      else if (allowAboveRoot) out.push("..");
    } else {
      out.push(part);
    }
  }
  return out;
}

export function basename(path, suffix) {
  const segment = splitSegment(path);
  let base = segment.length === 0 ? "" : segment[segment.length - 1];
  if (suffix && base.endsWith(suffix) && base !== suffix) base = base.slice(0, base.length - suffix.length);
  return base;
}

export function dirname(path) {
  const isAbsolute = path.startsWith("/");
  const segment = splitSegment(path);
  if (segment.length <= 1) return isAbsolute ? "/" : ".";
  const parent = segment.slice(0, segment.length - 1).join("/");
  return isAbsolute ? `/${parent}` : parent;
}

export function extname(path) {
  const base = basename(path);
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return "";
  return base.slice(dot);
}

export function join(...part) {
  const filtered = part.filter((entry) => typeof entry === "string" && entry.length > 0);
  if (filtered.length === 0) return ".";
  const isAbsolute = filtered[0].startsWith("/");
  const normalized = normalizeArray(splitSegment(filtered.join("/")), !isAbsolute);
  const joined = normalized.join("/");
  return isAbsolute ? `/${joined}` : joined || ".";
}

export function resolve(...part) {
  let resolved = "";
  let isAbsolute = false;
  for (let index = part.length - 1; index >= 0 && !isAbsolute; index -= 1) {
    const segment = part[index];
    if (typeof segment !== "string" || segment.length === 0) continue;
    resolved = `${segment}/${resolved}`;
    isAbsolute = segment.startsWith("/");
  }
  const normalized = normalizeArray(splitSegment(resolved), !isAbsolute);
  if (isAbsolute) return `/${normalized.join("/")}` || "/";
  return `/${normalized.join("/")}` || "/"; // anchor relative input on the virtual root
}

export function relative(from, to) {
  const fromParts = normalizeArray(splitSegment(resolve(from)), false);
  const toParts = normalizeArray(splitSegment(resolve(to)), false);
  let common = 0;
  while (common < fromParts.length && common < toParts.length && fromParts[common] === toParts[common]) common += 1;
  const up = fromParts.slice(common).map(() => "..");
  const down = toParts.slice(common);
  return [...up, ...down].join("/");
}

export default { sep, delimiter, basename, dirname, extname, join, resolve, relative };
