// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { createHash as nodeCreateHash } from "node:crypto";
import nodePath from "node:path";

import { Buffer as BufferShim } from "../web/shim/buffer.mjs";
import { createHash as shimCreateHash } from "../web/shim/crypto.mjs";
import * as pathShim from "../web/shim/path.mjs";
import * as fsShim from "../web/shim/fs.mjs";
import { runImageBytes, defaultWindowSize } from "../lib/present.mjs";
import { mapPe64State } from "../lib/pe64.mjs";
import { executeProbe64 } from "../lib/exec64.mjs";
import { loadDialogTemplate } from "../lib/rsrc.mjs";
import { dialogBaseUnit, dialogRectToPixel } from "../lib/user.mjs";

const puttyPath = "/Users/angelonrevelo/Code/bptk-corpus/stage/corpus-001/package/putty.exe";

// --- crypto shim: digest-exact against node:crypto --------------------------

test("crypto shim sha256 matches node:crypto digest exactly", () => {
  const input = ["", "abc", "The quick brown fox jumps over the lazy dog", "a".repeat(1000)];
  for (const value of input) {
    assert.equal(
      shimCreateHash("sha256").update(value).digest("hex"),
      nodeCreateHash("sha256").update(value).digest("hex"),
      `sha256 of ${JSON.stringify(value.slice(0, 12))}`,
    );
  }
  const long = new Uint8Array(200000);
  for (let index = 0; index < long.length; index += 1) long[index] = (index * 31 + 7) & 0xff;
  assert.equal(
    shimCreateHash("sha256").update(long).digest("hex"),
    nodeCreateHash("sha256").update(long).digest("hex"),
    "sha256 of a long buffer",
  );
  // Chained updates must fold identically to one update.
  assert.equal(
    shimCreateHash("sha256").update("abc").update("def").update("ghij").digest("hex"),
    nodeCreateHash("sha256").update("abcdefghij").digest("hex"),
    "sha256 chained update",
  );
});

// --- buffer shim: byte-identical against node:buffer for every method used ---

test("buffer shim integer and float read/write match node:buffer byte for byte", () => {
  const node = Buffer.alloc(64);
  const shim = BufferShim.alloc(64);
  const apply = (buffer) => {
    buffer.writeUInt8(0xab, 0);
    buffer.writeInt8(-5, 1);
    buffer.writeUInt16LE(0xbeef, 2);
    buffer.writeInt16LE(-1234, 4);
    buffer.writeUInt32LE(0xdeadbeef, 6);
    buffer.writeInt32LE(-999999, 10);
    buffer.writeBigUInt64LE(0x1122334455667788n, 16);
    buffer.writeBigInt64LE(-0x0102030405060708n, 24);
    buffer.writeFloatLE(3.5, 32);
    buffer.writeDoubleLE(2.718281828459045, 36);
  };
  apply(node);
  apply(shim);
  assert.equal(shim.toString("hex"), node.toString("hex"), "written bytes");
  assert.equal(shim.readUInt8(0), node.readUInt8(0));
  assert.equal(shim.readInt8(1), node.readInt8(1));
  assert.equal(shim.readUInt16LE(2), node.readUInt16LE(2));
  assert.equal(shim.readInt16LE(4), node.readInt16LE(4));
  assert.equal(shim.readUInt32LE(6), node.readUInt32LE(6));
  assert.equal(shim.readInt32LE(10), node.readInt32LE(10));
  assert.equal(shim.readBigUInt64LE(16), node.readBigUInt64LE(16));
  assert.equal(shim.readBigInt64LE(24), node.readBigInt64LE(24));
  assert.equal(shim.readFloatLE(32), node.readFloatLE(32));
  assert.equal(shim.readDoubleLE(36), node.readDoubleLE(36));
});

test("buffer shim string codecs match node:buffer", () => {
  const raw = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0xff, 0x00, 0x41, 0x7f, 0x80];
  for (const encoding of ["ascii", "latin1", "hex", "base64", "utf8"]) {
    assert.equal(
      BufferShim.from(raw).toString(encoding),
      Buffer.from(raw).toString(encoding),
      `toString ${encoding}`,
    );
  }
  for (const [text, encoding] of [["Hello, wörld!", "utf8"], ["cafe", "ascii"], ["deadBEEF01", "hex"], ["SGVsbG8=", "base64"], ["Ünïcødé", "latin1"]]) {
    assert.equal(
      BufferShim.from(text, encoding).toString("hex"),
      Buffer.from(text, encoding).toString("hex"),
      `from(${encoding})`,
    );
  }
});

test("buffer shim copy, subarray, fill, indexOf, equals, concat, compare, byteLength match node:buffer", () => {
  const source = "The quick brown fox";
  const nodeSource = Buffer.from(source);
  const shimSource = BufferShim.from(source);

  const nodeTarget = Buffer.alloc(8);
  const shimTarget = BufferShim.alloc(8);
  assert.equal(nodeSource.copy(nodeTarget, 1, 4, 10), shimSource.copy(shimTarget, 1, 4, 10), "copy return");
  assert.equal(shimTarget.toString("hex"), nodeTarget.toString("hex"), "copy bytes");

  assert.equal(shimSource.subarray(4, 9).toString(), nodeSource.subarray(4, 9).toString(), "subarray");
  // subarray must share memory, exactly as node:buffer does.
  const shimView = shimSource.subarray(0, 3);
  shimView[0] = 0x78;
  assert.equal(shimSource[0], 0x78, "subarray shares memory");

  const nodeFill = Buffer.alloc(10);
  const shimFill = BufferShim.alloc(10);
  nodeFill.fill(0xcd, 2, 8);
  shimFill.fill(0xcd, 2, 8);
  assert.equal(shimFill.toString("hex"), nodeFill.toString("hex"), "fill");

  assert.equal(shimSource.indexOf("brown"), nodeSource.indexOf("brown"), "indexOf string");
  assert.equal(shimSource.indexOf(0x66), nodeSource.indexOf(0x66), "indexOf byte");
  assert.equal(shimSource.indexOf("zebra"), nodeSource.indexOf("zebra"), "indexOf absent");
  assert.equal(shimSource.includes("quick"), nodeSource.includes("quick"), "includes");

  assert.equal(BufferShim.from("abc").equals(BufferShim.from("abc")), Buffer.from("abc").equals(Buffer.from("abc")));
  assert.equal(BufferShim.from("abc").equals(BufferShim.from("abd")), Buffer.from("abc").equals(Buffer.from("abd")));

  assert.equal(
    BufferShim.concat([BufferShim.from("foo"), BufferShim.from("bar"), BufferShim.from("baz")]).toString(),
    Buffer.concat([Buffer.from("foo"), Buffer.from("bar"), Buffer.from("baz")]).toString(),
    "concat",
  );

  assert.equal(BufferShim.compare(BufferShim.from("abc"), BufferShim.from("abd")), Buffer.compare(Buffer.from("abc"), Buffer.from("abd")));
  assert.equal(BufferShim.compare(BufferShim.from("abc"), BufferShim.from("ab")), Buffer.compare(Buffer.from("abc"), Buffer.from("ab")));
  assert.equal(BufferShim.byteLength("Hello, wörld!", "utf8"), Buffer.byteLength("Hello, wörld!", "utf8"), "byteLength");
  assert.equal(BufferShim.isBuffer(shimSource), true);
  assert.equal(BufferShim.isBuffer([1, 2, 3]), false);
});

// --- path shim: deterministic parse matches node:path.posix ------------------

test("path shim basename/extname/dirname/join/relative match node:path.posix", () => {
  const cases = ["/pkg/game/putty.exe", "putty.exe", "/a/b/c/", "/only", "noext"];
  for (const value of cases) {
    assert.equal(pathShim.basename(value), nodePath.posix.basename(value), `basename ${value}`);
    assert.equal(pathShim.extname(value), nodePath.posix.extname(value), `extname ${value}`);
    assert.equal(pathShim.dirname(value), nodePath.posix.dirname(value), `dirname ${value}`);
  }
  assert.equal(pathShim.basename("/a/b/game.exe", ".exe"), nodePath.posix.basename("/a/b/game.exe", ".exe"), "basename suffix");
  assert.equal(pathShim.join("a", "b", "../c", "./d"), nodePath.posix.join("a", "b", "../c", "./d"), "join");
  assert.equal(pathShim.relative("/a/b/c", "/a/b/d/e"), nodePath.posix.relative("/a/b/c", "/a/b/d/e"), "relative");
  assert.equal(pathShim.sep, nodePath.posix.sep, "sep");
});

// --- fs shim: every export refuses on the browser path ----------------------

test("fs shim stubs throw the browser-unavailable error", () => {
  const message = "filesystem is not available in the browser";
  for (const name of ["readFileSync", "openSync", "readSync", "closeSync", "fstatSync", "lstatSync", "statSync", "existsSync", "mkdirSync", "writeFileSync", "unlinkSync", "readdirSync", "createWriteStream"]) {
    assert.throws(() => fsShim[name]("anything"), new RegExp(message), `${name} throws`);
  }
  // constants keeps its shape so an import-time destructure does not throw.
  assert.equal(typeof fsShim.constants.O_RDONLY, "number");
});

// --- runImageBytes: a real staged payload's bytes -> a surface --------------

test("runImageBytes maps and runs PuTTY x64 bytes into a surface", () => {
  assert.equal(existsSync(puttyPath), true, "the staged PuTTY payload must exist");
  const bytes = new Uint8Array(readFileSync(puttyPath));
  const result = runImageBytes(bytes);

  assert.equal(result.machine, "x86_64", "PuTTY is a PE32+ x86-64 image");
  assert.equal(result.state, "probe_executed", "the bounded probe executed at least one instruction");
  assert.equal(typeof result.stop_reason, "string");
  assert.ok(result.instruction_count > 0, "instruction_count is positive");

  assert.ok(result.surface.width > 0, "surface width is positive");
  assert.ok(result.surface.height > 0, "surface height is positive");
  assert.ok(result.surface.rgba instanceof Uint8Array, "rgba is a Uint8Array");
  assert.equal(result.surface.rgba.length, result.surface.width * result.surface.height * 4, "rgba length is width*height*4");
  assert.equal(result.surface.width, defaultWindowSize.width);
  assert.equal(result.surface.height, defaultWindowSize.height);
});

test("runImageBytes composites PuTTY's About dialog into real painted pixels", () => {
  const bytes = new Uint8Array(readFileSync(puttyPath));
  const result = runImageBytes(bytes);
  const { rgba, width, height } = result.surface;
  const total = width * height;

  // The surface is no longer all-zero: the compositor painted the windows the
  // run created, so real pixels are present.
  let nonZero = 0;
  for (let index = 0; index < rgba.length; index += 4) {
    if (rgba[index] !== 0 || rgba[index + 1] !== 0 || rgba[index + 2] !== 0 || rgba[index + 3] !== 0) nonZero += 1;
  }
  assert.ok(nonZero > 0, "the surface is not all zero");

  // The dialog and its controls cover a non-trivial share of the surface: count
  // the pixels that are not the cleared desktop background (rgb 58,110,165).
  let nonBackground = 0;
  for (let index = 0; index < rgba.length; index += 4) {
    if (!(rgba[index] === 58 && rgba[index + 1] === 110 && rgba[index + 2] === 165)) nonBackground += 1;
  }
  assert.ok(nonBackground > total * 0.05, `painted pixels exceed 5% of the surface (${((100 * nonBackground) / total).toFixed(1)}%)`);

  // PuTTY's About dialog template is #32770 at DLU (140,40) size 270x136 with an
  // MS Shell Dlg 8pt font, so the base unit pair is (6,13) and the frame lands at
  // pixel (210,65) size 405x(221+14 caption)=405x235. Its client is COLOR_BTNFACE
  // grey and its caption band is the active-caption color. Sample both inside that
  // rect to prove the dialog background rectangle landed at its converted location.
  const dialog = { x: 210, y: 65, width: 405, height: 235, caption: 14 };
  const pixelAt = (x, y) => {
    const offset = (y * width + x) * 4;
    return [rgba[offset], rgba[offset + 1], rgba[offset + 2], rgba[offset + 3]];
  };
  assert.deepEqual(pixelAt(dialog.x + 4, dialog.y + 4), [0, 0, 128, 255], "the About dialog caption band is painted");
  assert.deepEqual(pixelAt(dialog.x + 3, dialog.y + dialog.caption + 2), [192, 192, 192, 255], "the About dialog client is COLOR_BTNFACE grey at its location");
  // Just outside the frame, the desktop shows through.
  assert.deepEqual(pixelAt(dialog.x - 4, dialog.y - 4), [58, 110, 165, 255], "desktop background outside the dialog");
});

test("PuTTY's dialog controls convert from DLU to non-overlapping pixel rects", () => {
  const bytes = new Uint8Array(readFileSync(puttyPath));
  const mapped = mapPe64State(bytes, null);
  const probe = executeProbe64(mapped, 1000000, { executable_name: "image.exe", capture_guest: true });
  const snapshot = probe.guest.user.paintSnapshot();
  const composited = probe.guest.gdi.compositeDesktop(snapshot, defaultWindowSize.width, defaultWindowSize.height);

  // The three About-dialog buttons the run painted.
  const button = composited.control_rect.filter((rect) => rect.kind === "button");
  assert.equal(button.length, 3, "the About dialog paints its three buttons");
  const byText = Object.fromEntries(button.map((rect) => [rect.text, rect]));
  for (const caption of ["&Close", "View &Licence", "Visit &Web Site"]) {
    assert.ok(byText[caption] !== undefined, `button "${caption}" is painted`);
  }

  // Every painted control rectangle is well-formed and lies within the surface.
  for (const rect of composited.control_rect) {
    assert.ok(rect.right > rect.left && rect.bottom > rect.top, `control "${rect.text}" has a positive rect`);
    assert.ok(rect.left >= 0 && rect.top >= 0 && rect.right <= defaultWindowSize.width && rect.bottom <= defaultWindowSize.height, `control "${rect.text}" is on-surface`);
  }

  // No two painted controls overlap (axis-aligned rectangle intersection is
  // empty for every pair). This is the geometry the DLU conversion buys: raw
  // template units treated as pixels left the buttons too narrow for their
  // captions, which spilled across each other.
  const overlaps = (a, b) => a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;
  for (let i = 0; i < composited.control_rect.length; i += 1) {
    for (let j = i + 1; j < composited.control_rect.length; j += 1) {
      const a = composited.control_rect[i];
      const b = composited.control_rect[j];
      assert.ok(!overlaps(a, b), `controls "${a.text}" and "${b.text}" do not overlap`);
    }
  }
  // The three buttons sit side by side, left to right, sharing a top edge.
  const ordered = ["View &Licence", "Visit &Web Site", "&Close"].map((caption) => byText[caption]);
  for (let i = 1; i < ordered.length; i += 1) {
    assert.ok(ordered[i].left >= ordered[i - 1].right, `"${ordered[i].text}" starts at or after "${ordered[i - 1].text}" ends`);
    assert.equal(ordered[i].top, ordered[i - 1].top, "the buttons share a top edge");
  }

  // The painted pixel rectangles match the DLU->pixel formula applied to the
  // real template for its own font, with no PuTTY-specific pixel constant: read
  // the template, convert the frame and each control under the template font's
  // base unit pair, and place each control at the frame origin plus the caption
  // band. The compositor's rects must equal that independent computation.
  const image = mapped.image ?? BufferShim.from(bytes);
  const resourceRva = mapped.directory?.[2]?.rva ?? 0;
  let aboutTemplate = null;
  for (let id = 100; id < 2000 && aboutTemplate === null; id += 1) {
    const template = loadDialogTemplate(image, resourceRva, id);
    if (template !== null && typeof template.title === "string" && /About/i.test(template.title)) aboutTemplate = template;
  }
  assert.ok(aboutTemplate !== null, "the About dialog template is present in the image");
  const unit = dialogBaseUnit(aboutTemplate.font);
  const frameRect = dialogRectToPixel({ x: aboutTemplate.x, y: aboutTemplate.y, cx: aboutTemplate.cx, cy: aboutTemplate.cy }, unit);
  const captionHeight = 14; // compositorMetric.caption_height
  const expectedButton = aboutTemplate.item
    .filter((item) => typeof item.title === "string" && byText[item.title] !== undefined)
    .map((item) => {
      const local = dialogRectToPixel({ x: item.x, y: item.y, cx: item.cx, cy: item.cy }, unit);
      const left = frameRect.x + local.x;
      const top = frameRect.y + captionHeight + local.y;
      return { text: item.title, left, top, right: left + local.width, bottom: top + local.height };
    });
  assert.ok(expectedButton.length >= 3, "the template names the three buttons");
  for (const expected of expectedButton) {
    const painted = byText[expected.text];
    assert.deepEqual(
      { left: painted.left, top: painted.top, right: painted.right, bottom: painted.bottom },
      { left: expected.left, top: expected.top, right: expected.right, bottom: expected.bottom },
      `button "${expected.text}" matches the DLU->pixel formula`,
    );
  }
});

test("runImageBytes is deterministic across two calls", () => {
  const bytes = new Uint8Array(readFileSync(puttyPath));
  const first = runImageBytes(bytes);
  const second = runImageBytes(bytes);
  assert.equal(first.instruction_count, second.instruction_count, "identical instruction_count");
  assert.equal(first.stop_reason, second.stop_reason, "identical stop_reason");
  assert.equal(first.surface.rgba.length, second.surface.rgba.length, "identical surface length");
  assert.deepEqual(Array.from(first.surface.rgba), Array.from(second.surface.rgba), "identical surface bytes");
});
