// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Static pre-flight census for BPTK-037 and BPTK-043. The census reads only
// the already-bounded inspection prefix and the inspected directory entry
// name, matches them against a named signature catalog, and returns a
// handle, warn, extract, or refuse routing decision plus an engine-family
// route. It never executes the input, never circumvents any protection, and
// never bundles engine or game code. The catalog names its own coverage: a
// signature outside it produces no census evidence.

const middlewareCatalog = Object.freeze([
  { match: "binkw32.dll", family: "Bink Video", dependency: "RAD Video codec" },
  { match: "binkw64.dll", family: "Bink Video", dependency: "RAD Video codec" },
  { match: "smackw32.dll", family: "Smacker Video", dependency: "RAD Video codec" },
  { match: "mss32.dll", family: "Miles Sound System", dependency: "RAD Audio middleware" },
  { match: "fmod.dll", family: "FMOD", dependency: "audio middleware" },
  { match: "fmodex.dll", family: "FMOD Ex", dependency: "audio middleware" },
  { match: "bass.dll", family: "BASS", dependency: "audio middleware" },
  { match: "openal32.dll", family: "OpenAL", dependency: "audio middleware" },
  { match: "ogg.dll", family: "Ogg Vorbis", dependency: "audio codec" },
  { match: "vorbis.dll", family: "Ogg Vorbis", dependency: "audio codec" },
  { match: "vorbisfile.dll", family: "Ogg Vorbis", dependency: "audio codec" },
  { match: "granny2.dll", family: "Granny", dependency: "animation middleware" },
  { match: "zlib1.dll", family: "zlib", dependency: "compression" },
  { match: "zlibwapi.dll", family: "zlib", dependency: "compression" },
  { match: "wing32.dll", family: "WinG", dependency: "legacy graphics shim" },
]);

// A proprietary codec without a lawful browser decode path is refused, in the
// same posture as the BPTK-040 video refusal.
const refusedCodecCatalog = Object.freeze([
  { match: "ir41_32.dll", family: "Indeo video", dependency: "proprietary codec" },
  { match: "ir50_32.dll", family: "Indeo video", dependency: "proprietary codec" },
  { match: "ir32_32.dll", family: "Indeo video", dependency: "proprietary codec" },
  { match: "wmvcore.dll", family: "Windows Media Video", dependency: "proprietary codec" },
  { match: "wmv8ds32.ax", family: "Windows Media Video", dependency: "proprietary codec" },
  { match: "wmv9vcm.dll", family: "Windows Media Video", dependency: "proprietary codec" },
]);

// SafeDisc is the documented static protection evidence of the era: disc and
// loader artifact name plus the embedded loader string. SecuROM, LaserLock,
// StarForce, and Tages have no equally defensible public static signature and
// are outside the catalog until one is recorded.
const protectionCatalog = Object.freeze([
  { match: "00000001.tmp", family: "SafeDisc", evidence: "loader artifact name" },
  { match: "clcd16.dll", family: "SafeDisc", evidence: "driver library name" },
  { match: "clcd32.dll", family: "SafeDisc", evidence: "driver library name" },
  { match: "clokspl.exe", family: "SafeDisc", evidence: "splash loader name" },
  { match: "dplayerx.dll", family: "SafeDisc", evidence: "player library name" },
  { match: "dplayer.dll", family: "SafeDisc", evidence: "player library name" },
  { match: "secdrv.sys", family: "SafeDisc", evidence: "Macrovision SECDRV.SYS driver" },
  { match: "game.icd", family: "SafeDisc", evidence: "encrypted executable sibling" },
]);

const safeDiscLoaderString = "BoG_ *90.0&!!";

const engineCatalog = Object.freeze([
  { suffix: ".wad", family: "id Tech 1", route: "PrBoom+", evidence: "WAD asset" },
  { magic: "IWAD", family: "id Tech 1", route: "PrBoom+", evidence: "IWAD magic" },
  { magic: "PWAD", family: "id Tech 1", route: "PrBoom+", evidence: "PWAD magic" },
  { suffix: ".grp", family: "Build", route: "EDuke32", evidence: "GRP asset" },
  { suffix: ".pak", family: "id Tech 2", route: "QuakeSpasm", evidence: "PAK asset" },
  { suffix: ".he0", family: "SCUMM", route: "ScummVM", evidence: "SCUMM heap asset" },
  { suffix: ".lec", family: "SCUMM", route: "ScummVM", evidence: "LucasArts asset" },
  { suffix: ".agi", family: "Sierra AGI", route: "Sarien", evidence: "AGI asset" },
  { name: "words.tok", family: "Sierra AGI", route: "Sarien", evidence: "AGI dictionary" },
  { name: "vol.0", family: "Sierra AGI", route: "Sarien", evidence: "AGI volume" },
  { name: "resource.map", family: "Sierra SCI", route: "ScummVM", evidence: "SCI resource map" },
  { name: "resource.001", family: "Sierra SCI", route: "ScummVM", evidence: "SCI resource" },
]);

// Walks a bounded PE prefix and returns the imported DLL name, or null when
// the import directory lies outside the prefix. The walk is bounded by a
// descriptor cap so a hostile import directory cannot loop.
function parsePeImportNames(prefix) {
  if (prefix.length < 0x100 || prefix[0] !== 0x4d || prefix[1] !== 0x5a) return { name: [], is_bounded: false };
  const headerOffset = prefix.readUInt32LE(0x3c);
  if (headerOffset + 248 > prefix.length || prefix.toString("ascii", headerOffset, headerOffset + 4) !== "PE\0\0") {
    return { name: [], is_bounded: false };
  }
  const optionalOffset = headerOffset + 24;
  if (prefix.readUInt16LE(optionalOffset) !== 0x10b) return { name: [], is_bounded: false };
  const importRva = prefix.readUInt32LE(optionalOffset + 104);
  if (importRva === 0) return { name: [], is_bounded: false };
  const sectionCount = prefix.readUInt16LE(headerOffset + 6);
  const optionalSize = prefix.readUInt16LE(headerOffset + 20);
  const sectionTable = optionalOffset + optionalSize;
  if (sectionTable + sectionCount * 40 > prefix.length) return { name: [], is_bounded: false };
  const section = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const entry = sectionTable + index * 40;
    section.push({
      virtual_address: prefix.readUInt32LE(entry + 12),
      virtual_size: prefix.readUInt32LE(entry + 8),
      raw_address: prefix.readUInt32LE(entry + 20),
    });
  }
  const toOffset = (rva) => {
    for (const current of section) {
      if (rva >= current.virtual_address && rva < current.virtual_address + Math.max(current.virtual_size, 1)) {
        return current.raw_address + rva - current.virtual_address;
      }
    }
    return null;
  };
  const descriptorOffset = toOffset(importRva);
  if (descriptorOffset === null || descriptorOffset + 20 > prefix.length) {
    return { name: [], is_bounded: true };
  }
  const name = [];
  for (let index = 0; index < 64; index += 1) {
    const record = descriptorOffset + index * 20;
    const nameRva = prefix.readUInt32LE(record + 12);
    if (nameRva === 0) break;
    const nameOffset = toOffset(nameRva);
    if (nameOffset === null || nameOffset + 256 > prefix.length) {
      return { name, is_bounded: true };
    }
    let end = nameOffset;
    while (end < prefix.length && end - nameOffset < 256 && prefix[end] !== 0) end += 1;
    name.push(prefix.toString("latin1", nameOffset, end).toLowerCase());
  }
  return { name, is_bounded: true };
}

function scanCatalog(catalog, haystack) {
  const found = [];
  for (const signature of catalog) {
    if (haystack.some((entry) => entry === signature.match || entry.endsWith(signature.match))) {
      found.push(signature);
    }
  }
  return found;
}

function censusEntryNames(entry) {
  return entry.filter((item) => item.type === "file").map((item) => item.path.split(/[\\/]/).pop().toLowerCase());
}

function censusSiblings(entry, signature) {
  return entry.filter((item) => item.type === "file" && item.path.split(/[\\/]/).pop().toLowerCase().endsWith(signature.match)).map((item) => item.path);
}

// Runs the full census over one bounded inspection value. prefix holds the
// inspected input head for file input, and entry holds the directory listing
// for directory input.
export function censusInput(inputName, prefix, entry) {
  const evidence = [];
  const middleware = [];
  const protection = [];
  const isDirectory = entry.length > 0;
  const siblingName = isDirectory ? censusEntryNames(entry) : [];
  const inputNameLower = (inputName ?? "").toLowerCase();

  // Import-name evidence applies to PE file input.
  let importName = [];
  let isImportBounded = false;
  if (!isDirectory && prefix.length > 0 && prefix[0] === 0x4d && prefix[1] === 0x5a) {
    const parsed = parsePeImportNames(prefix);
    importName = parsed.name;
    isImportBounded = parsed.is_bounded;
  }

  const importHaystack = [...importName, inputNameLower];
  for (const signature of middlewareCatalog) {
    if (importHaystack.includes(signature.match)) {
      middleware.push({ family: signature.family, dependency: signature.dependency, evidence: `import ${signature.match}` });
    } else if (isDirectory) {
      const sibling = censusSiblings(entry, signature);
      if (sibling.length > 0) middleware.push({ family: signature.family, dependency: signature.dependency, evidence: `sibling file ${sibling[0]}` });
    }
  }
  for (const signature of refusedCodecCatalog) {
    if (importHaystack.includes(signature.match)) {
      protection.push({ family: signature.family, evidence: `proprietary codec import ${signature.match}` });
    } else if (isDirectory) {
      const sibling = censusSiblings(entry, signature);
      if (sibling.length > 0) protection.push({ family: signature.family, evidence: `proprietary codec sibling ${sibling[0]}` });
    }
  }
  const protectionHaystack = [...siblingName, inputNameLower, importName];
  for (const signature of protectionCatalog) {
    const sibling = isDirectory ? censusSiblings(entry, signature) : [];
    if (protectionHaystack.includes(signature.match) || sibling.length > 0) {
      protection.push({ family: signature.family, evidence: `${signature.evidence} ${signature.match}` });
    }
  }
  if (!isDirectory && prefix.length > 0 && prefix.toString("latin1").includes(safeDiscLoaderString)) {
    protection.push({ family: "SafeDisc", evidence: `embedded loader string ${safeDiscLoaderString}` });
  }

  // Engine fingerprint from asset suffix, fixed asset name, or asset magic.
  let engine = { family: null, route: null, evidence: [] };
  const engineHaystack = isDirectory ? siblingName : [inputNameLower];
  for (const signature of engineCatalog) {
    if (signature.name !== undefined && engineHaystack.includes(signature.name)) {
      engine = { family: signature.family, route: signature.route, evidence: [signature.evidence], is_bundled: false };
      break;
    }
    if (signature.suffix !== undefined && engineHaystack.some((item) => item.endsWith(signature.suffix))) {
      engine = { family: signature.family, route: signature.route, evidence: [signature.evidence], is_bundled: false };
      break;
    }
    if (signature.magic !== undefined && !isDirectory && prefix.length >= 4 && prefix.toString("latin1", 0, 4) === signature.magic) {
      engine = { family: signature.family, route: signature.route, evidence: [signature.evidence], is_bundled: false };
      break;
    }
  }

  // Routing decision: protection evidence refuses before anything else, a
  // cabinet container routes to extraction, middleware warns, and clean
  // input is handled. Unmatched input is evidence of absence and stays in
  // the handle lane of whatever lane the inspector already chose.
  let route = "handle";
  const isCabinetContainer = !isDirectory && (inputNameLower.endsWith(".cab") || (prefix.length >= 4 && prefix.toString("ascii", 0, 4) === "MSCF"));
  if (protection.length > 0) route = "refuse";
  else if (isCabinetContainer) route = "extract";
  else if (middleware.length > 0 || (importName.length > 0 && !isImportBounded)) route = "warn";

  return {
    schema_version: 1,
    route,
    middleware,
    protection,
    engine,
    import_name: importName,
    is_import_bounded: isImportBounded,
    evidence,
  };
}
