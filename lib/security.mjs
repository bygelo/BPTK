// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { InputError, inspectPath } from "./input.mjs";
import { inspectInput } from "./inspect.mjs";

const root = resolve(fileURLToPath(import.meta.url), "..", "..");

// The bounded pre-execution threat scan (GS-089): the already-bounded prefix
// and input name are matched against a small named catalog, and a hit is a
// refusal at the import boundary, never a quarantine-and-continue. The scan is
// local, bounded, and carries no payload out of the process. The catalog names
// its own coverage: a threat outside it produces no evidence.
const threatCatalog = Object.freeze([
  {
    name: "EICAR test file",
    // The standard anti-virus test string; its presence marks the input as a
    // deliberate test carrier and is refused like any known-bad byte.
    pattern: "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    evidence: "standard test signature in payload byte",
  },
  { name: "eicar companion", match: "eicar.com", evidence: "known-bad file name" },
]);

function scanThreat(inputName, prefix) {
  const signatureHit = [];
  const text = prefix.toString("latin1");
  for (const signature of threatCatalog) {
    if (signature.pattern !== undefined && text.includes(signature.pattern)) {
      signatureHit.push({ name: signature.name, evidence: signature.evidence });
    } else if (signature.match !== undefined && inputName.toLowerCase() === signature.match) {
      signatureHit.push({ name: signature.name, evidence: signature.evidence });
    }
  }
  return {
    schema_version: 1,
    is_scanned: true,
    scan_scope: "bounded prefix and input name",
    signature_hit: signatureHit,
    is_flagged: signatureHit.length > 0,
    action: signatureHit.length > 0 ? "refuse" : "allow",
  };
}

export function inspectWithThreat(input) {
  const inspection = inspectInput(input);
  const raw = inspectPath(input);
  if (raw.type === "file") {
    inspection.threat_scan = scanThreat(raw.input_name, raw.prefix);
  } else {
    inspection.threat_scan = { schema_version: 1, is_scanned: false, scan_scope: "directory entry name only", signature_hit: [], is_flagged: false, action: "allow" };
  }
  return inspection;
}

// One import boundary for every surface that stages or packages input
// (GS-088 and GS-089): protection evidence refuses before any artifact is
// written, and a flagged threat is refused outright. The refusal names the
// family; nothing is unwrapped, patched, or emitted for a refused input.
export function assertImportSafety(inspection) {
  if (inspection.census?.route === "refuse") {
    const family = inspection.census.protection.map((entry) => entry.family).join(", ");
    throw new InputError("census_protection_refused", `The input carries copy-protection evidence (${family}); it is refused and never circumvented`);
  }
  if (inspection.threat_scan?.is_flagged === true) {
    const name = inspection.threat_scan.signature_hit.map((entry) => entry.name).join(", ");
    throw new InputError("threat_scan_flagged", `The threat scan flagged the input (${name}); it is quarantined from every staging path`);
  }
}

// The trust-tier boundary (GS-091): attested byte (pinned in the lawful corpus
// manifest) may reach the full lane; every unattested input is
// unknown-untrusted and gets scan and inspection only, with no network and no
// persistence; and protection or threat evidence refuses outright. The grade
// is a pure function of the input byte and evidence, so a tier never upgrades
// silently.
function gradeTrustTier(inspection, inputPath) {
  if (inspection.census?.route === "refuse") {
    return { tier: "refused", allowed_surface: ["refusal"], is_upgrade_possible: false, basis: `copy-protection evidence (${inspection.census.protection.map((entry) => entry.family).join(", ")})` };
  }
  if (inspection.threat_scan?.is_flagged === true) {
    return { tier: "refused", allowed_surface: ["refusal"], is_upgrade_possible: false, basis: `threat scan hit (${inspection.threat_scan.signature_hit.map((entry) => entry.name).join(", ")})` };
  }
  const attestedHash = loadAttestedHash();
  if (inspection.input_type === "file" && attestedHash.size > 0) {
    const actual = createHash("sha256").update(readFileSync(inputPath)).digest("hex");
    if (attestedHash.has(actual)) {
      return { tier: "attested", allowed_surface: ["inspect", "package", "run"], is_upgrade_possible: false, basis: "the payload byte match a pinned entry in the lawful corpus manifest" };
    }
  }
  return { tier: "unknown_untrusted", allowed_surface: ["inspect", "security"], is_upgrade_possible: false, basis: "no attestation pin matches the payload byte; scan and inspection only, no network and no persistence" };
}

function loadAttestedHash() {
  const hash = new Set();
  const manifestPath = process.env.BPTK_ACQUISITION_PATH || resolve(root, "data", "corpus.json");
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    for (const entry of manifest.record ?? []) {
      if (typeof entry.sha256 === "string") hash.add(entry.sha256);
    }
  } catch {
    // An absent manifest attests nothing; every input stays unknown-untrusted.
  }
  return hash;
}

function archivePathRisk(prefix) {
  const text = prefix.toString("latin1");
  return /(^|[\\/])\.\.([\\/]|$)/.test(text) ? ["Archive byte stream contains a parent-path marker"] : [];
}

export function analyzeSecurity(input) {
  const value = inspectPath(input);
  const inspection = inspectWithThreat(input);
  const risk = [];
  const control = [
    "Input is read locally with bounded file, entry, and depth limits",
    "Symbolic-link roots are rejected and nested symbolic links are not followed",
    "Imported content is never executed or uploaded by this command",
    "Network remains denied until an explicit mediated policy exists",
    "A threat-scan hit or protection evidence refuses the input at the import boundary",
  ];
  if (value.type === "directory") {
    const symlinkCount = value.entry.filter((entry) => entry.type === "symlink").length;
    if (symlinkCount > 0) risk.push(`${symlinkCount} nested symbolic link requires exclusion from packaging`);
  } else {
    if (value.prefix[0] === 0x4d && value.prefix[1] === 0x5a) risk.push("Executable content must remain inert during inspection");
    if (value.prefix.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) risk.push(...archivePathRisk(value.prefix));
  }
  const trustTier = gradeTrustTier(inspection, inspection.input_path);
  return {
    schema_version: 1,
    command: "security",
    input_path: value.input_path,
    review_state: "review_required",
    threat_scan: inspection.threat_scan,
    trust_tier: trustTier,
    census_route: inspection.census.route,
    risk,
    control,
    limit: { entry_count: 4096, depth_count: 8, file_size_byte: 67108864 },
    reviewer: null,
    is_approved: false,
  };
}

export function formatSecurity(report) {
  return [
    `Input: ${report.input_path}`,
    `Review: ${report.review_state}`,
    `Trust tier: ${report.trust_tier.tier} — ${report.trust_tier.basis}`,
    `Allowed surface: ${report.trust_tier.allowed_surface.join(", ")}`,
    `Threat scan: ${report.threat_scan.is_flagged ? `flagged (${report.threat_scan.signature_hit.map((entry) => entry.name).join(", ")})` : "clean"}`,
    ...report.risk.map((entry) => `Risk: ${entry}`),
    ...report.control.map((entry) => `Control: ${entry}`),
    `Limit: ${report.limit.entry_count} entry; depth ${report.limit.depth_count}; ${report.limit.file_size_byte} byte per file`,
    "Approval: open; no named security reviewer is recorded",
  ].join("\n");
}
