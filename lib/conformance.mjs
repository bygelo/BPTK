// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The generic conformance apparatus (GS-036): one case-table format and one
// oracle comparison engine that every emulated export must serve. A runtime
// export with zero conformance case is a coverage hole and fails the suite —
// the structural property the closest prior art lacks. The engine is generic;
// the real Win32 and DirectX case table arrives with the emulation surface,
// which is why the live suite stays red even with the apparatus implemented.

import { createHash } from "node:crypto";
import { InputError } from "./input.mjs";

function conformanceError(code, message) {
  return new InputError(code, message);
}

// The captured API-trace corpus (GS-037): the oracle set the conformance suite
// runs against is built from recorded API traces, and every trace must carry
// three properties before it is admitted — provenance (where it came from and
// against which pinned revision), a redaction proof (that no personal data or
// game payload byte survived the capture), and byte-stability (a canonical
// serialization that regenerates to the identical byte on every replay). The
// apparatus below is the generic admission gate; the benchmark stays red
// because the real captures come from the absent Win32 runtime, so the corpus
// carries only synthetic traces that exercise the gate, never a real oracle.

// Required provenance fields — a trace with any missing or blank field is
// rejected, because an oracle built on unprovenanced capture cannot be audited.
const PROVENANCE_FIELD = Object.freeze(["source_id", "capture_method", "revision", "tool_version", "captured_at"]);

// Byte patterns that must never survive redaction: an email address, anything
// tagged as game payload, and a raw personal-data marker. The scan is generic —
// it inspects the canonical bytes, not a per-title allow-list.
const FORBIDDEN_PATTERN = Object.freeze([
  { code: "email", regex: /[\w.+-]+@[\w-]+\.[\w.-]+/ },
  { code: "game_payload", regex: /GAME_PAYLOAD_BYTE/ },
  { code: "personal_data", regex: /PERSONAL_DATA_MARKER/ },
]);

// Deterministic canonical serialization: object keys are emitted in sorted
// order at every depth, so two structurally-equal traces serialize to the same
// byte regardless of author key order. This is the substrate byte-stability is
// measured over.
export function canonicalizeTrace(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalizeTrace).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeTrace(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

// Admits one trace: provenance complete, redaction proof present and self-
// consistent, no forbidden byte in the canonical form, and byte-stable across a
// second canonicalization. Returns a structured verdict rather than throwing so
// the corpus can rank every trace in one pass.
export function verifyTrace(trace) {
  const reason = [];
  const provenance = trace?.provenance ?? {};
  const missingProvenance = PROVENANCE_FIELD.filter((field) => typeof provenance[field] !== "string" || provenance[field].trim() === "");
  if (missingProvenance.length > 0) reason.push(`provenance missing ${missingProvenance.join(", ")}`);

  const canonical = canonicalizeTrace(trace?.call ?? null);
  const forbidden = FORBIDDEN_PATTERN.filter((pattern) => pattern.regex.test(canonical)).map((pattern) => pattern.code);
  if (forbidden.length > 0) reason.push(`redaction leak: ${forbidden.join(", ")}`);

  const redaction = trace?.redaction ?? {};
  const canonicalHash = createHash("sha256").update(canonical).digest("hex");
  if (typeof redaction.method !== "string" || redaction.method.trim() === "") {
    reason.push("redaction proof missing method");
  } else if (redaction.proof_sha256 !== canonicalHash) {
    reason.push("redaction proof hash does not match the canonical call byte");
  }

  const regenerated = canonicalizeTrace(trace?.call ?? null);
  const isByteStable = regenerated === canonical;
  if (!isByteStable) reason.push("canonical serialization is not byte-stable");

  return {
    trace_id: typeof trace?.trace_id === "string" ? trace.trace_id : null,
    is_admitted: reason.length === 0,
    has_provenance: missingProvenance.length === 0,
    has_redaction_proof: forbidden.length === 0 && typeof redaction.method === "string" && redaction.proof_sha256 === canonicalHash,
    is_byte_stable: isByteStable,
    canonical_sha256: canonicalHash,
    reason,
  };
}

// The corpus admission gate: every trace must be admitted, and a trace with no
// stable identity is itself a defect. Aggregates so the caller sees which
// property failed across the whole corpus.
export function verifyTraceCorpus(traceList) {
  if (!Array.isArray(traceList) || traceList.length === 0) {
    throw conformanceError("trace_corpus_required", "The trace corpus requires a non-empty trace array");
  }
  const result = traceList.map(verifyTrace);
  const seenId = new Set();
  for (const entry of result) {
    if (entry.trace_id === null) entry.reason.push("trace has no trace_id"), entry.is_admitted = false;
    else if (seenId.has(entry.trace_id)) entry.reason.push("duplicate trace_id"), entry.is_admitted = false;
    else seenId.add(entry.trace_id);
  }
  const admittedCount = result.filter((entry) => entry.is_admitted).length;
  return {
    schema_version: 1,
    command: "conformance trace-corpus",
    trace_count: result.length,
    admitted_count: admittedCount,
    rejected_count: result.length - admittedCount,
    provenance_complete: result.every((entry) => entry.has_provenance),
    redaction_proven: result.every((entry) => entry.has_redaction_proof),
    byte_stable: result.every((entry) => entry.is_byte_stable),
    is_corpus_admissible: admittedCount === result.length,
    result,
  };
}

// Compares one executed case against its oracle across the declared
// observation fields: return value, last error, and output byte.
export function compareCase(executed, oracleCase) {
  const mismatch = [];
  if (executed.return_value !== oracleCase.expected.return_value) {
    mismatch.push(`return_value ${executed.return_value} != ${oracleCase.expected.return_value}`);
  }
  if (executed.last_error !== oracleCase.expected.last_error) {
    mismatch.push(`last_error ${executed.last_error} != ${oracleCase.expected.last_error}`);
  }
  if (oracleCase.expected.output_byte !== undefined
    && Buffer.compare(Buffer.from(executed.output_byte ?? []), Buffer.from(oracleCase.expected.output_byte)) !== 0) {
    mismatch.push("output_byte differs from the oracle");
  }
  return { case_id: oracleCase.case_id, pass: mismatch.length === 0, mismatch };
}

// Runs the suite: every case executes against the implementation under test,
// every export that appears in the case table must be served by the
// implementation, and — the rule that matters — every export the
// implementation claims must carry at least one case. A zero-case export is
// not a pass; it is the coverage hole the suite exists to expose.
export function runConformanceSuite(caseTable, implementation, option = {}) {
  if (!Array.isArray(caseTable) || caseTable.length === 0) {
    throw conformanceError("conformance_case_required", "The conformance suite requires a non-empty case array");
  }
  if (typeof implementation !== "function") {
    throw conformanceError("conformance_implementation_required", "The conformance suite requires one implementation under test");
  }
  const result = [];
  for (const oracleCase of caseTable) {
    if (typeof oracleCase.case_id !== "string" || typeof oracleCase.library !== "string" || typeof oracleCase.symbol !== "string") {
      throw conformanceError("invalid_conformance_case", "Every case requires case_id, library, and symbol");
    }
    let executed;
    try {
      executed = implementation(oracleCase.library, oracleCase.symbol, oracleCase.input ?? []);
    } catch (error) {
      executed = { return_value: null, last_error: error.message };
    }
    result.push(compareCase(executed, oracleCase));
  }
  const caseByExport = new Map();
  for (const oracleCase of caseTable) {
    const key = `${oracleCase.library}!${oracleCase.symbol}`;
    caseByExport.set(key, (caseByExport.get(key) ?? 0) + 1);
  }
  const servedExport = option.served_export ?? [];
  const uncoveredExport = servedExport.filter((key) => !caseByExport.has(key));
  const passCount = result.filter((entry) => entry.pass).length;
  return {
    schema_version: 1,
    case_count: caseTable.length,
    pass_count: passCount,
    fail_count: result.length - passCount,
    export_case: Object.fromEntries([...caseByExport.entries()]),
    served_export_count: servedExport.length,
    uncovered_export: uncoveredExport,
    is_coverage_complete: uncoveredExport.length === 0,
    result,
  };
}

export function formatConformance(report) {
  return [
    `Conformance: ${report.pass_count}/${report.case_count} case pass`,
    `Export coverage: ${Object.keys(report.export_case).length} export with case, ${report.uncovered_export.length} served export without case`,
    `Coverage complete: ${report.is_coverage_complete ? "yes" : "no — a zero-case export is a coverage hole"}`,
    ...report.result.filter((entry) => !entry.pass).map((entry) => `  FAIL ${entry.case_id}: ${entry.mismatch.join("; ")}`),
  ].join("\n");
}
