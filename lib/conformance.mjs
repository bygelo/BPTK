// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The generic conformance apparatus (GS-036): one case-table format and one
// oracle comparison engine that every emulated export must serve. A runtime
// export with zero conformance case is a coverage hole and fails the suite —
// the structural property the closest prior art lacks. The engine is generic;
// the real Win32 and DirectX case table arrives with the emulation surface,
// which is why the live suite stays red even with the apparatus implemented.

import { InputError } from "./input.mjs";

function conformanceError(code, message) {
  return new InputError(code, message);
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
