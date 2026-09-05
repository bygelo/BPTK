// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { formatBenchmark, runBenchmark } from "./benchmark.mjs";
import { acquireCorpus, buildExportLedger, computeGeneralizationDelta, formatAcquire, formatCorpusRun, formatCorpusStatus, formatExportLedger, formatGeneralize, getCorpusStatus, loadRunRecords, runCorpus } from "./corpus.mjs";
import { formatDoctor, getDoctor } from "./doctor.mjs";
import { diagnoseEnginePort, formatEnginePort } from "./engine.mjs";
import { compareFoundation, formatFoundation } from "./foundation.mjs";
import { formatGraphicsDoctor, probeGraphics } from "./graphics.mjs";
import { formatInputError } from "./input.mjs";
import { formatImport, importAndRun } from "./import.mjs";
import { formatIngest, ingestInput } from "./ingest.mjs";
import { formatInspect, inspectInput } from "./inspect.mjs";
import { analyzeLegal, formatLegal } from "./legal.mjs";
import { formatAssetPackage, formatHostPackage, packageAsset, packageHost } from "./package.mjs";
import { benchmarkPerformance, formatPerformance } from "./performance.mjs";
import { configureThread, evaluateCompatibility, evaluateControl, evaluateNetwork, formatCompatibility, formatControl, formatNetwork, formatThread } from "./platform.mjs";
import { diagnoseSourcePort, formatSourcePort } from "./port.mjs";
import { createReport, formatReport } from "./report.mjs";
import { formatResearch, inspectResearch } from "./research.mjs";
import { formatRun, runPackage } from "./run.mjs";
import { analyzeSecurity, formatSecurity } from "./security.mjs";
import { diagnoseSave, formatSave } from "./storage.mjs";
import { formatStatus, getStatus } from "./status.mjs";

const disclaimer = "Browser Porting Toolkit is a working name. Local analysis exists; No supported Windows game runtime exists. No game runtime exists for unsupported inputs.";

function getHelp() {
  return [
    "BPTK 0.1.0-alpha.0 — roadmap tooling preview with local porting analysis",
    disclaimer,
    "",
    "Usage:",
    "  bptk help",
    "  bptk status [--json]",
    "  bptk doctor [--json]",
    "  bptk doctor --graphics [--json]",
    "  bptk legal <project> [--json]",
    "  bptk corpus status [--json]",
    "  bptk corpus acquire [--stage <dir>] [--json]",
    "  bptk corpus run [--stage <dir>] [--json]",
    "  bptk corpus generalize <before> <after> [--min <n>] [--adapter] [--json]",
    "  bptk corpus coverage [--stage <dir>] [--budget <n>] [--json]",
    "  bptk security <input> [--json]",
    "  bptk inspect <input> [--json]",
    "  bptk inspect <input> --target <x86_64|d3d11|modern> [--json]",
    "  bptk benchmark [--json]",
    "  bptk benchmark <package> --profile performance [--json]",
    "  bptk foundation compare <input> [--json]",
    "  bptk port --source <project> [--json]",
    "  bptk port --engine <engine> <asset> [--json]",
    "  bptk run <package> [--json]",
    "  bptk run <package> --save <profile> [--json]",
    "  bptk run <package> --network <off|prompt> [--json]",
    "  bptk run <package> --control <profile> [--json]",
    "  bptk package <project> --asset-mode stream [--json]",
    "  bptk package <project> --host <html|react> [--json]",
    "  bptk package <project> --thread <auto|on|off> [--json]",
    "  bptk compatibility <package> --browser <profile> [--json]",
    "  bptk import <input> [--json]",
    "  bptk import <input> --run [--json]",
    "  bptk import <input> --extract <dir> [--json]",
    "  bptk ingest <input> [--json]",
    "  bptk ingest <input> --output <dir> [--json]",
    "  bptk report <package> --record <off|consent> [--json]",
    "  bptk --version",
  ].join("\n");
}

function writeJson(stream, value) {
  stream.write(`${JSON.stringify(value, null, 2)}\n`);
}

function splitOption(argument) {
  const isJson = argument.includes("--json");
  const optionCount = argument.filter((entry) => entry === "--json").length;
  const positional = argument.filter((entry) => entry !== "--json");
  return { is_json: isJson, is_valid: optionCount <= 1, positional };
}

function writeReport(output, value, formatter, isJson) {
  if (isJson) writeJson(output, value);
  else output.write(`${formatter(value)}\n`);
}

export function runCli(argument = process.argv.slice(2), output = process.stdout, error = process.stderr) {
  const parsed = splitOption(argument);
  const command = parsed.positional[0] ?? "help";
  const option = parsed.positional.slice(1);
  const isJson = parsed.is_json;
  const isInvalidOption = !parsed.is_valid;

  if (command === "help" && option.length === 0 && !isJson) {
    output.write(`${getHelp()}\n`);
    return 0;
  }

  if (command === "--version" && option.length === 0 && !isJson) {
    output.write("0.1.0-alpha.0\n");
    return 0;
  }

  if (command === "status" && option.length === 0 && !isInvalidOption) {
    const value = getStatus();
    if (isJson) {
      writeJson(output, value);
    } else {
      output.write(`${formatStatus(value)}\n`);
    }
    return 0;
  }

  if (command === "doctor" && option.length === 0 && !isInvalidOption) {
    const value = getDoctor();
    if (isJson) {
      writeJson(output, value);
    } else {
      output.write(`${formatDoctor(value)}\n`);
    }
    return 0;
  }

  try {
    if (command === "doctor" && option.length === 1 && option[0] === "--graphics" && !isInvalidOption) {
      writeReport(output, probeGraphics(), formatGraphicsDoctor, isJson);
      return 0;
    }
    if (command === "legal" && option.length === 1 && !isInvalidOption) {
      writeReport(output, analyzeLegal(option[0]), formatLegal, isJson);
      return 0;
    }
    if (command === "corpus" && option.length === 1 && option[0] === "status" && !isInvalidOption) {
      writeReport(output, getCorpusStatus(), formatCorpusStatus, isJson);
      return 0;
    }
    if (command === "corpus" && option[0] === "acquire" && !isInvalidOption
      && (option.length === 1 || (option.length === 3 && option[1] === "--stage"))) {
      // The download runs under the declared bound and completes
      // asynchronously; the exit code is set on completion.
      acquireCorpus({ stage: option[2] }).then(
        (report) => writeReport(output, report, formatAcquire, isJson),
        (failure2) => {
          const failure = formatInputError(failure2);
          if (isJson) writeJson(error, failure);
          else error.write(`${failure.error_code}: ${failure.message}\n`);
          process.exitCode = 1;
        },
      );
      return undefined;
    }
    if (command === "corpus" && option[0] === "run" && !isInvalidOption
      && (option.length === 1 || (option.length === 3 && option[1] === "--stage"))) {
      writeReport(output, runCorpus({ stage: option[2] }), formatCorpusRun, isJson);
      return 0;
    }
    if (command === "corpus" && option[0] === "coverage" && !isInvalidOption
      && (option.length === 1
        || (option.length === 3 && option[1] === "--stage")
        || (option.length === 3 && option[1] === "--budget")
        || (option.length === 5 && option[1] === "--stage" && option[3] === "--budget"))) {
      const stageIndex = option.indexOf("--stage");
      const budgetIndex = option.indexOf("--budget");
      writeReport(
        output,
        buildExportLedger({
          stage: stageIndex > 0 ? option[stageIndex + 1] : undefined,
          gap_budget: budgetIndex > 0 ? Number(option[budgetIndex + 1]) : undefined,
        }),
        formatExportLedger,
        isJson,
      );
      return 0;
    }
    if (command === "corpus" && option[0] === "generalize" && !isInvalidOption
      && (option.length === 3
        || (option.length === 4 && option[3] === "--adapter")
        || (option.length === 5 && option[3] === "--min")
        || (option.length === 6 && option[3] === "--min" && option[5] === "--adapter"))) {
      const before = loadRunRecords(option[1]);
      const after = loadRunRecords(option[2]);
      const min = option[3] === "--min" ? Number(option[4]) : undefined;
      const report = computeGeneralizationDelta(before, after, { min, adapter: option.includes("--adapter") });
      writeReport(output, report, formatGeneralize, isJson);
      return report.is_generic || report.adapter_declared ? 0 : 1;
    }
    if (command === "security" && option.length === 1 && !isInvalidOption) {
      writeReport(output, analyzeSecurity(option[0]), formatSecurity, isJson);
      return 0;
    }
    if (command === "inspect" && option.length === 1 && !isInvalidOption) {
      writeReport(output, inspectInput(option[0]), formatInspect, isJson);
      return 0;
    }
    if (command === "inspect" && option.length === 3 && option[1] === "--target" && !isInvalidOption) {
      writeReport(output, inspectResearch(option[0], option[2]), formatResearch, isJson);
      return 0;
    }
    if (command === "benchmark" && option.length === 0 && !isInvalidOption) {
      writeReport(output, runBenchmark(), formatBenchmark, isJson);
      return 0;
    }
    if (command === "benchmark" && option.length === 3 && option[1] === "--profile" && option[2] === "performance" && !isInvalidOption) {
      writeReport(output, benchmarkPerformance(option[0]), formatPerformance, isJson);
      return 0;
    }
    if (command === "foundation" && option.length === 2 && option[0] === "compare" && !isInvalidOption) {
      writeReport(output, compareFoundation(option[1]), formatFoundation, isJson);
      return 0;
    }
    if (command === "port" && option.length === 2 && option[0] === "--source" && !isInvalidOption) {
      writeReport(output, diagnoseSourcePort(option[1]), formatSourcePort, isJson);
      return 0;
    }
    if (command === "port" && option.length === 3 && option[0] === "--engine" && !isInvalidOption) {
      writeReport(output, diagnoseEnginePort(option[1], option[2]), formatEnginePort, isJson);
      return 0;
    }
    if (command === "run" && option.length === 1 && !isInvalidOption) {
      writeReport(output, runPackage(option[0]), formatRun, isJson);
      return 0;
    }
    if (command === "run" && option.length === 3 && option[1] === "--network" && !isInvalidOption) {
      writeReport(output, evaluateNetwork(option[0], option[2]), formatNetwork, isJson);
      return 0;
    }
    if (command === "run" && option.length === 3 && option[1] === "--control" && !isInvalidOption) {
      writeReport(output, evaluateControl(option[0], option[2]), formatControl, isJson);
      return 0;
    }
    if (command === "run" && option.length === 3 && option[1] === "--save" && !isInvalidOption) {
      writeReport(output, diagnoseSave(option[0], option[2]), formatSave, isJson);
      return 0;
    }
    if (command === "package" && option.length === 3 && option[1] === "--asset-mode" && option[2] === "stream" && !isInvalidOption) {
      writeReport(output, packageAsset(option[0]), formatAssetPackage, isJson);
      return 0;
    }
    if (command === "package" && option.length === 3 && option[1] === "--host" && !isInvalidOption) {
      writeReport(output, packageHost(option[0], option[2]), formatHostPackage, isJson);
      return 0;
    }
    if (command === "package" && option.length === 3 && option[1] === "--thread" && !isInvalidOption) {
      writeReport(output, configureThread(option[0], option[2]), formatThread, isJson);
      return 0;
    }
    if (command === "compatibility" && option.length === 3 && option[1] === "--browser" && !isInvalidOption) {
      writeReport(output, evaluateCompatibility(option[0], option[2]), formatCompatibility, isJson);
      return 0;
    }
    if (command === "import" && option.length === 2 && option[1] === "--run" && !isInvalidOption) {
      writeReport(output, importAndRun(option[0]), formatImport, isJson);
      return 0;
    }
    if (command === "import" && option.length === 1 && !isInvalidOption) {
      writeReport(output, importAndRun(option[0]), formatImport, isJson);
      return 0;
    }
    if (command === "import" && option.length === 3 && option[1] === "--extract" && !isInvalidOption) {
      writeReport(output, importAndRun(option[0], { extract: option[2] }), formatImport, isJson);
      return 0;
    }
    if (command === "ingest" && option.length === 1 && !isInvalidOption) {
      writeReport(output, ingestInput(option[0]), formatIngest, isJson);
      return 0;
    }
    if (command === "ingest" && option.length === 3 && option[1] === "--output" && !isInvalidOption) {
      writeReport(output, ingestInput(option[0], { output: option[2] }), formatIngest, isJson);
      return 0;
    }
    if (command === "report" && option.length === 3 && option[1] === "--record" && !isInvalidOption) {
      writeReport(output, createReport(option[0], option[2]), formatReport, isJson);
      return 0;
    }
  } catch (exception) {
    const failure = formatInputError(exception);
    if (isJson) writeJson(error, failure);
    else error.write(`${failure.error_code}: ${failure.message}\n`);
    return 1;
  }

  error.write(`Unknown command or option: ${argument.join(" ") || "<empty>"}\n\n${getHelp()}\n`);
  return 1;
}
