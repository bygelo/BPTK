// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { formatBenchmark, runBenchmark } from "./benchmark.mjs";
import { formatCorpusStatus, getCorpusStatus } from "./corpus.mjs";
import { formatDoctor, getDoctor } from "./doctor.mjs";
import { compareFoundation, formatFoundation } from "./foundation.mjs";
import { formatInputError } from "./input.mjs";
import { formatInspect, inspectInput } from "./inspect.mjs";
import { analyzeLegal, formatLegal } from "./legal.mjs";
import { diagnoseSourcePort, formatSourcePort } from "./port.mjs";
import { formatRun, runPackage } from "./run.mjs";
import { analyzeSecurity, formatSecurity } from "./security.mjs";
import { formatStatus, getStatus } from "./status.mjs";

const disclaimer = "Browser Porting Toolkit is a working name. Local analysis exists; No game runtime exists.";

function getHelp() {
  return [
    "BPTK 0.1.0-alpha.0 — roadmap tooling preview with local porting analysis",
    disclaimer,
    "",
    "Usage:",
    "  bptk help",
    "  bptk status [--json]",
    "  bptk doctor [--json]",
    "  bptk legal <project> [--json]",
    "  bptk corpus status [--json]",
    "  bptk security <input> [--json]",
    "  bptk inspect <input> [--json]",
    "  bptk benchmark [--json]",
    "  bptk foundation compare <input> [--json]",
    "  bptk port --source <project> [--json]",
    "  bptk run <package> [--json]",
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
    if (command === "legal" && option.length === 1 && !isInvalidOption) {
      writeReport(output, analyzeLegal(option[0]), formatLegal, isJson);
      return 0;
    }
    if (command === "corpus" && option.length === 1 && option[0] === "status" && !isInvalidOption) {
      writeReport(output, getCorpusStatus(), formatCorpusStatus, isJson);
      return 0;
    }
    if (command === "security" && option.length === 1 && !isInvalidOption) {
      writeReport(output, analyzeSecurity(option[0]), formatSecurity, isJson);
      return 0;
    }
    if (command === "inspect" && option.length === 1 && !isInvalidOption) {
      writeReport(output, inspectInput(option[0]), formatInspect, isJson);
      return 0;
    }
    if (command === "benchmark" && option.length === 0 && !isInvalidOption) {
      writeReport(output, runBenchmark(), formatBenchmark, isJson);
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
    if (command === "run" && option.length === 1 && !isInvalidOption) {
      writeReport(output, runPackage(option[0]), formatRun, isJson);
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
