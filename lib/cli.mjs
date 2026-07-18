// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { formatDoctor, getDoctor } from "./doctor.mjs";
import { formatStatus, getStatus } from "./status.mjs";

const disclaimer = "Browser Porting Toolkit is a working name. No game runtime exists.";

function getHelp() {
  return [
    "BPTK 0.1.0-alpha.0 — roadmap tooling preview",
    disclaimer,
    "",
    "Usage:",
    "  bptk help",
    "  bptk status [--json]",
    "  bptk doctor [--json]",
    "  bptk --version",
  ].join("\n");
}

function writeJson(stream, value) {
  stream.write(`${JSON.stringify(value, null, 2)}\n`);
}

export function runCli(argument = process.argv.slice(2), output = process.stdout, error = process.stderr) {
  const command = argument[0] ?? "help";
  const option = argument.slice(1);
  const isJson = option.length === 1 && option[0] === "--json";
  const hasInvalidOption = option.length > 0 && !isJson;

  if (command === "help" && option.length === 0) {
    output.write(`${getHelp()}\n`);
    return 0;
  }

  if (command === "--version" && option.length === 0) {
    output.write("0.1.0-alpha.0\n");
    return 0;
  }

  if (command === "status" && !hasInvalidOption) {
    const value = getStatus();
    if (isJson) {
      writeJson(output, value);
    } else {
      output.write(`${formatStatus(value)}\n`);
    }
    return 0;
  }

  if (command === "doctor" && !hasInvalidOption) {
    const value = getDoctor();
    if (isJson) {
      writeJson(output, value);
    } else {
      output.write(`${formatDoctor(value)}\n`);
    }
    return 0;
  }

  error.write(`Unknown command or option: ${argument.join(" ") || "<empty>"}\n\n${getHelp()}\n`);
  return 1;
}
