#!/usr/bin/env node
// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { runCli } from "../lib/cli.mjs";

// The corpus acquire path is asynchronous (it downloads under the declared
// bound) and sets its own exit code on completion; every other path returns
// the exit code synchronously.
const outcome = runCli(process.argv.slice(2));
if (outcome !== undefined) {
  process.exitCode = outcome;
}
