#!/usr/bin/env node
// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { runCli } from "../lib/cli.mjs";

process.exitCode = runCli(process.argv.slice(2));
