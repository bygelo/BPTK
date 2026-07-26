// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";

export function findCommand(command) {
  const pathPart = (process.env.PATH || "").split(delimiter).filter(Boolean);
  for (const directory of pathPart) {
    const candidate = join(directory, command);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Continue through the bounded PATH list.
    }
  }
  return null;
}

export function getToolchain() {
  return {
    clang: findCommand("clang"),
    cmake: findCommand("cmake"),
    ninja: findCommand("ninja"),
    emcc: findCommand("emcc"),
    emrun: findCommand("emrun"),
  };
}
