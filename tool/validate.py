#!/usr/bin/env python3
# Copyright 2026 Maphy Technologies
# SPDX-License-Identifier: Apache-2.0
"""Validate the BPTK product and roadmap package with the Python standard library."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from os.path import basename
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "bench/roadmap/manifest.json"
CANDIDATE_PATH = ROOT / "bench/roadmap/candidate.json"
CATALOG_PATH = ROOT / "bench/roadmap/fixture/catalog.json"
SPEC_PATH = ROOT / "bench/roadmap/spec"
PACKAGE_PATH = ROOT / "package.json"
PACKAGE_LOCK_PATH = ROOT / "package-lock.json"
PACKAGE_CONTENT_PATH = ROOT / "bench/npm/content.json"
STATUS_PATH = ROOT / "data/status.json"

REQUIRED_PATH = [
    ROOT / "README.md",
    ROOT / "ROADMAP.md",
    ROOT / "CHANGELOG.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "LICENSE",
    ROOT / "NOTICE",
    ROOT / ".gitignore",
    ROOT / ".github/workflows/roadmap.yml",
    ROOT / "package.json",
    ROOT / "package-lock.json",
    ROOT / "bin/bptk.mjs",
    ROOT / "data/status.json",
    ROOT / "lib/cli.mjs",
    ROOT / "lib/doctor.mjs",
    ROOT / "lib/index.mjs",
    ROOT / "lib/status.mjs",
    ROOT / "script/package.mjs",
    ROOT / "script/status.mjs",
    ROOT / "tool/eligibility.mjs",
    ROOT / "tool/fullness.mjs",
    ROOT / "tool/residency.mjs",
    ROOT / "test/cli.test.mjs",
    PACKAGE_CONTENT_PATH,
    ROOT / "doc/ARCHITECTURE.md",
    ROOT / "doc/TESTING.md",
    ROOT / "doc/legal-boundary.md",
    ROOT / "doc/RELEASE.md",
    ROOT / "doc/roadmap-rejected.md",
    ROOT / "doc/source-audit.md",
    ROOT / "doc/third-party.md",
    ROOT / "bench/roadmap/README.md",
    MANIFEST_PATH,
    CANDIDATE_PATH,
    CATALOG_PATH,
    Path(__file__).resolve(),
]

ITEM_FIELD = {
    "item_id",
    "title",
    "tier",
    "kind",
    "prerequisite",
    "deliverable",
    "benchmark_id",
    "failure_meaning",
    "risk",
    "source_evidence",
    "promotion_state",
}

SPEC_FIELD = {
    "benchmark_id",
    "item_id",
    "kind",
    "threshold_owner",
    "state",
    "gate",
    "exclusion_reason",
    "prerequisite",
    "promotion_trigger",
    "expected_failing_assertion",
    "owner_item",
    "active_gate_evidence",
    "fixture",
    "procedure",
    "pass_criterion",
}

CANDIDATE_FIELD = {
    "candidate_id",
    "origin",
    "decision",
    "target_id",
    "summary",
    "dedupe_key",
}

FIXTURE_FIELD = {
    "fixture_id",
    "category",
    "purpose",
    "artifact",
    "license",
    "is_redistributable",
    "state",
}

BANNED_KEY = {
    "items",
    "prerequisites",
    "sources",
    "source_evidences",
    "fixtures",
    "procedures",
    "pass_criteria",
    "results",
    "counts",
    "specs",
}

BANNED_DIRECTORY = {
    "docs",
    "tools",
    "benchmarks",
    "specs",
    "fixtures",
    "tests",
    "packages",
    "sources",
    "assets",
    "items",
}

BINARY_SUFFIX = {
    ".exe",
    ".dll",
    ".zip",
    ".wgb",
    ".pak",
    ".iso",
    ".rom",
    ".bin",
    ".wasm",
}

ALLOWED_SUFFIX = {".md", ".json", ".mjs", ".py"}
WEB_SUFFIX = {".mjs", ".html", ".css"}
ALLOWED_NAME = {"LICENSE", "NOTICE"}
ALLOWED_SPECIAL_PATH = {Path(".gitignore"), Path(".github/workflows/roadmap.yml"), Path(".github/CODEOWNERS")}
ALLOWED_MJS_PATH = {
    Path("bin/bptk.mjs"),
    Path("data/corpus.json"),
    Path("data/corpus-run.json"),
    Path("data/sdk-api.json"),
    Path("data/coverage-ratchet.json"),
    Path("MAINTAINERS.md"),
    Path(".github/CODEOWNERS"),
    Path("data/corpus-run.json"),
    Path("lib/abi.mjs"),
    Path("lib/audio.mjs"),
    Path("lib/benchmark.mjs"),
    Path("lib/bound.mjs"),
    Path("lib/census.mjs"),
    Path("lib/clock.mjs"),
    Path("lib/cli.mjs"),
    Path("lib/conformance.mjs"),
    Path("lib/corpus.mjs"),
    Path("lib/doctor.mjs"),
    Path("lib/engine.mjs"),
    Path("lib/emulator.mjs"),
    Path("lib/exec64.mjs"),
    Path("lib/extract.mjs"),
    Path("lib/foundation.mjs"),
    Path("lib/gdi.mjs"),
    Path("lib/gl.mjs"),
    Path("lib/graphics.mjs"),
    Path("lib/hle.mjs"),
    Path("lib/input.mjs"),
    Path("lib/import.mjs"),
    Path("lib/i386-compile.mjs"),
    Path("lib/i386.mjs"),
    Path("lib/ingest.mjs"),
    Path("lib/index.mjs"),
    Path("lib/inspect.mjs"),
    Path("lib/legal.mjs"),
    Path("lib/lift64.mjs"),
    Path("lib/live.mjs"),
    Path("lib/net.mjs"),
    Path("lib/package.mjs"),
    Path("lib/performance.mjs"),
    Path("lib/platform.mjs"),
    Path("lib/pe.mjs"),
    Path("lib/pe64.mjs"),
    Path("lib/port.mjs"),
    Path("lib/present.mjs"),
    Path("lib/recompile.mjs"),
    Path("lib/replay.mjs"),
    Path("lib/report.mjs"),
    Path("lib/research.mjs"),
    Path("lib/rsrc.mjs"),
    Path("lib/runtime.mjs"),
    Path("lib/run.mjs"),
    Path("lib/sdl.mjs"),
    Path("lib/security.mjs"),
    Path("lib/seh.mjs"),
    Path("lib/sevenzip.mjs"),
    Path("lib/shader.mjs"),
    Path("lib/sidecar.mjs"),
    Path("lib/simd.mjs"),
    Path("lib/status.mjs"),
    Path("lib/storage.mjs"),
    Path("lib/thread.mjs"),
    Path("lib/tier.mjs"),
    Path("lib/tierrun.mjs"),
    Path("lib/toolchain.mjs"),
    Path("lib/user.mjs"),
    Path("lib/wasm64.mjs"),
    Path("lib/x64decode.mjs"),
    Path("script/package.mjs"),
    Path("script/status.mjs"),
    Path("tool/eligibility.mjs"),
    Path("tool/fullness.mjs"),
    Path("tool/residency.mjs"),
    Path("test/abi.test.mjs"),
    Path("test/audio.test.mjs"),
    Path("test/clock.test.mjs"),
    Path("test/cli.test.mjs"),
    Path("test/corpus.test.mjs"),
    Path("test/benchmark.test.mjs"),
    Path("test/boundary.test.mjs"),
    Path("test/census.test.mjs"),
    Path("test/emulator.test.mjs"),
    Path("test/engine.test.mjs"),
    Path("test/exec64.test.mjs"),
    Path("test/extract.test.mjs"),
    Path("test/fullness.test.mjs"),
    Path("test/graphics.test.mjs"),
    Path("test/i386.test.mjs"),
    Path("test/import.test.mjs"),
    Path("test/ingest.test.mjs"),
    Path("test/inspect.test.mjs"),
    Path("test/library.test.mjs"),
    Path("test/lift64.test.mjs"),
    Path("test/live.test.mjs"),
    Path("test/net.test.mjs"),
    Path("test/package.test.mjs"),
    Path("test/pe64.test.mjs"),
    Path("test/pe-export.test.mjs"),
    Path("test/performance.test.mjs"),
    Path("test/policy.test.mjs"),
    Path("test/recompile.test.mjs"),
    Path("test/replay.test.mjs"),
    Path("test/port.test.mjs"),
    Path("test/report.test.mjs"),
    Path("test/rsrc.test.mjs"),
    Path("test/run-host.test.mjs"),
    Path("test/runtime.test.mjs"),
    Path("test/sdl.test.mjs"),
    Path("test/security.test.mjs"),
    Path("test/seh.test.mjs"),
    Path("test/shader.test.mjs"),
    Path("test/sidecar.test.mjs"),
    Path("test/simd.test.mjs"),
    Path("test/gdi.test.mjs"),
    Path("test/gl.test.mjs"),
    Path("test/governance.test.mjs"),
    Path("test/hle.test.mjs"),
    Path("test/thread.test.mjs"),
    Path("test/tier.test.mjs"),
    Path("test/tierrun.test.mjs"),
    Path("test/user.test.mjs"),
    Path("test/present.test.mjs"),
    Path("test/wasm64.test.mjs"),
    Path("test/x64decode.test.mjs"),
    Path("web/host.mjs"),
    Path("web/shim/buffer.mjs"),
    Path("web/shim/crypto.mjs"),
    Path("web/shim/fs.mjs"),
    Path("web/shim/path.mjs"),
    Path("web/shim/perf_hooks.mjs"),
}
LICENSE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
PACKAGE_NAME = "@bygelo/bptk"
PACKAGE_VERSION = "0.1.0-alpha.0"
