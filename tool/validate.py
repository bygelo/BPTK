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
