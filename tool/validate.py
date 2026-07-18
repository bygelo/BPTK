#!/usr/bin/env python3
# Copyright 2026 Maphy Technologies
# SPDX-License-Identifier: Apache-2.0
"""Validate the BPTK roadmap-only package with the Python standard library."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "bench/roadmap/manifest.json"
CANDIDATE_PATH = ROOT / "bench/roadmap/candidate.json"
CATALOG_PATH = ROOT / "bench/roadmap/fixture/catalog.json"
SPEC_PATH = ROOT / "bench/roadmap/spec"

REQUIRED_PATH = [
    ROOT / "README.md",
    ROOT / "ROADMAP.md",
    ROOT / "CHANGELOG.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "LICENSE",
    ROOT / "NOTICE",
    ROOT / ".github/workflows/roadmap.yml",
    ROOT / "doc/ARCHITECTURE.md",
    ROOT / "doc/TESTING.md",
    ROOT / "doc/legal-boundary.md",
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

ALLOWED_SUFFIX = {".md", ".json", ".py"}
ALLOWED_NAME = {"LICENSE", "NOTICE"}
ALLOWED_SPECIAL_PATH = {Path(".github/workflows/roadmap.yml")}
LICENSE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"


def load_json(path: Path, error: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exception:
        error.append(f"{path.relative_to(ROOT)} is not strict JSON: {exception}")
        return {}
    if not isinstance(value, dict):
        error.append(f"{path.relative_to(ROOT)} must contain a JSON object")
        return {}
    return value


def walk_key(value: Any, location: str, error: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in BANNED_KEY:
                error.append(f"plural JSON key {key!r} at {location}")
            walk_key(child, f"{location}.{key}", error)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk_key(child, f"{location}[{index}]", error)


def validate_path(error: list[str]) -> None:
    for path in REQUIRED_PATH:
        if not path.is_file():
            error.append(f"required file missing: {path.relative_to(ROOT)}")

    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if ".git" in relative.parts:
            continue
        if path.is_dir() and path.name in BANNED_DIRECTORY:
            error.append(f"plural directory name is disallowed: {relative}")
        if not path.is_file():
            continue
        if path.suffix.lower() in BINARY_SUFFIX:
            error.append(f"game or executable binary is disallowed in planning scope: {relative}")
        if relative not in ALLOWED_SPECIAL_PATH and path.name not in ALLOWED_NAME and path.suffix.lower() not in ALLOWED_SUFFIX:
            error.append(f"product or unrecognized file is disallowed in planning scope: {relative}")
        if path.suffix == ".py" and path.resolve() != Path(__file__).resolve():
            error.append(f"only the planning validator may be Python in this pass: {relative}")


def validate_link(error: list[str]) -> None:
    pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in ROOT.rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        for target in pattern.findall(text):
            clean_target = target.strip().strip("<>")
            if clean_target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            file_target = clean_target.split("#", 1)[0]
            if not file_target:
                continue
            resolved = (path.parent / file_target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                error.append(f"local link escapes repository in {path.relative_to(ROOT)}: {target}")
                continue
            if not resolved.exists():
                error.append(f"broken local link in {path.relative_to(ROOT)}: {target}")


def validate_claim(error: list[str]) -> None:
    pattern = [
        r"\bruns? every Windows game\b",
        r"\bworks? with anything\b",
        r"\ball games work\b",
        r"\bfully tested\b",
        r"\blegally cleared\b",
    ]
    for file_name in ("README.md", "ROADMAP.md"):
        path = ROOT / file_name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for claim in pattern:
            if re.search(claim, text, flags=re.IGNORECASE):
                error.append(f"unsupported completion or compatibility implication in {file_name}: {claim}")


def validate_license(error: list[str]) -> None:
    license_path = ROOT / "LICENSE"
    notice_path = ROOT / "NOTICE"
    inventory_path = ROOT / "doc/third-party.md"
    if license_path.is_file():
        license_hash = hashlib.sha256(license_path.read_bytes()).hexdigest()
        if license_hash != LICENSE_SHA256:
            error.append("LICENSE must match the canonical Apache-2.0 text")
    if notice_path.is_file():
        notice_text = notice_path.read_text(encoding="utf-8")
        for token in ("Copyright 2026 Maphy Technologies", "Apache License, Version 2.0", "incorporates no third-party software", "external CI tools"):
            if token not in notice_text:
                error.append(f"NOTICE missing required licensing statement: {token}")
    if inventory_path.is_file():
        inventory_text = inventory_path.read_text(encoding="utf-8")
        inventory_lower = inventory_text.lower()
        for token in (
            "contains no incorporated third-party software",
            "does not relicense",
            "user-supplied",
            "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            "ece7cb06caefa5fff74198d8649806c4678c61a1",
            "ci-only",
        ):
            if token not in inventory_lower:
                error.append(f"third-party inventory missing boundary statement: {token}")

    legal_path = ROOT / "doc/legal-boundary.md"
    if legal_path.is_file():
        legal_text = legal_path.read_text(encoding="utf-8")
        for token in ("Public availability of this planning repository", "not public-product-name clearance", "No runtime or product release"):
            if token not in legal_text:
                error.append(f"legal boundary missing planning-publication scope: {token}")

    contribution_path = ROOT / "CONTRIBUTING.md"
    if contribution_path.is_file():
        contribution_text = contribution_path.read_text(encoding="utf-8")
        for token in ("Apache License 2.0", "right to provide it", "does not convert third-party material"):
            if token not in contribution_text:
                error.append(f"contribution policy missing licensing statement: {token}")

    workflow_path = ROOT / ".github/workflows/roadmap.yml"
    if workflow_path.is_file():
        workflow_text = workflow_path.read_text(encoding="utf-8")
        for token in (
            "contents: read",
            "python3 tool/validate.py",
            "pull_request:",
            "push:",
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        ):
            if token not in workflow_text:
                error.append(f"roadmap workflow missing safety or gate statement: {token}")
        if re.search(r"uses:\s+[^\s]+@v\d", workflow_text):
            error.append("roadmap workflow action must use an immutable commit, not a mutable major tag")


def validate_graph(item_by_id: dict[str, dict[str, Any]], error: list[str]) -> None:
    state: dict[str, int] = {}

    def visit(item_id: str, trail: list[str]) -> None:
        marker = state.get(item_id, 0)
        if marker == 1:
            error.append(f"dependency cycle: {' -> '.join(trail + [item_id])}")
            return
        if marker == 2:
            return
        state[item_id] = 1
        for prerequisite_id in item_by_id[item_id].get("prerequisite", []):
            if prerequisite_id not in item_by_id:
                error.append(f"{item_id} references missing prerequisite {prerequisite_id}")
                continue
            visit(prerequisite_id, trail + [item_id])
        state[item_id] = 2

    for item_id in item_by_id:
        visit(item_id, [])


def expand_source_reference(value: str, error: list[str], item_id: str) -> set[str]:
    source_id: set[str] = set()
    normalized = value.replace("SRC-", "")
    for token in normalized.split("/"):
        token = token.strip()
        if not token:
            continue
        range_part = re.split(r"[–-]", token)
        try:
            if len(range_part) == 1:
                source_id.add(f"SRC-{int(range_part[0]):03d}")
            elif len(range_part) == 2:
                start = int(range_part[0])
                end = int(range_part[1])
                if start > end:
                    raise ValueError("descending range")
                source_id.update(f"SRC-{number:03d}" for number in range(start, end + 1))
            else:
                raise ValueError("invalid range")
        except ValueError:
            error.append(f"{item_id} has invalid ROADMAP source reference {value!r}")
    return source_id


def main() -> int:
    error: list[str] = []
    validate_path(error)
    validate_link(error)
    validate_claim(error)
    validate_license(error)

    manifest = load_json(MANIFEST_PATH, error) if MANIFEST_PATH.is_file() else {}
    candidate_manifest = load_json(CANDIDATE_PATH, error) if CANDIDATE_PATH.is_file() else {}
    catalog = load_json(CATALOG_PATH, error) if CATALOG_PATH.is_file() else {}
    walk_key(manifest, "manifest", error)
    walk_key(candidate_manifest, "candidate", error)
    walk_key(catalog, "catalog", error)

    item_value = manifest.get("item", [])
    item = item_value if isinstance(item_value, list) else []
    if not isinstance(item_value, list):
        error.append("manifest.item must be an array")

    item_by_id: dict[str, dict[str, Any]] = {}
    benchmark_id: set[str] = set()
    for entry in item:
        if not isinstance(entry, dict):
            error.append("every manifest.item entry must be an object")
            continue
        missing = ITEM_FIELD - entry.keys()
        if missing:
            error.append(f"item {entry.get('item_id', '<unknown>')} missing field: {sorted(missing)}")
        item_id = entry.get("item_id")
        if not isinstance(item_id, str):
            error.append("item_id must be a string")
            continue
        if item_id in item_by_id:
            error.append(f"duplicate item_id: {item_id}")
        item_by_id[item_id] = entry
        current_benchmark_id = entry.get("benchmark_id")
        if current_benchmark_id in benchmark_id:
            error.append(f"duplicate benchmark_id in manifest: {current_benchmark_id}")
        if isinstance(current_benchmark_id, str):
            benchmark_id.add(current_benchmark_id)
        if entry.get("tier") not in {"P0", "P1", "P2", "P3", "P4"}:
            error.append(f"{item_id} has invalid tier")
        if entry.get("kind") not in {"runtime", "evidence"}:
            error.append(f"{item_id} has invalid benchmark kind")
        if entry.get("promotion_state") not in {"planned", "implemented", "passing"}:
            error.append(f"{item_id} has invalid promotion_state")

    validate_graph(item_by_id, error)

    source_text = (ROOT / "doc/source-audit.md").read_text(encoding="utf-8") if (ROOT / "doc/source-audit.md").is_file() else ""
    source_id = set(re.findall(r"^### (SRC-\d+)\b", source_text, flags=re.MULTILINE))
    for item_id, entry in item_by_id.items():
        for current_source_id in entry.get("source_evidence", []):
            if current_source_id not in source_id:
                error.append(f"{item_id} references unknown source evidence {current_source_id}")

    roadmap_text = (ROOT / "ROADMAP.md").read_text(encoding="utf-8") if (ROOT / "ROADMAP.md").is_file() else ""
    roadmap_source_by_item: dict[str, set[str]] = {}
    for line in roadmap_text.splitlines():
        if not line.startswith("| BPTK-"):
            continue
        part = [value.strip() for value in line.strip().strip("|").split("|")]
        if len(part) != 7:
            error.append(f"invalid ROADMAP item row: {line}")
            continue
        item_id = part[0]
        roadmap_source_by_item[item_id] = expand_source_reference(part[4], error, item_id)
    if set(roadmap_source_by_item) != set(item_by_id):
        error.append("ROADMAP item row set must equal manifest item set")
    for item_id, entry in item_by_id.items():
        roadmap_source_id = roadmap_source_by_item.get(item_id, set())
        if roadmap_source_id != set(entry.get("source_evidence", [])):
            error.append(f"{item_id} ROADMAP source scope differs from manifest")

    fixture_value = catalog.get("fixture", [])
    fixture = fixture_value if isinstance(fixture_value, list) else []
    if not isinstance(fixture_value, list):
        error.append("catalog.fixture must be an array")
    fixture_id: set[str] = set()
    for entry in fixture:
        if not isinstance(entry, dict) or not isinstance(entry.get("fixture_id"), str):
            error.append("every fixture entry must have a string fixture_id")
            continue
        missing = FIXTURE_FIELD - entry.keys()
        if missing:
            error.append(f"fixture {entry.get('fixture_id', '<unknown>')} missing field: {sorted(missing)}")
        current_fixture_id = entry["fixture_id"]
        if current_fixture_id in fixture_id:
            error.append(f"duplicate fixture_id: {current_fixture_id}")
        fixture_id.add(current_fixture_id)
        if entry.get("state") != "planned":
            error.append(f"planning fixture must remain planned: {current_fixture_id}")
        if not isinstance(entry.get("is_redistributable"), bool):
            error.append(f"{current_fixture_id} is_redistributable must be boolean")

    spec_by_item: dict[str, dict[str, Any]] = {}
    spec_benchmark_id: set[str] = set()
    if SPEC_PATH.is_dir():
        for path in sorted(SPEC_PATH.glob("*.json")):
            spec = load_json(path, error)
            walk_key(spec, str(path.relative_to(ROOT)), error)
            missing = SPEC_FIELD - spec.keys()
            if missing:
                error.append(f"spec {path.name} missing field: {sorted(missing)}")
            item_id = spec.get("item_id")
            if not isinstance(item_id, str):
                error.append(f"spec {path.name} has invalid item_id")
                continue
            if path.name != f"{item_id.lower()}.json":
                error.append(f"spec filename does not match item_id: {path.name}")
            if item_id in spec_by_item:
                error.append(f"duplicate spec owner: {item_id}")
            spec_by_item[item_id] = spec
            current_benchmark_id = spec.get("benchmark_id")
            if current_benchmark_id in spec_benchmark_id:
                error.append(f"duplicate benchmark_id in spec: {current_benchmark_id}")
            if isinstance(current_benchmark_id, str):
                spec_benchmark_id.add(current_benchmark_id)
            for fixture_reference in spec.get("fixture", []):
                if isinstance(fixture_reference, str) and fixture_reference.startswith("FIX-"):
                    if fixture_reference not in fixture_id:
                        error.append(f"{item_id} references unknown fixture {fixture_reference}")
                elif isinstance(fixture_reference, str):
                    if not (ROOT / fixture_reference).exists():
                        error.append(f"{item_id} references missing evidence file {fixture_reference}")

    if set(item_by_id) != set(spec_by_item):
        missing_spec = sorted(set(item_by_id) - set(spec_by_item))
        orphan_spec = sorted(set(spec_by_item) - set(item_by_id))
        if missing_spec:
            error.append(f"item without spec: {missing_spec}")
        if orphan_spec:
            error.append(f"orphan spec: {orphan_spec}")

    for item_id, entry in item_by_id.items():
        spec = spec_by_item.get(item_id)
        if not spec:
            continue
        if spec.get("benchmark_id") != entry.get("benchmark_id"):
            error.append(f"{item_id} benchmark_id differs between manifest and spec")
        if spec.get("kind") != entry.get("kind"):
            error.append(f"{item_id} kind differs between manifest and spec")
        if spec.get("prerequisite") != entry.get("prerequisite"):
            error.append(f"{item_id} prerequisite differs between manifest and spec")
        if spec.get("owner_item") != item_id:
            error.append(f"{item_id} owner_item must equal item_id")
        if entry.get("promotion_state") == "planned":
            if spec.get("state") != "red" or spec.get("gate") != "excluded":
                error.append(f"planned {item_id} must be red and excluded")
            for field in ("exclusion_reason", "promotion_trigger", "expected_failing_assertion", "active_gate_evidence"):
                if not isinstance(spec.get(field), str) or not spec[field].strip():
                    error.append(f"planned {item_id} needs non-empty {field}")
        if entry.get("promotion_state") in {"implemented", "passing"} and spec.get("gate") != "active":
            error.append(f"implemented {item_id} must be active")
        if entry.get("promotion_state") == "passing" and spec.get("state") != "green":
            error.append(f"passing {item_id} must be green")

    threshold_spec = spec_by_item.get("BPTK-002", {})
    threshold_text = json.dumps(threshold_spec, sort_keys=True).lower()
    for token in ("numeric", "startup", "frame", "audio", "memory", "variance", "sample"):
        if token not in threshold_text:
            error.append(f"BPTK-002 must precommit {token} threshold metadata")
    for item_id, spec in spec_by_item.items():
        current_threshold_owner = spec.get("threshold_owner")
        if item_id == "BPTK-002":
            if current_threshold_owner != "self":
                error.append("BPTK-002 threshold_owner must be self")
        elif spec.get("kind") == "runtime":
            if current_threshold_owner != "BPTK-002":
                error.append(f"{item_id} runtime acceptance must consume the frozen BPTK-002 threshold")
        elif current_threshold_owner not in {None, "BPTK-002"}:
            error.append(f"{item_id} evidence threshold_owner must be null or BPTK-002")
    required_integration_fixture = {
        "BPTK-016": {"FIX-009", "FIX-027"},
        "BPTK-024": {"FIX-014", "FIX-017", "FIX-027"},
    }
    for item_id, required_fixture_id in required_integration_fixture.items():
        actual_fixture_id = set(spec_by_item.get(item_id, {}).get("fixture", []))
        if not required_fixture_id.issubset(actual_fixture_id):
            error.append(f"{item_id} missing integrated fixture ownership: {sorted(required_fixture_id - actual_fixture_id)}")
    p1_integration_prerequisite = {f"BPTK-{number:03d}" for number in range(8, 16)}
    if not p1_integration_prerequisite.issubset(set(item_by_id.get("BPTK-016", {}).get("prerequisite", []))):
        error.append("BPTK-016 must own the integrated P1 gate by depending on BPTK-008 through BPTK-015")

    count = manifest.get("count", {})
    if not isinstance(count, dict):
        error.append("manifest.count must be an object")
        count = {}
    required_count = {"raw", "accepted", "rejected", "deferred", "implemented", "passing"}
    missing_count = required_count - count.keys()
    if missing_count:
        error.append(f"manifest.count missing field: {sorted(missing_count)}")

    rejected_text = (ROOT / "doc/roadmap-rejected.md").read_text(encoding="utf-8") if (ROOT / "doc/roadmap-rejected.md").is_file() else ""
    rejected_id = set(re.findall(r"^### (R-\d+)\b", rejected_text, flags=re.MULTILINE))
    deferred_id = set(re.findall(r"^### (D-\d+)\b", rejected_text, flags=re.MULTILINE))
    rejected_count = len(rejected_id)
    deferred_count = len(deferred_id)
    implemented_count = sum(entry.get("promotion_state") in {"implemented", "passing"} for entry in item_by_id.values())
    passing_count = sum(entry.get("promotion_state") == "passing" for entry in item_by_id.values())

    expected_count = {
        "accepted": len(item_by_id),
        "rejected": rejected_count,
        "deferred": deferred_count,
        "implemented": implemented_count,
        "passing": passing_count,
    }
    for key, value in expected_count.items():
        if count.get(key) != value:
            error.append(f"count.{key} is {count.get(key)!r}, expected {value}")
    if count.get("raw") != count.get("accepted", 0) + count.get("rejected", 0) + count.get("deferred", 0):
        error.append("count.raw must equal accepted + rejected + deferred")
    if count.get("passing", 0) > count.get("implemented", 0):
        error.append("count.passing cannot exceed count.implemented")

    candidate_value = candidate_manifest.get("candidate", [])
    candidate = candidate_value if isinstance(candidate_value, list) else []
    if not isinstance(candidate_value, list):
        error.append("candidate.candidate must be an array")
    candidate_id: set[str] = set()
    dedupe_key: set[str] = set()
    target_by_decision: dict[str, set[str]] = {"accepted": set(), "rejected": set(), "deferred": set()}
    origin_count: dict[str, int] = {"repository": 0, "product": 0, "prior_art": 0, "constraint": 0}
    for index, entry in enumerate(candidate, start=1):
        if not isinstance(entry, dict):
            error.append("every candidate entry must be an object")
            continue
        missing = CANDIDATE_FIELD - entry.keys()
        if missing:
            error.append(f"candidate {entry.get('candidate_id', '<unknown>')} missing field: {sorted(missing)}")
        current_candidate_id = entry.get("candidate_id")
        expected_candidate_id = f"CAND-{index:03d}"
        if current_candidate_id != expected_candidate_id:
            error.append(f"candidate sequence expected {expected_candidate_id}, found {current_candidate_id}")
        if current_candidate_id in candidate_id:
            error.append(f"duplicate candidate_id: {current_candidate_id}")
        if isinstance(current_candidate_id, str):
            candidate_id.add(current_candidate_id)
        current_dedupe_key = entry.get("dedupe_key")
        if current_dedupe_key in dedupe_key:
            error.append(f"duplicate candidate dedupe_key: {current_dedupe_key}")
        if isinstance(current_dedupe_key, str):
            dedupe_key.add(current_dedupe_key)
        decision = entry.get("decision")
        target_id = entry.get("target_id")
        if decision not in target_by_decision or not isinstance(target_id, str):
            error.append(f"{current_candidate_id} has invalid decision or target_id")
        else:
            if target_id in target_by_decision[decision]:
                error.append(f"duplicate {decision} candidate target: {target_id}")
            target_by_decision[decision].add(target_id)
        origin = entry.get("origin")
        if origin not in origin_count:
            error.append(f"{current_candidate_id} has invalid origin {origin!r}")
        else:
            origin_count[origin] += 1

    if target_by_decision["accepted"] != set(item_by_id):
        error.append("accepted candidate target set must equal manifest item set")
    if target_by_decision["rejected"] != rejected_id:
        error.append("rejected candidate target set must equal rejection ledger set")
    if target_by_decision["deferred"] != deferred_id:
        error.append("deferred candidate target set must equal defer ledger set")
    if len(candidate) != count.get("raw"):
        error.append("candidate ledger length must equal count.raw")
    for decision in ("accepted", "rejected", "deferred"):
        if len(target_by_decision[decision]) != count.get(decision):
            error.append(f"candidate {decision} count differs from manifest count")
    declared_origin_count = candidate_manifest.get("origin_count", {})
    if declared_origin_count != origin_count:
        error.append(f"candidate origin_count is {declared_origin_count!r}, expected {origin_count!r}")

    architecture_text = (ROOT / "doc/ARCHITECTURE.md").read_text(encoding="utf-8") if (ROOT / "doc/ARCHITECTURE.md").is_file() else ""
    testing_text = (ROOT / "doc/TESTING.md").read_text(encoding="utf-8") if (ROOT / "doc/TESTING.md").is_file() else ""
    for field in ("compatibility_state", "evidence_state"):
        if field not in architecture_text or field not in testing_text:
            error.append(f"compatibility schema field {field} must be synchronized in architecture and testing docs")
    legal_text = (ROOT / "doc/legal-boundary.md").read_text(encoding="utf-8") if (ROOT / "doc/legal-boundary.md").is_file() else ""
    if "remotely executing imported game code are outside BPTK" not in legal_text:
        error.append("legal boundary must keep remote game execution outside BPTK scope")

    accepted_count = count.get("accepted", 0)
    passing_manifest_count = count.get("passing", 0)
    percent = round((passing_manifest_count / accepted_count) * 100) if accepted_count else 0
    coverage_text = f"{passing_manifest_count} / {accepted_count} ({percent}%)"
    for file_name in ("README.md", "ROADMAP.md"):
        path = ROOT / file_name
        if path.is_file() and coverage_text not in path.read_text(encoding="utf-8"):
            error.append(f"{file_name} must contain current coverage {coverage_text}")

    if len(spec_by_item) != count.get("accepted"):
        error.append("spec count must equal accepted count")
    if benchmark_id != spec_benchmark_id:
        error.append("manifest and spec benchmark_id set differ")

    if error:
        print("FAIL roadmap package")
        for message in sorted(set(error)):
            print(f"- {message}")
        return 1

    print(
        "PASS roadmap package: "
        f"{accepted_count} accepted / {implemented_count} implemented / "
        f"{passing_count} passing; {len(spec_by_item)} red benchmark specification quarantined."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
