#!/usr/bin/env python3
"""Run the immutable b630d79 oracle with benchmark-controlled OSV data."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from scan_kernel.engine.plugins.agent_skills.cli import FormatChoice, _scan_state
from scan_kernel.engine.plugins.agent_skills.nodes.analyzers import (
    static_patterns_supply_chain as supply_chain,
)
from scan_kernel.engine.plugins.agent_skills.nodes.analyzers.osv_client import VulnResult
from scan_kernel.engine.plugins.agent_skills.nodes.analyzers import ANALYZER_NODES
from scan_kernel.engine.plugins.agent_skills.nodes.analyzers import static_runner
from scan_kernel.engine.plugins.agent_skills.nodes.build_context import build_context
from scan_kernel.engine.plugins.agent_skills.nodes.filter_findings import filter_findings
from scan_kernel.engine.plugins.agent_skills.nodes.report import report
from scan_kernel.engine.plugins.agent_skills.nodes.resolve_input import resolve_input


_PROFILE_STATE: dict[str, Any] = {}
_REDUCED_PROFILE_STATE: dict[str, Any] = {}
_REPRESENTATIVE_FOR: dict[str, str] = {}


def reusable_analyzer(name: str) -> bool:
    return (
        (name.startswith("static_patterns_") and name != "static_patterns_supply_chain")
        or name == "static_yara"
        or name.startswith("behavioral_")
    )


def build_reduced_state(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Collapse semantically equivalent files for per-file analyzers only.

    Findings are expanded back into original component order below. The key
    retains every path-derived static-runner decision, so this removes repeated
    computation without removing any reported occurrence.
    """
    components = list(state.get("components") or [])
    file_cache = state.get("file_cache") or {}
    representatives: list[str] = []
    representative_for: dict[str, str] = {}
    seen: dict[tuple[Any, ...], str] = {}
    for path in components:
        content = str(file_cache.get(path, ""))
        normalized = str(path).replace("\\", "/").lower()
        key = (
            content,
            static_runner._infer_file_type(path),
            static_runner._is_eval_dataset(path),
            static_runner._is_binary_file(path, content),
            static_runner._is_documentation_markdown(path),
            normalized.endswith("skill.md"),
        )
        representative = seen.get(key)
        if representative is None:
            representative = path
            seen[key] = path
            representatives.append(path)
        representative_for[path] = representative

    reduced = dict(state)
    reduced["components"] = representatives
    reduced["file_cache"] = {path: file_cache[path] for path in representatives}
    metadata_by_path = {
        str(item.get("path", "")): item for item in (state.get("component_metadata") or [])
    }
    reduced["component_metadata"] = [
        metadata_by_path[path] for path in representatives if path in metadata_by_path
    ]
    return reduced, representative_for


def expand_reduced_findings(findings: list[Any]) -> list[Any]:
    by_representative: dict[str, list[Any]] = {}
    for finding in findings:
        by_representative.setdefault(finding.file, []).append(finding)
    expanded: list[Any] = []
    for path in _PROFILE_STATE.get("components") or []:
        representative = _REPRESENTATIVE_FOR.get(path, path)
        expanded.extend(replace(finding, file=path) for finding in by_representative.get(representative, []))
    return expanded


def run_analyzer(name: str) -> tuple[str, dict[str, Any], int]:
    started = time.perf_counter_ns()
    reduced = reusable_analyzer(name)
    update = ANALYZER_NODES[name](_REDUCED_PROFILE_STATE if reduced else _PROFILE_STATE)
    if reduced and update.get("findings"):
        update = dict(update)
        update["findings"] = expand_reduced_findings(list(update["findings"]))
    return name, update, (time.perf_counter_ns() - started) // 1_000_000


def normalize_name(value: str) -> str:
    return value.lower().replace("_", "-")


def install_frozen_osv(path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1:
        raise ValueError("OSV fixture schema_version must be 1")
    responses: dict[tuple[str, str, str], list[VulnResult]] = {}
    for response in document.get("responses", []):
        key = (
            str(response.get("ecosystem", "")).lower(),
            normalize_name(str(response.get("name", ""))),
            str(response.get("version", "")),
        )
        responses[key] = [
            VulnResult(
                vuln_id=str(vulnerability.get("id", "UNKNOWN")),
                summary=str(vulnerability.get("summary", "")),
                severity=str(vulnerability.get("severity", "HIGH")),
                aliases=tuple(str(alias) for alias in vulnerability.get("aliases", [])),
            )
            for vulnerability in response.get("vulnerabilities", [])
        ]

    def query_batch(packages: list[tuple[str, str | None]], ecosystem: str) -> list[list[VulnResult]]:
        return [
            responses.get((ecosystem.lower(), normalize_name(name), version or ""), [])
            for name, version in packages
        ]

    supply_chain.query_batch = query_batch
    supply_chain.was_osv_reachable = lambda: True


def dependency_snapshot(state: dict[str, Any]) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    file_cache = state.get("file_cache") or {}
    for path in state.get("components") or []:
        lower_path = str(path).lower()
        content = str(file_cache.get(path, ""))
        if "package.json" in lower_path:
            coordinates = supply_chain._extract_packages_from_package_json(content)
            ecosystem = "npm"
        elif "pyproject.toml" in lower_path:
            coordinates = supply_chain._extract_packages_from_pyproject(content)
            ecosystem = "PyPI"
        elif any(name in lower_path for name in ("requirements", "setup.py", "pipfile")):
            coordinates = supply_chain._extract_packages_from_requirements(content)
            ecosystem = "PyPI"
        else:
            continue
        for name, version, line in coordinates:
            dependencies.append(
                {
                    "name": name,
                    "version": version or "",
                    "ecosystem": ecosystem,
                    "file": path,
                    "line": line,
                }
            )
    return sorted(dependencies, key=lambda item: (item["file"], item["line"], item["name"]))


def run_profiled_pipeline(initial_state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
    global _PROFILE_STATE, _REDUCED_PROFILE_STATE, _REPRESENTATIVE_FOR
    state = dict(initial_state)
    timings: dict[str, int] = {}

    def run_stage(name: str, operation: Any) -> dict[str, Any]:
        started = time.perf_counter_ns()
        update = operation(state)
        timings[name] = (time.perf_counter_ns() - started) // 1_000_000
        return update

    state.update(run_stage("resolve_input", resolve_input))
    state.update(run_stage("build_context", build_context))
    findings = list(state.get("findings") or [])
    _PROFILE_STATE = state
    _REDUCED_PROFILE_STATE, _REPRESENTATIVE_FOR = build_reduced_state(state)
    timings["unique_analysis_files"] = len(_REDUCED_PROFILE_STATE.get("components") or [])
    names = list(ANALYZER_NODES)
    analyzer_started = time.perf_counter_ns()
    workers = min(len(names), max(1, int(os.environ.get("SCAN_KERNEL_ORACLE_JOBS", "8"))))
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        analyzer_results = list(executor.map(run_analyzer, names))
    timings["analyzers_wall"] = (time.perf_counter_ns() - analyzer_started) // 1_000_000
    for name, update, elapsed_ms in analyzer_results:
        timings[f"analyzer:{name}"] = elapsed_ms
        findings.extend(update.get("findings") or [])
    state["findings"] = findings
    state.update(run_stage("filter_findings", filter_findings))
    state.update(run_stage("scoring_and_report", report))
    return state, timings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--osv-fixture", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--timing", required=True, type=Path)
    args = parser.parse_args()

    install_frozen_osv(args.osv_fixture)
    state = _scan_state(args.target, FormatChoice.json, baseline=args.baseline)
    result, timings = run_profiled_pipeline(state)
    inventory = {
        "components": result.get("component_metadata") or [],
        "manifest": result.get("manifest") or {},
        "dependencies": dependency_snapshot(result),
        "scoring_findings": [
            {
                "rule_id": finding.rule_id or "UNKNOWN",
                "severity": finding.severity,
                "confidence": finding.confidence,
                "file": finding.file,
                "start_line": finding.start_line,
                "matched_text": finding.matched_text or "",
            }
            for finding in (result.get("filtered_findings") or [])
        ],
    }
    args.inventory.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    args.timing.write_text(
        json.dumps({"schema_version": 1, "stages_ms": timings}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(result["report_body"])


if __name__ == "__main__":
    main()
