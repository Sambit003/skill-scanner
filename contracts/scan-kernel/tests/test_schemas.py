import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]


def _schema(name: str, version: str = "v1") -> dict:
    return json.loads((ROOT / version / name).read_text(encoding="utf-8"))


def test_protocol_schemas_are_valid_draft_2020_12() -> None:
    for version in ("v1", "v2"):
        for name in ("request.schema.json", "response.schema.json"):
            jsonschema.Draft202012Validator.check_schema(_schema(name, version))


def test_canonical_scan_request_is_valid() -> None:
    jsonschema.validate(
        {
            "operation": "scan",
            "protocol_version": "1",
            "target": "./skill",
            "asset_type": "agent_skill",
            "output_formats": ["json", "sarif"],
            "timeout_seconds": 300,
        },
        _schema("request.schema.json"),
    )


def test_canonical_error_response_is_valid() -> None:
    jsonschema.validate(
        {
            "protocol_version": "1",
            "ok": False,
            "error": {"code": "SCAN_FAILED", "message": "fixture failure"},
        },
        _schema("response.schema.json"),
    )


def test_canonical_v2_scan_request_is_valid() -> None:
    jsonschema.validate(
        {
            "operation": "scan",
            "protocol_version": "2",
            "target": "./skills",
            "asset_type": "agent_skill",
            "output_formats": ["json"],
            "timeout_seconds": 300,
            "scan_scope": "skill_folders",
            "include_readme": False,
        },
        _schema("request.schema.json", "v2"),
    )


def test_canonical_v2_scan_response_is_valid() -> None:
    jsonschema.validate(
        {
            "protocol_version": "2",
            "ok": True,
            "result": {
                "kind": "scan",
                "summary": {
                    "risk_score": 0,
                    "vulnerability_score": 0,
                    "exposure_score": 0,
                    "severity": "LOW",
                    "recommendation": "SAFE",
                    "safe_to_install": True,
                    "findings_count": 1,
                    "findings_by_severity": {"MEDIUM": 1},
                    "findings_by_category": {"Resource Management": 1},
                    "scanner_version": "test",
                    "scan_mode": "deterministic",
                    "scan_scope": "skill_folders",
                    "include_readme": False,
                },
                "findings": [
                    {
                        "id": "EA4",
                        "category": "Resource Management",
                        "severity": "MEDIUM",
                        "confidence": 0.8,
                        "location": {
                            "file": "SKILL.md",
                            "start_line": 1,
                            "end_line": None,
                        },
                        "frameworks": {
                            "mapping_version": "2026.09-1",
                            "owasp_agentic": ["AST03"],
                            "owasp_llm": ["LLM03:2026", "LLM06:2026"],
                            "nist_gai_risks": ["Information Security"],
                            "nist_rmf": ["MEASURE 2.7"],
                        },
                    }
                ],
                "reports": {
                    "json": {"content": "{}", "content_type": "application/json"}
                },
            },
        },
        _schema("response.schema.json", "v2"),
    )


def test_canonical_v2_rules_response_is_valid() -> None:
    jsonschema.validate(
        {
            "protocol_version": "2",
            "ok": True,
            "result": {
                "kind": "rules",
                "items": [
                    {
                        "rule_id": "EA4",
                        "rule_family": "EA",
                        "title": "Unbounded Resource Use",
                        "category": "Resource Management",
                        "description": "Unbounded loops without rate limits.",
                        "remediation": "Add limits.",
                        "documentation_url": "/v1/rules/EA4",
                        "frameworks": {
                            "mapping_version": "2026.09-1",
                            "owasp_agentic": ["AST03"],
                            "owasp_llm": ["LLM03:2026", "LLM06:2026"],
                            "nist_gai_risks": ["Information Security"],
                            "nist_rmf": ["MEASURE 2.7"],
                        },
                    }
                ],
            },
        },
        _schema("response.schema.json", "v2"),
    )



def test_scan_response_capabilities_are_optional_and_validated() -> None:
    for version in ("v1", "v2"):
        schema = _schema("response.schema.json", version)
        summary = {
            "risk_score": 0,
            "severity": "LOW",
            "recommendation": "SAFE",
            "safe_to_install": True,
            "findings_count": 0,
            "findings_by_severity": {},
            "findings_by_category": {},
            "scanner_version": "test",
            "scan_mode": "deterministic",
        }
        if version == "v2":
            summary.update({"scan_scope": "skill_folders", "include_readme": False})
        result = {
            "kind": "scan",
            "summary": summary,
            "findings": [],
            "reports": {"json": {"content": "{}", "content_type": "application/json"}},
        }
        response = {"protocol_version": version[1:], "ok": True, "result": result}
        jsonschema.validate(response, schema)
        result["capabilities"] = [
            {
                "rule_id": "AST4",
                "label": "Runs shell commands",
                "location": {"file": "scripts/run.py", "start_line": 3, "end_line": None},
                "snippet": "subprocess.run(['ls'])",
            }
        ]
        jsonschema.validate(response, schema)
        result["capabilities"][0]["severity"] = "MEDIUM"
        try:
            jsonschema.validate(response, schema)
        except jsonschema.ValidationError:
            continue
        raise AssertionError(f"{version}: a capability entry must not carry finding fields")
