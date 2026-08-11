import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]


def _schema(name: str) -> dict:
    return json.loads((ROOT / "v1" / name).read_text(encoding="utf-8"))


def test_protocol_v1_schemas_are_valid_draft_2020_12() -> None:
    for name in ("request.schema.json", "response.schema.json"):
        jsonschema.Draft202012Validator.check_schema(_schema(name))


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
