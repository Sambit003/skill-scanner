from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import jsonschema


REPO_ROOT = Path(__file__).resolve().parents[3]
RESPONSE_SCHEMA = json.loads(
    (REPO_ROOT / "contracts/scan-kernel/v1/response.schema.json").read_text(encoding="utf-8")
)


def run_engine(payload: object | str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "packages")
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        [sys.executable, "-m", "scan_kernel.engine.protocol_cli"],
        cwd=REPO_ROOT,
        env=env,
        input=raw,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def request_for(fixture: str, *, asset_type: str = "agent_skill") -> dict[str, object]:
    return {
        "operation": "scan",
        "protocol_version": "1",
        "target": str(Path(__file__).parent / "fixtures" / fixture),
        "asset_type": asset_type,
        "output_formats": ["json", "markdown", "sarif", "terminal"],
        "timeout_seconds": 20,
    }


def test_success_response_matches_v1_contract() -> None:
    completed = run_engine(request_for("safe_skill"))

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    jsonschema.validate(payload, RESPONSE_SCHEMA)
    assert payload["ok"] is True
    assert set(payload["result"]["reports"]) == {"json", "markdown", "sarif", "terminal"}


def test_security_findings_are_a_successful_process_result() -> None:
    completed = run_engine(request_for("malicious_skill"))

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    jsonschema.validate(payload, RESPONSE_SCHEMA)
    assert payload["result"]["summary"]["findings_count"] > 0


def test_invalid_json_returns_machine_readable_error() -> None:
    completed = run_engine("not-json")

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    jsonschema.validate(payload, RESPONSE_SCHEMA)
    assert payload["error"]["code"] == "INVALID_REQUEST"


def test_unknown_protocol_version_is_rejected() -> None:
    request = request_for("safe_skill")
    request["protocol_version"] = "99"

    completed = run_engine(request)

    assert completed.returncode == 2
    assert json.loads(completed.stdout)["error"]["code"] == "INVALID_REQUEST"


def test_unsupported_asset_type_is_rejected() -> None:
    completed = run_engine(request_for("safe_skill", asset_type="unknown"))

    assert completed.returncode == 2
    assert json.loads(completed.stdout)["error"]["code"] == "UNSUPPORTED_ASSET_TYPE"


def test_rule_registry_is_available_through_the_process_contract() -> None:
    completed = run_engine({"operation": "list_rules", "protocol_version": "1"})

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    jsonschema.validate(payload, RESPONSE_SCHEMA)
    assert payload["result"]["kind"] == "rules"
    assert payload["result"]["items"]


def test_single_rule_is_available_through_the_process_contract() -> None:
    completed = run_engine(
        {"operation": "get_rule", "protocol_version": "1", "rule_id": "P1"}
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    jsonschema.validate(payload, RESPONSE_SCHEMA)
    assert payload["result"]["rule"]["rule_id"] == "P1"
