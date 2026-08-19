import pytest
from pydantic import ValidationError

from backend.domain.models.schemas import ScanCreateRequest, ScanResponse


def test_scan_scope_defaults_to_installable_skill_folders() -> None:
    request = ScanCreateRequest(target="https://github.com/example/skills")

    assert request.scan_scope == "skill_folders"
    assert request.include_readme is False


def test_readme_cannot_be_enabled_for_manifest_only_scope() -> None:
    with pytest.raises(ValidationError, match="include_readme is not applicable"):
        ScanCreateRequest(
            target="https://github.com/example/skills",
            scan_scope="skill_files",
            include_readme=True,
        )


def test_scan_response_exposes_scope() -> None:
    response = ScanResponse.model_validate(
        {
            "id": "scan-id",
            "asset_target": "https://github.com/example/skills",
            "repository_key": "github.com/example/skills",
            "asset_type": "agent_skill",
            "scan_scope": "repository",
            "include_readme": True,
            "status": "QUEUED",
            "created_at": "2026-08-19T00:00:00Z",
        }
    )

    assert response.scan_scope == "repository"
    assert response.include_readme is True
    assert response.repository_key == "github.com/example/skills"
