from unittest.mock import AsyncMock

import pytest

from backend.domain.repository_identity import repository_key
from backend.services.scan_service import ScanService


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://github.com/MattPocock/skills.git/", "github.com/mattpocock/skills"),
        (
            "https://github.com/mattpocock/skills/blob/main/skills/code-review/SKILL.md",
            "github.com/mattpocock/skills",
        ),
        (
            "https://raw.githubusercontent.com/mattpocock/skills/main/skills/code-review/SKILL.md",
            "github.com/mattpocock/skills",
        ),
        (
            "https://gitlab.com/group/subgroup/skills/-/raw/main/SKILL.md",
            "gitlab.com/group/subgroup/skills",
        ),
        (
            "https://bitbucket.org/team/skills/src/main/SKILL.md",
            "bitbucket.org/team/skills",
        ),
        ("git@github.com:example/skills.git", "github.com/example/skills"),
        (
            "https://downloads.example.com/skills/SKILL.md?revision=1",
            "https://downloads.example.com/skills/skill.md",
        ),
    ],
)
def test_repository_key(target: str, expected: str) -> None:
    assert repository_key(target) == expected


@pytest.mark.asyncio
async def test_repository_history_filter_is_forwarded_without_configuration_filters() -> None:
    repository = AsyncMock()
    repository.list_scans.return_value = []
    service = ScanService(repository)

    result = await service.list_scans(
        limit=100,
        repository_key="github.com/mattpocock/skills",
    )

    assert result == []
    repository.list_scans.assert_awaited_once_with(
        limit=100,
        offset=0,
        target=None,
        repository_key="github.com/mattpocock/skills",
        scan_scope=None,
        include_readme=None,
    )
