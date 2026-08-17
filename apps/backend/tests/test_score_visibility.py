from backend.core.config import settings
from backend.services.score_visibility import redact_report_content, visible_risk_score


def test_scores_are_hidden_by_default() -> None:
    assert visible_risk_score(87) is None


def test_scores_can_be_enabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "SHOW_RISK_SCORES", True)

    assert visible_risk_score(87) == 87


def test_json_report_redacts_summary_score() -> None:
    report = '{"summary":{"risk_score":87,"severity":"HIGH"},"findings":[]}'

    redacted = redact_report_content(report, "json")

    assert '"risk_score": null' in redacted
    assert '"severity": "HIGH"' in redacted


def test_markdown_report_replaces_score_with_severity() -> None:
    report = "# ScanKernel report\n\n**Risk:** 87/100 (HIGH)  \n**Recommendation:** DO_NOT_INSTALL  \n"

    redacted = redact_report_content(report, "markdown")

    assert "87/100" not in redacted
    assert "**Risk:**" not in redacted
    assert "**Severity:** HIGH" in redacted


def test_terminal_report_removes_score() -> None:
    report = "ScanKernel: risk 87/100 HIGH — DO_NOT_INSTALL\nAR1 HIGH SKILL.md:1 pattern\n"

    redacted = redact_report_content(report, "terminal")

    assert "87/100" not in redacted
    assert "risk 87/100" not in redacted
    assert redacted.startswith("ScanKernel: HIGH — DO_NOT_INSTALL")
