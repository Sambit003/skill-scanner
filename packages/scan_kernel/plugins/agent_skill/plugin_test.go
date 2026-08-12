package agentskill

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

func testFixture(t *testing.T, name string) string {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(source), "..", "..", "testdata", name)
}

func TestSafeAndMaliciousFixtures(t *testing.T) {
	plugin := New()
	for _, test := range []struct {
		name    string
		minimum int
		safe    bool
	}{
		{name: "safe_skill", minimum: 0, safe: true},
		{name: "malicious_skill", minimum: 2, safe: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := plugin.Scan(context.Background(), model.ScanRequest{Target: testFixture(t, test.name), AssetType: "skill", OutputFormats: []string{"json", "markdown", "sarif", "terminal"}, TimeoutSeconds: 10})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) < test.minimum {
				t.Fatalf("got %d findings, want at least %d", len(result.Findings), test.minimum)
			}
			if result.Summary.SafeToInstall != test.safe {
				t.Fatalf("safe_to_install=%v, want %v (risk=%d)", result.Summary.SafeToInstall, test.safe, result.Summary.RiskScore)
			}
			if len(result.Reports) != 4 {
				t.Fatalf("got %d reports", len(result.Reports))
			}
		})
	}
}

func TestRiskScoreUsesDiminishingReturns(t *testing.T) {
	findings := []model.Finding{
		{ID: "P1", Severity: "HIGH", Confidence: 1, Finding: "one", MatchedText: "one", Location: model.Location{File: "a.md", StartLine: 1}, Tags: []string{"static", "P1"}},
		{ID: "P1", Severity: "HIGH", Confidence: 1, Finding: "two", MatchedText: "two", Location: model.Location{File: "a.md", StartLine: 2}, Tags: []string{"static", "P1"}},
		{ID: "P1", Severity: "HIGH", Confidence: 1, Finding: "three", MatchedText: "three", Location: model.Location{File: "a.md", StartLine: 3}, Tags: []string{"static", "P1"}},
		{ID: "P1", Severity: "HIGH", Confidence: 1, Finding: "four", MatchedText: "four", Location: model.Location{File: "a.md", StartLine: 4}, Tags: []string{"static", "P1"}},
	}
	summary := summarize(findings, []component{{Path: "a.md", Executable: false}})
	if summary.RiskScore != 43 {
		t.Fatalf("risk score=%d, want 43", summary.RiskScore)
	}
}

func TestRiskScorePreservesPythonEmptyMatchedTextDeduplication(t *testing.T) {
	findings := []model.Finding{
		{ID: "P1", Severity: "HIGH", Confidence: .5, Finding: "display one", Location: model.Location{File: "a.md", StartLine: 1}},
		{ID: "P1", Severity: "HIGH", Confidence: .8, Finding: "display two", Location: model.Location{File: "a.md", StartLine: 2}},
		{ID: "P1", Severity: "HIGH", Confidence: .6, Finding: "display three", Location: model.Location{File: "b.md", StartLine: 1}},
	}
	summary := summarize(findings, []component{{Path: "a.md"}, {Path: "b.md"}})
	if summary.RiskScore != 27 {
		t.Fatalf("risk score=%d, want 27", summary.RiskScore)
	}
}

func TestRiskSeverityBandBoundaries(t *testing.T) {
	tests := []struct {
		name, severity, recommendation string
		safe                           bool
		findings                       []model.Finding
		score                          int
	}{
		{name: "20", score: 20, severity: "LOW", recommendation: "SAFE", safe: true, findings: []model.Finding{{ID: "A", Severity: "HIGH", Confidence: .8, MatchedText: "a"}}},
		{name: "21", score: 21, severity: "MEDIUM", recommendation: "CAUTION", findings: []model.Finding{{ID: "A", Severity: "HIGH", Confidence: .84, MatchedText: "a"}}},
		{name: "50", score: 50, severity: "MEDIUM", recommendation: "CAUTION", findings: []model.Finding{{ID: "A", Severity: "CRITICAL", Confidence: 1, MatchedText: "a"}}},
		{name: "51", score: 51, severity: "HIGH", recommendation: "DO_NOT_INSTALL", findings: []model.Finding{{ID: "A", Severity: "CRITICAL", Confidence: 1, MatchedText: "a"}, {ID: "B", Severity: "LOW", Confidence: .2, MatchedText: "b"}}},
		{name: "80", score: 80, severity: "HIGH", recommendation: "DO_NOT_INSTALL", findings: []model.Finding{{ID: "A", Severity: "CRITICAL", Confidence: 1, MatchedText: "a"}, {ID: "B", Severity: "HIGH", Confidence: 1, MatchedText: "b"}, {ID: "C", Severity: "LOW", Confidence: 1, MatchedText: "c"}}},
		{name: "81", score: 81, severity: "CRITICAL", recommendation: "DO_NOT_INSTALL", findings: []model.Finding{{ID: "A", Severity: "CRITICAL", Confidence: 1, MatchedText: "a"}, {ID: "B", Severity: "HIGH", Confidence: 1, MatchedText: "b"}, {ID: "C", Severity: "LOW", Confidence: 1, MatchedText: "c"}, {ID: "D", Severity: "LOW", Confidence: .2, MatchedText: "d"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for index := range test.findings {
				test.findings[index].Location = model.Location{File: test.name + ".md", StartLine: index + 1}
			}
			summary := summarize(test.findings, []component{{Path: test.name + ".md"}})
			if summary.RiskScore != test.score || summary.Severity != test.severity || summary.Recommendation != test.recommendation || summary.SafeToInstall != test.safe {
				t.Fatalf("summary=%#v, want score=%d severity=%s recommendation=%s safe=%v", summary, test.score, test.severity, test.recommendation, test.safe)
			}
		})
	}
}
