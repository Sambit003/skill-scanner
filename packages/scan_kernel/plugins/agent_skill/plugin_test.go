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
		{ID: "P1", Severity: "HIGH", Confidence: 1, Finding: "one", Location: model.Location{File: "a.md", StartLine: 1}, Tags: []string{"static", "P1"}},
		{ID: "P1", Severity: "HIGH", Confidence: 1, Finding: "two", Location: model.Location{File: "a.md", StartLine: 2}, Tags: []string{"static", "P1"}},
		{ID: "P1", Severity: "HIGH", Confidence: 1, Finding: "three", Location: model.Location{File: "a.md", StartLine: 3}, Tags: []string{"static", "P1"}},
		{ID: "P1", Severity: "HIGH", Confidence: 1, Finding: "four", Location: model.Location{File: "a.md", StartLine: 4}, Tags: []string{"static", "P1"}},
	}
	summary := summarize(findings, []component{{Path: "a.md", Executable: false}})
	if summary.RiskScore != 43 {
		t.Fatalf("risk score=%d, want 43", summary.RiskScore)
	}
}
