//go:build yara_native

package agentskill

import (
	"strings"
	"testing"
)

func TestNativeYARAUsesCanonicalMetadataAndNamespace(t *testing.T) {
	findings, err := scanYARA([]component{{Path: "payload.txt", Type: "text", Content: "stratum+tcp://pool.example"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.ID != "YR3" || !strings.Contains(finding.Pattern, "crypto_stratum_protocol") {
			continue
		}
		if finding.Severity != "HIGH" || finding.Confidence != .9 {
			t.Fatalf("YR3 metadata=(%s, %.2f), want (HIGH, .90)", finding.Severity, finding.Confidence)
		}
		if !strings.HasSuffix(finding.Pattern, "[cryptominers]") {
			t.Fatalf("pattern=%q, want canonical namespace suffix", finding.Pattern)
		}
		if finding.Finding != "stratum+tcp://" || len(finding.Tags) != 1 || finding.Tags[0] != "YARA Match" {
			t.Fatalf("finding=%q tags=%v", finding.Finding, finding.Tags)
		}
		return
	}
	t.Fatalf("missing native YR3 finding: %#v", findings)
}
