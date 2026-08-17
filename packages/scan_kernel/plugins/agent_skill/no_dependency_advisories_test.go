//go:build no_dependency_advisories

package agentskill

import (
	"context"
	"testing"
)

func TestNoDependencyAdvisoriesSuppressesSC4(t *testing.T) {
	items := []component{
		{Path: "requirements.txt", Type: "text", Content: "pycrypto==2.6.1\nrequests==2.30.0\nreqeusts==2.0.0\n"},
		{Path: "package.json", Type: "json", Content: "{\n  \"dependencies\": {\n    \"request\": \"^2.88.2\",\n    \"lodahs\": \"4.17.21\"\n  }\n}\n"},
	}

	findings := analyzeDependencies(context.Background(), items, false)
	if got := countRule(findings, "SC4"); got != 0 {
		t.Fatalf("SC4 count=%d, want 0; findings=%#v", got, findings)
	}
	if got := countRule(findings, "SC5"); got != 2 {
		t.Fatalf("SC5 count=%d, want 2; findings=%#v", got, findings)
	}
	if got := countRule(findings, "SC6"); got != 2 {
		t.Fatalf("SC6 count=%d, want 2; findings=%#v", got, findings)
	}
}

func TestNoDependencyAdvisoriesSuppressesSC4RuleDoc(t *testing.T) {
	for _, doc := range ruleDocuments() {
		if doc.RuleID == "SC4" {
			t.Fatalf("SC4 rule doc should be hidden in no_dependency_advisories builds: %#v", doc)
		}
	}
}
