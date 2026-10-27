package agentskill

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

func TestFrameworkOverridesMatchSpecification(t *testing.T) {
	expectedOverrides := map[string][]string{
		"P6":  {"LLM08:2026"},
		"P7":  {"LLM08:2026"},
		"P8":  {"LLM08:2026"},
		"EA4": {"LLM03:2026", "LLM06:2026"},
		"OH3": {"LLM06:2026", "LLM10:2026"},
		"MP2": {"LLM01:2026", "LLM06:2026"},
		"MP3": {"LLM01:2026", "LLM05:2026"},
		"TT1": {"LLM02:2026", "LLM10:2026"},
		"TT2": {"LLM02:2026", "LLM10:2026"},
		"TT5": {"LLM10:2026"},
		"AS1": {"LLM02:2026", "LLM08:2026"},
		"YR5": {"LLM01:2026"},
	}

	if len(ruleFrameworkOverrides) != len(expectedOverrides) {
		t.Fatalf("ruleFrameworkOverrides len=%d, want %d", len(ruleFrameworkOverrides), len(expectedOverrides))
	}

	for ruleID, want := range expectedOverrides {
		got, ok := ruleFrameworkOverrides[ruleID]
		if !ok {
			t.Errorf("missing override for rule %s", ruleID)
			continue
		}
		gotSorted := append([]string(nil), got...)
		wantSorted := append([]string(nil), want...)
		sort.Strings(gotSorted)
		sort.Strings(wantSorted)
		if !reflect.DeepEqual(gotSorted, wantSorted) {
			t.Errorf("override for %s: got %v, want %v", ruleID, got, want)
		}
	}
}

func TestFrameworkCompletenessAndFormat(t *testing.T) {
	astRegex := regexp.MustCompile(`^AST(0[1-9]|10)$`)
	llmRegex := regexp.MustCompile(`^LLM(0[1-9]|10):2026$`)
	rmfRegex := regexp.MustCompile(`^(GOVERN|MAP|MEASURE|MANAGE) \d+\.\d+$`)

	// Load vendored catalogs
	gaiCatalogPath := filepath.Join("catalogs", "nist-ai-600-1.json")
	gaiBytes, err := os.ReadFile(gaiCatalogPath)
	if err != nil {
		t.Fatalf("failed to read nist-ai-600-1.json: %v", err)
	}
	var gaiData struct {
		Elements []struct {
			ID string `json:"id"`
		} `json:"elements"`
	}
	if err := json.Unmarshal(gaiBytes, &gaiData); err != nil {
		t.Fatalf("failed to unmarshal nist-ai-600-1.json: %v", err)
	}
	validGaiRisks := make(map[string]bool)
	for _, el := range gaiData.Elements {
		validGaiRisks[el.ID] = true
	}

	docs := ruleDocuments()
	if len(docs) == 0 {
		t.Fatal("no rule documents returned")
	}

	for _, doc := range docs {
		fw := doc.Frameworks
		if fw.MappingVersion != mappingVersion {
			t.Errorf("rule %s has mapping version %q, want %q", doc.RuleID, fw.MappingVersion, mappingVersion)
		}
		if len(fw.OwaspAgentic) == 0 {
			t.Errorf("rule %s has empty owasp_agentic", doc.RuleID)
		}
		for _, ast := range fw.OwaspAgentic {
			if !astRegex.MatchString(ast) {
				t.Errorf("rule %s invalid AST tag %q", doc.RuleID, ast)
			}
		}
		if len(fw.OwaspLLM) == 0 {
			t.Errorf("rule %s has empty owasp_llm", doc.RuleID)
		}
		for _, llm := range fw.OwaspLLM {
			if !llmRegex.MatchString(llm) {
				t.Errorf("rule %s invalid LLM tag %q", doc.RuleID, llm)
			}
		}
		if len(fw.NistGaiRisks) == 0 {
			t.Errorf("rule %s has empty nist_gai_risks", doc.RuleID)
		}
		for _, risk := range fw.NistGaiRisks {
			if !validGaiRisks[risk] {
				t.Errorf("rule %s has uncataloged NIST GAI risk %q", doc.RuleID, risk)
			}
		}
		for _, rmf := range fw.NistRmf {
			if !rmfRegex.MatchString(rmf) {
				t.Errorf("rule %s invalid RMF subcategory %q", doc.RuleID, rmf)
			}
		}

		// Ensure sorted and deduplicated
		checkSortedAndDedup := func(field string, arr []string) {
			for i := 1; i < len(arr); i++ {
				if arr[i-1] >= arr[i] {
					t.Errorf("rule %s field %s not strictly sorted: %v", doc.RuleID, field, arr)
				}
			}
		}
		checkSortedAndDedup("owasp_agentic", fw.OwaspAgentic)
		checkSortedAndDedup("owasp_llm", fw.OwaspLLM)
		checkSortedAndDedup("nist_gai_risks", fw.NistGaiRisks)
		checkSortedAndDedup("nist_rmf", fw.NistRmf)
	}
}

func TestFrameworksPrecedenceAndEmptyRmf(t *testing.T) {
	// EA1 is LLM03-only -> should have empty nist_rmf
	ea1 := frameworksForRule("EA1")
	if !reflect.DeepEqual(ea1.OwaspLLM, []string{"LLM03:2026"}) {
		t.Errorf("EA1 owasp_llm = %v, want [LLM03:2026]", ea1.OwaspLLM)
	}
	if len(ea1.NistRmf) != 0 {
		t.Errorf("EA1 nist_rmf = %v, want []", ea1.NistRmf)
	}

	// EA4 is override: LLM03 + LLM06 -> carries MEASURE 2.7
	ea4 := frameworksForRule("EA4")
	if !reflect.DeepEqual(ea4.OwaspLLM, []string{"LLM03:2026", "LLM06:2026"}) {
		t.Errorf("EA4 owasp_llm = %v, want [LLM03:2026, LLM06:2026]", ea4.OwaspLLM)
	}
	if !reflect.DeepEqual(ea4.NistRmf, []string{"MEASURE 2.7"}) {
		t.Errorf("EA4 nist_rmf = %v, want [MEASURE 2.7]", ea4.NistRmf)
	}

	// OH1 is LLM10-only -> empty nist_rmf
	oh1 := frameworksForRule("OH1")
	if len(oh1.NistRmf) != 0 {
		t.Errorf("OH1 nist_rmf = %v, want []", oh1.NistRmf)
	}

	// OH3 is override: LLM06 + LLM10 -> carries MEASURE 2.7
	oh3 := frameworksForRule("OH3")
	if !reflect.DeepEqual(oh3.NistRmf, []string{"MEASURE 2.7"}) {
		t.Errorf("OH3 nist_rmf = %v, want [MEASURE 2.7]", oh3.NistRmf)
	}

	// SC1 has LLM04 -> carries GOVERN 6.1, MANAGE 3.1, MAP 4.1, MEASURE 2.7
	sc1 := frameworksForRule("SC1")
	wantSc1Rmf := []string{"GOVERN 6.1", "MANAGE 3.1", "MAP 4.1", "MEASURE 2.7"}
	if !reflect.DeepEqual(sc1.NistRmf, wantSc1Rmf) {
		t.Errorf("SC1 nist_rmf = %v, want %v", sc1.NistRmf, wantSc1Rmf)
	}
}

func TestFrameworksReportRendering(t *testing.T) {
	findings := []model.Finding{
		{
			ID:          "EA4",
			Category:    "Resource Management",
			Severity:    "MEDIUM",
			Confidence:  0.8,
			Pattern:     "while true without rate limit",
			Explanation: "Unbounded loop",
			Remediation: "Add limits",
			Location:    model.Location{File: "agent.py", StartLine: 10},
			Frameworks:  frameworksForRule("EA4"),
		},
	}
	summary := model.Summary{
		RiskScore:      25,
		Severity:       "MEDIUM",
		Recommendation: "REVIEW",
		ScanScope:      "skill_folders",
	}

	// Markdown report test
	md := renderMarkdown(summary, findings)
	if !strings.Contains(md, "## Compliance summary") {
		t.Error("Markdown report missing '## Compliance summary'")
	}
	if !strings.Contains(md, "2026.09-1") {
		t.Error("Markdown report missing mapping version")
	}
	if !strings.Contains(md, "LLM03:2026") || !strings.Contains(md, "LLM06:2026") {
		t.Error("Markdown report missing expected LLM categories")
	}

	// SARIF report test
	sarifStr, err := renderSARIF(summary, findings)
	if err != nil {
		t.Fatalf("renderSARIF failed: %v", err)
	}
	var sarifObj map[string]any
	if err := json.Unmarshal([]byte(sarifStr), &sarifObj); err != nil {
		t.Fatalf("unmarshal SARIF failed: %v", err)
	}
	runs, ok := sarifObj["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatal("SARIF missing runs")
	}
	run := runs[0].(map[string]any)
	taxonomies, ok := run["taxonomies"].([]any)
	if !ok || len(taxonomies) != 4 {
		t.Fatalf("SARIF taxonomies count=%d, want 4", len(taxonomies))
	}
	props := run["properties"].(map[string]any)
	if props["mapping_version"] != mappingVersion {
		t.Errorf("SARIF mapping_version = %v, want %s", props["mapping_version"], mappingVersion)
	}
}
