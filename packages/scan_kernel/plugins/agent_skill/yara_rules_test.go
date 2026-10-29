package agentskill

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

func TestBundledYARAKeepsOnlyThePromptInjectionRule(t *testing.T) {
	entries, err := os.ReadDir("yara_rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "agent_skills.yar" {
		t.Fatalf("bundled YARA files=%v, want only agent_skills.yar", entries)
	}
	raw, err := os.ReadFile(filepath.Join("yara_rules", "agent_skills.yar"))
	if err != nil {
		t.Fatal(err)
	}
	if rules := regexp.MustCompile(`(?m)^rule\s+(\w+)`).FindAllStringSubmatch(string(raw), -1); len(rules) != 1 || rules[0][1] != "agent_skill_prompt_injection_hidden_instructions" {
		t.Fatalf("bundled rules=%v, want only the YR5 prompt-injection rule", rules)
	}
}

func TestPromptInjectionYARARuleHasItsOwnCategory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("yara_rules", "agent_skills.yar"))
	if err != nil {
		t.Fatal(err)
	}
	rule := string(raw)[strings.Index(string(raw), "rule agent_skill_prompt_injection_hidden_instructions\n"):]
	rule = rule[:strings.Index(rule, "\n}")]
	if !strings.Contains(rule, `category = "prompt_injection"`) {
		t.Fatalf("prompt-injection YARA rule is not in the prompt_injection category:\n%s", rule)
	}
	var document *model.RuleDocument
	for _, candidate := range ruleDocuments() {
		if candidate.RuleID == "YR5" {
			document = &candidate
			break
		}
	}
	if document == nil {
		t.Fatal("rule documents do not list YR5")
	}
	if document.Title != "Prompt Injection Signature" || document.Category != "YARA Match" {
		t.Errorf("YR5 document=%q/%q, want Prompt Injection Signature/YARA Match", document.Title, document.Category)
	}
	if got := document.Frameworks.OwaspLLM; len(got) != 1 || got[0] != "LLM01:2026" {
		t.Errorf("YR5 owasp_llm=%v, want [LLM01:2026] rather than the YR family's supply-chain default", got)
	}
	if policy := classifyRule("YR5"); policy.Class != ruleEvidence || policy.Context != contextInstructions {
		t.Errorf("YR5 policy=%+v, want evidence in instruction files like P1", policy)
	}
}
