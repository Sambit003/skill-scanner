package agentskill

// Tests for the rules fitted to Claude Code skills: a SKILL.md whose YAML
// front matter uses the documented fields (name, description, when_to_use,
// allowed-tools, hooks, ...) rather than permissions, triggers or version.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// claudeSkill returns a SKILL.md with extra front matter fields and a body.
func claudeSkill(frontmatter, body string) string {
	return "---\nname: report-helper\ndescription: Formats weekly reports.\n" + frontmatter + "---\n\n" + body
}

// scanSkillFiles writes files into skills/report-helper and scans the tree.
func scanSkillFiles(t *testing.T, files map[string]string) model.ScanResult {
	t.Helper()
	root := t.TempDir()
	skill := filepath.Join(root, "skills", "report-helper")
	for name, content := range files {
		path := filepath.Join(skill, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result, err := New().Scan(context.Background(), model.ScanRequest{Target: root, AssetType: "skill", Offline: true,
		OutputFormats: []string{"json"}, TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestLeastPrivilegeRulesNeedADeclaredPermissionsField(t *testing.T) {
	shell := "import subprocess\nsubprocess.run(['ls'])\n"
	network := "import requests\nrequests.get('https://example.com')\n"
	for name, frontmatter := range map[string]string{
		"no permissions field": "",
		"allowed-tools only":   "allowed-tools: Read, Grep\n",
		"allowed-tools list":   "allowed-tools:\n  - Bash(git status:*)\n",
	} {
		result := scanSkillFiles(t, map[string]string{"SKILL.md": claudeSkill(frontmatter, "Run run.py.\n"), "run.py": shell + network})
		for _, id := range []string{"LP1", "LP2", "LP3", "LP4"} {
			if hasRule(result.Findings, id) {
				t.Errorf("%s: %s fired on a Claude skill without a permissions field", name, id)
			}
		}
	}
	for _, test := range []struct{ name, frontmatter, script, rule string }{
		{"empty list", "permissions: []\n", shell, "LP3"},
		{"capability not declared", "permissions: [read]\n", network, "LP1"},
		{"wildcard list", "permissions: ['*']\n", shell, "LP2"},
		{"wildcard scalar", "permissions: \"*\"\n", shell, "LP2"},
		{"permission not used", "permissions: [network]\n", "print('hello')\n", "LP4"},
	} {
		result := scanSkillFiles(t, map[string]string{"SKILL.md": claudeSkill(test.frontmatter, "Run run.py.\n"), "run.py": test.script})
		if !hasRule(result.Findings, test.rule) {
			t.Errorf("%s: %s missing for a declared permissions field; findings=%v", test.name, test.rule, ruleIDs(result.Findings))
		}
	}
}

func ruleIDs(findings []model.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	return ids
}
