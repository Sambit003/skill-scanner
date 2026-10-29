package agentskill

import "testing"

func TestOffensiveToolingIsALowNote(t *testing.T) {
	skill := func(body string) string { return claudeSkill("", body) }
	result := scanSkillFiles(t, map[string]string{"SKILL.md": skill("Covers Metasploit, mimikatz and nmap -sS scans for authorized pentests.\n" +
		"Detect XMRig miners talking stratum+tcp to a pool.\n")})
	notes := 0
	for _, finding := range result.Findings {
		if len(finding.ID) == 3 && finding.ID[:2] == "YR" {
			t.Errorf("built-in YARA finding %s reported", finding.ID)
		}
		if finding.ID == "SC12" {
			notes++
			if finding.Severity != "LOW" || finding.Location.StartLine != 6 {
				t.Errorf("SC12 %s on line %d, want LOW on line 6", finding.Severity, finding.Location.StartLine)
			}
		}
		if kind, ok := behaviourOf(finding); ok {
			t.Errorf("%s tagged %s", finding.ID, kind)
		}
	}
	if notes != 1 {
		t.Errorf("SC12 count=%d, want one note per file", notes)
	}
	if policy := classifyRule("SC12"); policy.Class != ruleHygiene {
		t.Errorf("SC12 policy=%+v, want hygiene", policy)
	}
	// Ordinary words that share a tool's name are not tools.
	result = scanSkillFiles(t, map[string]string{"SKILL.md": skill("The hydra pattern and john's empire of responders are fierce.\n")})
	if hasRule(result.Findings, "SC12") {
		t.Error("ordinary words reported as offensive tooling")
	}
}
