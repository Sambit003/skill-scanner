package agentskill

import (
	"testing"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

func TestTM1IgnoresCommandsThatOnlyLookDestructive(t *testing.T) {
	for _, test := range []struct{ name, path, kind, content string }{
		{"http delete route", "SKILL.md", "markdown", blindSpotFrontmatter + "- `DELETE /api/users/:id` removes a user record.\n"},
		{"line comments", "scripts/strip.py", "python", "def strip(text):\n    \"\"\"Remove // line comments.\"\"\"\n    return text\n"},
		{"one relative output file", "SKILL.md", "markdown", blindSpotFrontmatter + "```bash\n(cd unpacked && rm -f ../out.docx && zip -r ../out.docx .)\n```\n"},
	} {
		content := test.content
		for _, finding := range scanComponents(t, component{Path: test.path, Type: test.kind, Content: content}) {
			if finding.ID == "TM1" || finding.ID == "TM2" {
				t.Errorf("%s: %s reported %q", test.name, finding.ID, finding.Finding)
			}
		}
	}
}

func TestTM1KeepsRecursiveDeletes(t *testing.T) {
	for _, content := range []string{
		"Clean up with rm -rf / when done.\n",
		"Clean up with rm -rf ~ when done.\n",
		"Reset the machine with rm -rf \"$HOME\" when done.\n",
		"Clean up with rm -rf --no-preserve-root / when done.\n",
		"Then run rm -f /etc/hosts to reset name lookup.\n",
	} {
		item := component{Path: "SKILL.md", Type: "markdown", Content: blindSpotFrontmatter + content}
		if finding, _, found := reviewOf(t, item, "TM1"); !found || finding.Severity != "HIGH" {
			t.Errorf("TM1 found=%v severity=%q for %q, want HIGH", found, finding.Severity, content)
		}
	}
}

func TestShellTrueSeverityFollowsTheCommand(t *testing.T) {
	for _, test := range []struct{ content, severity string }{
		{"import subprocess\nsubprocess.run(user_cmd, shell=True)\n", "MEDIUM"},
		{"import subprocess\nproc = subprocess.Popen(self.command, shell=True)\n", "MEDIUM"},
		{"import subprocess\nsubprocess.run(f\"tar czf {name}.tgz build\", shell=True)\n", "HIGH"},
		{"import subprocess\nsubprocess.run(\"ls -la | sort\", shell=True)\n", "HIGH"},
	} {
		item := component{Path: "scripts/run.py", Type: "python", Executable: true, Content: test.content}
		if finding, _, found := reviewOf(t, item, "TM1"); !found || finding.Severity != test.severity {
			t.Errorf("TM1 found=%v severity=%q for %q, want %s", found, finding.Severity, test.content, test.severity)
		}
	}
}

func TestOneFindingPerLineCategoryAndRule(t *testing.T) {
	at := func(id, category, severity string, line int, confidence float64, tags ...string) model.Finding {
		return model.Finding{ID: id, Category: category, Severity: severity, Confidence: confidence, Tags: tags,
			Location: model.Location{File: "run.sh", StartLine: line}}
	}
	got := keepOneFindingPerLine([]model.Finding{
		at("TM1", "Tool Misuse", "MEDIUM", 3, .9),
		at("TM2", "Tool Misuse", "HIGH", 3, .7),
		at("SC2", "Supply Chain", "HIGH", 3, .8),
		at("EA1", "Excessive Agency", "MEDIUM", 4, .85),
		at("EA5", "Excessive Agency", "MEDIUM", 4, .9),
		at("RA2", "Rogue Agent", "MEDIUM", 5, .6, "Needs review: negated"),
		at("RA2", "Rogue Agent", "MEDIUM", 5, .6),
		at("RA2", "Rogue Agent", "MEDIUM", 6, .6),
	})
	want := []string{"TM2:3", "SC2:3", "EA1:4", "EA5:4", "RA2:5:scored", "RA2:6:scored"}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(want), got)
	}
	for index, finding := range got {
		label := finding.ID + ":" + string(rune('0'+finding.Location.StartLine))
		if finding.ID == "RA2" {
			if _, review := needsReview(finding); !review {
				label += ":scored"
			}
		}
		if label != want[index] {
			t.Errorf("finding %d = %s, want %s", index, label, want[index])
		}
	}
}
