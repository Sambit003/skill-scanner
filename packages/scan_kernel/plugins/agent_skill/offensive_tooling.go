package agentskill

// Offensive tooling: a skill that names penetration-testing tools, exploit
// frameworks or miners is often a security skill describing them. The name
// alone is a LOW note (SC12), never a malware finding; what the skill does
// with the tool is judged by the behaviour rules.

import (
	"regexp"
	"sort"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// offensiveToolName matches well-known offensive tools by names that are not
// ordinary words.
var offensiveToolName = regexp.MustCompile(`(?i)\b(?:mimikatz|metasploit|msfconsole|msfvenom|meterpreter|cobalt\s?strike|nmap|masscan|sqlmap|` +
	`hashcat|john\s+the\s+ripper|thc-hydra|crackmapexec|netexec|impacket|bloodhound|sharphound|rubeus|lazagne|` +
	`xmrig|coinhive|cryptonight|stratum\+tcp|beef-xss|empire\s+c2|sliver\s+c2|havoc\s+c2)\b`)

// analyzeOffensiveTooling reports (SC12, LOW) the first line of a file that
// names offensive tools, listing every tool the file names.
func analyzeOffensiveTooling(item component) []model.Finding {
	matches := offensiveToolName.FindAllStringIndex(item.Content, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	for _, match := range matches {
		name := strings.ToLower(strings.Join(strings.Fields(item.Content[match[0]:match[1]]), " "))
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	line := 1 + strings.Count(item.Content[:matches[0][0]], "\n")
	explanation, remediation := ruleText("SC12")
	text := truncateRunes("Mentions offensive tooling: "+strings.Join(names, ", "), 200)
	return []model.Finding{{ID: "SC12", Category: "Supply Chain", Pattern: "Mentions Offensive Tooling", Severity: "LOW",
		Confidence: .9, Location: model.Location{File: item.Path, StartLine: line}, Finding: text, MatchedText: text,
		Explanation: explanation, Remediation: remediation, CodeSnippet: lineSnippet(item.Content, line), Tags: []string{"Supply Chain"}}}
}
