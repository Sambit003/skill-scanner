package agentskill

import (
	"regexp"
	"strings"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func sanitizeFindings(findings []model.Finding) []model.Finding {
	for index := range findings {
		finding := &findings[index]
		finding.Finding = cleanFindingText(finding.Finding)
		finding.MatchedText = cleanFindingText(finding.MatchedText)
		finding.Explanation = cleanFindingText(finding.Explanation)
		finding.Remediation = cleanFindingText(finding.Remediation)
		finding.CodeSnippet = cleanFindingText(finding.CodeSnippet)
		finding.Intent = cleanFindingText(finding.Intent)
	}
	return findings
}

func cleanFindingText(value string) string {
	value = ansiEscape.ReplaceAllString(value, "")
	return strings.Map(func(char rune) rune {
		if char == '\t' || char == '\n' || char == '\r' {
			return char
		}
		if char <= 0x08 || char == 0x0b || char == 0x0c || char >= 0x0e && char <= 0x1f || char == 0x7f {
			return -1
		}
		return char
	}, value)
}
