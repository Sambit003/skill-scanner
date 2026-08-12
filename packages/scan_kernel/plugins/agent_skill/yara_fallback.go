//go:build !yara_native

package agentskill

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// The development build keeps a deterministic signature subset so contributors
// can test without libyara. Release bundles enable the yara_native build tag.
func scanYARA(ctx context.Context, items []component, customRules string) ([]model.Finding, error) {
	if customRules != "" {
		return nil, fmt.Errorf("custom YARA rules require a native-YARA build")
	}
	signatures := []struct {
		id, title, severity, expression string
	}{
		{"YR1", "Reverse-shell or malware signature", "CRITICAL", `(?i)(/dev/tcp/|meterpreter|powershell.{0,80}-enc|nc\s+(-e|--exec))`},
		{"YR2", "Webshell signature", "CRITICAL", `(?i)(c99shell|r57shell|webshell|eval\s*\(\s*\$_(POST|GET|REQUEST))`},
		{"YR3", "Cryptominer signature", "HIGH", `(?i)(stratum\+tcp|xmrig|coinhive|cryptonight)`},
		{"YR4", "Hack-tool signature", "HIGH", `(?i)(mimikatz|nmap\s+-s[STUV]|sqlmap|metasploit)`},
	}
	var findings []model.Finding
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, signature := range signatures {
			compiled := regexp.MustCompile(signature.expression)
			for _, match := range compiled.FindAllStringIndex(item.Content, 10) {
				line := 1 + strings.Count(item.Content[:match[0]], "\n")
				findings = append(findings, model.Finding{ID: signature.id, Category: "YARA Match", Pattern: signature.title,
					Severity: signature.severity, Confidence: .90, Location: model.Location{File: item.Path, StartLine: line}, Finding: signature.title,
					Explanation: "A bundled malware signature matched this content.", Remediation: "Remove the matched payload and investigate its origin.",
					CodeSnippet: lineSnippet(item.Content, line), Tags: []string{"yara", signature.id}})
			}
		}
	}
	return findings, nil
}
