package agentskill

// Analyzers for the Claude Code skill front matter fields that change what
// runs without the user being asked: allowed-tools pre-approves tools while
// the skill is active.

import (
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
	"gopkg.in/yaml.v3"
)

// splitAllowedTools splits an allowed-tools string on commas and whitespace
// outside parentheses, so "Read Grep Bash(git add:*)" and "Read, Bash(gh *)"
// keep each scoped entry whole.
func splitAllowedTools(text string) []string {
	var entries []string
	depth, start := 0, -1
	flush := func(end int) {
		if start >= 0 {
			entries = append(entries, text[start:end])
			start = -1
		}
	}
	for index, char := range text {
		switch {
		case char == '(':
			depth++
		case char == ')' && depth > 0:
			depth--
		case depth == 0 && (char == ',' || char == ' ' || char == '\t' || char == '\n' || char == '\r'):
			flush(index)
			continue
		}
		if start < 0 {
			start = index
		}
	}
	flush(len(text))
	return entries
}

// toolPreApprovalSeverity rates one allowed-tools entry. Shell access with no
// scope (Bash, Bash(*), Bash(**), or "*" for every tool) is MEDIUM; unscoped
// file writes and edits, web fetches, and whole MCP servers or MCP wildcards
// are LOW. Scoped entries such as Bash(gh *) and read-only tools return "".
func toolPreApprovalSeverity(entry string) string {
	name, scope := strings.TrimSpace(entry), ""
	if open := strings.IndexByte(name, '('); open >= 0 && strings.HasSuffix(name, ")") {
		name, scope = strings.TrimSpace(name[:open]), name[open+1:len(name)-1]
	}
	unscoped := strings.Trim(scope, " \t*") == ""
	lower := strings.ToLower(name)
	switch {
	case name == "*", lower == "bash" && unscoped:
		return "MEDIUM"
	case unscoped && (lower == "write" || lower == "edit" || lower == "multiedit" || lower == "notebookedit" || lower == "webfetch"):
		return "LOW"
	case strings.HasPrefix(lower, "mcp__"):
		// mcp__server (no tool part) approves every tool of that server.
		server, tool, hasTool := strings.Cut(name[len("mcp__"):], "__")
		if !hasTool || tool == "" || server == "" || strings.Contains(name, "*") {
			return "LOW"
		}
	}
	return ""
}

// analyzeToolPreApproval reports (EA5) allowed-tools entries that pre-approve
// broad tool use. One finding per skill carries the highest severity, located
// on the line of the first entry with that severity.
func analyzeToolPreApproval(content string) []model.Finding {
	key, value := mappingEntry(frontmatterRoot(content), "allowed-tools")
	if value == nil {
		return nil
	}
	var scalars []*yaml.Node
	switch value.Kind {
	case yaml.ScalarNode:
		scalars = append(scalars, value)
	case yaml.SequenceNode:
		for _, item := range value.Content {
			if item.Kind == yaml.ScalarNode {
				scalars = append(scalars, item)
			}
		}
	}
	severity, line := "", key.Line
	var broad []string
	for _, scalar := range scalars {
		for _, entry := range splitAllowedTools(scalar.Value) {
			rated := toolPreApprovalSeverity(entry)
			if rated == "" {
				continue
			}
			broad = append(broad, entry)
			if severity == "" || (rated == "MEDIUM" && severity != "MEDIUM") {
				severity, line = rated, scalar.Line
			}
		}
	}
	if severity == "" {
		return nil
	}
	text := "allowed-tools: " + strings.Join(broad, ", ")
	explanation, remediation := ruleText("EA5")
	return []model.Finding{{ID: "EA5", Category: "Excessive Agency", Pattern: "Broad Tool Pre-Approval", Severity: severity,
		Confidence: .9, Location: model.Location{File: "SKILL.md", StartLine: line}, Finding: text, MatchedText: text,
		Explanation: explanation, Remediation: remediation, CodeSnippet: lineSnippet(content, line), Tags: []string{"Excessive Agency"}}}
}
