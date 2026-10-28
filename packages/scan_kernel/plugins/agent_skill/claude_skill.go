package agentskill

// Analyzers for Claude Code skill front matter: allowed-tools pre-approves
// tools while the skill is active, and description and when_to_use decide
// when the skill is loaded.

import (
	"regexp"
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

// Activation-hijack wording in description and when_to_use, the fields Claude
// reads to decide when to load a skill. "Use when the user asks about X"
// scopes a skill; these phrases claim every request, push other skills aside,
// or ask for activation whether or not the request is relevant.
const (
	hijackUse   = `(?:use[ds]?|using|appl(?:y|ies|ied)|invok(?:e[sd]?|ing)|activat(?:e[sd]?|ing)|trigger(?:s|ed|ing)?|load(?:s|ed|ing)?|select(?:s|ed)?|call(?:s|ed)?)`
	hijackSelf  = `(?:this\s+skill|this|it|me)`
	hijackScope = `(?:(?:single|user(?:'s)?|incoming|new|subsequent|possible)\s+)?(?:requests?|tasks?|messages?|questions?|quer(?:y|ies)|prompts?|conversations?|chats?|interactions?|inputs?|turns?|replies|responses?|sessions?)`
)

var activationHijackPatterns = []struct {
	id, title string
	compiled  *regexp.Regexp
	// qualifiable patterns end on a scope noun that a following clause can
	// narrow ("any request involving a YouTube URL"); see scopedByQualifier.
	qualifiable bool
}{
	// TR1: the skill claims every request.
	{"TR1", "Overly Broad Trigger", regexp.MustCompile(`(?i)\b` + hijackUse + `\s+` + hijackSelf + `\s+(?:skill\s+)?(?:(?:also|always|automatically|proactively)\s+)?(?:for|on|with|in|to|during)\s+(?:every|all|any|each)\s+` + hijackScope + `\b`), true},
	{"TR1", "Overly Broad Trigger", regexp.MustCompile(`(?i)\b(?:should|must|is\s+to)\s+be\s+` + hijackUse + `\s+(?:for|on|with|in)\s+(?:every|all|any|each)\s+` + hijackScope + `\b`), true},
	{"TR1", "Overly Broad Trigger", regexp.MustCompile(`(?i)\b(?:use|trigger(?:s|ed)?|activat(?:e|es|ed))\s+(?:for|on)\s+(?:every|all|any|each)\s+` + hijackScope + `\b`), true},
	{"TR1", "Overly Broad Trigger", regexp.MustCompile(`(?i)\b` + hijackUse + `\s+` + hijackSelf + `\s+(?:skill\s+)?(?:for|on|with|in)\s+(?:everything|anything)\b`), true},
	{"TR1", "Overly Broad Trigger", regexp.MustCompile(`(?i)\b(?:for|on|in)\s+(?:every|all|any|each)\s+` + hijackScope + `\s*,?\s*(?:always\s+)?` + hijackUse + `\s+` + hijackSelf + `\b`), false},
	{"TR1", "Overly Broad Trigger", regexp.MustCompile(`(?i)\balways\s+` + hijackUse + `\s+(?:this\s+skill|me)\s*(?:[.!;]|\z|,\s*(?:no\s+matter|regardless|even|whatever))`), false},
	// TR2: the skill pushes other skills aside.
	{"TR2", "Shadow Command Trigger", regexp.MustCompile(`(?i)\bbefore\s+(?:any|all|every)\s+other\s+(?:skills?|tools?)\b`), false},
	{"TR2", "Shadow Command Trigger", regexp.MustCompile(`(?i)\b(?:instead\s+of|rather\s+than|in\s+place\s+of|over)\s+(?:any\s+|all\s+)?(?:the\s+)?other\s+skills?\b`), false},
	{"TR2", "Shadow Command Trigger", regexp.MustCompile(`(?i)\balways\s+` + hijackUse + `\s+` + hijackSelf + `\s+(?:skill\s+)?first\b`), false},
	{"TR2", "Shadow Command Trigger", regexp.MustCompile(`(?i)\b(?:(?:takes?|has|gets?)\s+(?:precedence|priority)\s+over|overrides?|supersedes?|outranks?)\s+(?:all\s+|any\s+)?(?:the\s+)?other\s+skills?\b`), false},
	{"TR2", "Shadow Command Trigger", regexp.MustCompile(`(?i)\b` + hijackUse + `\s+` + hijackSelf + `\s+(?:skill\s+)?before\s+(?:any|all|every)\s+(?:other\s+)?(?:skills?|tools?)\b`), false},
	// TR3: activation whether or not the request is relevant.
	{"TR3", "Keyword Baiting Trigger", regexp.MustCompile(`(?i)\bregardless\s+of\s+(?:what|whatever)\s+(?:the\s+user|users?|they|you|people)\s+(?:asks?|says?|wants?|requests?|types?|needs?|is\s+asking)\b`), false},
	{"TR3", "Keyword Baiting Trigger", regexp.MustCompile(`(?i)\bregardless\s+of\s+(?:the\s+)?(?:topic|request|task|question|subject|relevance)\b`), false},
	{"TR3", "Keyword Baiting Trigger", regexp.MustCompile(`(?i)\bno\s+matter\s+(?:what\s+(?:the\s+user|users?|they|you)\s+(?:asks?|says?|wants?|requests?|types?)|(?:the|what)\s+(?:topic|request|task|question))\b`), false},
	{"TR3", "Keyword Baiting Trigger", regexp.MustCompile(`(?i)\beven\s+(?:if|when|though)\s+(?:it(?:'s|\s+is|\s+seems)|this\s+skill\s+is|the\s+(?:request|task|question|topic)\s+(?:is|seems))\s+(?:not\s+relevant|irrelevant|unrelated|off[- ]topic|not\s+related)\b`), false},
	{"TR3", "Keyword Baiting Trigger", regexp.MustCompile(`(?i)\beven\s+(?:for|on|with)\s+(?:unrelated|irrelevant|off[- ]topic)\s+` + hijackScope + `\b`), false},
	{"TR3", "Keyword Baiting Trigger", regexp.MustCompile(`(?i)\b(?:for|on)\s+whatever\s+the\s+user\s+(?:asks|says|wants|requests|types)\b`), false},
}

var (
	hijackQualifier = regexp.MustCompile(`(?i)^\s*(?:where|that|which|who|whose|when|whenever|if|involving|related|relating|about|regarding|concerning|mentioning|containing|asking|with|in|from|of|on|under|within|for)\b`)
	hijackRequest   = regexp.MustCompile(`(?i)(?:requests?|tasks?|questions?|quer(?:y|ies))$`)
	hijackToVerb    = regexp.MustCompile(`(?i)^\s*to\s+[a-z]`)
)

// scopedByQualifier reports a scope noun narrowed by the text after it: "any
// request involving a YouTube URL", "all tasks in this repository", or "any
// request to summarize work". "Every turn to detect ..." states a purpose, so
// "to" narrows only requests, tasks, questions and queries.
func scopedByQualifier(matched, rest string) bool {
	return hijackQualifier.MatchString(rest) || (hijackRequest.MatchString(matched) && hijackToVerb.MatchString(rest))
}

// analyzeActivationHijack reports TR1-TR3 for activation-hijack wording in
// the description and when_to_use fields: at most one finding per rule and
// field, on the field's line.
func analyzeActivationHijack(content string) []model.Finding {
	root := frontmatterRoot(content)
	var findings []model.Finding
	for _, field := range []string{"description", "when_to_use"} {
		key, value := mappingEntry(root, field)
		if value == nil || value.Kind != yaml.ScalarNode {
			continue
		}
		reported := map[string]bool{}
		for _, pattern := range activationHijackPatterns {
			if reported[pattern.id] {
				continue
			}
			location := pattern.compiled.FindStringIndex(value.Value)
			if location == nil {
				continue
			}
			matched := value.Value[location[0]:location[1]]
			if pattern.qualifiable && scopedByQualifier(matched, value.Value[location[1]:]) {
				continue
			}
			reported[pattern.id] = true
			matched = truncateRunes(strings.Join(strings.Fields(matched), " "), 200)
			explanation, remediation := ruleText(pattern.id)
			findings = append(findings, model.Finding{ID: pattern.id, Category: "Trigger Abuse", Pattern: pattern.title, Severity: "MEDIUM",
				Confidence: .8, Location: model.Location{File: "SKILL.md", StartLine: key.Line}, Finding: field + ": " + matched,
				MatchedText: matched, Explanation: explanation, Remediation: remediation, CodeSnippet: lineSnippet(content, key.Line),
				Tags: []string{"Trigger Abuse"}})
		}
	}
	return findings
}
