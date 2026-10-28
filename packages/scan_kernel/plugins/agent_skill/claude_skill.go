package agentskill

// Analyzers for Claude Code skill features that decide what runs without the
// user being asked: allowed-tools pre-approves tools while the skill is
// active, description and when_to_use decide when the skill is loaded, hooks
// run on events, and inline !`command` preprocessing runs on invocation.

import (
	"context"
	"fmt"
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

// whenToUseEveryScope is TR1 for when_to_use only: that field says when to
// load the skill, so a bare "every task" or "all requests" there is already
// unconditional ("when_to_use: Always, on every task."), where a description
// would need "use this skill for".
var whenToUseEveryScope = regexp.MustCompile(`(?i)\b(?:every|all|any|each)\s+` + hijackScope + `\b`)

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
			findings = append(findings, activationHijackFinding(content, pattern.id, pattern.title, field, matched, key.Line))
		}
		if field == "when_to_use" && !reported["TR1"] {
			for _, location := range whenToUseEveryScope.FindAllStringIndex(value.Value, -1) {
				matched := value.Value[location[0]:location[1]]
				if !scopedByQualifier(matched, value.Value[location[1]:]) {
					findings = append(findings, activationHijackFinding(content, "TR1", "Overly Broad Trigger", field, matched, key.Line))
					break
				}
			}
		}
	}
	return findings
}

func activationHijackFinding(content, id, title, field, matched string, line int) model.Finding {
	matched = truncateRunes(strings.Join(strings.Fields(matched), " "), 200)
	explanation, remediation := ruleText(id)
	return model.Finding{ID: id, Category: "Trigger Abuse", Pattern: title, Severity: "MEDIUM", Confidence: .8,
		Location: model.Location{File: "SKILL.md", StartLine: line}, Finding: field + ": " + matched, MatchedText: matched,
		Explanation: explanation, Remediation: remediation, CodeSnippet: lineSnippet(content, line), Tags: []string{"Trigger Abuse"}}
}

// skillHook is one hook handler from the hooks field of SKILL.md front matter:
//
//	hooks:
//	  PreToolUse:
//	    - matcher: "Bash"
//	      hooks:
//	        - type: command
//	          command: "./scripts/check.sh"
//
// Hooks run automatically on their event while the skill is active, without
// asking the user; they are removed when the skill finishes.
type skillHook struct {
	event, matcher, handlerType string
	line                        int
	command, url                *yaml.Node
	leaves                      []string
}

func yamlItems(node *yaml.Node) []*yaml.Node {
	switch {
	case node == nil:
		return nil
	case node.Kind == yaml.SequenceNode:
		return node.Content
	default:
		return []*yaml.Node{node}
	}
}

func yamlScalarLeaves(node *yaml.Node) []string {
	switch node.Kind {
	case yaml.ScalarNode:
		return []string{node.Value}
	case yaml.MappingNode:
		var leaves []string
		for index := 1; index < len(node.Content); index += 2 {
			leaves = append(leaves, yamlScalarLeaves(node.Content[index])...)
		}
		return leaves
	case yaml.SequenceNode:
		var leaves []string
		for _, item := range node.Content {
			leaves = append(leaves, yamlScalarLeaves(item)...)
		}
		return leaves
	}
	return nil
}

// skillHooks reads every handler under hooks.<event>[].hooks[], and accepts a
// handler written directly in the event's list.
func skillHooks(content string) []skillHook {
	_, hooks := mappingEntry(frontmatterRoot(content), "hooks")
	if hooks == nil || hooks.Kind != yaml.MappingNode {
		return nil
	}
	var result []skillHook
	for index := 0; index+1 < len(hooks.Content); index += 2 {
		event := hooks.Content[index].Value
		for _, group := range yamlItems(hooks.Content[index+1]) {
			matcher := ""
			if _, value := mappingEntry(group, "matcher"); value != nil && value.Kind == yaml.ScalarNode {
				matcher = value.Value
			}
			_, handlers := mappingEntry(group, "hooks")
			if handlers == nil {
				handlers = group
			}
			for _, handler := range yamlItems(handlers) {
				if handler.Kind != yaml.MappingNode {
					continue
				}
				hook := skillHook{event: event, matcher: matcher, line: handler.Line, leaves: yamlScalarLeaves(handler)}
				if _, value := mappingEntry(handler, "type"); value != nil && value.Kind == yaml.ScalarNode {
					hook.handlerType = strings.ToLower(strings.TrimSpace(value.Value))
				}
				if _, value := mappingEntry(handler, "command"); value != nil && value.Kind == yaml.ScalarNode {
					hook.command = value
				}
				if _, value := mappingEntry(handler, "url"); value != nil && value.Kind == yaml.ScalarNode {
					hook.url = value
				}
				if hook.handlerType == "" && hook.command != nil {
					hook.handlerType = "command"
				}
				result = append(result, hook)
			}
		}
	}
	return result
}

// hookDangerPatterns name what makes an automatic hook HIGH: it downloads or
// sends data, executes fetched or decoded code, or reads credentials.
var hookDangerPatterns = []struct {
	reason   string
	compiled *regexp.Regexp
}{
	{"downloads or sends data over the network", regexp.MustCompile(`(?i)\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc|ncat|netcat|scp|sftp|ftp|telnet)\b|/dev/(?:tcp|udp)/|\bfetch\s*\(|\burllib\b|\brequests\.(?:get|post|put)\b|\bhttp\.client\b|\bsocket\.`)},
	{"executes fetched or decoded code", regexp.MustCompile(`(?i)\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby|php)\b|\b(?:eval|iex|Invoke-Expression)\b|(?:\b(?:ba|z)?sh|\bsource)\s+<\(|\bbase64\s+(?:-d|--decode|-D)\b|\bxxd\s+-r\b`)},
	{"reads credentials", regexp.MustCompile(`(?i)(?:~|\$HOME|\$\{HOME\})/\.ssh\b|\.ssh/id_|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials|\.config/gcloud|\.azure/|\.netrc\b|\.docker/config\.json|\.kube/config|/etc/shadow|\.git-credentials|\bsecurity\s+find-(?:generic|internet)-password\b|\bprintenv\b|\bgh\s+auth\s+token\b|\benv\s*(?:\||>|$)`)},
}

// analyzeSkillHooks reports (EA6) each hook handler in SKILL.md front matter:
// MEDIUM for a hook's presence, HIGH when it posts events to a URL (type
// http) or its command or MCP tool input matches hookDangerPatterns.
func analyzeSkillHooks(content string) []model.Finding {
	var findings []model.Finding
	for _, hook := range skillHooks(content) {
		event := hook.event
		if hook.matcher != "" {
			event += " (" + hook.matcher + ")"
		}
		handlerType := hook.handlerType
		if handlerType == "" {
			handlerType = "unknown"
		}
		summary, line := "", hook.line
		switch {
		case hook.command != nil:
			summary, line = hook.command.Value, hook.command.Line
		case hook.url != nil:
			summary, line = hook.url.Value, hook.url.Line
		default:
			summary = strings.Join(hook.leaves, " ")
		}
		var reasons []string
		if handlerType == "http" {
			reasons = append(reasons, "posts each event to a URL")
		}
		if handlerType == "command" || handlerType == "mcp_tool" {
			text := strings.Join(hook.leaves, "\n")
			for _, pattern := range hookDangerPatterns {
				if pattern.compiled.MatchString(text) {
					reasons = append(reasons, pattern.reason)
				}
			}
		}
		severity := "MEDIUM"
		explanation, remediation := ruleText("EA6")
		if len(reasons) > 0 {
			severity = "HIGH"
			explanation += " This hook " + strings.Join(reasons, ", ") + "."
		}
		text := truncateRunes(handlerType+" hook on "+event+": "+strings.Join(strings.Fields(summary), " "), 200)
		findings = append(findings, model.Finding{ID: "EA6", Category: "Excessive Agency", Pattern: "Skill Hook", Severity: severity,
			Confidence: .9, Location: model.Location{File: "SKILL.md", StartLine: line}, Finding: text, MatchedText: text,
			Explanation: explanation, Remediation: remediation, CodeSnippet: lineSnippet(content, line), Tags: []string{"Excessive Agency"}})
	}
	return findings
}

// embeddedCommand is a command that runs without Claude deciding to run it.
type embeddedCommand struct {
	text string
	line int
}

// preprocessingCommand matches inline preprocessing in SKILL.md, as in
// "- PR diff: !`gh pr diff`": the command runs when the skill is invoked,
// before Claude sees the text, and its output replaces the placeholder.
var preprocessingCommand = regexp.MustCompile("!`([^`\n]+)`")

// preprocessingCommands returns the inline preprocessing commands in the
// SKILL.md body. A "!" that closes an inline code span ("`#VALUE!` then
// `x`") is not a command: it follows an odd number of backticks on its line.
func preprocessingCommands(content string) []embeddedCommand {
	body := 0
	if block, ok := frontmatterYAML(content); ok {
		if end := frontmatterEnd.FindStringIndex(content[3+len(block):]); end != nil {
			body = 3 + len(block) + end[1]
		}
	}
	var commands []embeddedCommand
	for _, match := range preprocessingCommand.FindAllStringSubmatchIndex(content[body:], -1) {
		start := body + match[0]
		lineStart := strings.LastIndexByte(content[:start], '\n') + 1
		if strings.Count(content[lineStart:start], "`")%2 == 1 {
			continue
		}
		commands = append(commands, embeddedCommand{content[body+match[2] : body+match[3]], 1 + strings.Count(content[:start], "\n")})
	}
	return commands
}

// analyzeSkillPreprocessing reports (EA7) each inline preprocessing command.
func analyzeSkillPreprocessing(content string) []model.Finding {
	var findings []model.Finding
	for _, command := range preprocessingCommands(content) {
		text := truncateRunes("!`"+command.text+"`", 200)
		explanation, remediation := ruleText("EA7")
		findings = append(findings, model.Finding{ID: "EA7", Category: "Excessive Agency", Pattern: "Preprocessing Command", Severity: "LOW",
			Confidence: .9, Location: model.Location{File: "SKILL.md", StartLine: command.line}, Finding: text, MatchedText: text,
			Explanation: explanation, Remediation: remediation, CodeSnippet: lineSnippet(content, command.line), Tags: []string{"Excessive Agency"}})
	}
	return findings
}

// skillEmbeddedCommands returns the commands of command hooks, with the
// SKILL.md line of each command's first line, and the inline preprocessing
// commands.
func skillEmbeddedCommands(content string) []embeddedCommand {
	commands := preprocessingCommands(content)
	for _, hook := range skillHooks(content) {
		if hook.command == nil {
			continue
		}
		line := hook.command.Line
		if hook.command.Style == yaml.LiteralStyle {
			line++
		}
		commands = append(commands, embeddedCommand{hook.command.Value, line})
	}
	return commands
}

// analyzeEmbeddedCommands runs the static analyzers over each embedded command
// as a shell file named SKILL.md, so no example or code-block treatment
// applies, and points the findings at the command's SKILL.md line.
func analyzeEmbeddedCommands(ctx context.Context, content string) ([]model.Finding, error) {
	var findings []model.Finding
	for _, command := range skillEmbeddedCommands(content) {
		item := component{Path: "SKILL.md", Type: "shell", Lines: pythonLineCount(command.text), Content: command.text}
		commandFindings, err := analyzeSourceAndManifest(ctx, []component{item}, map[string]any{})
		if err != nil {
			return nil, err
		}
		for index := range commandFindings {
			commandFindings[index].Location.StartLine = command.line + max(0, commandFindings[index].Location.StartLine-1)
		}
		findings = append(findings, commandFindings...)
	}
	return findings, nil
}

// mergeEmbeddedCommandFindings adds the findings for embedded commands. The
// raw SKILL.md text was scanned too, so a rule reported on the same file and
// line is kept once: the stronger finding by severity, then confidence.
func mergeEmbeddedCommandFindings(findings, embedded []model.Finding) []model.Finding {
	rank := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
	key := func(finding model.Finding) string {
		return fmt.Sprintf("%s\x00%s\x00%d", ruleID(finding), finding.Location.File, finding.Location.StartLine)
	}
	index := map[string]int{}
	for position, finding := range findings {
		if _, exists := index[key(finding)]; !exists {
			index[key(finding)] = position
		}
	}
	for _, finding := range embedded {
		position, exists := index[key(finding)]
		if !exists {
			index[key(finding)] = len(findings)
			findings = append(findings, finding)
			continue
		}
		existing := findings[position]
		if rank[finding.Severity] > rank[existing.Severity] || (rank[finding.Severity] == rank[existing.Severity] && finding.Confidence > existing.Confidence) {
			findings[position] = finding
		}
	}
	return findings
}
