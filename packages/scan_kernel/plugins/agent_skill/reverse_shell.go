package agentskill

// Reverse shells: a program that connects out to a remote host and wires an
// interactive shell to the connection, handing the machine to whoever
// listens. RA3 reports the common forms in every language, on one line or
// across a few lines of one file, and base64 or -EncodedCommand payloads
// that decode to one. Descriptions in documentation stay untagged.

import (
	"net"
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// reverseShellSignature is an anchor line plus companion patterns that must
// all match within window lines of it (0: on the anchor line).
type reverseShellSignature struct {
	language   string
	anchor     *regexp.Regexp
	companions []*regexp.Regexp
	window     int
}

const shellName = `(?:/(?:usr/)?bin/)?(?:ba|z|k|da)?sh\b`

var reverseShellSignatures = []reverseShellSignature{
	{"bash", regexp.MustCompile(`(?i)/dev/(?:tcp|udp)/[^/\s"'` + "`" + `]+/[^\s"'` + "`" + `;&|)]+`),
		[]*regexp.Regexp{regexp.MustCompile(`(?i)\b(?:ba|z|k|da)?sh\s+-i\b|0>&\s*1\b|0<&\s*\d+|\b(?:ba|z|k|da)?sh\b[^\n]*<&\s*\d+` +
			`|\bwhile\s+read\s+(?:-\w+\s+)*\w+[^\n]*?\bdo\s+(?:eval\s+)?["']?\$\{?\w+`)}, 3},
	{"netcat", regexp.MustCompile(`(?i)\b(?:nc|ncat|netcat)(?:\.exe)?\b[^\n|;&]*\s-[a-z]*[ec]\s+["']?(?:` + shellName + `|cmd(?:\.exe)?\b|powershell(?:\.exe)?\b)`), nil, 0},
	{"netcat", regexp.MustCompile(`(?i)\b(?:ba|z|k|da)?sh\s+-i\b[^\n]*\|\s*(?:nc|ncat|netcat|openssl\s+s_client)\b|\b(?:nc|ncat|netcat|openssl\s+s_client)\b[^\n|]*\|\s*` + shellName + `[^\n|]*\|\s*(?:nc|ncat|netcat|openssl\s+s_client)\b`), nil, 0},
	{"socat", regexp.MustCompile(`(?i)\bsocat\b[^\n]*\b(?:exec|system):\s*["']?` + shellName),
		[]*regexp.Regexp{regexp.MustCompile(`(?i)\b(?:tcp[46]?|tcp-connect|ssl|openssl)(?:-connect)?:`)}, 0},
	{"python", regexp.MustCompile(`\.connect\s*\(\s*\(|\bsocket\.create_connection\s*\(`),
		[]*regexp.Regexp{regexp.MustCompile(`\bos\.dup2\s*\(|\bstdin\s*=\s*\w+\.fileno\s*\(`),
			regexp.MustCompile(`\bpty\.spawn\s*\(|\bsubprocess\.(?:call|Popen|run|check_call)\s*\(\s*\[?\s*["']` + shellName + `|["']` + shellName + `(?:\s+-i)?["']`)}, 12},
	{"perl", regexp.MustCompile(`\bopen\s*\(\s*STDIN\s*,\s*["']>&`),
		[]*regexp.Regexp{regexp.MustCompile(`\bsocket\s*\(|IO::Socket::INET`), regexp.MustCompile(`\bexec\s*\(?\s*["']` + shellName)}, 6},
	{"ruby", regexp.MustCompile(`\bTCPSocket\.(?:new|open)\s*\(`),
		[]*regexp.Regexp{regexp.MustCompile(`["']` + shellName), regexp.MustCompile(`<&|>&|:in\s*=>|\[:in|\.reopen\s*\(|\.to_i\b|IO\.popen`)}, 8},
	{"php", regexp.MustCompile(`\bfsockopen\s*\(`),
		[]*regexp.Regexp{regexp.MustCompile(`\b(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(`), regexp.MustCompile(shellName + `|cmd\.exe`)}, 6},
	{"node", regexp.MustCompile(`\bnet\.(?:connect|createConnection)\s*\(|\bnew\s+net\.Socket\s*\(|\.connect\s*\(\s*\d+\s*,`),
		[]*regexp.Regexp{regexp.MustCompile(`\b(?:spawn|exec)\s*\(\s*["'](?:` + shellName + `|cmd(?:\.exe)?["'])`), regexp.MustCompile(`\.pipe\s*\(`)}, 12},
	{"PowerShell", regexp.MustCompile(`(?i)\bNet\.Sockets\.TCPClient\s*\(`),
		[]*regexp.Regexp{regexp.MustCompile(`(?i)\.GetStream\s*\(`), regexp.MustCompile(`(?i)\b(?:iex|Invoke-Expression)\b`)}, 10},
}

// reverseShellAt returns the language and the anchor offsets of the first
// reverse shell in text.
func reverseShellAt(text string) (string, []int) {
	for _, signature := range reverseShellSignatures {
		for _, match := range signature.anchor.FindAllStringIndex(text, -1) {
			if window := lineWindow(text, match[0], signature.window); allMatch(signature.companions, window) {
				return signature.language, match
			}
		}
	}
	return "", nil
}

// lineWindow returns the lines within n lines of the line holding offset.
func lineWindow(text string, offset, n int) string {
	start := strings.LastIndexByte(text[:offset], '\n') + 1
	for range n {
		if start == 0 {
			break
		}
		start = strings.LastIndexByte(text[:start-1], '\n') + 1
	}
	end := offset
	for count := 0; count <= n; count++ {
		index := strings.IndexByte(text[end:], '\n')
		if index < 0 {
			end = len(text)
			break
		}
		end += index + 1
	}
	return text[start:end]
}

func allMatch(patterns []*regexp.Regexp, text string) bool {
	for _, pattern := range patterns {
		if !pattern.MatchString(text) {
			return false
		}
	}
	return true
}

var (
	ipLiteral = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// hostPlaceholder is a stand-in for the listener's address in a lesson or
	// cheat sheet: ATTACKER_IP, LHOST, <ip>, {host}, $IP, x.x.x.x.
	hostPlaceholder = regexp.MustCompile(`(?i)\b(?:attacker(?:[_-]?(?:ip|host))?|lhost|rhost|your[_-]?ip|ip[_-]?address|listener[_-]?ip)\b|<[^>\n]{0,20}(?:ip|host|addr)[^>\n]{0,20}>|\{[^}\n]{0,20}(?:ip|host)[^}\n]{0,20}\}|\$\{?[A-Z_]*(?:IP|HOST)\b|\bx\.x\.x\.x\b`)
)

// labListener reports a reverse shell aimed at a placeholder, or only at
// private or loopback addresses: a lab exercise or a lesson, not a remote
// listener.
func labListener(window string) bool {
	if hostPlaceholder.MatchString(window) {
		return true
	}
	ips := ipLiteral.FindAllString(window, -1)
	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified()) {
			return false
		}
	}
	return len(ips) > 0
}

// insideInlineCode reports an offset inside a backtick code span on its line.
func insideInlineCode(content string, offset int) bool {
	lineStart := strings.LastIndexByte(content[:offset], '\n') + 1
	return strings.Count(content[lineStart:offset], "`")%2 == 1
}

var (
	// runInstruction tells the agent or user to run something.
	runInstruction = regexp.MustCompile(`(?i)\b(?:run|execute|exec|paste|type|enter|launch|start)\b`)
	// descriptiveContext describes a reverse shell instead of asking for one:
	// what attackers or malware do, an example, or detection.
	descriptiveContext = regexp.MustCompile(`(?i)\b(?:attackers?|an\s+attacker|adversar(?:y|ies)|malware|threat\s+actors?|intruders?)\b` +
		`|\bfor\s+example\b|\be\.g\.|\bsuch\s+as\b|\btypical\b|\blooks?\s+like\b` +
		`|\b(?:detect\w*|flag\w*|look\s+for|hunt\w*|indicators?|signatures?|iocs?|alert\w*)\b`)
	markdownHeading = regexp.MustCompile(`(?m)^#{1,6}\s+(.*)$`)
)

// reverseShellDescribed reports a SKILL.md reverse shell in a descriptive
// context: descriptive wording on its line or the three lines before it (the
// lines before a fenced block's opening fence), or under a heading about
// detection.
func reverseShellDescribed(item component, offset int) bool {
	anchor := offset
	for _, block := range fencedCodeBlocks(item.Content) {
		if offset >= block.start && offset < block.end {
			anchor = block.start
			break
		}
	}
	lineEnd := len(item.Content)
	if index := strings.IndexByte(item.Content[offset:], '\n'); index >= 0 {
		lineEnd = offset + index
	}
	before := lineWindow(item.Content[:anchor+1], anchor, 3)
	if descriptiveContext.MatchString(before) || descriptiveContext.MatchString(item.Content[strings.LastIndexByte(item.Content[:offset], '\n')+1:lineEnd]) {
		return true
	}
	headings := markdownHeading.FindAllStringSubmatch(item.Content[:anchor], -1)
	return len(headings) > 0 && descriptiveContext.MatchString(headings[len(headings)-1][1])
}

// analyzeReverseShells reports (RA3, CRITICAL) a reverse shell. It is tagged
// reverse-shell when it would run: in a script line or hook, a SKILL.md
// fenced block, or SKILL.md inline code under an instruction to run it, that
// is not a table row, an example, a description (reverseShellDescribed,
// which also marks it for review) or review text, aimed at a listener that is
// not a placeholder or a private address.
func analyzeReverseShells(item component) []model.Finding {
	language, match := reverseShellAt(item.Content)
	if match == nil {
		return nil
	}
	lineNumber := 1 + strings.Count(item.Content[:match[0]], "\n")
	line := lineSnippet(item.Content, lineNumber)
	explanation, remediation := ruleText("RA3")
	explanation += " Form: " + language + "."
	matched := truncateRunes(strings.TrimSpace(line), 200)
	context := contextAtOffset(item.Content, match[0], 3)
	finding := model.Finding{ID: "RA3", Category: "Rogue Agent", Pattern: "Reverse Shell", Severity: "CRITICAL", Confidence: .9,
		Location: model.Location{File: item.Path, StartLine: lineNumber}, Finding: matched, MatchedText: matched,
		Explanation: explanation, Remediation: remediation, CodeSnippet: context, Tags: []string{"Rogue Agent"}}
	if reason := proseReviewReason(item, "RA3", match[0]); reason != "" {
		finding = markForReview(finding, reason)
	} else if (item.Type == "markdown" || item.Type == "text") && reverseShellDescribed(item, match[0]) {
		finding = markForReview(finding, reviewDescription)
	}
	if reverseShellRuns(item, match[0], context) {
		finding = markBehaviour(finding, behaviourReverseShell)
	}
	return []model.Finding{finding}
}

// reverseShellRuns reports a reverse shell match that would run, as
// analyzeReverseShells describes.
func reverseShellRuns(item component, offset int, context string) bool {
	if scriptCommentLine(item, offset) || labListener(lineWindow(item.Content, offset, 12)) {
		return false
	}
	if runsUnreviewed(item, offset) {
		return true
	}
	if !isSkillManifestPath(item.Path) || exampleTreatmentAt(item, offset, context, isCodeExample) != exampleNone {
		return false
	}
	lineStart := strings.LastIndexByte(item.Content[:offset], '\n') + 1
	lineEnd := len(item.Content)
	if index := strings.IndexByte(item.Content[offset:], '\n'); index >= 0 {
		lineEnd = offset + index
	}
	line := item.Content[lineStart:lineEnd]
	if isTableRow(line) || isCodeExample(line) || reverseShellDescribed(item, offset) {
		return false
	}
	// A fenced block is a command to run; inline code needs an instruction
	// to run it on its line.
	return insideFencedCodeBlock(item, offset) ||
		insideInlineCode(item.Content, offset) && runInstruction.MatchString(item.Content[lineStart:offset])
}
