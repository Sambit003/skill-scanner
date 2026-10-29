package agentskill

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

var (
	rp1NPX            = regexp.MustCompile(`(?i)\b(?:npx|bunx|pnpx)[ \t]+(?:-+\w+[ \t]+)*((?:@?[a-zA-Z][\w.-]*/)?[a-zA-Z][\w.-]*)`)
	rp1UVX            = regexp.MustCompile(`(?i)(?:uvx|uv[\t\n\v\f\r \x{001c}-\x{001f}\x{0085}\x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]+tool[\t\n\v\f\r \x{001c}-\x{001f}\x{0085}\x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]+run)[\t\n\v\f\r \x{001c}-\x{001f}\x{0085}\x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]+(?:-+\w+[\t\n\v\f\r \x{001c}-\x{001f}\x{0085}\x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]+)*([a-zA-Z][\w.-]*)`)
	rp1PIP            = regexp.MustCompile(`(?i)pip\d?\s+install\s+(?:-+\w+\s+)*([a-zA-Z][\w.-]*)`)
	rp1Docker         = regexp.MustCompile(`(?i)docker[ \t]+(?:pull|run|create)[ \t]+([^\n]*)`)
	versionPin        = regexp.MustCompile(`@[\d.]+\b|==[\d.]+|:[\d.]+|@sha256:`)
	ra2Hidden         = regexp.MustCompile(`(?i)(?:create|write|mkdir)\s+[^|\n]*(?:~/|/home/|/tmp/)\.([a-z_-]+)`)
	as3Skill          = regexp.MustCompile(`(?i)skills?/([a-z][a-z0-9_-]+)/SKILL\.md`)
	pe2Sudo           = regexp.MustCompile(`(?im)sudo\s+`)
	sc7Trust          = regexp.MustCompile(`(?im)--disable-content-trust\b`)
	passwdMountPrefix = regexp.MustCompile(`(?i)(?:-v|--volume)(?:=|\s+)['"]?$`)
)

func isReadOnlyPasswdVolumeMatch(content string, match []int) bool {
	if len(match) < 2 || !strings.EqualFold(content[match[0]:match[1]], "/etc/passwd") {
		return false
	}
	lower := strings.ToLower(content)
	const volume = "/etc/passwd:/etc/passwd:ro"
	for search := 0; search < len(lower); {
		relative := strings.Index(lower[search:], volume)
		if relative < 0 {
			break
		}
		start := search + relative
		end := start + len(volume)
		sourceStart, sourceEnd := start, start+len("/etc/passwd")
		targetStart, targetEnd := sourceEnd+1, sourceEnd+1+len("/etc/passwd")
		if (sourceStart <= match[0] && match[1] <= sourceEnd) || (targetStart <= match[0] && match[1] <= targetEnd) {
			prefixStart := max(0, start-1000)
			prefix := content[prefixStart:start]
			commandAt := max(strings.LastIndex(strings.ToLower(prefix), "docker run"), strings.LastIndex(strings.ToLower(prefix), "podman run"))
			if commandAt >= 0 {
				between := prefix[commandAt:]
				if validDockerContinuation(between) && passwdMountPrefix.MatchString(between) && validPasswdMountSuffix(content, start, end) {
					return true
				}
			}
		}
		search = start + 1
	}
	return false
}

// isMarkdownBoldWildcard reports an EA1 wildcard match whose "*" is the first
// half of the closing "**" of a bold label such as "**Tools:**".
func isMarkdownBoldWildcard(content string, match []int) bool {
	star := strings.LastIndexByte(content[match[0]:match[1]], '*')
	next := match[0] + star + 1
	return star >= 0 && next < len(content) && content[next] == '*'
}

func validDockerContinuation(value string) bool {
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case ';', '&', '|':
			return false
		case '\n':
			if index == 0 || value[index-1] != '\\' {
				return false
			}
		}
	}
	return true
}

func validPasswdMountSuffix(content string, start, end int) bool {
	quote := byte(0)
	if start > 0 && (content[start-1] == '\'' || content[start-1] == '"') {
		quote = content[start-1]
	}
	if quote != 0 {
		if end >= len(content) || content[end] != quote {
			return false
		}
		end++
	}
	return end == len(content) || content[end] == '\\' || content[end] == ' ' || content[end] == '\t' || content[end] == '\r' || content[end] == '\n'
}

func analyzeUnsupportedRegexSemantics(item component) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, match := range as3Skill.FindAllStringSubmatchIndex(item.Content, -1) {
		if len(match) < 4 || strings.EqualFold(item.Content[match[2]:match[3]], "CURRENT") || isDocumentationSkillLink(item, match) {
			continue
		}
		pattern := staticPattern{ID: "AS3", Title: "Skill Enumeration", Category: "Agent Snooping", Severity: "MEDIUM", Confidence: .8}
		if finding, ok := findingFromStaticMatch(item, pattern, []int{match[0], match[1]}); ok {
			findings = append(findings, finding)
		}
	}
	for _, match := range pe2Sudo.FindAllStringIndex(item.Content, -1) {
		tail := strings.ToLower(item.Content[match[1]:])
		if strings.HasPrefix(tail, "-v") || strings.HasPrefix(tail, "-l") || strings.HasPrefix(tail, "--version") || strings.HasPrefix(tail, "--list") {
			continue
		}
		pattern := staticPattern{ID: "PE2", Title: "Sudo/Root Execution", Category: "Privilege Escalation", Severity: "MEDIUM", Confidence: .7}
		if finding, ok := findingFromStaticMatch(item, pattern, match); ok {
			findings = append(findings, finding)
		}
	}
	for _, match := range sc7Trust.FindAllStringIndex(item.Content, -1) {
		if strings.HasPrefix(strings.ToLower(item.Content[match[1]:]), "=false") {
			continue
		}
		pattern := staticPattern{ID: "SC7", Title: "Untrusted Container Image", Category: "Supply Chain", Severity: "HIGH", Confidence: .85}
		if finding, ok := findingFromStaticMatch(item, pattern, match); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

// isDocumentationSkillLink reports a relative skills/<name>/SKILL.md path
// written as a Markdown link, or as inline code holding only the path, outside
// program source. Such a path cross-references a sibling skill in the same
// repository. Absolute paths, paths under an agent's skill directory
// (~/.claude/skills/...), commands in a code span (`cat .../SKILL.md`) and
// preprocessing commands (!`...`) are still reported.
func isDocumentationSkillLink(item component, match []int) bool {
	if isSourceCodeType(item.Type) {
		return false
	}
	lineStart := strings.LastIndexByte(item.Content[:match[0]], '\n') + 1
	lineEnd := len(item.Content)
	if index := strings.IndexByte(item.Content[match[1]:], '\n'); index >= 0 {
		lineEnd = match[1] + index
	}
	before, after := item.Content[lineStart:match[0]], item.Content[match[1]:lineEnd]
	prefix := before[strings.LastIndexAny(before, " \t`([")+1:]
	if strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "~$") || containsAny(strings.ToLower(prefix), ".claude/", ".codex/", ".gemini/", ".agents/") {
		return false
	}
	// "!`...`" is a preprocessing command that runs on invocation, not a
	// reference to the path.
	inCode := strings.HasSuffix(before, "`"+prefix) && !strings.HasSuffix(before, "!`"+prefix) && strings.HasPrefix(after, "`")
	inLinkTarget := strings.LastIndex(before, "](") > strings.LastIndex(before, ")")
	inLinkText := strings.LastIndex(before, "[") > strings.LastIndex(before, "]") && strings.Contains(after, "](")
	return inCode || inLinkTarget || inLinkText
}

func analyzeRA2HiddenPersistence(item component) []model.Finding {
	var findings []model.Finding
	for _, match := range ra2Hidden.FindAllStringSubmatchIndex(item.Content, -1) {
		if len(match) < 4 {
			continue
		}
		name := strings.ToLower(item.Content[match[2]:match[3]])
		if name == "git" || name == "ssh" || name == "aws" {
			continue
		}
		pattern := newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .6, `a^`)
		if finding, ok := findingFromStaticMatch(item, pattern, []int{match[0], match[1]}); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func analyzeMCPRugPull(items []component, manifest map[string]any) []model.Finding {
	var findings []model.Finding
	for _, item := range items {
		findings = append(findings, rp1CommandFindings(item)...)
	}
	manifestText := pythonManifestRepr(manifest)
	for _, match := range rp1NPX.FindAllStringSubmatchIndex(manifestText, -1) {
		if !isMCPServerPackage(manifestText[match[2]:match[3]]) && !rp1MCPAdd.MatchString(manifestText[max(0, match[0]-100):match[0]]) {
			continue
		}
		matched := manifestText[match[0]:match[1]]
		explanation, remediation := rp1Text("npx")
		findings = append(findings, model.Finding{ID: "RP1", Category: "MCP Rug Pull", Severity: rp1Severity, Confidence: .7,
			Location: model.Location{File: "SKILL.md", StartLine: 1}, MatchedText: truncate(matched, 200),
			Explanation: explanation, Remediation: remediation, Tags: []string{"ASI16"}})
	}
	findings = append(findings, analyzeRP2ManifestPreStaging(manifestText)...)
	if version, ok := manifest["version"].(string); ok {
		version = strings.TrimSpace(version)
		if version == "*" || version == "latest" || version == "any" {
			findings = append(findings, model.Finding{ID: "RP3", Category: "MCP Rug Pull",
				Severity: "LOW", Confidence: .8, Location: model.Location{File: "SKILL.md", StartLine: 1}, MatchedText: version,
				Explanation: "An unpinned version allows automatic updates to any future version, creating a rug-pull risk.",
				Remediation: "Pin to a specific version (e.g. '1.2.3').", Tags: []string{"ASI16"}})
		} else if strings.HasPrefix(version, ">=") || strings.HasPrefix(version, "^") {
			confidence := .5
			if strings.HasPrefix(version, ">=") {
				confidence = .4
			}
			findings = append(findings, model.Finding{ID: "RP3", Category: "MCP Rug Pull",
				Severity: "LOW", Confidence: confidence, Location: model.Location{File: "SKILL.md", StartLine: 1}, MatchedText: version,
				Explanation: "Broad version constraints allow automatic major-version updates.", Remediation: "Pin to a specific version or narrow the range.",
				Tags: []string{"ASI16"}})
		}
	}
	return findings
}

func analyzeRP2ManifestPreStaging(manifestText string) []model.Finding {
	patterns := []struct {
		re         *regexp.Regexp
		confidence float64
	}{
		// manifestText is a Python-style repr, so keys are single-quoted; a
		// JSON permissions block inside a string value keeps double quotes.
		// A declared permissions list may be empty, so require entries.
		{regexp.MustCompile(`(?i)['"]permissions?['"]\s*:\s*\[[^\]]+\]`), .6},
		{regexp.MustCompile(`(?i)(?:add|grant|request|require)\s+(?:new|additional|extra|more)\s+(?:permissions?|tools?|access)`), .7},
	}
	findings := make([]model.Finding, 0)
	for _, pattern := range patterns {
		for _, match := range pattern.re.FindAllStringIndex(manifestText, -1) {
			matched := manifestText[match[0]:match[1]]
			findings = append(findings, model.Finding{ID: "RP2", Category: "MCP Rug Pull", Severity: "LOW", Confidence: pattern.confidence,
				Location: model.Location{File: "SKILL.md", StartLine: 1}, MatchedText: truncate(matched, 200),
				Explanation: "Language in the manifest suggests the skill may request additional permissions or tools in future versions. This is a pre-staging indicator for rug-pull attacks.",
				Remediation: "Review the skill's stated permissions. Consider pinning to a specific version and auditing updates.", Tags: []string{"ASI16"}})
		}
	}
	return findings
}

func pythonManifestRepr(value any) string {
	switch typed := value.(type) {
	case nil:
		return "None"
	case string:
		return "'" + strings.ReplaceAll(strings.ReplaceAll(typed, "\\", "\\\\"), "'", "\\'") + "'"
	case bool:
		if typed {
			return "True"
		}
		return "False"
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, pythonManifestRepr(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, pythonManifestRepr(key)+": "+pythonManifestRepr(typed[key]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprint(typed)
	}
}

// Python used (.{2,20}?)\1{20,}. Go's RE2 deliberately has no backreferences,
// so reproduce that one expression with a bounded deterministic search.
func repeatedContextMatches(item component) []model.Finding {
	var findings []model.Finding
	lineOffset := 0
	for _, line := range strings.SplitAfter(item.Content, "\n") {
		body := strings.TrimSuffix(line, "\n")
		runes := []rune(body)
		byteOffsets := make([]int, len(runes)+1)
		byteOffset := 0
		for index, value := range runes {
			byteOffsets[index] = byteOffset
			byteOffset += len(string(value))
		}
		byteOffsets[len(runes)] = len(body)
		for start := 0; start < len(runes); start++ {
			matched := false
			for width := 2; width <= 20 && start+width*21 <= len(runes); width++ {
				unitRunes := runes[start : start+width]
				unit := string(unitRunes)
				count := 1
				for start+(count+1)*width <= len(runes) && strings.EqualFold(string(runes[start+count*width:start+(count+1)*width]), unit) {
					count++
				}
				if count < 21 {
					continue
				}
				end := start + count*width
				if !trivialRepeatedUnit(unit) {
					pattern := newStaticPattern("MP2", "Context Window Stuffing", "Memory Poisoning", "MEDIUM", .8, `a^`)
					finding, ok := findingFromStaticMatch(item, pattern, []int{lineOffset + byteOffsets[start], lineOffset + byteOffsets[end]})
					if ok {
						findings = append(findings, finding)
					}
				}
				start = end - 1
				matched = true
				break
			}
			if matched {
				continue
			}
		}
		lineOffset += len(line)
	}
	return findings
}

// trivialRepeatedUnit reports repeated units that cannot carry text: a single
// repeated character, or a unit with no letters or digits at all, such as
// Markdown table padding, box-drawing borders and separator rows.
func trivialRepeatedUnit(unit string) bool {
	chars := map[rune]bool{}
	hasWhitespace, hasText := false, false
	for _, char := range unit {
		if char == ' ' || char == '\t' {
			hasWhitespace = true
		}
		if char != ' ' && char != '\t' && char != '\n' && char != '\r' {
			chars[char] = true
		}
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			hasText = true
		}
	}
	return !hasText || (len(chars) <= 1 && !hasWhitespace)
}

func truncate(value string, limit int) string {
	return truncateRunes(value, limit)
}
