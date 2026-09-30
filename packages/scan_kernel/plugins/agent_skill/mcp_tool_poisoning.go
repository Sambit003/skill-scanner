package agentskill

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

const tp3MaxParamDescriptionLength = 500

type metadataText struct {
	text       string
	field      string
	identifier bool
}

type textRange struct{ start, end int }

var (
	tp1InstructionKeywords = regexp.MustCompile(`(?i)SYSTEM:|IGNORE\s+PREVIOUS|OVERRIDE|YOU\s+MUST`)
	tp1HTMLComment         = regexp.MustCompile(`(?s)<\\?!--.*?-->`)
	tp1MarkdownComment     = regexp.MustCompile(`\[//\]:\s*#\s*\(.*?\)`)
	tp1ZeroWidth           = regexp.MustCompile("[\u200b\u200c\u200d]+\\S")
	tp1Base64              = regexp.MustCompile(`[A-Za-z0-9+/]{50,}={0,2}`)
	tp1DataURI             = regexp.MustCompile(`data:text/[^;]+;base64,`)

	tp3InstructionOverride = regexp.MustCompile(`(?i)ignore\s+previous|override\s+safety|you\s+are\s+now|disregard\s+(?:all|any)\s+instructions`)
	tp3SystemToken         = regexp.MustCompile(`(?i)SYSTEM:|<system>|\[INST\]|<\|im_start\|>system`)
	tp3Exfiltration        = regexp.MustCompile(`(?i)send\s+to|transmit|upload\s+conversation|exfiltrate`)
	tp3URL                 = regexp.MustCompile(`(?i)https?://\S+`)
	tp3ShellCommand        = regexp.MustCompile(`(?i)\bcurl\b|\bwget\b|bash\s+-c|sh\s+-c|\beval\b`)
)

var tp2Confusables = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'і': 'i',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
	'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
	'α': 'a', 'ε': 'e', 'ο': 'o',
}

var tp2RTL = map[rune]bool{
	'\u202e': true, '\u202d': true, '\u2066': true, '\u2067': true,
	'\u2068': true, '\u2069': true,
}

var tp2Invisible = map[rune]bool{'\u00ad': true, '\u034f': true, '\u2060': true}

func analyzeMCPToolPoisoning(manifest map[string]any) []model.Finding {
	if len(manifest) == 0 {
		return nil
	}
	metadata := extractMetadataTexts(manifest)
	findings := make([]model.Finding, 0)
	for _, value := range metadata {
		findings = append(findings, checkTP1(value.text, value.field)...)
	}
	for _, value := range metadata {
		findings = append(findings, checkTP2(value.text, value.field, value.identifier)...)
	}
	findings = append(findings, checkTP3(manifestParameters(manifest))...)
	return findings
}

func extractMetadataTexts(manifest map[string]any) []metadataText {
	values := make([]metadataText, 0)
	appendString := func(raw any, field string, identifier bool) {
		if value, ok := raw.(string); ok && value != "" {
			values = append(values, metadataText{text: value, field: field, identifier: identifier})
		}
	}
	appendString(manifest["name"], "name", true)
	appendString(manifest["description"], "description", false)
	if triggers, ok := manifest["triggers"].([]any); ok {
		for index, trigger := range triggers {
			appendString(trigger, fmt.Sprintf("triggers[%d]", index), true)
		}
	}
	for index, parameter := range manifestParameters(manifest) {
		appendString(parameter["name"], fmt.Sprintf("parameters[%d].name", index), true)
		appendString(parameter["description"], fmt.Sprintf("parameters[%d].description", index), false)
	}
	return values
}

func manifestParameters(manifest map[string]any) []map[string]any {
	raw, ok := manifest["parameters"].([]any)
	if !ok {
		return nil
	}
	parameters := make([]map[string]any, 0, len(raw))
	for _, value := range raw {
		if parameter, ok := value.(map[string]any); ok {
			parameters = append(parameters, parameter)
		}
	}
	return parameters
}

func checkTP1(value, field string) []model.Finding {
	findings := make([]model.Finding, 0)
	covered := make([]textRange, 0)
	for _, match := range tp1DataURI.FindAllStringIndex(value, -1) {
		covered = append(covered, textRange{start: match[0], end: match[1]})
		findings = append(findings, mcpPoisonFinding("TP1", "HIGH", .85,
			fmt.Sprintf("Data URI found in '%s': potential hidden payload delivery.", field), value[match[0]:match[1]],
			"Data URIs embedded in metadata fields can encode and deliver hidden payloads to AI agents processing the manifest.",
			"Remove data URIs from metadata fields. Metadata should contain plain text only."))
	}
	for _, match := range tp1HTMLComment.FindAllStringIndex(value, -1) {
		matched := value[match[0]:match[1]]
		confidence := .9
		if tp1InstructionKeywords.MatchString(matched) {
			confidence = .95
		}
		findings = append(findings, mcpPoisonFinding("TP1", "HIGH", confidence,
			fmt.Sprintf("HTML comment found in '%s': potential hidden instruction.", field), matched,
			"HTML comments in tool metadata are invisible to users but may be processed by AI agents, enabling hidden instruction injection.",
			"Remove HTML comments from metadata fields. Metadata should contain plain, visible text only."))
	}
	for _, match := range tp1MarkdownComment.FindAllStringIndex(value, -1) {
		findings = append(findings, mcpPoisonFinding("TP1", "HIGH", .9,
			fmt.Sprintf("Markdown comment found in '%s': potential hidden instruction.", field), value[match[0]:match[1]],
			"Markdown-style comments in metadata fields may hide instructions from users while still being processed by AI systems.",
			"Remove markdown comments from metadata fields."))
	}
	for _, match := range tp1ZeroWidth.FindAllStringIndex(value, -1) {
		findings = append(findings, mcpPoisonFinding("TP1", "HIGH", .85,
			fmt.Sprintf("Zero-width character(s) followed by visible text found in '%s': potential steganographic instruction.", field), value[match[0]:match[1]],
			"Zero-width Unicode characters are invisible to humans but detectable by AI. When followed by visible text, they indicate hidden content injection.",
			"Strip zero-width Unicode characters (U+200B, U+200C, U+200D) from all metadata fields."))
	}
	for _, match := range tp1Base64.FindAllStringIndex(value, -1) {
		overlaps := false
		for _, dataURI := range covered {
			if match[0] >= dataURI.start && match[1] <= dataURI.end+200 {
				overlaps = true
				break
			}
		}
		if overlaps {
			continue
		}
		raw := value[match[0]:match[1]]
		padded := raw + strings.Repeat("=", (4-len(raw)%4)%4)
		decoded, err := base64.StdEncoding.DecodeString(padded)
		if err != nil || !utf8.Valid(decoded) {
			continue
		}
		findings = append(findings, mcpPoisonFinding("TP1", "HIGH", .75,
			fmt.Sprintf("Base64-encoded blob found in '%s': potential hidden encoded instruction.", field), truncateWithEllipsis(raw, 80),
			"Long base64-encoded strings in metadata fields may encode hidden instructions intended to be decoded and executed by AI agents.",
			"Remove base64-encoded blobs from metadata fields. Metadata should contain only human-readable plain text."))
	}
	return findings
}

func checkTP2(value, field string, identifier bool) []model.Finding {
	findings := make([]model.Finding, 0)
	homoglyph := false
	if identifier {
		confusables := make([]string, 0)
		for _, char := range value {
			if latin, ok := tp2Confusables[char]; ok {
				confusables = append(confusables, fmt.Sprintf("U+%04X (looks like '%c')", char, latin))
			}
		}
		if len(confusables) > 0 {
			homoglyph = true
			findings = append(findings, mcpPoisonFinding("TP2", "HIGH", .9,
				fmt.Sprintf("Homoglyph characters detected in identifier '%s': %s. Visual spoofing of identifier name.", field, strings.Join(confusables[:min(3, len(confusables))], ", ")), value,
				"Confusable Unicode characters (e.g., Cyrillic or Greek lookalikes of Latin letters) can make a malicious tool name appear identical to a trusted one.",
				"Replace all non-ASCII characters in identifier fields with their ASCII equivalents. Use a Unicode normalization/confusables check in CI."))
		}
	}
	rtl := codepointsMatching(value, tp2RTL)
	if len(rtl) > 0 {
		findings = append(findings, mcpPoisonFinding("TP2", "HIGH", .95,
			fmt.Sprintf("RTL/directional override character(s) found in '%s': %s. Text direction manipulation detected.", field, formatCodepoints(rtl)), truncateRunes(value, 100),
			"RTL override characters (U+202E, U+202D, U+2066-U+2069) can reverse text rendering to make malicious content appear benign.",
			"Remove all directional override Unicode characters from metadata fields."))
	}
	if identifier {
		invisible := codepointsMatching(value, tp2Invisible)
		if len(invisible) > 0 {
			findings = append(findings, mcpPoisonFinding("TP2", "HIGH", .8,
				fmt.Sprintf("Invisible formatting character(s) found in identifier '%s': %s.", field, formatCodepoints(invisible)), value,
				"Invisible Unicode formatting characters (soft hyphen U+00AD, CGJ U+034F, word joiner U+2060) inserted into identifiers create visually identical but technically different names.",
				"Strip invisible formatting characters (U+00AD, U+034F, U+2060) from all identifier fields."))
		}
	}
	if identifier && !homoglyph {
		scripts := map[string]bool{}
		for _, char := range value {
			if char < 128 {
				if unicode.IsLetter(char) {
					scripts["LATIN"] = true
				}
				continue
			}
			if unicode.IsLetter(char) {
				if script := unicodeScript(char); script != "" {
					scripts[script] = true
				}
			}
		}
		if len(scripts) > 1 {
			names := make([]string, 0, len(scripts))
			for script := range scripts {
				names = append(names, script)
			}
			sort.Strings(names)
			findings = append(findings, mcpPoisonFinding("TP2", "HIGH", .85,
				fmt.Sprintf("Mixed script detected in identifier '%s': %s. Multiple Unicode scripts in a single identifier name.", field, strings.Join(names, ", ")), value,
				"Mixing characters from multiple Unicode scripts in a single identifier is a common technique to create visually ambiguous tool names.",
				"Restrict identifier fields to a single Unicode script. Prefer ASCII-only identifiers."))
		}
	}
	return findings
}

func checkTP3(parameters []map[string]any) []model.Finding {
	findings := make([]model.Finding, 0)
	for index, parameter := range parameters {
		name := fmt.Sprintf("param[%d]", index)
		if value, ok := parameter["name"].(string); ok {
			name = value
		}
		if description, ok := parameter["description"].(string); ok && description != "" {
			for _, check := range []struct {
				re          *regexp.Regexp
				confidence  float64
				message     string
				explanation string
				remediation string
			}{
				{tp3InstructionOverride, .85, "Instruction override phrase", "Instruction-override phrases in parameter descriptions can hijack AI agent behavior when the tool description is processed as a prompt.", "Remove instruction-override language from parameter descriptions. Descriptions should explain the parameter's purpose only."},
				{tp3SystemToken, .9, "System prompt token", "System prompt tokens injected into parameter descriptions may alter the AI agent's system context when the tool schema is processed.", "Remove system prompt tokens (SYSTEM:, <system>, [INST], etc.) from parameter descriptions."},
				{tp3Exfiltration, .85, "Potential exfiltration instruction", "Exfiltration-related phrases in parameter descriptions may instruct AI agents to leak conversation data or sensitive information.", "Remove data transmission instructions from parameter descriptions."},
			} {
				if match := check.re.FindString(description); match != "" {
					findings = append(findings, mcpPoisonFinding("TP3", "MEDIUM", check.confidence,
						fmt.Sprintf("%s in parameter '%s' description: '%s'.", check.message, name, match), match, check.explanation, check.remediation))
				}
			}
			if utf8.RuneCountInString(description) > tp3MaxParamDescriptionLength {
				findings = append(findings, mcpPoisonFinding("TP3", "MEDIUM", .65,
					fmt.Sprintf("Excessive parameter description length for '%s': %d chars (limit: %d).", name, utf8.RuneCountInString(description), tp3MaxParamDescriptionLength), "",
					"Unusually long parameter descriptions may contain hidden instructions padded with benign content to evade simple keyword detection.",
					fmt.Sprintf("Keep parameter descriptions under %d characters. Move extended documentation to separate files.", tp3MaxParamDescriptionLength)))
			}
		}
		if raw, exists := parameter["default"]; exists && raw != nil {
			value := fmt.Sprint(raw)
			matched := firstSuspiciousDefault(value)
			if matched != "" {
				findings = append(findings, mcpPoisonFinding("TP3", "MEDIUM", .75,
					fmt.Sprintf("Suspicious default value for parameter '%s': contains '%s'.", name, matched), matched,
					"Default parameter values containing URLs or shell commands may trigger unintended network requests or command execution when used by an AI agent without explicit user input.",
					"Remove URLs and shell commands from parameter default values. Default values should be safe, static, representative examples."))
			}
		}
	}
	return findings
}

func firstSuspiciousDefault(value string) string {
	if match := tp3URL.FindString(value); match != "" {
		host := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(match, "http://"), "https://"))
		if !(host == "localhost" || strings.HasPrefix(host, "localhost:") || strings.HasPrefix(host, "localhost/") || strings.HasPrefix(host, "localhost?") || strings.HasPrefix(host, "localhost#") ||
			host == "127.0.0.1" || strings.HasPrefix(host, "127.0.0.1:") || strings.HasPrefix(host, "127.0.0.1/") || strings.HasPrefix(host, "127.0.0.1?") || strings.HasPrefix(host, "127.0.0.1#")) {
			return match
		}
	}
	return tp3ShellCommand.FindString(value)
}

func mcpPoisonFinding(id, severity string, confidence float64, message, matched, explanation, remediation string) model.Finding {
	return model.Finding{ID: id, Category: "MCP Tool Poisoning", Severity: severity, Confidence: confidence,
		Location: model.Location{File: "SKILL.md", StartLine: 1}, MatchedText: matched, Explanation: explanation,
		Remediation: remediation, Tags: []string{"ASI02", "AML.T0080"}}
}

func codepointsMatching(value string, candidates map[rune]bool) []rune {
	result := make([]rune, 0)
	for _, char := range value {
		if candidates[char] {
			result = append(result, char)
		}
	}
	return result
}

func formatCodepoints(values []rune) string {
	parts := make([]string, 0, min(3, len(values)))
	for _, value := range values[:min(3, len(values))] {
		parts = append(parts, fmt.Sprintf("U+%04X", value))
	}
	return strings.Join(parts, ", ")
}

func unicodeScript(char rune) string {
	for _, candidate := range []struct {
		name  string
		table *unicode.RangeTable
	}{
		{"LATIN", unicode.Latin}, {"CYRILLIC", unicode.Cyrillic}, {"GREEK", unicode.Greek},
		{"ARABIC", unicode.Arabic}, {"HEBREW", unicode.Hebrew}, {"CJK", unicode.Han},
		{"HIRAGANA", unicode.Hiragana}, {"KATAKANA", unicode.Katakana}, {"HANGUL", unicode.Hangul},
		{"THAI", unicode.Thai}, {"DEVANAGARI", unicode.Devanagari},
	} {
		if unicode.Is(candidate.table, char) {
			return candidate.name
		}
	}
	return ""
}

func truncateRunes(value string, limit int) string {
	chars := []rune(value)
	if len(chars) <= limit {
		return value
	}
	return string(chars[:limit])
}

func truncateWithEllipsis(value string, limit int) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	return truncateRunes(value, limit) + "..."
}
