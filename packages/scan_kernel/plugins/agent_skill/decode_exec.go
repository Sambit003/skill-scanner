package agentskill

// Decode to exec: a base64 literal decoded and piped straight into a shell
// hides the command it runs. The literal is decoded as text, in memory, and
// never run; the decoded text is checked with the download-and-run logic.

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var (
	// base64ToShell matches base64 -d|-D|--decode piped into a shell, or
	// decoded inside sh -c "$(...)".
	base64ToShell = regexp.MustCompile(`(?i)\bbase64\s+(?:-d|-D|--decode)\b[^\n|]*\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:ba|z)?sh\b` +
		`|\b(?:ba|z)?sh\s+-c\s+["']?\$\([^)\n]*\bbase64\s+(?:-d|-D|--decode)\b`)
	base64Literal = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
)

const decodeDepth = 3

// decodeBase64Text decodes a base64 literal that holds printable text.
func decodeBase64Text(literal string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(literal)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(literal, "=")); err != nil {
			return "", false
		}
	}
	text := string(raw)
	if !utf8.ValidString(text) {
		return "", false
	}
	for _, char := range text {
		if !unicode.IsPrint(char) && !unicode.IsSpace(char) {
			return "", false
		}
	}
	return text, true
}

// decodedDownloadAndRun decodes the base64 literals of a decode-to-shell line
// and returns the decoded text that downloads and runs remote code, following
// nested decode-to-shell layers up to decodeDepth.
func decodedDownloadAndRun(line string, depth int) (string, bool) {
	if depth == 0 {
		return "", false
	}
	for _, literal := range base64Literal.FindAllString(line, -1) {
		decoded, ok := decodeBase64Text(literal)
		if !ok {
			continue
		}
		if commands, _ := downloadAndRunOrigins(decoded); len(commands) > 0 {
			return decoded, true
		}
		if base64ToShell.MatchString(decoded) {
			if nested, ok := decodedDownloadAndRun(decoded, depth-1); ok {
				return nested, true
			}
		}
	}
	return "", false
}

// analyzeDecodeToExec reports (SC3, CRITICAL) a base64 literal piped to a
// shell whose decoded text downloads and runs remote code, in any file and
// in any Markdown position: fenced, inline code or plain prose. Matches that
// need review, or sit in a documentation example, are left untagged.
func analyzeDecodeToExec(item component) []model.Finding {
	if !strings.Contains(strings.ToLower(item.Content), "base64") {
		return nil
	}
	var findings []model.Finding
	for _, match := range base64ToShell.FindAllStringIndex(item.Content, -1) {
		lineStart := strings.LastIndexByte(item.Content[:match[0]], '\n') + 1
		lineEnd := len(item.Content)
		if index := strings.IndexByte(item.Content[match[1]:], '\n'); index >= 0 {
			lineEnd = match[1] + index
		}
		line := item.Content[lineStart:lineEnd]
		decoded, ok := decodedDownloadAndRun(line, decodeDepth)
		if !ok || scriptCommentLine(item, match[0]) {
			continue
		}
		explanation, remediation := ruleText("SC3")
		explanation += " The base64 text decodes to a command that downloads and runs remote code: " +
			truncateRunes(strings.Join(strings.Fields(decoded), " "), 200)
		matched := truncateRunes(strings.TrimSpace(line), 200)
		lineNumber := 1 + strings.Count(item.Content[:match[0]], "\n")
		finding := model.Finding{ID: "SC3", Category: "Supply Chain", Pattern: "Encoded Download and Execute", Severity: "CRITICAL",
			Confidence: .95, Location: model.Location{File: item.Path, StartLine: lineNumber}, Finding: matched, MatchedText: matched,
			Explanation: explanation, Remediation: remediation, CodeSnippet: contextAtOffset(item.Content, match[0], 3),
			Tags: []string{"Supply Chain"}}
		if reason := proseReviewReason(item, "SC3", match[0]); reason != "" {
			finding = markForReview(finding, reason)
		}
		if exampleTreatmentAt(item, match[0], finding.CodeSnippet, isCodeExample) == exampleNone {
			finding = markBehaviour(finding, behaviourDecodeToExec)
		}
		findings = append(findings, finding)
	}
	return findings
}
