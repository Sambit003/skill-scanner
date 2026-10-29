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

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

var (
	// base64ToShell matches base64 -d|-D|--decode piped into a shell, or
	// decoded inside sh -c "$(...)" or eval $(...).
	base64ToShell = regexp.MustCompile(`(?i)\bbase64\s+(?:-d|-D|--decode)\b[^\n|]*\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:ba|z)?sh\b` +
		`|\b(?:(?:ba|z)?sh\s+-c|eval)\s+["']?\$\([^)\n]*\bbase64\s+(?:-d|-D|--decode)\b`)
	base64Literal = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
	// decodeExecCall matches the SC3 code patterns that decode and run in one
	// call: exec or eval of b64decode, codecs.decode(..., 'hex'),
	// marshal.loads, compile(... base64), bytes.fromhex, bytearray.fromhex
	// or zlib/gzip.decompress; eval(atob(...)); new Function(atob(...)); and
	// (lambda _: exec(...)). A bare marshal.loads, an _0x name, a long hex or
	// base64 string, __import__('os').system and a prose "decode this and
	// run" are obfuscation, not a decoded payload run, and stay untagged.
	decodeExecCall = regexp.MustCompile(`(?i)^(?:(?:exec|eval)\s*\(|new\s+Function\s*\(|\(lambda\s+_:\s*exec\s*\()`)
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

// decodedPayload decodes the base64 literals of a decode-to-shell line and
// returns the decoded text that downloads and runs remote code
// (behaviourDownloadAndRun), opens a reverse shell (behaviourReverseShell) or
// sends a credential file away (behaviourCredentialExfiltration), following
// nested decode-to-shell layers up to decodeDepth.
func decodedPayload(line string, depth int) (string, string, bool) {
	if depth == 0 {
		return "", "", false
	}
	for _, literal := range base64Literal.FindAllString(line, -1) {
		decoded, ok := decodeBase64Text(literal)
		if !ok {
			continue
		}
		if commands, _ := downloadAndRunOrigins(decoded); len(commands) > 0 {
			return decoded, behaviourDownloadAndRun, true
		}
		if _, match := reverseShellAt(decoded); match != nil {
			return decoded, behaviourReverseShell, true
		}
		if shellSendsCredentialFile(decoded) {
			return decoded, behaviourCredentialExfiltration, true
		}
		if base64ToShell.MatchString(decoded) {
			if nested, kind, ok := decodedPayload(decoded, depth-1); ok {
				return nested, kind, true
			}
		}
	}
	return "", "", false
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
		decoded, payload, ok := decodedPayload(line, decodeDepth)
		if !ok || scriptCommentLine(item, match[0]) {
			continue
		}
		lineNumber := 1 + strings.Count(item.Content[:match[0]], "\n")
		finding := decodedPayloadFinding(item, match[0], lineNumber, line, decoded, payload, "base64 text")
		if reason := proseReviewReason(item, finding.ID, match[0]); reason != "" {
			finding = markForReview(finding, reason)
		}
		if exampleTreatmentAt(item, match[0], finding.CodeSnippet, isCodeExample) == exampleNone {
			kind := behaviourDecodeToExec
			if payload != behaviourDownloadAndRun {
				kind = payload
			}
			finding = markBehaviour(finding, kind)
		}
		findings = append(findings, finding)
	}
	return findings
}

// decodedPayloadFinding reports encoded text that decodes to a payload: SC3
// for download-and-run or sending a credential file, RA3 for a reverse
// shell, all CRITICAL.
func decodedPayloadFinding(item component, offset, lineNumber int, line, decoded, payload, encoding string) model.Finding {
	id, category, pattern, what := "SC3", "Supply Chain", "Encoded Download and Execute", "a command that downloads and runs remote code"
	switch payload {
	case behaviourReverseShell:
		id, category, pattern, what = "RA3", "Rogue Agent", "Encoded Reverse Shell", "a reverse shell"
	case behaviourCredentialExfiltration:
		pattern, what = "Encoded Credential Exfiltration", "a command that sends a credential file to a remote host"
	}
	explanation, remediation := ruleText(id)
	explanation += " The " + encoding + " decodes to " + what + ": " + truncateRunes(strings.Join(strings.Fields(decoded), " "), 200)
	matched := truncateRunes(strings.TrimSpace(line), 200)
	return model.Finding{ID: id, Category: category, Pattern: pattern, Severity: "CRITICAL",
		Confidence: .95, Location: model.Location{File: item.Path, StartLine: lineNumber}, Finding: matched, MatchedText: matched,
		Explanation: explanation, Remediation: remediation, CodeSnippet: contextAtOffset(item.Content, offset, 3),
		Tags: []string{category}}
}
