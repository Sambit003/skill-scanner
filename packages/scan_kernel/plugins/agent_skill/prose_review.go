package agentskill

// Prose review: some matches in Markdown or text prose describe the behavior
// rather than ask for it. A rule match that is negated ("never run sudo"),
// quoted ("ignore previous instructions" as an example), in a table row, or
// in a test fixture stays in the report with its severity, but carries a
// "Needs review: <reason>" tag, half its confidence, and no weight in the risk
// score or verdict.

import (
	"path"
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

const (
	reviewTagPrefix    = "Needs review: "
	reviewConfidence   = .5
	reviewNegated      = "negated"
	reviewQuoted       = "quoted"
	reviewTable        = "table"
	reviewTestFixture  = "test fixture"
	negationWindowSize = 100
)

// reviewExemptRules are never downgraded: instruction override (P1),
// exfiltration instructions and flows (P3, P8, E1, E4), harmful content (P5)
// and the data-flow rules (TT1-TT5).
var reviewExemptRules = map[string]bool{"P1": true, "P3": true, "P5": true, "P8": true, "E1": true, "E4": true,
	"TT1": true, "TT2": true, "TT3": true, "TT4": true, "TT5": true}

var (
	reviewNegation = regexp.MustCompile(`(?i)\b(?:never|don'?t|do\s+not|avoid|must\s+not|mustn'?t|should\s+not|shouldn'?t)\b`)
	// "Never forget to X" and "don't fail to X" ask for X.
	reviewDoubleNegation = regexp.MustCompile(`(?i)^\s+(?:forget|fail|neglect|hesitate|miss|skip|stop|cease|omit)\b`)
	reviewSentenceEnd    = regexp.MustCompile(`[.!?]\s`)
)

// needsReview returns the review reason a finding carries, if any.
func needsReview(finding model.Finding) (string, bool) {
	for _, tag := range finding.Tags {
		if reason, ok := strings.CutPrefix(tag, reviewTagPrefix); ok {
			return reason, true
		}
	}
	return "", false
}

// isTestFixturePath reports a file under tests/, fixtures/ or testdata/, or
// named *_test.*.
func isTestFixturePath(filePath string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filePath, "\\", "/"))
	parts := strings.Split(normalized, "/")
	for _, part := range parts[:len(parts)-1] {
		if part == "tests" || part == "fixtures" || part == "testdata" {
			return true
		}
	}
	return strings.Contains(path.Base(normalized), "_test.")
}

// proseReviewReason returns why a match at offset needs review, or "". It
// applies only to Markdown and text prose: never to front matter, fenced
// code, inline code spans (in a skill they usually mark a command to run) or
// script files, and never to reviewExemptRules.
func proseReviewReason(item component, ruleID string, offset int) string {
	if reviewExemptRules[ruleID] || (item.Type != "markdown" && item.Type != "text") {
		return ""
	}
	if block, ok := frontmatterYAML(item.Content); ok && offset < 3+len(block)+len("\n---") {
		return ""
	}
	if insideFencedCodeBlock(item, offset) {
		return ""
	}
	lineStart := strings.LastIndexByte(item.Content[:offset], '\n') + 1
	lineEnd := len(item.Content)
	if index := strings.IndexByte(item.Content[offset:], '\n'); index >= 0 {
		lineEnd = offset + index
	}
	before, after := item.Content[lineStart:offset], item.Content[offset:lineEnd]
	if strings.Count(before, "`")%2 == 1 {
		return ""
	}
	switch {
	case isTestFixturePath(item.Path):
		return reviewTestFixture
	case isTableRow(item.Content[lineStart:lineEnd]):
		return reviewTable
	case insideDoubleQuotes(before, after):
		return reviewQuoted
	case negatedBefore(before):
		return reviewNegated
	}
	return ""
}

func isTableRow(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "|") && strings.Count(trimmed, "|") >= 2
}

// insideDoubleQuotes reports a match inside a quotation on its line: straight
// double quotes with an odd count before it and one after, or a typographic
// opening quote not yet closed. A quoted path, URL or command is not a
// quotation: paths with spaces must be quoted to be used at all.
func insideDoubleQuotes(before, after string) bool {
	if strings.Count(before, `"`)%2 == 1 {
		if end := strings.IndexByte(after, '"'); end >= 0 {
			return !looksLikePathOrCommand(before[strings.LastIndexByte(before, '"')+1:] + after[:end])
		}
	}
	if strings.Count(before, "\u201c") > strings.Count(before, "\u201d") {
		if end := strings.Index(after, "\u201d"); end >= 0 {
			return !looksLikePathOrCommand(before[strings.LastIndex(before, "\u201c")+len("\u201c"):] + after[:end])
		}
	}
	return false
}

var (
	quotedFileExtension = regexp.MustCompile(`\.[A-Za-z0-9]{1,8}$`)
	quotedCommandWord   = regexp.MustCompile(`(?i)^(?:sudo|curl|wget|rm|cat|cp|mv|chmod|chown|ssh|scp|rsync|docker|kubectl|npx|npm|pip|pip3|uvx|python[0-9.]*|node|bash|sh|zsh|git|gh|aws|gcloud|az|open|source|eval|exec|powershell|pwsh|iwr|iex|nc|base64|tar|find|grep|echo|printf|export|env|set)\b`)
)

// looksLikePathOrCommand reports quoted text that is a path, URL or command
// rather than a quotation: it contains / \ ~ or $, ends in a file extension,
// or starts with a command word.
func looksLikePathOrCommand(quoted string) bool {
	trimmed := strings.TrimSpace(quoted)
	return strings.ContainsAny(trimmed, "/\\~$") || quotedFileExtension.MatchString(trimmed) || quotedCommandWord.MatchString(trimmed)
}

// negatedBefore reports a negation shortly before the match in the same
// sentence and clause: no sentence end, comma or semicolon in between, and
// not a double negation such as "never forget to".
func negatedBefore(before string) bool {
	if ends := reviewSentenceEnd.FindAllStringIndex(before, -1); len(ends) > 0 {
		before = before[ends[len(ends)-1][1]:]
	}
	if len(before) > negationWindowSize {
		before = before[len(before)-negationWindowSize:]
	}
	negations := reviewNegation.FindAllStringIndex(before, -1)
	if len(negations) == 0 {
		return false
	}
	rest := before[negations[len(negations)-1][1]:]
	return !strings.ContainsAny(rest, ",;") && !reviewDoubleNegation.MatchString(rest)
}

// markForReview downgrades a finding: half the confidence and a review tag.
func markForReview(finding model.Finding, reason string) model.Finding {
	finding.Confidence *= reviewConfidence
	finding.Tags = append(finding.Tags, reviewTagPrefix+reason)
	return finding
}
