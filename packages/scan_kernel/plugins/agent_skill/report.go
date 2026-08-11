package agentskill

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo"
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var severityPoints = map[string]float64{"CRITICAL": 50, "HIGH": 25, "MEDIUM": 10, "LOW": 5}
var diminishingWeights = []float64{1, .5, .25}

func summarize(findings []model.Finding, items []component) model.Summary {
	executable := map[string]bool{}
	for _, item := range items {
		executable[item.Path] = item.Executable
	}
	ordered := deduplicateForScoring(findings)
	rank := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ruleID(ordered[i]) != ruleID(ordered[j]) {
			return ruleID(ordered[i]) < ruleID(ordered[j])
		}
		return rank[strings.ToUpper(ordered[i].Severity)] < rank[strings.ToUpper(ordered[j].Severity)]
	})
	occurrences := map[string]int{}
	score := 0.0
	for _, finding := range ordered {
		confidence := max(0, min(1, finding.Confidence))
		id := ruleID(finding)
		index := occurrences[id]
		occurrences[id]++
		if confidence <= 0 || index >= len(diminishingWeights) {
			continue
		}
		points := severityPoints[strings.ToUpper(finding.Severity)]
		if points == 0 {
			points = 5
		}
		contribution := points * diminishingWeights[index] * confidence
		if executable[finding.Location.File] {
			contribution *= 1.3
		}
		score += contribution
	}
	risk := min(100, max(0, int(score)))
	severity, recommendation := "LOW", "SAFE"
	switch {
	case risk >= 81:
		severity, recommendation = "CRITICAL", "DO_NOT_INSTALL"
	case risk >= 51:
		severity, recommendation = "HIGH", "DO_NOT_INSTALL"
	case risk >= 21:
		severity, recommendation = "MEDIUM", "CAUTION"
	}
	bySeverity, byCategory := map[string]int{}, map[string]int{}
	for _, finding := range findings {
		bySeverity[finding.Severity]++
		byCategory[finding.Category]++
	}
	return model.Summary{RiskScore: risk, Severity: severity, Recommendation: recommendation, SafeToInstall: risk <= 20,
		FindingsCount: len(findings), FindingsBySeverity: bySeverity, FindingsByCategory: byCategory,
		ScannerVersion: scannerVersion, ScanMode: "deterministic"}
}

func deduplicateForScoring(findings []model.Finding) []model.Finding {
	sameFileBest := map[string]int{}
	sameFile := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		matched := truncate(strings.TrimSpace(scoringMatchedText(finding)), 100)
		key := ruleID(finding) + "\x00" + finding.Location.File + "\x00" + matched
		if index, exists := sameFileBest[key]; exists {
			if finding.Confidence > sameFile[index].Confidence {
				sameFile[index] = finding
			}
			continue
		}
		sameFileBest[key] = len(sameFile)
		sameFile = append(sameFile, finding)
	}
	crossFileBest := map[string]int{}
	result := make([]model.Finding, 0, len(sameFile))
	for _, finding := range sameFile {
		matched := strings.TrimSpace(scoringMatchedText(finding))
		if matched == "" {
			result = append(result, finding)
			continue
		}
		key := ruleID(finding) + "\x00" + truncate(matched, 100)
		if index, exists := crossFileBest[key]; exists {
			if finding.Confidence > result[index].Confidence {
				result[index] = finding
			}
			continue
		}
		crossFileBest[key] = len(result)
		result = append(result, finding)
	}
	return result
}

func scoringMatchedText(finding model.Finding) string {
	if finding.MatchedText != "" {
		return finding.MatchedText
	}
	return finding.Finding
}

func renderReports(formats []string, summary model.Summary, findings []model.Finding) (map[string]model.Report, error) {
	reports := map[string]model.Report{}
	for _, format := range formats {
		if _, exists := reports[format]; exists {
			continue
		}
		var content, contentType string
		var err error
		switch format {
		case "json":
			content, contentType, err = renderJSON(summary, findings), "application/json", nil
		case "markdown":
			content, contentType = renderMarkdown(summary, findings), "text/markdown; charset=utf-8"
		case "terminal":
			content, contentType = renderTerminal(summary, findings), "text/plain; charset=utf-8"
		case "sarif":
			content, err = renderSARIF(findings)
			contentType = "application/sarif+json"
		default:
			return nil, fmt.Errorf("unsupported output format %q", format)
		}
		if err != nil {
			return nil, err
		}
		reports[format] = model.Report{Content: content, ContentType: contentType}
	}
	return reports, nil
}

func renderJSON(summary model.Summary, findings []model.Finding) string {
	raw, _ := json.MarshalIndent(map[string]any{"summary": summary, "findings": findings}, "", "  ")
	return string(raw)
}

func renderMarkdown(summary model.Summary, findings []model.Finding) string {
	var output strings.Builder
	fmt.Fprintf(&output, "# ScanKernel report\n\n**Risk:** %d/100 (%s)  \n**Recommendation:** %s  \n**Findings:** %d\n", summary.RiskScore, summary.Severity, summary.Recommendation, len(findings))
	for _, finding := range findings {
		fmt.Fprintf(&output, "\n## %s — %s\n\n- Severity: %s\n- Location: `%s:%d`\n- Category: %s\n\n%s\n\nRemediation: %s\n", ruleID(finding), cleanText(finding.Pattern), finding.Severity, finding.Location.File, finding.Location.StartLine, finding.Category, cleanText(finding.Explanation), cleanText(finding.Remediation))
	}
	return output.String()
}

func renderTerminal(summary model.Summary, findings []model.Finding) string {
	var output strings.Builder
	fmt.Fprintf(&output, "ScanKernel: risk %d/100 %s — %s\n", summary.RiskScore, summary.Severity, summary.Recommendation)
	for _, finding := range findings {
		fmt.Fprintf(&output, "%s %-8s %s:%d %s\n", ruleID(finding), finding.Severity, finding.Location.File, finding.Location.StartLine, cleanText(finding.Pattern))
	}
	return output.String()
}

func renderSARIF(findings []model.Finding) (string, error) {
	rules := map[string]map[string]any{}
	results := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		id := ruleID(finding)
		rules[id] = map[string]any{"id": id, "name": finding.Pattern, "shortDescription": map[string]string{"text": finding.Explanation}}
		level := "note"
		if finding.Severity == "HIGH" || finding.Severity == "CRITICAL" {
			level = "error"
		} else if finding.Severity == "MEDIUM" {
			level = "warning"
		}
		region := map[string]any{"startLine": finding.Location.StartLine}
		if finding.Location.EndLine != nil {
			region["endLine"] = *finding.Location.EndLine
		}
		results = append(results, map[string]any{"ruleId": id, "level": level, "message": map[string]string{"text": cleanText(finding.Explanation)},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": finding.Location.File}, "region": region}}}})
	}
	ruleList := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return fmt.Sprint(ruleList[i]["id"]) < fmt.Sprint(ruleList[j]["id"]) })
	document := map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "ScanKernel", "version": buildinfo.Version, "rules": ruleList}}, "results": results}}}
	raw, err := json.MarshalIndent(document, "", "  ")
	return string(raw), err
}

func cleanText(value string) string {
	return strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || !unicode.IsControl(character) {
			return character
		}
		return -1
	}, value)
}
