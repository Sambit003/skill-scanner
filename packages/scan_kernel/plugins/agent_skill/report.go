package agentskill

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo"
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var severityPoints = map[string]float64{"CRITICAL": 50, "HIGH": 25, "MEDIUM": 10, "LOW": 5}
var diminishingWeights = []float64{1, .5, .25}

const exposureFullScale = 8.5

func summarize(findings []model.Finding, items []component) model.Summary {
	// Filter first, then de-duplicate each list: a copy that cannot count
	// (under review, or out of its rule's context) must not hide one that can.
	evidence := make([]model.Finding, 0, len(findings))
	capabilities := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if isEvidenceFinding(finding) {
			evidence = append(evidence, finding)
		}
		if isCapabilityFinding(finding) {
			capabilities = append(capabilities, finding)
		}
	}
	evidence, capabilities = deduplicateForScoring(evidence), deduplicateForScoring(capabilities)
	vulnerability := computeVulnerabilityScore(evidence, items)
	exposure := computeExposureScore(capabilities, len(items))
	combined := float64(vulnerability) + (1-float64(vulnerability)/100)*.30*exposure
	risk := min(100, max(0, int(combined)))
	tier, floorFinding := verdictFloor(findings)
	risk = max(risk, tierFloors[tier])
	severity, recommendation := riskBand(risk)

	bySeverity, byCategory := map[string]int{}, map[string]int{}
	for _, finding := range findings {
		bySeverity[finding.Severity]++
		byCategory[finding.Category]++
	}
	return model.Summary{RiskScore: risk, VulnerabilityScore: vulnerability, ExposureScore: exposure,
		Severity: severity, Recommendation: recommendation, SafeToInstall: risk <= 20,
		FindingsCount: len(findings), FindingsBySeverity: bySeverity, FindingsByCategory: byCategory,
		ScannerVersion: scannerVersion, ScanMode: "deterministic",
		VerdictReason: verdictReason(recommendation, risk, tier, floorFinding, len(evidence))}
}

// verdictFloor returns the highest tier any finding sets and the finding that
// sets it: the most severe, then the most confident, then the first by file
// and line.
func verdictFloor(findings []model.Finding) (ruleTier, model.Finding) {
	best, bestFinding := tierNone, model.Finding{}
	for _, finding := range findings {
		tier := findingTier(finding)
		if tier == tierNone || tier < best {
			continue
		}
		if tier == best && !floorFindingBefore(finding, bestFinding) {
			continue
		}
		best, bestFinding = tier, finding
	}
	return best, bestFinding
}

func floorFindingBefore(left, right model.Finding) bool {
	leftRank, rightRank := tierSeverityRank[strings.ToUpper(left.Severity)], tierSeverityRank[strings.ToUpper(right.Severity)]
	switch {
	case leftRank != rightRank:
		return leftRank > rightRank
	case left.Confidence != right.Confidence:
		return left.Confidence > right.Confidence
	case left.Location.File != right.Location.File:
		return left.Location.File < right.Location.File
	}
	return left.Location.StartLine < right.Location.StartLine
}

// behaviourReasons and floorRuleReasons describe a floor finding in
// verdict_reason; other rules fall back to their catalog title.
var behaviourReasons = map[string]string{
	behaviourDownloadAndRun:         "remote code downloaded and run",
	behaviourDecodeToExec:           "decoded payload piped to a shell",
	behaviourInstallLure:            "install step that runs code fetched from outside the skill",
	behaviourReverseShell:           "reverse shell",
	behaviourCredentialExfiltration: "credentials sent off the machine",
	behaviourCredentialTheftFlow:    "password prompt whose answer is sent off the machine",
}

var floorRuleReasons = map[string]string{
	"TT3": "credentials sent off the machine",
	"SC3": "obfuscated code decoded and run",
	"P1":  "instruction to ignore previous instructions",
	"P2":  "hidden instructions",
	"P3":  "instruction to send conversation or user data to an external destination",
	"P4":  "instruction to manipulate the user or hide something from them",
	"P8":  "instruction to send the system prompt out through a tool",
	"E4":  "instruction to leak the conversation context",
	"AR3": "instruction to turn off safety policies",
	"TP1": "hidden instructions in a tool description",
	"TP3": "instructions injected in a tool parameter description",
	"YR5": "prompt-injection signature",
	"SC8": "file only partly scanned because it is over the size limit",
	"EA6": "hook that sends data or runs fetched code",
}

// verdictReason names what set the recommendation. A floor names its finding
// when the floor alone gives the recommendation; otherwise the reason is the
// additive risk score.
func verdictReason(recommendation string, risk int, tier ruleTier, finding model.Finding, evidence int) string {
	if _, floorRecommendation := riskBand(tierFloors[tier]); tier != tierNone && floorRecommendation == recommendation {
		description := floorRuleReasons[ruleID(finding)]
		if kind, ok := behaviourOf(finding); ok && behaviourReasons[kind] != "" {
			description = behaviourReasons[kind]
		}
		if description == "" {
			description = strings.ToLower(ruleTitles[ruleID(finding)])
		}
		return fmt.Sprintf("%s: %s (%s, %s:%d)", recommendation, description, ruleID(finding), finding.Location.File, finding.Location.StartLine)
	}
	switch {
	case evidence == 1:
		return fmt.Sprintf("%s: risk %d from 1 evidence finding", recommendation, risk)
	case evidence > 1:
		return fmt.Sprintf("%s: risk %d from %d evidence findings", recommendation, risk, evidence)
	case risk > 0:
		return fmt.Sprintf("%s: risk %d from exposure only, no evidence findings", recommendation, risk)
	}
	return recommendation + ": no evidence findings"
}

func computeVulnerabilityScore(findings []model.Finding, items []component) int {
	executable := map[string]bool{}
	for _, item := range items {
		executable[item.Path] = item.Executable
	}
	ordered := append([]model.Finding(nil), findings...)
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
		if confidence <= 0 {
			continue
		}
		id := ruleID(finding)
		index := occurrences[id]
		occurrences[id]++
		if index >= len(diminishingWeights) {
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
	return min(100, max(0, int(score)))
}

func computeExposureScore(findings []model.Finding, componentCount int) float64 {
	categories := map[string]bool{}
	for _, finding := range findings {
		if finding.Category != "" {
			categories[finding.Category] = true
		}
	}
	if len(categories) == 0 && componentCount <= 0 {
		return 0
	}
	breadth := math.Log2(1 + float64(len(categories)))
	volume := math.Log2(1 + float64(len(findings)))
	size := math.Log2(1 + float64(componentCount))
	raw := .40*breadth*2.2 + .35*volume + .25*size
	score := min(100, 100*raw/exposureFullScale)
	return math.Round(score*10) / 10
}

func riskBand(risk int) (string, string) {
	severity, recommendation := "LOW", "SAFE"
	switch {
	case risk >= 81:
		severity, recommendation = "CRITICAL", "DO_NOT_INSTALL"
	case risk >= 51:
		severity, recommendation = "HIGH", "DO_NOT_INSTALL"
	case risk >= 21:
		severity, recommendation = "MEDIUM", "CAUTION"
	}
	return severity, recommendation
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
	severityRank := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sort.SliceStable(result, func(i, j int) bool {
		leftRank, leftOK := severityRank[strings.ToUpper(result[i].Severity)]
		rightRank, rightOK := severityRank[strings.ToUpper(result[j].Severity)]
		if !leftOK {
			leftRank = 4
		}
		if !rightOK {
			rightRank = 4
		}
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if result[i].Location.File != result[j].Location.File {
			return result[i].Location.File < result[j].Location.File
		}
		return result[i].Location.StartLine < result[j].Location.StartLine
	})
	return result
}

func scoringMatchedText(finding model.Finding) string {
	// Python's scoring identity is based exclusively on matched_text. A
	// user-facing finding snippet is not a substitute: findings without a
	// matched_text value deliberately remain distinct across files.
	return finding.MatchedText
}

func renderReports(formats []string, summary model.Summary, findings []model.Finding, capabilities []model.Capability) (map[string]model.Report, error) {
	reports := map[string]model.Report{}
	for _, format := range formats {
		if _, exists := reports[format]; exists {
			continue
		}
		var content, contentType string
		var err error
		switch format {
		case "json":
			content, contentType, err = renderJSON(summary, findings, capabilities), "application/json", nil
		case "markdown":
			content, contentType = renderMarkdown(summary, findings, capabilities), "text/markdown; charset=utf-8"
		case "terminal":
			content, contentType = renderTerminal(summary, findings, capabilities), "text/plain; charset=utf-8"
		case "sarif":
			content, err = renderSARIF(summary, findings)
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

func renderJSON(summary model.Summary, findings []model.Finding, capabilities []model.Capability) string {
	document := map[string]any{"summary": summary, "findings": findings}
	if len(capabilities) > 0 {
		document["capabilities"] = capabilities
	}
	raw, _ := json.MarshalIndent(document, "", "  ")
	return string(raw)
}

// capabilitiesIntro heads the capabilities section of the text reports.
const capabilitiesIntro = "What this skill can do. These are not findings and do not change the risk score; review them against what the skill says it does."

var astTaxaNames = map[string]string{
	"AST01": "Malicious Skills",
	"AST02": "Supply Chain Compromise",
	"AST03": "Over-Privileged Skills",
	"AST04": "Insecure Metadata",
	"AST05": "Untrusted External Instructions",
	"AST06": "Weak Isolation",
	"AST07": "Update Drift",
	"AST08": "Poor Scanning",
	"AST09": "No Governance",
	"AST10": "Cross-Platform Reuse",
}

var llmTaxaNames = map[string]string{
	"LLM01:2026": "Prompt Injection",
	"LLM02:2026": "Sensitive Information Disclosure",
	"LLM03:2026": "Excessive Agency",
	"LLM04:2026": "Supply Chain",
	"LLM05:2026": "Data & Model Poisoning",
	"LLM06:2026": "Unbounded Consumption",
	"LLM07:2026": "Misinformation",
	"LLM08:2026": "Hidden Context Exposure",
	"LLM09:2026": "Vector & Embedding Weaknesses",
	"LLM10:2026": "Improper Output Handling",
}

var rmfTaxaNames = map[string]string{
	"GOVERN 6.1":   "Third-Party Software & Data Risk Policies",
	"MANAGE 3.1":   "Third-Party AI Risk Management",
	"MAP 4.1":      "AI Harms & Impact Identification",
	"MEASURE 2.7":  "AI Security & Resilience Evaluation",
	"MEASURE 2.10": "AI Privacy Risk Evaluation",
}

func renderMarkdown(summary model.Summary, findings []model.Finding, capabilities []model.Capability) string {
	var output strings.Builder
	fmt.Fprintf(&output, "# ScanKernel report\n\n**Risk:** %d/100 (%s)  \n**Recommendation:** %s  \n**Scope:** %s  \n**README files:** %s  \n**Findings:** %d\n", summary.RiskScore, summary.Severity, summary.Recommendation, summary.ScanScope, readmeStatus(summary.IncludeReadme), len(findings))
	if summary.VerdictReason != "" {
		fmt.Fprintf(&output, "**Verdict reason:** %s\n", cleanText(summary.VerdictReason))
	}

	output.WriteString("\n## Compliance summary\n\n")
	fmt.Fprintf(&output, "- **Mapping version:** %s\n", mappingVersion)
	output.WriteString("- **Framework alignment:** Provides evidence toward OWASP Agentic Skills Top 10 (v1.0 2026 Edition), OWASP GenAI LLM Top 10 (2026), NIST AI 600-1, and NIST AI RMF 1.0.\n")
	output.WriteString("- **Audit boundary:** Classification provides mechanism-level evidence toward security controls and does not constitute formal compliance or certification.\n\n")

	output.WriteString("### OWASP LLM Top 10 (2026) category breakdown\n\n")
	output.WriteString("| Category | CRITICAL | HIGH | MEDIUM | LOW | Total |\n")
	output.WriteString("|---|---|---|---|---|---|\n")

	llmCategories := []struct {
		id    string
		title string
	}{
		{"LLM01:2026", "Prompt Injection"},
		{"LLM02:2026", "Sensitive Information Disclosure"},
		{"LLM03:2026", "Excessive Agency"},
		{"LLM04:2026", "Supply Chain"},
		{"LLM05:2026", "Data & Model Poisoning"},
		{"LLM06:2026", "Unbounded Consumption"},
		{"LLM07:2026", "Misinformation"},
		{"LLM08:2026", "Hidden Context Exposure"},
		{"LLM09:2026", "Vector & Embedding Weaknesses"},
		{"LLM10:2026", "Improper Output Handling"},
	}

	crossTab := map[string]map[string]int{}
	for _, cat := range llmCategories {
		crossTab[cat.id] = map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	}

	for _, finding := range findings {
		sev := strings.ToUpper(finding.Severity)
		for _, cat := range finding.Frameworks.OwaspLLM {
			if counts, ok := crossTab[cat]; ok {
				counts[sev]++
			}
		}
	}

	for _, cat := range llmCategories {
		counts := crossTab[cat.id]
		total := counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"] + counts["LOW"]
		fmt.Fprintf(&output, "| %s %s | %d | %d | %d | %d | %d |\n",
			cat.id, cat.title, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], total)
	}

	output.WriteString("\n### Static coverage status\n\n")
	output.WriteString("- **Detections present (6/10):** LLM01, LLM02, LLM03, LLM04, LLM08, LLM10\n")
	output.WriteString("- **Partial coverage (2/10):** LLM05 (persistent memory-store poisoning only; model training/fine-tuning out of static scope), LLM06 (static loop/resource markers only; runtime rate/cost testing out of static scope)\n")
	output.WriteString("- **Not covered (2/10):** LLM07 (content quality/misinformation is runtime-only), LLM09 (vector/embedding weaknesses require vector database analysis)\n")

	for _, finding := range findings {
		fmt.Fprintf(&output, "\n## %s — %s\n\n- Severity: %s\n- Location: `%s:%d`\n- Category: %s\n",
			ruleID(finding), cleanText(finding.Pattern), finding.Severity, finding.Location.File, finding.Location.StartLine, finding.Category)
		if reason, review := needsReview(finding); review {
			fmt.Fprintf(&output, "- Needs review: %s (not counted in the risk score)\n", reason)
		}

		if len(finding.Frameworks.OwaspAgentic) > 0 {
			fmt.Fprintf(&output, "- OWASP Agentic Skills: %s\n", strings.Join(finding.Frameworks.OwaspAgentic, ", "))
		}
		if len(finding.Frameworks.OwaspLLM) > 0 {
			fmt.Fprintf(&output, "- OWASP GenAI LLM (2026): %s\n", strings.Join(finding.Frameworks.OwaspLLM, ", "))
		}
		if len(finding.Frameworks.NistGaiRisks) > 0 {
			fmt.Fprintf(&output, "- NIST AI 600-1 Risks: %s\n", strings.Join(finding.Frameworks.NistGaiRisks, ", "))
		}
		if len(finding.Frameworks.NistRmf) > 0 {
			fmt.Fprintf(&output, "- NIST AI RMF Controls: %s\n", strings.Join(finding.Frameworks.NistRmf, ", "))
		}

		fmt.Fprintf(&output, "\n%s\n\nRemediation: %s\n", cleanText(finding.Explanation), cleanText(finding.Remediation))
	}
	if len(capabilities) > 0 {
		fmt.Fprintf(&output, "\n## What this skill can do\n\n%s\n\n", capabilitiesIntro)
		for _, capability := range capabilities {
			fmt.Fprintf(&output, "- %s (%s) at `%s:%d`\n", cleanText(capability.Label), capability.RuleID, capability.Location.File, capability.Location.StartLine)
		}
	}
	return output.String()
}

func renderTerminal(summary model.Summary, findings []model.Finding, capabilities []model.Capability) string {
	var output strings.Builder
	fmt.Fprintf(&output, "ScanKernel: risk %d/100 %s — %s [%s, README %s]\n", summary.RiskScore, summary.Severity, summary.Recommendation, summary.ScanScope, readmeStatus(summary.IncludeReadme))
	if summary.VerdictReason != "" {
		fmt.Fprintf(&output, "Verdict reason: %s\n", cleanText(summary.VerdictReason))
	}
	for _, finding := range findings {
		review := ""
		if reason, ok := needsReview(finding); ok {
			review = " [needs review: " + reason + "]"
		}
		fmt.Fprintf(&output, "%s %-8s %s:%d %s%s\n", ruleID(finding), finding.Severity, finding.Location.File, finding.Location.StartLine, cleanText(finding.Pattern), review)
	}
	if len(capabilities) > 0 {
		fmt.Fprintf(&output, "\nWhat this skill can do (not findings; no effect on the risk score):\n")
		for _, capability := range capabilities {
			fmt.Fprintf(&output, "  %-5s %s:%d %s\n", capability.RuleID, capability.Location.File, capability.Location.StartLine, cleanText(capability.Label))
		}
	}
	return output.String()
}

func renderSARIF(summary model.Summary, findings []model.Finding) (string, error) {
	rules := map[string]map[string]any{}
	results := make([]map[string]any, 0, len(findings))

	astTaxaUsed := map[string]bool{}
	llmTaxaUsed := map[string]bool{}
	rmfTaxaUsed := map[string]bool{}
	gaiTaxaUsed := map[string]bool{}

	for _, finding := range findings {
		id := ruleID(finding)
		fw := finding.Frameworks
		fw.Normalize()

		var relationships []map[string]any
		tagSet := map[string]bool{}

		for _, ast := range fw.OwaspAgentic {
			astTaxaUsed[ast] = true
			tagSet[ast] = true
			relationships = append(relationships, map[string]any{
				"target": map[string]any{
					"id":            ast,
					"toolComponent": map[string]any{"name": "OWASP Agentic Skills Top 10"},
				},
				"kinds": []string{"relevant"},
			})
		}
		for _, llm := range fw.OwaspLLM {
			llmTaxaUsed[llm] = true
			tagSet[llm] = true
			relationships = append(relationships, map[string]any{
				"target": map[string]any{
					"id":            llm,
					"toolComponent": map[string]any{"name": "OWASP GenAI LLM Top 10"},
				},
				"kinds": []string{"relevant"},
			})
		}
		for _, rmf := range fw.NistRmf {
			rmfTaxaUsed[rmf] = true
			tagSet[rmf] = true
			relationships = append(relationships, map[string]any{
				"target": map[string]any{
					"id":            rmf,
					"toolComponent": map[string]any{"name": "NIST AI RMF"},
				},
				"kinds": []string{"relevant"},
			})
		}
		for _, gai := range fw.NistGaiRisks {
			gaiTaxaUsed[gai] = true
			tagSet[gai] = true
			relationships = append(relationships, map[string]any{
				"target": map[string]any{
					"id":            gai,
					"toolComponent": map[string]any{"name": "NIST AI 600-1"},
				},
				"kinds": []string{"relevant"},
			})
		}

		var tags []string
		for t := range tagSet {
			tags = append(tags, t)
		}
		sort.Strings(tags)

		ruleEntry := map[string]any{
			"id":               id,
			"name":             finding.Pattern,
			"shortDescription": map[string]string{"text": finding.Explanation},
			"properties":       map[string]any{"tags": tags},
		}
		if len(relationships) > 0 {
			ruleEntry["relationships"] = relationships
		}
		rules[id] = ruleEntry

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
		result := map[string]any{
			"ruleId": id, "level": level,
			"message": map[string]string{"text": cleanText(finding.Explanation)},
			"locations": []any{map[string]any{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": finding.Location.File},
					"region":           region,
				},
			}},
		}
		if reason, review := needsReview(finding); review {
			result["properties"] = map[string]any{"needs_review": reason}
		}
		results = append(results, result)
	}

	ruleList := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return fmt.Sprint(ruleList[i]["id"]) < fmt.Sprint(ruleList[j]["id"]) })

	buildTaxa := func(used map[string]bool, nameMap map[string]string) []map[string]any {
		var ids []string
		for id := range used {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			name := id
			if nameMap != nil && nameMap[id] != "" {
				name = nameMap[id]
			}
			out = append(out, map[string]any{"id": id, "name": name})
		}
		return out
	}

	taxonomies := []map[string]any{
		{
			"name":       "OWASP Agentic Skills Top 10",
			"version":    "1.0 (2026 Edition)",
			"properties": map[string]any{"snapshot_date": "2026-08-03"},
			"taxa":       buildTaxa(astTaxaUsed, astTaxaNames),
		},
		{
			"name":    "OWASP GenAI LLM Top 10",
			"version": "2026",
			"taxa":    buildTaxa(llmTaxaUsed, llmTaxaNames),
		},
		{
			"name":    "NIST AI RMF",
			"version": "1.0",
			"taxa":    buildTaxa(rmfTaxaUsed, rmfTaxaNames),
		},
		{
			"name":    "NIST AI 600-1",
			"version": "1.0",
			"taxa":    buildTaxa(gaiTaxaUsed, nil),
		},
	}

	document := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":    "ScanKernel",
					"version": buildinfo.Version,
					"rules":   ruleList,
				},
			},
			"taxonomies": taxonomies,
			"properties": map[string]any{
				"scan_scope":          summary.ScanScope,
				"include_readme":      readmeIncluded(summary.IncludeReadme),
				"mapping_version":     mappingVersion,
				"framework_hierarchy": "Primary: OWASP Agentic Skills Top 10 (v1.0 2026 Edition); Mechanism: OWASP GenAI LLM Top 10 (2026); Alignment: NIST AI 600-1 & NIST AI RMF 1.0",
			},
			"results": results,
		}},
	}
	raw, err := json.MarshalIndent(document, "", "  ")
	return string(raw), err
}

func readmeStatus(include *bool) string {
	if readmeIncluded(include) {
		return "included"
	}
	return "excluded"
}

func readmeIncluded(include *bool) bool {
	return include != nil && *include
}

func cleanText(value string) string {
	return strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || !unicode.IsControl(character) {
			return character
		}
		return -1
	}, value)
}
