package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

type corpusLock struct {
	SchemaVersion int     `json:"schema_version"`
	OracleCommit  string  `json:"oracle_commit"`
	Assets        []asset `json:"assets"`
}

type asset struct {
	ID     string `json:"id"`
	Commit string `json:"commit"`
}

type location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   *int   `json:"end_line"`
}

type finding struct {
	ID         string   `json:"id"`
	Category   string   `json:"category"`
	Severity   string   `json:"severity"`
	Confidence float64  `json:"confidence"`
	Location   location `json:"location"`
	Finding    *string  `json:"finding"`
}

type pythonReport struct {
	Risk struct {
		Score          int    `json:"score"`
		Severity       string `json:"severity"`
		Recommendation string `json:"recommendation"`
	} `json:"risk_assessment"`
	Issues []finding `json:"issues"`
}

type goReport struct {
	Summary struct {
		RiskScore          int            `json:"risk_score"`
		Severity           string         `json:"severity"`
		Recommendation     string         `json:"recommendation"`
		SafeToInstall      bool           `json:"safe_to_install"`
		FindingsBySeverity map[string]int `json:"findings_by_severity"`
		FindingsByCategory map[string]int `json:"findings_by_category"`
	} `json:"summary"`
	Findings []finding `json:"findings"`
}

type component struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Lines      int    `json:"lines"`
	Executable bool   `json:"executable"`
	SizeBytes  int    `json:"size_bytes"`
}

type dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	File      string `json:"file"`
	Line      int    `json:"line"`
}

type inventory struct {
	Components      []component         `json:"components"`
	Manifest        map[string]any      `json:"manifest"`
	Dependencies    []dependency        `json:"dependencies"`
	ScoringFindings []normalizedFinding `json:"scoring_findings"`
}

type timing struct {
	PythonScanMS int64  `json:"python_scan_ms"`
	GoScanMS     int64  `json:"go_scan_ms"`
	PythonStatus string `json:"python_status"`
	GoStatus     string `json:"go_status"`
}

type normalizedFinding struct {
	RuleID      string  `json:"rule_id"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	File        string  `json:"file"`
	StartLine   int     `json:"start_line"`
	EndLine     *int    `json:"end_line"`
	MatchedText string  `json:"matched_text"`
	Category    string  `json:"category"`
}

type contribution struct {
	RuleID      string  `json:"rule_id"`
	File        string  `json:"file"`
	MatchedText string  `json:"matched_text"`
	Occurrence  int     `json:"occurrence"`
	Points      float64 `json:"points"`
}

type layerResult struct {
	Equal  bool   `json:"equal"`
	Detail string `json:"detail,omitempty"`
}

type ruleDrift struct {
	RuleID      string `json:"rule_id"`
	PythonCount int    `json:"python_count"`
	GoCount     int    `json:"go_count"`
}

type assetResult struct {
	ID            string                 `json:"id"`
	Commit        string                 `json:"commit"`
	Status        string                 `json:"status"`
	Timings       timing                 `json:"timings"`
	Layers        map[string]layerResult `json:"layers"`
	RuleDrift     []ruleDrift            `json:"rule_drift,omitempty"`
	PythonScore   int                    `json:"python_score"`
	GoScore       int                    `json:"go_score"`
	PythonBand    string                 `json:"python_band"`
	GoBand        string                 `json:"go_band"`
	BlockingDrift int                    `json:"blocking_drift"`
}

type parityReport struct {
	SchemaVersion int           `json:"schema_version"`
	OracleCommit  string        `json:"oracle_commit"`
	CorpusSize    int           `json:"corpus_size"`
	AcquisitionMS int64         `json:"acquisition_ms"`
	Completed     int           `json:"completed"`
	Within90S     int           `json:"within_90_seconds"`
	ExactParity   int           `json:"exact_parity"`
	BlockingDrift int           `json:"blocking_drift"`
	Assets        []assetResult `json:"assets"`
	PerRule       []ruleDrift   `json:"per_rule"`
}

type exceptionDocument struct {
	SchemaVersion int               `json:"schema_version"`
	Exceptions    []reviewException `json:"exceptions"`
}

type reviewException struct {
	Fixture       string `json:"fixture"`
	Rule          string `json:"rule"`
	ExpectedDelta string `json:"expected_delta"`
	Rationale     string `json:"rationale"`
	Approval      string `json:"approval"`
}

func main() {
	var lockPath, resultsDir, exceptionsPath, jsonPath, markdownPath string
	var acquisitionMS int64
	var limit int
	flag.StringVar(&lockPath, "lock", "testdata/parity/corpus.lock.json", "pinned corpus lock")
	flag.StringVar(&resultsDir, "results", "dist/parity/results", "raw result directory")
	flag.StringVar(&exceptionsPath, "exceptions", "testdata/parity/reviewed-exceptions.json", "reviewed exceptions")
	flag.StringVar(&jsonPath, "json", "dist/parity/report.json", "JSON report")
	flag.StringVar(&markdownPath, "markdown", "dist/parity/report.md", "Markdown report")
	flag.Int64Var(&acquisitionMS, "acquisition-ms", 0, "corpus acquisition milliseconds")
	flag.IntVar(&limit, "limit", 100, "number of locked assets to compare (development smoke only)")
	flag.Parse()

	report, err := compare(lockPath, resultsDir, exceptionsPath, acquisitionMS, limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := writeReports(report, jsonPath, markdownPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("Parity: %d/%d complete, %d within 90s, %d exact, %d blocking drift(s)\n", report.Completed, report.CorpusSize, report.Within90S, report.ExactParity, report.BlockingDrift)
	if report.BlockingDrift != 0 || report.Completed != report.CorpusSize || report.Within90S != report.CorpusSize {
		os.Exit(1)
	}
}

func compare(lockPath, resultsDir, exceptionsPath string, acquisitionMS int64, limit int) (parityReport, error) {
	var lock corpusLock
	if err := readJSON(lockPath, &lock); err != nil {
		return parityReport{}, err
	}
	if lock.SchemaVersion != 1 || len(lock.Assets) != 100 {
		return parityReport{}, fmt.Errorf("corpus lock must use schema 1 and contain exactly 100 assets")
	}
	if limit < 1 || limit > len(lock.Assets) {
		return parityReport{}, fmt.Errorf("limit must be between 1 and %d", len(lock.Assets))
	}
	lockedAssets := lock.Assets[:limit]
	var exceptions exceptionDocument
	if err := readJSON(exceptionsPath, &exceptions); err != nil {
		return parityReport{}, err
	}
	if exceptions.SchemaVersion != 1 {
		return parityReport{}, errors.New("reviewed exceptions schema_version must be 1")
	}
	for _, exception := range exceptions.Exceptions {
		if exception.Fixture == "" || exception.Rule == "" || exception.ExpectedDelta == "" || exception.Rationale == "" || exception.Approval == "" {
			return parityReport{}, errors.New("every reviewed exception requires fixture, rule, expected_delta, rationale, and approval")
		}
	}

	report := parityReport{SchemaVersion: 1, OracleCommit: lock.OracleCommit, CorpusSize: len(lockedAssets), AcquisitionMS: acquisitionMS}
	perRule := map[string]*ruleDrift{}
	for _, corpusAsset := range lockedAssets {
		result := compareAsset(resultsDir, corpusAsset)
		if err := writeAssetReport(resultsDir, result); err != nil {
			return parityReport{}, err
		}
		report.Assets = append(report.Assets, result)
		if result.Status == "complete" {
			report.Completed++
		}
		if result.Status == "complete" && result.Timings.PythonScanMS <= 90_000 && result.Timings.GoScanMS <= 90_000 {
			report.Within90S++
		}
		if result.BlockingDrift == 0 && result.Status == "complete" {
			report.ExactParity++
		}
		report.BlockingDrift += result.BlockingDrift
		for _, drift := range result.RuleDrift {
			entry := perRule[drift.RuleID]
			if entry == nil {
				entry = &ruleDrift{RuleID: drift.RuleID}
				perRule[drift.RuleID] = entry
			}
			entry.PythonCount += drift.PythonCount
			entry.GoCount += drift.GoCount
		}
	}
	for _, drift := range perRule {
		report.PerRule = append(report.PerRule, *drift)
	}
	sort.Slice(report.PerRule, func(i, j int) bool { return report.PerRule[i].RuleID < report.PerRule[j].RuleID })
	return report, nil
}

func compareAsset(resultsDir string, corpusAsset asset) assetResult {
	slug := strings.ReplaceAll(corpusAsset.ID, "/", "__")
	root := filepath.Join(resultsDir, slug)
	result := assetResult{ID: corpusAsset.ID, Commit: corpusAsset.Commit, Status: "complete", Layers: map[string]layerResult{}}
	if err := readJSON(filepath.Join(root, "timing.json"), &result.Timings); err != nil || result.Timings.PythonStatus != "ok" || result.Timings.GoStatus != "ok" {
		result.Status = "failed"
		result.BlockingDrift++
		result.Layers["execution"] = layerResult{Detail: errorDetail(err, result.Timings)}
		return result
	}
	var python pythonReport
	var goResult goReport
	var pythonInventory, goInventory inventory
	for path, destination := range map[string]any{
		filepath.Join(root, "python.json"):           &python,
		filepath.Join(root, "go.json"):               &goResult,
		filepath.Join(root, "python.inventory.json"): &pythonInventory,
		filepath.Join(root, "go.inventory.json"):     &goInventory,
	} {
		if err := readJSON(path, destination); err != nil {
			result.Status = "failed"
			result.BlockingDrift++
			result.Layers["execution"] = layerResult{Detail: err.Error()}
			return result
		}
	}

	inputEqual := reflect.DeepEqual(pythonInventory.Components, goInventory.Components) &&
		reflect.DeepEqual(pythonInventory.Manifest, goInventory.Manifest) &&
		reflect.DeepEqual(pythonInventory.Dependencies, goInventory.Dependencies)
	result.Layers["input"] = layerResult{Equal: inputEqual, Detail: equalityDetail(inputEqual, "files/types/executable flags, manifest, or dependencies differ")}
	pythonOriginal := normalizeFindings(python.Issues, pythonInventory.ScoringFindings)
	goOriginal := normalizeFindings(goResult.Findings, goInventory.ScoringFindings)
	pythonFindings, goFindings := sortedFindings(pythonOriginal), sortedFindings(goOriginal)
	rawEqual := reflect.DeepEqual(pythonFindings, goFindings)
	result.Layers["raw_findings"] = layerResult{Equal: rawEqual, Detail: equalityDetail(rawEqual, firstFindingDifference(pythonFindings, goFindings))}
	pythonContributions := scoringContributions(pythonInventory.ScoringFindings, pythonInventory.Components)
	goContributions := scoringContributions(goInventory.ScoringFindings, goInventory.Components)
	scoringEqual := reflect.DeepEqual(pythonContributions, goContributions)
	result.Layers["scoring"] = layerResult{Equal: scoringEqual, Detail: equalityDetail(scoringEqual, firstContributionDifference(pythonContributions, goContributions))}
	result.PythonScore, result.GoScore = python.Risk.Score, goResult.Summary.RiskScore
	result.PythonBand, result.GoBand = python.Risk.Severity, goResult.Summary.Severity
	pythonSeverity, pythonCategory := totals(python.Issues)
	finalEqual := python.Risk.Score == goResult.Summary.RiskScore && python.Risk.Severity == goResult.Summary.Severity &&
		python.Risk.Recommendation == goResult.Summary.Recommendation && reflect.DeepEqual(pythonSeverity, goResult.Summary.FindingsBySeverity) &&
		reflect.DeepEqual(pythonCategory, goResult.Summary.FindingsByCategory)
	result.Layers["final"] = layerResult{Equal: finalEqual, Detail: equalityDetail(finalEqual, "score, band, recommendation, or category totals differ")}

	result.RuleDrift = countDrift(pythonFindings, goFindings)
	for _, layer := range result.Layers {
		if !layer.Equal {
			result.BlockingDrift++
		}
	}
	return result
}

func normalizeFindings(findings []finding, scoring []normalizedFinding) []normalizedFinding {
	result := make([]normalizedFinding, 0, len(findings))
	for index, value := range findings {
		matched := ""
		if index < len(scoring) {
			matched = scoring[index].MatchedText
		} else if value.Finding != nil {
			matched = *value.Finding
		}
		result = append(result, normalizedFinding{RuleID: value.ID, Severity: value.Severity, Confidence: value.Confidence,
			File: value.Location.File, StartLine: value.Location.StartLine, EndLine: value.Location.EndLine, MatchedText: matched, Category: value.Category})
	}
	return result
}

func sortedFindings(findings []normalizedFinding) []normalizedFinding {
	result := append([]normalizedFinding(nil), findings...)
	sort.SliceStable(result, func(i, j int) bool { return findingKey(result[i]) < findingKey(result[j]) })
	return result
}

func findingKey(value normalizedFinding) string {
	end := -1
	if value.EndLine != nil {
		end = *value.EndLine
	}
	return fmt.Sprintf("%s\x00%s\x00%09d\x00%09d\x00%s\x00%s\x00%020.10f", value.RuleID, value.File, value.StartLine, end, value.Severity, value.MatchedText, value.Confidence)
}

func scoringContributions(findings []normalizedFinding, components []component) []contribution {
	type bestEntry struct {
		finding normalizedFinding
		index   int
	}
	sameFile := make([]normalizedFinding, 0, len(findings))
	sameBest := map[string]bestEntry{}
	for _, value := range findings {
		matched := truncateRunes(strings.TrimSpace(value.MatchedText), 100)
		key := value.RuleID + "\x00" + value.File + "\x00" + matched
		if existing, ok := sameBest[key]; ok {
			if value.Confidence > existing.finding.Confidence {
				sameFile[existing.index] = value
				sameBest[key] = bestEntry{finding: value, index: existing.index}
			}
			continue
		}
		sameBest[key] = bestEntry{finding: value, index: len(sameFile)}
		sameFile = append(sameFile, value)
	}
	result := make([]normalizedFinding, 0, len(sameFile))
	crossBest := map[string]bestEntry{}
	for _, value := range sameFile {
		matched := strings.TrimSpace(value.MatchedText)
		if matched == "" {
			result = append(result, value)
			continue
		}
		key := value.RuleID + "\x00" + truncateRunes(matched, 100)
		if existing, ok := crossBest[key]; ok {
			if value.Confidence > existing.finding.Confidence {
				result[existing.index] = value
				crossBest[key] = bestEntry{finding: value, index: existing.index}
			}
			continue
		}
		crossBest[key] = bestEntry{finding: value, index: len(result)}
		result = append(result, value)
	}
	rank := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].RuleID != result[j].RuleID {
			return result[i].RuleID < result[j].RuleID
		}
		leftRank, leftOK := rank[strings.ToUpper(result[i].Severity)]
		rightRank, rightOK := rank[strings.ToUpper(result[j].Severity)]
		if !leftOK {
			leftRank = 4
		}
		if !rightOK {
			rightRank = 4
		}
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if result[i].File != result[j].File {
			return result[i].File < result[j].File
		}
		return result[i].StartLine < result[j].StartLine
	})
	executable := map[string]bool{}
	for _, value := range components {
		executable[value.Path] = value.Executable
	}
	occurrences := map[string]int{}
	weights := []float64{1, .5, .25}
	points := map[string]float64{"CRITICAL": 50, "HIGH": 25, "MEDIUM": 10, "LOW": 5}
	contributions := make([]contribution, 0, len(result))
	for _, value := range result {
		confidence := math.Max(0, math.Min(1, value.Confidence))
		if confidence <= 0 {
			continue
		}
		occurrence := occurrences[value.RuleID]
		occurrences[value.RuleID]++
		if occurrence >= len(weights) {
			continue
		}
		base := points[strings.ToUpper(value.Severity)]
		if base == 0 {
			base = 5
		}
		valuePoints := base * weights[occurrence] * confidence
		if executable[value.File] {
			valuePoints *= 1.3
		}
		contributions = append(contributions, contribution{RuleID: value.RuleID, File: value.File, MatchedText: value.MatchedText, Occurrence: occurrence + 1, Points: valuePoints})
	}
	return contributions
}

func countDrift(python, goFindings []normalizedFinding) []ruleDrift {
	pythonCounts, goCounts := map[string]int{}, map[string]int{}
	for _, value := range python {
		pythonCounts[value.RuleID]++
	}
	for _, value := range goFindings {
		goCounts[value.RuleID]++
	}
	ids := map[string]bool{}
	for id := range pythonCounts {
		ids[id] = true
	}
	for id := range goCounts {
		ids[id] = true
	}
	var result []ruleDrift
	for id := range ids {
		if pythonCounts[id] != goCounts[id] {
			result = append(result, ruleDrift{RuleID: id, PythonCount: pythonCounts[id], GoCount: goCounts[id]})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RuleID < result[j].RuleID })
	return result
}

func totals(findings []finding) (map[string]int, map[string]int) {
	severity, category := map[string]int{}, map[string]int{}
	for _, value := range findings {
		severity[value.Severity]++
		category[value.Category]++
	}
	return severity, category
}

func firstFindingDifference(left, right []normalizedFinding) string {
	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		if !reflect.DeepEqual(left[index], right[index]) {
			return fmt.Sprintf("first difference at normalized finding %d: python=%s go=%s", index, findingKey(left[index]), findingKey(right[index]))
		}
	}
	return fmt.Sprintf("finding counts differ: python=%d go=%d", len(left), len(right))
}

func firstContributionDifference(left, right []contribution) string {
	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		if !reflect.DeepEqual(left[index], right[index]) {
			return fmt.Sprintf("first contribution difference at %d: python=%+v go=%+v", index, left[index], right[index])
		}
	}
	return fmt.Sprintf("contribution counts differ: python=%d go=%d", len(left), len(right))
}

func readJSON(path string, destination any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func writeReports(report parityReport, jsonPath, markdownPath string) error {
	if err := os.MkdirAll(filepath.Dir(jsonPath), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	var markdown strings.Builder
	fmt.Fprintf(&markdown, "# ScanKernel Python-to-Go parity\n\n- Oracle: `%s`\n- Corpus: %d pinned assets\n- Acquisition: %d ms (outside scan gate)\n- Completed: %d/%d\n- Within 90 seconds per engine: %d/%d\n- Exact parity: %d/%d\n- Blocking drift: %d\n\n", report.OracleCommit, report.CorpusSize, report.AcquisitionMS, report.Completed, report.CorpusSize, report.Within90S, report.CorpusSize, report.ExactParity, report.CorpusSize, report.BlockingDrift)
	markdown.WriteString("| Asset | Python ms | Go ms | Input | Findings | Scoring | Final | Score | Band |\n|---|---:|---:|---|---|---|---|---:|---|\n")
	for _, value := range report.Assets {
		fmt.Fprintf(&markdown, "| %s | %d | %d | %s | %s | %s | %s | %d/%d | %s/%s |\n", value.ID, value.Timings.PythonScanMS, value.Timings.GoScanMS, mark(value.Layers["input"].Equal), mark(value.Layers["raw_findings"].Equal), mark(value.Layers["scoring"].Equal), mark(value.Layers["final"].Equal), value.PythonScore, value.GoScore, value.PythonBand, value.GoBand)
	}
	markdown.WriteString("\n## Per-rule count drift\n\n| Rule | Python | Go |\n|---|---:|---:|\n")
	for _, value := range report.PerRule {
		fmt.Fprintf(&markdown, "| %s | %d | %d |\n", value.RuleID, value.PythonCount, value.GoCount)
	}
	return os.WriteFile(markdownPath, []byte(markdown.String()), 0o644)
}

func writeAssetReport(resultsDir string, result assetResult) error {
	root := filepath.Join(resultsDir, strings.ReplaceAll(result.ID, "/", "__"))
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "drift.json"), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	var markdown strings.Builder
	fmt.Fprintf(&markdown, "# %s parity\n\n- Commit: `%s`\n- Status: %s\n- Python scan: %d ms\n- Go scan: %d ms\n- Blocking drift: %d\n\n", result.ID, result.Commit, result.Status, result.Timings.PythonScanMS, result.Timings.GoScanMS, result.BlockingDrift)
	markdown.WriteString("| Layer | Result | Detail |\n|---|---|---|\n")
	for _, name := range []string{"execution", "input", "raw_findings", "scoring", "final"} {
		layer, exists := result.Layers[name]
		if !exists {
			continue
		}
		detail := strings.ReplaceAll(layer.Detail, "|", "\\|")
		fmt.Fprintf(&markdown, "| %s | %s | %s |\n", name, mark(layer.Equal), detail)
	}
	if len(result.RuleDrift) > 0 {
		markdown.WriteString("\n## Per-rule count drift\n\n| Rule | Python | Go |\n|---|---:|---:|\n")
		for _, drift := range result.RuleDrift {
			fmt.Fprintf(&markdown, "| %s | %d | %d |\n", drift.RuleID, drift.PythonCount, drift.GoCount)
		}
	}
	return os.WriteFile(filepath.Join(root, "drift.md"), []byte(markdown.String()), 0o644)
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func equalityDetail(equal bool, detail string) string {
	if equal {
		return ""
	}
	return detail
}

func errorDetail(err error, value timing) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("python=%s go=%s", value.PythonStatus, value.GoStatus)
}

func mark(value bool) string {
	if value {
		return "OK"
	}
	return "DRIFT"
}
