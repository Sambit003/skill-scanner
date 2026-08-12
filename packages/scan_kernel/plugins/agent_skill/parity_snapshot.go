//go:build parity

package agentskill

import (
	"encoding/json"
	"os"
	"sort"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

type parityInputSnapshot struct {
	Components      []component            `json:"components"`
	Manifest        map[string]any         `json:"manifest"`
	Dependencies    []dependencyCoordinate `json:"dependencies"`
	ScoringFindings []parityScoringFinding `json:"scoring_findings"`
}

type parityScoringFinding struct {
	RuleID      string  `json:"rule_id"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	File        string  `json:"file"`
	StartLine   int     `json:"start_line"`
	MatchedText string  `json:"matched_text"`
}

// writeParitySnapshot is compiled only into parity builds. It exposes the
// scanner's interpreted input layer without changing the production CLI or
// process protocol.
func writeParitySnapshot(prepared *preparedInput) error {
	destination := os.Getenv("SCAN_KERNEL_PARITY_SNAPSHOT")
	if destination == "" {
		return nil
	}
	components := append([]component(nil), prepared.Components...)
	dependencies := make([]dependencyCoordinate, 0)
	for _, item := range components {
		dependencies = append(dependencies, extractDependencyCoordinates(item)...)
	}
	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].File != dependencies[j].File {
			return dependencies[i].File < dependencies[j].File
		}
		if dependencies[i].Line != dependencies[j].Line {
			return dependencies[i].Line < dependencies[j].Line
		}
		return dependencies[i].Name < dependencies[j].Name
	})
	raw, err := json.MarshalIndent(parityInputSnapshot{Components: components, Manifest: prepared.Manifest, Dependencies: dependencies}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(destination, append(raw, '\n'), 0o600)
}

// writeParityScoringSnapshot records the actual post-baseline inputs supplied
// to scoring. MatchedText is intentionally not part of the public protocol,
// so parity builds expose it only through this benchmark side channel.
func writeParityScoringSnapshot(findings []model.Finding) error {
	destination := os.Getenv("SCAN_KERNEL_PARITY_SNAPSHOT")
	if destination == "" {
		return nil
	}
	var snapshot parityInputSnapshot
	raw, err := os.ReadFile(destination)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	for _, finding := range findings {
		snapshot.ScoringFindings = append(snapshot.ScoringFindings, parityScoringFinding{
			RuleID: ruleID(finding), Severity: finding.Severity, Confidence: finding.Confidence,
			File: finding.Location.File, StartLine: finding.Location.StartLine, MatchedText: finding.MatchedText,
		})
	}
	raw, err = json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(destination, append(raw, '\n'), 0o600)
}
