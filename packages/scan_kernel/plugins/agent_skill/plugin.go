package agentskill

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

type Plugin struct{}

const scannerVersion = "1.0.0"

func New() Plugin { return Plugin{} }

func (Plugin) Descriptor() model.PluginDescriptor {
	return model.PluginDescriptor{ID: "agent_skill", Aliases: []string{"skill", "agent-skills", "agent_skills"}, Version: scannerVersion,
		SupportedExtensions: []string{".md", ".markdown", ".py", ".sh", ".bash", ".zsh", ".json", ".yaml", ".yml", ".toml", ".txt", ".js", ".ts", ".rb", ".go", ".rs", ".zip"}}
}

func (Plugin) Rules() []model.RuleDocument { return ruleDocuments() }

func (Plugin) Scan(ctx context.Context, request model.ScanRequest) (model.ScanResult, error) {
	timings := newParityTimings()
	defer timings.finish()
	prepared, err := prepare(ctx, request.Target, request.Offline)
	if err != nil {
		return model.ScanResult{}, err
	}
	timings.mark("prepare")
	defer prepared.cleanup()
	if err := ctx.Err(); err != nil {
		return model.ScanResult{}, err
	}
	if err := writeParitySnapshot(prepared); err != nil {
		return model.ScanResult{}, fmt.Errorf("write parity input snapshot: %w", err)
	}
	timings.mark("input_snapshot")
	findings, err := analyzeSourceAndManifest(ctx, prepared.Components, prepared.Manifest)
	if err != nil {
		return model.ScanResult{}, err
	}
	timings.mark("source_and_manifest")
	findings = append(findings, analyzeDependencies(ctx, prepared.Components, request.Offline)...)
	if err := ctx.Err(); err != nil {
		return model.ScanResult{}, err
	}
	timings.mark("dependencies")
	findings = append(findings, analyzeTriggers(prepared.Manifest)...)
	timings.mark("triggers")
	yaraFindings, err := scanYARA(ctx, prepared.Components, request.YARARulesDir)
	if err != nil {
		return model.ScanResult{}, fmt.Errorf("YARA scan: %w", err)
	}
	timings.mark("yara")
	findings = orderFindingsByAnalyzer(sanitizeFindings(append(findings, yaraFindings...)))
	baseline, err := loadBaseline(request.BaselinePath)
	if err != nil {
		return model.ScanResult{}, err
	}
	kept, _ := filterBaseline(findings, baseline)
	timings.mark("normalize_and_baseline")
	if err := writeParityScoringSnapshot(kept); err != nil {
		return model.ScanResult{}, fmt.Errorf("write parity scoring snapshot: %w", err)
	}
	formats := request.OutputFormats
	if len(formats) == 0 {
		formats = []string{"json"}
	}
	for index := range formats {
		formats[index] = strings.ToLower(formats[index])
	}
	summary := summarize(kept, prepared.Components)
	reports, err := renderReports(formats, summary, kept)
	if err != nil {
		return model.ScanResult{}, err
	}
	timings.mark("scoring_and_report")
	return model.ScanResult{Kind: "scan", Summary: summary, Findings: kept, Reports: reports}, nil
}
