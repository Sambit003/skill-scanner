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
	scanScope := request.ScanScope
	if scanScope == "" {
		scanScope = model.ScanScopeSkillFolders
	}
	prepared, err := prepare(ctx, request.Target, request.Offline, scanScope, request.IncludeReadme)
	if err != nil {
		return model.ScanResult{}, err
	}
	defer prepared.cleanup()
	if err := ctx.Err(); err != nil {
		return model.ScanResult{}, err
	}
	findings, err := analyzeSourceAndManifest(ctx, prepared.Components, map[string]any{})
	if err != nil {
		return model.ScanResult{}, err
	}
	findings = append(findings, analyzeDependencies(ctx, prepared.Components, request.Offline)...)
	if err := ctx.Err(); err != nil {
		return model.ScanResult{}, err
	}
	for _, skill := range prepared.Skills {
		manifestFindings := analyzeMCPRugPull(nil, skill.Manifest)
		manifestFindings = append(manifestFindings, analyzeMCPLeastPrivilege(skill.Components, skill.Manifest)...)
		manifestFindings = append(manifestFindings, analyzeMCPToolPoisoning(skill.Manifest)...)
		manifestFindings = append(manifestFindings, analyzeTriggers(skill.Manifest)...)
		findings = append(findings, rebaseSkillFindings(manifestFindings, skill.Root)...)
	}
	yaraFindings, err := scanYARA(ctx, prepared.Components, request.YARARulesDir)
	if err != nil {
		return model.ScanResult{}, fmt.Errorf("YARA scan: %w", err)
	}
	findings = applyFrameworkMappings(orderFindingsByAnalyzer(sanitizeFindings(append(findings, yaraFindings...))))
	baseline, err := loadBaseline(request.BaselinePath)
	if err != nil {
		return model.ScanResult{}, err
	}
	kept, _ := filterBaseline(findings, baseline)
	formats := request.OutputFormats
	if len(formats) == 0 {
		formats = []string{"json"}
	}
	for index := range formats {
		formats[index] = strings.ToLower(formats[index])
	}
	summary := summarize(kept, prepared.Components)
	summary.ScanScope = scanScope
	includeReadme := request.IncludeReadme
	summary.IncludeReadme = &includeReadme
	reports, err := renderReports(formats, summary, kept)
	if err != nil {
		return model.ScanResult{}, err
	}
	return model.ScanResult{Kind: "scan", Summary: summary, Findings: kept, Reports: reports}, nil
}

func rebaseSkillFindings(findings []model.Finding, root string) []model.Finding {
	if root == "." {
		return findings
	}
	for index := range findings {
		findings[index].Location.File = strings.TrimPrefix(root+"/"+findings[index].Location.File, "./")
	}
	return findings
}
