package agentskill

import (
	"context"
	"fmt"
	"strings"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

type Plugin struct{}

const scannerVersion = "1.0.0"

func New() Plugin { return Plugin{} }

func (Plugin) Descriptor() model.PluginDescriptor {
	return model.PluginDescriptor{ID: "agent_skill", Aliases: []string{"skill", "agent-skills", "agent_skills"}, Version: scannerVersion,
		SupportedExtensions: []string{".md", ".markdown", ".py", ".sh", ".bash", ".zsh", ".json", ".yaml", ".yml", ".toml", ".txt", ".js", ".ts", ".rb", ".go", ".rs", ".ps1", ".psm1", ".bat", ".cmd", ".zip"}}
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
	findings = append(findings, analyzeSymlinks(prepared.Links, prepared.Components, prepared.Skills)...)
	findings = append(findings, analyzeBundledFiles(prepared.Components, prepared.Skills)...)
	if prepared.NoManifest && len(prepared.Components) > 0 {
		findings = append(findings, noManifestFinding(prepared.Components))
	}
	for _, skill := range prepared.Skills {
		if skill.NonStandardManifest {
			findings = append(findings, skillInstructionFileFinding(skill.ManifestPath,
				"No SKILL.md in this folder; this file has skill front matter and was scanned as the skill's instruction file"))
		}
	}
	if err := ctx.Err(); err != nil {
		return model.ScanResult{}, err
	}
	for _, skill := range prepared.Skills {
		manifestFindings := analyzeMCPRugPull(nil, skill.Manifest)
		manifestFindings = append(manifestFindings, analyzeMCPLeastPrivilege(skill.Components, skill.Manifest)...)
		manifestFindings = append(manifestFindings, analyzeMCPToolPoisoning(skill.Manifest)...)
		manifestFindings = append(manifestFindings, analyzeTriggers(skill.Manifest, skill.TriggerLines)...)
		manifestFindings = append(manifestFindings, analyzeFrontmatterSyntax(skill.ManifestContent)...)
		manifestFindings = append(manifestFindings, analyzeActivationHijack(skill.ManifestContent)...)
		manifestFindings = append(manifestFindings, analyzeToolPreApproval(skill.ManifestContent)...)
		manifestFindings = append(manifestFindings, analyzeSkillHooks(skill.ManifestContent)...)
		manifestFindings = append(manifestFindings, analyzeSkillPreprocessing(skill.ManifestContent)...)
		manifestFindings = append(manifestFindings, analyzeInstallLures(skill)...)
		findings = append(findings, rebaseSkillFindings(manifestFindings, skill.Root)...)
		embedded, err := analyzeEmbeddedCommands(ctx, skill.ManifestContent)
		if err != nil {
			return model.ScanResult{}, err
		}
		findings = mergeEmbeddedCommandFindings(findings, rebaseSkillFindings(embedded, skill.Root))
	}
	yaraFindings, err := scanYARA(ctx, prepared.Components, request.YARARulesDir)
	if err != nil {
		return model.ScanResult{}, fmt.Errorf("YARA scan: %w", err)
	}
	findings = clearOwnInstallerBehaviour(append(findings, yaraFindings...), prepared.Skills, prepared.Components)
	findings = keepOneFindingPerLine(applyFrameworkMappings(orderFindingsByAnalyzer(sanitizeFindings(findings))))
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
	var capabilities []model.Capability
	if request.ListCapabilities {
		summary, kept, capabilities = scoreAndListCapabilities(kept, prepared.Components)
	}
	// Secret values are masked only in output, after scoring (which
	// de-duplicates on matched text) and baseline filtering.
	kept = maskFindingSecrets(kept)
	capabilities = maskCapabilitySnippets(capabilities)
	summary.ScanScope = scanScope
	includeReadme := request.IncludeReadme
	summary.IncludeReadme = &includeReadme
	reports, err := renderReports(formats, summary, kept, capabilities)
	if err != nil {
		return model.ScanResult{}, err
	}
	return model.ScanResult{Kind: "scan", Summary: summary, Findings: kept, Capabilities: capabilities, Reports: reports}, nil
}

// noManifestFinding reports (SC9) a target without SKILL.md in any letter
// case. It points at the shallowest Markdown file other than a README, the
// likeliest stand-in for the instruction file (SKILLS.md, prompt.md), or else
// the first file.
func noManifestFinding(components []component) model.Finding {
	file, rank := components[0].Path, -1
	for _, item := range components {
		if item.Type != "markdown" {
			continue
		}
		itemRank := 2 * strings.Count(item.Path, "/")
		if isReadmePath(item.Path) {
			itemRank++
		}
		if rank < 0 || itemRank < rank {
			file, rank = item.Path, itemRank
		}
	}
	return skillInstructionFileFinding(file, "No SKILL.md in the target; all files were scanned")
}

func skillInstructionFileFinding(file, text string) model.Finding {
	explanation, remediation := ruleText("SC9")
	return model.Finding{ID: "SC9", Category: "Supply Chain", Pattern: "No Skill Instruction File", Severity: "LOW", Confidence: 1,
		Location: model.Location{File: file, StartLine: 1}, Finding: text, MatchedText: text,
		Explanation: explanation, Remediation: remediation, Tags: []string{"Supply Chain"}}
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
