package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo"
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/bundle"
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/protocol"
	"gopkg.in/yaml.v3"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, input io.Reader, output, diagnostic io.Writer) int {
	registry := bundle.Registry()
	if len(args) == 0 || args[0] == "engine" {
		return protocol.Serve(context.Background(), registry, input, output, diagnostic)
	}
	switch args[0] {
	case "version":
		info := buildinfo.Current(registry.PluginIDs())
		if len(args) > 1 && args[1] == "--json" {
			_ = json.NewEncoder(output).Encode(info)
		} else {
			fmt.Fprintf(output, "ScanKernel %s (%s) %s %s\n", info.Version, info.Commit, info.GoVersion, info.Target)
		}
		return 0
	case "rules":
		return rules(args[1:], registry.Rules(), output, diagnostic)
	case "scan":
		return scan(args[1:], registry, output, diagnostic)
	case "baseline":
		return baseline(args[1:], registry, output, diagnostic)
	case "mcp":
		return serveMCP(registry, diagnostic)
	default:
		fmt.Fprintf(diagnostic, "unknown command %q\n", args[0])
		usage(diagnostic)
		return 2
	}
}

type scanner interface {
	Scan(context.Context, model.ScanRequest) (model.ScanResult, error)
}

func scan(args []string, registry scanner, output, diagnostic io.Writer) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	assetType := flags.String("type", "skill", "compiled asset plugin")
	formats := flags.String("format", "terminal", "comma-separated: json,markdown,sarif,terminal")
	timeout := flags.Duration("timeout", 5*time.Minute, "scan timeout")
	baseline := flags.String("baseline", "", "baseline YAML or JSON")
	yaraRules := flags.String("yara-rules", "", "custom YARA rule directory")
	offline := flags.Bool("offline", false, "disable remote targets")
	scanScope := flags.String("scope", model.ScanScopeSkillFolders, "scan scope: skill_files, skill_folders, repository")
	includeReadme := flags.Bool("include-readme", false, "include README and README.* files in the selected scope")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		fmt.Fprintln(diagnostic, "usage: scan-kernel-engine scan [flags] <target>")
		return 2
	}
	requested := strings.Split(*formats, ",")
	for index := range requested {
		requested[index] = strings.ToLower(strings.TrimSpace(requested[index]))
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := registry.Scan(ctx, model.ScanRequest{Target: flags.Arg(0), AssetType: *assetType, OutputFormats: requested,
		TimeoutSeconds: timeout.Seconds(), BaselinePath: *baseline, YARARulesDir: *yaraRules, Offline: *offline,
		ScanScope: *scanScope, IncludeReadme: *includeReadme, ListCapabilities: true})
	if err != nil {
		fmt.Fprintf(diagnostic, "ScanKernel scan failed: %v\n", err)
		return 3
	}
	for _, format := range requested {
		report, exists := result.Reports[format]
		if exists {
			fmt.Fprintln(output, report.Content)
		}
	}
	return 0
}

func rules(args []string, docs []model.RuleDocument, output, diagnostic io.Writer) int {
	if len(args) == 0 || args[0] == "list" {
		for _, rule := range docs {
			fmt.Fprintf(output, "%s\t%s\t%s\n", rule.RuleID, rule.Category, rule.Title)
		}
		return 0
	}
	if args[0] == "show" && len(args) == 2 {
		for _, rule := range docs {
			if rule.RuleID == args[1] {
				_ = json.NewEncoder(output).Encode(rule)
				return 0
			}
		}
		fmt.Fprintln(diagnostic, "rule documentation is not available")
		return 2
	}
	fmt.Fprintln(diagnostic, "usage: scan-kernel-engine rules [list|show RULE_ID]")
	return 2
}

func baseline(args []string, registry scanner, output, diagnostic io.Writer) int {
	flags := flag.NewFlagSet("baseline", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	destination := flags.String("output", ".scan_kernel-baseline.yaml", "baseline YAML or JSON path")
	reason := flags.String("reason", "Accepted finding (auto-generated baseline)", "recorded suppression reason")
	offline := flags.Bool("offline", false, "disable remote targets and advisory lookups")
	scanScope := flags.String("scope", model.ScanScopeSkillFolders, "scan scope: skill_files, skill_folders, repository")
	includeReadme := flags.Bool("include-readme", false, "include README and README.* files in the selected scope")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		fmt.Fprintln(diagnostic, "usage: scan-kernel-engine baseline [flags] <target>")
		return 2
	}
	result, err := registry.Scan(context.Background(), model.ScanRequest{Target: flags.Arg(0), AssetType: "skill", OutputFormats: []string{"json"}, TimeoutSeconds: 300, Offline: *offline,
		ScanScope: *scanScope, IncludeReadme: *includeReadme})
	if err != nil {
		fmt.Fprintf(diagnostic, "ScanKernel baseline failed: %v\n", err)
		return 3
	}
	entries := make([]map[string]any, 0, len(result.Findings))
	for _, finding := range result.Findings {
		end := ""
		if finding.Location.EndLine != nil {
			end = fmt.Sprint(*finding.Location.EndLine)
		}
		raw := strings.Join([]string{finding.ID, finding.Location.File, fmt.Sprint(finding.Location.StartLine), end, strings.TrimSpace(finding.Explanation)}, "|")
		digest := sha256.Sum256([]byte(raw))
		entries = append(entries, map[string]any{"hash": fmt.Sprintf("sha256:%x", digest[:8]), "rule_id": finding.ID, "file": finding.Location.File, "reason": *reason})
	}
	document := map[string]any{"version": 1, "rules": []any{}, "fingerprints": entries}
	var encoded []byte
	if strings.EqualFold(filepath.Ext(*destination), ".json") {
		encoded, err = json.MarshalIndent(document, "", "  ")
	} else {
		encoded, err = yaml.Marshal(document)
	}
	if err == nil {
		err = os.WriteFile(*destination, encoded, 0o600)
	}
	if err != nil {
		fmt.Fprintf(diagnostic, "write baseline: %v\n", err)
		return 3
	}
	fmt.Fprintf(output, "Wrote baseline with %d findings to %s\n", len(entries), *destination)
	return 0
}

type mcpScanInput struct {
	Target        string `json:"target" jsonschema:"path or approved remote URL of the Agent Skill"`
	Offline       bool   `json:"offline,omitempty" jsonschema:"disable remote target resolution"`
	ScanScope     string `json:"scan_scope,omitempty" jsonschema:"scan scope: skill_files, skill_folders, or repository"`
	IncludeReadme bool   `json:"include_readme,omitempty" jsonschema:"include README files in the selected scope"`
}

type mcpScanOutput struct {
	Result model.ScanResult `json:"result" jsonschema:"deterministic ScanKernel result"`
}

// serveMCP uses the official MCP Go SDK and delegates to the same plugin registry
// used by the process protocol and human-facing CLI.
func serveMCP(registry scanner, diagnostic io.Writer) int {
	server := mcp.NewServer(&mcp.Implementation{Name: "ScanKernel", Version: buildinfo.Version}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "scan_skill", Description: "Scan an Agent Skill for deterministic security findings"},
		func(ctx context.Context, _ *mcp.CallToolRequest, input mcpScanInput) (*mcp.CallToolResult, mcpScanOutput, error) {
			scope := input.ScanScope
			if scope == "" {
				scope = model.ScanScopeSkillFolders
			}
			result, err := registry.Scan(ctx, model.ScanRequest{Target: input.Target, AssetType: "skill", OutputFormats: []string{"json"}, TimeoutSeconds: 300, Offline: input.Offline,
				ScanScope: scope, IncludeReadme: input.IncludeReadme, ListCapabilities: true})
			return nil, mcpScanOutput{Result: result}, err
		})
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(diagnostic, "ScanKernel MCP server failed: %v\n", err)
		return 3
	}
	return 0
}

func usage(output io.Writer) {
	fmt.Fprintln(output, "usage: scan-kernel-engine <scan|baseline|rules|version|mcp|engine>")
}
