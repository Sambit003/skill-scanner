package agentskill

// The capabilities list ("What this skill can do") holds behavior that is
// ordinary for a skill with scripts: running shell commands, reading named
// environment variables, plain API calls, dynamic imports, and tools run from
// a package registry. These are listed apart from the findings. Their
// findings still feed the risk score exactly as before, so moving them out
// of the findings array changes no score or verdict.

import (
	"regexp"
	"sort"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// capabilityLabels are the rules whose findings move to the capabilities
// list, with the plain label shown there. E1 and E2 move only in part; see
// capabilityLabel.
var capabilityLabels = map[string]string{
	"AST3": "Imports code dynamically",
	"AST4": "Runs shell commands",
	"AST6": "Compiles code at runtime",
	"AST7": "Looks up functions by name at runtime",
	"E1":   "Makes network requests",
	"E2":   "Reads environment variables",
}

var (
	// envRead is E2 reading one named variable; enumerating or harvesting the
	// environment (os.environ.items(), Object.keys(process.env),
	// env | grep secret, "collect all environment variables") stays a finding.
	envRead = regexp.MustCompile(`(?i)^(?:os\.environ\s*\[|os\.environ\.get\b|os\.environ\s*\.\s*copy\b|process\.env\s*\[|printenv\s)`)
	// exfiltrationInstruction is the prose form of E1 ("send user data to
	// https://..."), which stays a finding.
	exfiltrationInstruction = regexp.MustCompile(`(?i)^(?:send|transmit|post|upload)\s`)
	// sensitivePayload marks a request whose surrounding code sends file
	// contents, the environment or secrets, conversation content, credential
	// files or host identity. Such an E1 stays a finding.
	sensitivePayload = regexp.MustCompile(`(?i)\bopen\s*\(|\.read(?:_text|_bytes)?\s*\(|\breadFile(?:Sync)?\b|(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)[\s=]+["']?[^\s"']*@|--post-file|\bos\.environ\b|\bgetenv\b|\bprocess\.env\b|\$\(\s*(?:env|printenv|cat)\b|\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*\}?|\b(?:conversation|chat_history|transcript|system_prompt)\b|\.ssh\b|\.aws\b|\bid_rsa\b|\bcredentials\b|\.env\b|\bcookies?\b|\bhostname\b|\bwhoami\b|\bgetpass\b|\bplatform\.node\b|\buname\b`)
)

// capabilityLabel returns the capabilities-list label for a finding that
// describes what the skill can do, or "" for a finding that stays one. A
// finding marked for review stays a finding.
func capabilityLabel(finding model.Finding) string {
	label, moves := capabilityLabels[ruleID(finding)]
	if !moves {
		return ""
	}
	if _, review := needsReview(finding); review {
		return ""
	}
	matched := strings.TrimSpace(finding.MatchedText)
	switch ruleID(finding) {
	case "E2":
		if !envRead.MatchString(matched) {
			return ""
		}
	case "E1":
		if exfiltrationInstruction.MatchString(matched) || sensitivePayload.MatchString(finding.CodeSnippet+"\n"+matched) {
			return ""
		}
	}
	return label
}

// splitCapabilities moves the findings that describe what the skill can do
// into capability entries, one per label and file at its first line, with a
// one-line snippet of that line. Snippets are masked by the caller.
func splitCapabilities(findings []model.Finding, items []component) ([]model.Finding, []model.Capability) {
	content := make(map[string]string, len(items))
	for _, item := range items {
		content[item.Path] = item.Content
	}
	kept := make([]model.Finding, 0, len(findings))
	var capabilities []model.Capability
	for _, finding := range findings {
		label := capabilityLabel(finding)
		if label == "" {
			kept = append(kept, finding)
			continue
		}
		capabilities = append(capabilities, model.Capability{RuleID: ruleID(finding), Label: label,
			Location: model.Location{File: finding.Location.File, StartLine: finding.Location.StartLine},
			Snippet:  lineSnippet(content[finding.Location.File], finding.Location.StartLine)})
	}
	return kept, capabilities
}

// unpinnedToolCapabilities lists the ordinary tools a skill runs from a
// package or container registry without a pinned version: unpinned npx,
// bunx, pnpx, uvx and docker commands that do not start an MCP server (those
// are RP1 findings).
func unpinnedToolCapabilities(items []component) []model.Capability {
	var capabilities []model.Capability
	for _, item := range items {
		if isBinaryScannerPath(item.Path) {
			continue
		}
		regions := mcpConfigRegions(item)
		lineOf := func(offset int) int { return 1 + strings.Count(item.Content[:offset], "\n") }
		isServer := func(offset int, name string) bool {
			start := strings.LastIndexByte(item.Content[:offset], '\n') + 1
			line, _, _ := strings.Cut(item.Content[start:], "\n")
			return isMCPServerPackage(name) || rp1MCPAdd.MatchString(line) || insideSpans(regions, offset)
		}
		add := func(offset int, label string) {
			line := lineOf(offset)
			capabilities = append(capabilities, model.Capability{RuleID: "SC1", Label: label,
				Location: model.Location{File: item.Path, StartLine: line}, Snippet: lineSnippet(item.Content, line)})
		}
		for _, re := range []*regexp.Regexp{rp1NPX, rp1UVX} {
			for _, match := range re.FindAllStringSubmatchIndex(item.Content, -1) {
				full := item.Content[match[0]:match[1]]
				rest, _, _ := strings.Cut(item.Content[match[1]:], "\n")
				name := strings.TrimRight(item.Content[match[2]:match[3]], ".,;:")
				if strings.Contains(full, "\n") || versionPin.MatchString(full+rest) || isServer(match[0], name) {
					continue
				}
				add(match[0], "Runs "+name+" from a package registry without a pinned version")
			}
		}
		for _, match := range rp1Docker.FindAllStringSubmatchIndex(item.Content, -1) {
			command, _, _ := strings.Cut(item.Content[match[2]:match[3]], "`")
			image, _ := dockerImage(strings.Fields(command))
			if image == "" || strings.HasPrefix(image, "$") || versionPin.MatchString(image) || isServer(match[0], image) {
				continue
			}
			add(match[0], "Runs "+image+" from a container registry without a pinned version")
		}
	}
	return capabilities
}

// mergeCapabilities keeps one entry per label and file, at its first line,
// in file and line order.
func mergeCapabilities(lists ...[]model.Capability) []model.Capability {
	var all []model.Capability
	for _, list := range lists {
		all = append(all, list...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Location.File != all[j].Location.File {
			return all[i].Location.File < all[j].Location.File
		}
		return all[i].Location.StartLine < all[j].Location.StartLine
	})
	seen := map[string]bool{}
	merged := make([]model.Capability, 0, len(all))
	for _, capability := range all {
		key := capability.Label + "\x00" + capability.Location.File
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, capability)
	}
	return merged
}

// scoreAndListCapabilities scores every finding, then moves the capability
// findings out of the findings list. The risk score therefore includes them
// exactly as before, while the finding counts describe the findings that
// remain. Unpinned registry tools join the capabilities list.
func scoreAndListCapabilities(findings []model.Finding, items []component) (model.Summary, []model.Finding, []model.Capability) {
	summary := summarize(findings, items)
	kept, moved := splitCapabilities(findings, items)
	capabilities := mergeCapabilities(moved, unpinnedToolCapabilities(items))
	counted := summarize(kept, items)
	summary.FindingsCount, summary.FindingsBySeverity, summary.FindingsByCategory = counted.FindingsCount, counted.FindingsBySeverity, counted.FindingsByCategory
	return summary, kept, capabilities
}

// maskCapabilitySnippets masks secret values in capability snippets, as
// maskFindingSecrets does for findings.
func maskCapabilitySnippets(capabilities []model.Capability) []model.Capability {
	for index := range capabilities {
		capabilities[index].Snippet = maskSecrets(capabilities[index].Snippet, isSourceCodePath(capabilities[index].Location.File))
	}
	return capabilities
}
