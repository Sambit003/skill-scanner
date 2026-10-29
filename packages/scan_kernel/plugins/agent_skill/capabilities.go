package agentskill

// The capabilities list ("What this skill can do") holds behavior that is
// ordinary for a skill with scripts: running shell commands, reading named
// environment variables, dynamic imports, plain network requests, and tools
// run from a package registry. These are listed apart from the findings.
// Their findings still feed the risk score exactly as before, so moving them
// out of the findings array changes no score or verdict.

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

// capabilityLabels are the rules whose findings move to the capabilities
// list, with the plain label shown there. E1, E2, SC13 and SC14 move only in
// part; see capabilityLabel and splitCapabilities.
var capabilityLabels = map[string]string{
	"AST3": "Imports code dynamically",
	"AST4": "Runs shell commands",
	"AST6": "Compiles code at runtime",
	"AST7": "Looks up functions by name at runtime",
	"E1":   "Sends network requests",
	"E2":   "Reads environment variables",
	"SC13": "Ships a compiled program or archive",
	"SC14": "Ships a PowerShell or batch script",
}

var (
	// requestSensitiveData is a request that carries secrets, environment
	// values or file contents.
	requestSensitiveData = regexp.MustCompile(`(?i)\bos\.(?:environ|getenv)\b|\bprocess\.env\b|\bgetenv\s*\(|\bENV\[|\$env:|\$\{?[A-Z][A-Z0-9_]*\}?` +
		`|\bopen\s*\(|\.read(?:_text|_bytes)?\s*\(|\breadFile(?:Sync)?\b|\bcreateReadStream\b|\bGet-Content\b|\$\((?:cat|base64|tar|env|printenv)\b|\bfiles\s*=` +
		`|\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form)[\s=]*["']?(?:[^\s"'@]*=)?@|\s(?:-T|--upload-file|--post-file)\b` +
		`|\b(?:password|passwd|secret|token|api[_-]?key|credentials?|cookies?|private[_-]?key|ssh)\b`)
	// requestSendsUserData is an instruction to send user data, context or
	// files out.
	requestSendsUserData = regexp.MustCompile(`(?i)(?:send|transmit|post|upload)\s+(?:user\s+)?(?:data|information|context|files?)\b`)
)

// riskyReceiver reports a request destination that collects whatever it is
// sent: a collection or webhook host, a paste site, or a raw IP address.
func riskyReceiver(text string) bool {
	if collectionHost.MatchString(text) {
		return true
	}
	for _, raw := range originURL.FindAllString(text, -1) {
		if loopbackOrigin(raw) {
			continue
		}
		candidate := raw
		if !strings.Contains(candidate, "://") {
			candidate = "http://" + candidate
		}
		if parsed, err := url.Parse(strings.TrimRight(candidate, ".,:")); err == nil {
			host := strings.ToLower(parsed.Hostname())
			if net.ParseIP(host) != nil || pasteSiteHost.MatchString(host) {
				return true
			}
		}
	}
	return false
}

// requestCallText returns an E1 request as written: from the start of its
// line to the end of the first call opened there, or the line and its
// backslash continuations.
func requestCallText(content string, line int) string {
	lines := strings.Split(content, "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	offset := 0
	for _, previous := range lines[:line-1] {
		offset += len(previous) + 1
	}
	text := lines[line-1]
	if open := strings.IndexByte(text, '('); open >= 0 {
		return text[:open] + balancedCallText(content, offset+open)
	}
	for next := line; next < len(lines) && strings.HasSuffix(strings.TrimSpace(text), "\\"); next++ {
		text += "\n" + lines[next]
	}
	return text
}

// sensitiveRequestText reports a request that carries secrets, environment
// values or file contents, instructs sending user data, or goes to a
// collection, webhook or paste host or a raw IP.
func sensitiveRequestText(call, matched string) bool {
	return requestSensitiveData.MatchString(call) || requestSendsUserData.MatchString(matched) || riskyReceiver(call)
}

// dataFlowRules are the taint rules whose finding on a request's line means
// the request sends data the file read or computed.
var dataFlowRules = map[string]bool{"TT1": true, "TT2": true, "TT3": true, "TT4": true}

// envRead is E2 reading one named variable; enumerating or harvesting the
// environment (os.environ.items(), Object.keys(process.env),
// env | grep secret, "collect all environment variables") stays a finding.
var envRead = regexp.MustCompile(`(?i)^(?:os\.environ\s*\[|os\.environ\.get\b|os\.environ\s*\.\s*copy\b|process\.env\s*\[|printenv\s)`)

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
	if ruleID(finding) == "E2" && !envRead.MatchString(strings.TrimSpace(finding.MatchedText)) {
		return ""
	}
	// A shipped program or script moves only when nothing more is known
	// (MEDIUM); one SKILL.md says to run, or a Windows technique, stays.
	if (ruleID(finding) == "SC13" || ruleID(finding) == "SC14") && finding.Severity != "MEDIUM" {
		return ""
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
	// An E1 request stays a finding when sensitiveRequestText says so, when
	// a taint flow ends on its line, or when its file has a behaviour-tagged
	// finding.
	taggedFiles, flowLines := map[string]bool{}, map[string]bool{}
	for _, finding := range findings {
		if _, tagged := behaviourOf(finding); tagged {
			taggedFiles[finding.Location.File] = true
		}
		if dataFlowRules[ruleID(finding)] {
			flowLines[finding.Location.File+"\x00"+strconv.Itoa(finding.Location.StartLine)] = true
		}
	}
	kept := make([]model.Finding, 0, len(findings))
	var capabilities []model.Capability
	for _, finding := range findings {
		label := capabilityLabel(finding)
		if ruleID(finding) == "E1" && label != "" && (taggedFiles[finding.Location.File] ||
			flowLines[finding.Location.File+"\x00"+strconv.Itoa(finding.Location.StartLine)] ||
			sensitiveRequestText(requestCallText(content[finding.Location.File], finding.Location.StartLine), finding.MatchedText)) {
			label = ""
		}
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
