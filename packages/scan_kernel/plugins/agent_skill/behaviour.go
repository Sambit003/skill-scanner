package agentskill

// Behaviour markers: a finding whose match is malicious behaviour, not a
// capability a benign skill may also need, carries a "Behaviour: <kind>" tag
// and at least behaviourConfidence. A finding that needs review (negated,
// quoted, table, test fixture) never carries one.

import (
	"math"
	"net"
	"net/url"
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

const (
	behaviourTagPrefix  = "Behaviour: "
	behaviourConfidence = .85
	// behaviourDownloadAndRun: remote code fetched and run from an untrusted
	// origin, or in a place that runs without review.
	behaviourDownloadAndRun = "download-and-run"
	// behaviourDecodeToExec: encoded text decoded and run by a shell.
	behaviourDecodeToExec = "decode-to-exec"
	// behaviourInstallLure: the user is told to run something fetched from
	// outside the skill before the skill works.
	behaviourInstallLure = "install-lure"
)

// behaviourOf returns the behaviour kind a finding carries, if any.
func behaviourOf(finding model.Finding) (string, bool) {
	for _, tag := range finding.Tags {
		if kind, ok := strings.CutPrefix(tag, behaviourTagPrefix); ok {
			return kind, true
		}
	}
	return "", false
}

// markBehaviour tags a finding as malicious behaviour of the given kind and
// raises its confidence to behaviourConfidence. Review tagging wins: a
// finding that needs review is returned unchanged.
func markBehaviour(finding model.Finding, kind string) model.Finding {
	if _, review := needsReview(finding); review {
		return finding
	}
	if _, tagged := behaviourOf(finding); tagged {
		return finding
	}
	finding.Confidence = math.Max(finding.Confidence, behaviourConfidence)
	finding.Tags = append(finding.Tags, behaviourTagPrefix+kind)
	return finding
}

var (
	// downloadAndRunCommand matches remote code fetched and run in one
	// command: curl|wget ... | sh, sh -c "$(curl ...)", sh <(curl ...),
	// curl -o f && sh f, iwr ... | iex, eval(fetch(...)).
	downloadAndRunCommand = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby)\b` +
		`|(?:\b(?:ba|z)?sh|\bsource|\beval)\s+(?:-c\s+)?["']?(?:<\(|\$\()\s*(?:curl|wget)\b[^\n)]*\)` +
		`|\b(?:curl|wget)\b[^\n&;|]*\s-[oO]\s*\S+\s*(?:&&|;)\s*(?:sudo\s+)?(?:(?:ba|z)?sh\b|chmod\s+\+x\b|\./)` +
		`|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(?:iex|Invoke-Expression)\b|\biex\s*\(\s*(?:New-Object\s+Net\.WebClient|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)[^\n]*` +
		`|\b(?:eval|exec)\s*\(\s*(?:await\s+)?(?:fetch|urllib|requests|httpx)\b[^\n]*|\bnew\s+Function\s*\([^\n]*\bfetch\s*\([^\n]*`)
	// originURL matches a URL with a scheme, or a bare IPv4 address with an
	// optional port and path.
	originURL = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"` + "`" + `<>()\[\]{}|;]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s'"` + "`" + `<>()\[\]{}|;]*)?`)
	// pasteSiteHost names public paste and snippet sites: anyone can publish
	// a script there, and it can change after the skill is reviewed.
	pasteSiteHost = regexp.MustCompile(`(?i)^(?:www\.)?(?:pastebin\.(?:com|pl)|glot\.io|rentry\.(?:co|org)|paste\.ee|hastebin\.com|dpaste\.(?:com|org)|ghostbin\.[a-z]+|controlc\.com|justpaste\.it|termbin\.com|paste\.rs|ix\.io|sprunge\.us|0x0\.st|privatebin\.net|bpa\.st|katb\.in|pastie\.org|paste\.centos\.org|pasted\.co)$`)
)

// untrustedOrigin reports a URL that no vendor installer is served from: plain
// http or ftp, a raw IP address, or a paste site.
func untrustedOrigin(raw string) bool {
	candidate := strings.TrimRight(raw, ".,:")
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return false
	}
	return !strings.EqualFold(parsed.Scheme, "https") || net.ParseIP(host) != nil || pasteSiteHost.MatchString(host)
}

// downloadAndRunOrigins returns the download-and-run commands in text and
// whether any of them fetches from an untrusted origin.
func downloadAndRunOrigins(text string) (commands []string, untrusted bool) {
	for _, command := range downloadAndRunCommand.FindAllString(text, -1) {
		commands = append(commands, command)
		for _, origin := range originURL.FindAllString(command, -1) {
			if untrustedOrigin(origin) {
				untrusted = true
			}
		}
	}
	return commands, untrusted
}

// isScriptFile reports a file that runs as code.
func isScriptFile(item component) bool {
	return item.Type == "shell" || item.Type == "python" || item.Type == "javascript" || item.Executable
}

// scriptCommentLine reports a script line that is a comment, so it never runs.
func scriptCommentLine(item component, offset int) bool {
	if !isScriptFile(item) {
		return false
	}
	lineStart := strings.LastIndexByte(item.Content[:offset], '\n') + 1
	line := strings.TrimSpace(item.Content[lineStart:])
	for _, marker := range []string{"#", "//", "/*", "*", "--", "REM ", "::"} {
		if strings.HasPrefix(line, marker) {
			return true
		}
	}
	return false
}

// runsUnreviewed reports a match in a place that runs without the agent or
// the user reading it first: a non-comment line of a script (SKILL.md hook
// commands and !`command` preprocessing are analyzed as shell scripts), or a
// hooks configuration file.
func runsUnreviewed(item component, offset int) bool {
	normalized := strings.ToLower(strings.ReplaceAll(item.Path, "\\", "/"))
	if strings.HasSuffix(normalized, "/hooks.json") || normalized == "hooks.json" {
		return true
	}
	return isScriptFile(item) && !scriptCommentLine(item, offset)
}

// downloadAndRunBehaviour returns behaviourDownloadAndRun for a remote code
// execution match whose line fetches from an untrusted origin, or that runs
// unreviewed and is not a vendor installer served over https from a trusted
// host. Matches in documentation examples and script comments are left
// untagged.
func downloadAndRunBehaviour(item component, match []int, example bool) string {
	lineStart := strings.LastIndexByte(item.Content[:match[0]], '\n') + 1
	lineEnd := len(item.Content)
	if index := strings.IndexByte(item.Content[match[1]:], '\n'); index >= 0 {
		lineEnd = match[1] + index
	}
	commands, untrusted := downloadAndRunOrigins(item.Content[lineStart:lineEnd])
	switch {
	case len(commands) == 0 || example || scriptCommentLine(item, match[0]):
		return ""
	case untrusted:
		return behaviourDownloadAndRun
	case runsUnreviewed(item, match[0]):
		for _, command := range commands {
			if !isSafeSupplyChainPattern(command) {
				return behaviourDownloadAndRun
			}
		}
	}
	return ""
}
