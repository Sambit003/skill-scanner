package agentskill

// Install lures: SKILL.md instructions that make the user run something from
// outside the skill before the skill works. The code never ships with the
// skill, so no scan of the skill can review it:
//   - a script on a paste site, copied and run in a terminal;
//   - an archive extracted with a password given in the text (which keeps
//     it from being scanned on the way in), then an executable run;
//   - a binary or archive from a GitHub releases URL, when the text also
//     gives an archive password, tells the user to run an executable, or
//     holds a paste-site lure.
// A plain "install our CLI from our releases page" is not a lure.

import (
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var (
	lureURL = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"` + "`" + `<>()\[\]{}]+`)
	// lureTerminalRun is an instruction to run copied text in a terminal.
	lureTerminalRun = regexp.MustCompile(`(?i)\b(?:paste|run|execute|enter|type)\b[^\n]{0,80}?\b(?:terminal|shell|command[- ]?line|console|powershell|cmd|command\s+prompt)\b` +
		`|\bcopy\b[^\n]{0,60}?\b(?:script|command|code|installer|snippet)\b`)
	// lureArchivePassword is a password given in the text: "password: 1234",
	// "pass = x", "with password x".
	lureArchivePassword = regexp.MustCompile(`(?i)\b(?:password|passcode|passphrase|pass|pwd)\s*(?:\bis\b|:|=)\s*[*_` + "`" + `'"]*[^\s*_` + "`" + `'"]{1,40}` +
		`|\bwith\s+(?:the\s+)?(?:password|passcode|pass|pwd)\s+[*_` + "`" + `'"]*[^\s*_` + "`" + `'"]{1,40}`)
	lureArchive = regexp.MustCompile(`(?i)\b(?:extract|unzip|unpack|unrar|decompress|archive|zip|rar|7z|7-zip)\b`)
	// lureRunExecutable tells the user to run a Windows executable.
	lureRunExecutable = regexp.MustCompile(`(?i)\b(?:run|launch|execute|open|start|double[- ]?click)\b[^\n]{0,80}?[\w.-]+\.(?:exe|msi|bat|scr|ps1|vbs|jar)\b`)
	// lureReleaseAsset is a file downloaded from a GitHub release.
	lureReleaseAsset = regexp.MustCompile(`(?i)\bgithub\.com/[\w.-]+/[\w.-]+/releases/(?:latest/)?download/[^\s'"` + "`" + `<>()\[\]]+`)
)

// lureLine is one line of a lure, with the offset of the match on it.
type lureLine struct {
	offset int
	text   string
}

// analyzeInstallLures reports (SC2, HIGH) each line of an install lure in
// SKILL.md, tagged install-lure unless it needs review.
func analyzeInstallLures(item component) []model.Finding {
	if !isSkillManifestPath(item.Path) {
		return nil
	}
	var lines []lureLine
	for offset := 0; offset < len(item.Content); {
		end := len(item.Content)
		if index := strings.IndexByte(item.Content[offset:], '\n'); index >= 0 {
			end = offset + index
		}
		lines = append(lines, lureLine{offset, item.Content[offset:end]})
		offset = end + 1
	}
	near := func(index, before, after int, pattern *regexp.Regexp) bool {
		for other := max(0, index-before); other <= min(len(lines)-1, index+after); other++ {
			if pattern.MatchString(lines[other].text) {
				return true
			}
		}
		return false
	}
	type lure struct {
		line   int
		start  int
		reason string
	}
	var paste, password, run, release []lure
	for index, line := range lines {
		for _, match := range lureURL.FindAllStringIndex(line.text, -1) {
			if pasteSiteURL(line.text[match[0]:match[1]]) && near(index, 0, 1, lureTerminalRun) {
				paste = append(paste, lure{index, match[0], "tells the user to copy a script from a paste site and run it in a terminal"})
				break
			}
		}
		if match := lureArchivePassword.FindStringIndex(line.text); match != nil && near(index, 2, 2, lureArchive) {
			password = append(password, lure{index, match[0], "gives a password to extract a downloaded archive, which keeps its contents from being scanned"})
		}
		if match := lureRunExecutable.FindStringIndex(line.text); match != nil {
			run = append(run, lure{index, match[0], "tells the user to run a downloaded executable"})
		}
		if match := lureReleaseAsset.FindStringIndex(line.text); match != nil {
			release = append(release, lure{index, match[0], "makes a binary downloaded from a GitHub release a prerequisite"})
		}
	}
	reported := paste
	// A password archive or a release download is a lure together with an
	// executable to run, or with each other. A release download is also part
	// of a paste-site lure in the same file.
	if (len(password) > 0 && (len(run) > 0 || len(release) > 0)) || (len(release) > 0 && len(run) > 0) {
		reported = append(append(append(reported, password...), run...), release...)
	} else if len(paste) > 0 {
		reported = append(reported, release...)
	}
	var findings []model.Finding
	seen := map[int]bool{}
	for _, lure := range reported {
		if seen[lure.line] {
			continue
		}
		seen[lure.line] = true
		offset := lines[lure.line].offset + lure.start
		explanation, remediation := ruleText("SC2")
		explanation += " This SKILL.md " + lure.reason + " before the skill works: the code is not part of the skill, so it cannot be reviewed."
		matched := truncateRunes(strings.TrimSpace(lines[lure.line].text), 200)
		finding := model.Finding{ID: "SC2", Category: "Supply Chain", Pattern: "Install Lure", Severity: "HIGH", Confidence: .9,
			Location: model.Location{File: item.Path, StartLine: lure.line + 1}, Finding: matched, MatchedText: matched,
			Explanation: explanation, Remediation: remediation, CodeSnippet: contextAtOffset(item.Content, offset, 3),
			Tags: []string{"Supply Chain"}}
		if reason := proseReviewReason(item, "SC2", offset); reason != "" {
			finding = markForReview(finding, reason)
		}
		findings = append(findings, markBehaviour(finding, behaviourInstallLure))
	}
	return findings
}

// pasteSiteURL reports a URL on a paste site.
func pasteSiteURL(raw string) bool {
	rest := raw[strings.Index(raw, "://")+3:]
	if end := strings.IndexAny(rest, "/?#:"); end >= 0 {
		rest = rest[:end]
	}
	return pasteSiteHost.MatchString(strings.TrimSuffix(rest, "."))
}
