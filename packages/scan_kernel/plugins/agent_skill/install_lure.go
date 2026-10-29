package agentskill

// Install lures: SKILL.md instructions that make the user run something from
// outside the skill before the skill works. The code never ships with the
// skill, so no scan of the skill can review it:
//   - a script taken from a paste site and run in a terminal;
//   - an archive extracted with a literal password given in the text (which
//     keeps it from being scanned on the way in), then an executable run;
//   - a file from a GitHub releases URL, when the text also gives an archive
//     password, holds a paste-site lure, or has the user run a downloaded
//     executable as a precondition ("before using the skill").
// A vendor release ("download ripgrep from its releases page, extract it and
// run rg.exe"), a release from the skill's own repository, sharing text to a
// paste site, and running a script that ships with the skill are not lures.

import (
	"path"
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var (
	lureURL = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"` + "`" + `<>()\[\]{}]+`)
	// lureTerminalRun is an instruction to run text in a terminal.
	lureTerminalRun = regexp.MustCompile(`(?i)\b(?:paste|run|execute|enter|type)\b[^\n]{0,80}?\b(?:terminal|shell|command[- ]?line|console|powershell|cmd|command\s+prompt)\b`)
	// lureToPasteSite is text sent to the URL that follows: "paste it at",
	// "upload the log to", "share it on a new note in".
	lureToPasteSite = regexp.MustCompile(`(?i)\b(?:paste|upload|post|share|send|put|save|submit|publish|add)\b[^.!?\n]*\b(?:to|at|on|in|into)\b[^.!?\n]*$`)
	// lureArchivePassword is a password given in the text: "password: 1234",
	// "pass = x", "with password x".
	lureArchivePassword = regexp.MustCompile(`(?i)\b(?:password|passcode|passphrase|pass|pwd)\s*(?:\bis\b|:|=)\s*[*_` + "`" + `'"]*([^\s*_` + "`" + `'"]{1,40})` +
		`|\bwith\s+(?:the\s+)?(?:password|passcode|pass|pwd)\s+[*_` + "`" + `'"]*([^\s*_` + "`" + `'"]{1,40})`)
	// lurePasswordPlaceholder is a password that is not given: a variable or
	// a template placeholder.
	lurePasswordPlaceholder = regexp.MustCompile(`^(?:\$|%|<|\{|\[)`)
	// lureExtract is the step that uses the password.
	lureExtract = regexp.MustCompile(`(?i)\b(?:extract|unzip|unpack|unrar|decompress|7z\s+x)\b`)
	// lureRunExecutable tells the user to run a Windows executable.
	lureRunExecutable = regexp.MustCompile(`(?i)\b(?:run|launch|execute|open|start|double[- ]?click)\b[^\n]{0,80}?\b([\w./-]+\.(?:exe|msi|bat|scr|ps1|vbs|jar))\b`)
	// lureReleaseAsset is a file downloaded from a GitHub release.
	lureReleaseAsset = regexp.MustCompile(`(?i)\bgithub\.com/([\w.-]+)/([\w.-]+)/releases/(?:latest/)?download/[^\s'"` + "`" + `<>()\[\]]+`)
	// lureMandatory makes a step a precondition of the skill.
	lureMandatory = regexp.MustCompile(`(?i)\bbefore\s+(?:using|starting|running|launching|you\s+(?:use|start|run))\s+(?:the|this)\s+skill\b` +
		`|\b(?:skill|it)\s+(?:will\s+not|won'?t|cannot|can'?t|does\s+not|doesn'?t)\s+work\b|\b(?:mandatory|required)\b[^\n]{0,40}\bskill\b`)
)

var lureNonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)

// releaseOwnedBySkill reports a release from the skill's own repository: the
// repository name contains the skill's name, or the front matter homepage or
// repository names the account and repository. Such a download is the
// skill's own binary, never a lure.
func releaseOwnedBySkill(skill skillInput, account, repository string) bool {
	normalize := func(text string) string { return lureNonAlphanumeric.ReplaceAllString(strings.ToLower(text), "") }
	account, repository = normalize(account), normalize(repository)
	if name, ok := skill.Manifest["name"].(string); ok && len(normalize(name)) >= 3 && strings.Contains(repository, normalize(name)) {
		return true
	}
	for _, key := range []string{"homepage", "repository", "repo", "source", "url"} {
		if value, ok := skill.Manifest[key].(string); ok {
			if normalized := normalize(value); strings.Contains(normalized, account) && strings.Contains(normalized, repository) {
				return true
			}
		}
	}
	return false
}

// lureLine is one line of a lure, with the offset of the match on it.
type lureLine struct {
	offset int
	text   string
}

// analyzeInstallLures reports (SC2, HIGH) each line of an install lure in a
// skill's instruction file, tagged install-lure unless it needs review.
func analyzeInstallLures(skill skillInput) []model.Finding {
	manifest := skill.ManifestPath
	if skill.Root != "." {
		manifest = strings.TrimPrefix(manifest, skill.Root+"/")
	}
	var item component
	shipped := map[string]bool{}
	for _, candidate := range skill.Components {
		if candidate.Path == manifest {
			item = candidate
		}
		shipped[strings.ToLower(candidate.Path)] = true
		shipped[strings.ToLower(path.Base(candidate.Path))] = true
	}
	if item.Path == "" {
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
	mandatory := false
	for index, line := range lines {
		for _, match := range lureURL.FindAllStringIndex(line.text, -1) {
			if pasteSiteURL(line.text[match[0]:match[1]]) && !lureToPasteSite.MatchString(line.text[:match[0]]) && near(index, 0, 1, lureTerminalRun) {
				paste = append(paste, lure{index, match[0], "tells the user to take a script from a paste site and run it in a terminal"})
				break
			}
		}
		for _, match := range lureArchivePassword.FindAllStringSubmatchIndex(line.text, -1) {
			value := ""
			if match[2] >= 0 {
				value = line.text[match[2]:match[3]]
			} else {
				value = line.text[match[4]:match[5]]
			}
			if !lurePasswordPlaceholder.MatchString(value) && !strings.Contains(value, "{{") && near(index, 2, 2, lureExtract) {
				password = append(password, lure{index, match[0], "gives a password to extract a downloaded archive, which keeps its contents from being scanned"})
				break
			}
		}
		if match := lureRunExecutable.FindStringSubmatchIndex(line.text); match != nil {
			file := strings.ToLower(strings.TrimPrefix(line.text[match[2]:match[3]], "./"))
			if !shipped[file] && !shipped[path.Base(file)] {
				run = append(run, lure{index, match[0], "tells the user to run a downloaded executable"})
			}
		}
		if match := lureReleaseAsset.FindStringSubmatchIndex(line.text); match != nil &&
			!releaseOwnedBySkill(skill, line.text[match[2]:match[3]], line.text[match[4]:match[5]]) {
			release = append(release, lure{index, match[0], "makes a file downloaded from a GitHub release a prerequisite"})
		}
		mandatory = mandatory || lureMandatory.MatchString(line.text)
	}
	// A release download is a lure with an archive password, a paste-site
	// lure, or a downloaded executable the user must run before using the
	// skill. An executable to run alone is not enough (vendor releases say
	// the same), nor is a precondition alone (a skill installing its own
	// CLI).
	releaseLure := len(release) > 0 && (len(password) > 0 || len(paste) > 0 || (mandatory && len(run) > 0))
	reported := paste
	if releaseLure {
		reported = append(append(append(reported, password...), run...), release...)
	} else if len(password) > 0 && len(run) > 0 {
		reported = append(append(reported, password...), run...)
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
		explanation += " This skill " + lure.reason + " before the skill works: the code is not part of the skill, so it cannot be reviewed."
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
