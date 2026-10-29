package agentskill

// Symbolic links: the scanner never follows a link outside the scanned root,
// so a file the skill reads through such a link is never scanned. SC11
// reports the link instead: HIGH when it points at a secret or system
// location, MEDIUM for any other target outside the root or a dangling link,
// and LOW for a file read from elsewhere in the root, outside the skill
// folder, whose findings are reported at the link's path.

import (
	"path/filepath"
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// symlinkEntry is a symbolic link that leaves the scanned root or dangles.
type symlinkEntry struct {
	Path     string // the link, relative to the scanned root
	Target   string // the link text as written
	Secret   bool
	Dangling bool
}

var (
	// secretLocation matches credential stores and system locations wherever
	// they are: SSH and cloud credentials, .env files, keychains, /etc.
	secretLocation = regexp.MustCompile(`(?i)(?:^|/)(?:\.ssh|\.aws|\.gnupg|\.kube|\.azure|\.config/gcloud|\.config/gh|\.docker)(?:/|$)` +
		`|(?:^|/)\.env(?:\.[^/]*)?$|(?:^|/)\.(?:netrc|git-credentials|npmrc|pypirc)$` +
		`|(?:^|/)Library/Keychains(?:/|$)|\.keychain(?:-db)?$|^(?:/private)?/etc(?:/|$)|^/(?:root|var/root)(?:/|$)`)
	// agentConfigLocation matches agent configuration in a home directory.
	// It applies only to absolute or ~ links: a relative link to .claude/
	// points into the project, not the user's own agent settings.
	agentConfigLocation = regexp.MustCompile(`(?i)(?:^|/)(?:\.claude|\.claude\.json|\.codex|\.cursor|\.gemini|\.clawdbot|\.openclaw)(?:/|$)`)
)

// secretLinkTarget reports a link whose text or resolved path names a secret
// or system location.
func secretLinkTarget(raw, resolved string) bool {
	for _, candidate := range []string{filepath.ToSlash(raw), filepath.ToSlash(resolved)} {
		if secretLocation.MatchString(candidate) {
			return true
		}
	}
	home := strings.HasPrefix(raw, "~") || filepath.IsAbs(raw)
	return home && agentConfigLocation.MatchString(filepath.ToSlash(raw))
}

// selectLinks keeps the links in scan scope: inside a skill folder, or the
// instruction file itself for skill_files. Without skills every link is in
// scope, as every file is.
func selectLinks(links []symlinkEntry, skills []skillInput, scanScope string) []symlinkEntry {
	if len(skills) == 0 || scanScope == model.ScanScopeRepository {
		return links
	}
	var selected []symlinkEntry
	for _, link := range links {
		for _, skill := range skills {
			if (scanScope == model.ScanScopeSkillFiles && link.Path == skill.ManifestPath) ||
				(scanScope != model.ScanScopeSkillFiles && pathWithinSkill(link.Path, skill.Root)) {
				selected = append(selected, link)
				break
			}
		}
	}
	return selected
}

// analyzeSymlinks reports (SC11) links that leave the scanned root or
// dangle, and files read through a link from outside their skill folder.
func analyzeSymlinks(links []symlinkEntry, components []component, skills []skillInput) []model.Finding {
	var findings []model.Finding
	for _, link := range links {
		severity, text := "MEDIUM", "Symbolic link to a file outside the scanned folder; the skill uses a file this scan could not see: "+link.Target
		switch {
		case link.Secret:
			severity, text = "HIGH", "Symbolic link to a secret or system location: "+link.Target
		case link.Dangling:
			text = "Dangling symbolic link; the skill uses a file this scan could not see: " + link.Target
		}
		findings = append(findings, symlinkFinding(link.Path, severity, text))
	}
	for _, item := range components {
		if item.LinkTarget == "" {
			continue
		}
		for _, skill := range skills {
			if pathWithinSkill(item.Path, skill.Root) {
				if !pathWithinSkill(item.LinkTarget, skill.Root) {
					findings = append(findings, symlinkFinding(item.Path, "LOW",
						"Symbolic link to "+item.LinkTarget+", outside the skill folder; it was scanned at the link's path"))
				}
				break
			}
		}
	}
	return findings
}

func symlinkFinding(path, severity, text string) model.Finding {
	explanation, remediation := ruleText("SC11")
	text = truncateRunes(text, 200)
	return model.Finding{ID: "SC11", Category: "Supply Chain", Pattern: "Symbolic Link Outside the Skill", Severity: severity,
		Confidence: .9, Location: model.Location{File: path, StartLine: 1}, Finding: text, MatchedText: text,
		Explanation: explanation, Remediation: remediation, Tags: []string{"Supply Chain"}}
}
