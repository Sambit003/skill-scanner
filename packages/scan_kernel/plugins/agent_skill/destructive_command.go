package agentskill

// Destructive-command checks for TM1 and TM2: an HTTP DELETE endpoint, a
// "Remove // comments" docstring and rm -f of one relative file (a build
// script removing its own output before re-zipping) are not destructive.
// rm -rf of /, ~ or $HOME and --no-preserve-root still are.

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

var (
	// httpDeleteEndpoint is an API route: DELETE /api/users/:id.
	httpDeleteEndpoint = regexp.MustCompile(`^DELETE\s+/`)
	// commentMarkerPath is "remove // line comments" or "/* ... */".
	commentMarkerPath = regexp.MustCompile(`(?i)^(?:delete|remove)\s+['"]?/[/*]`)
	// singleFileRemoval is rm with flags and one operand.
	singleFileRemoval = regexp.MustCompile(`\brm\s+((?:-[A-Za-z]+\s+)*)(?:--\s+)?(['"]?)([^\s'"|;&>]+)['"]?`)
	// shellTrueCall captures the first argument of a shell=True call.
	shellTrueCall = regexp.MustCompile(`(?:subprocess\.\w+|Popen)\s*\(\s*([A-Za-z_rRbBuUfF"'(\[])`)
)

// harmlessDestructiveMatch reports a TM1 or TM2 match that only looks
// destructive.
func harmlessDestructiveMatch(ruleID, matched string) bool {
	if ruleID == "TM1" && (httpDeleteEndpoint.MatchString(matched) || commentMarkerPath.MatchString(matched)) {
		return true
	}
	return removesOneRelativeFile(matched)
}

// removesOneRelativeFile reports rm without recursion or glob on one
// relative path: rm -f ../out.docx, rm -f build.log.
func removesOneRelativeFile(matched string) bool {
	start := strings.Index(matched, "rm")
	if start < 0 {
		return false
	}
	removal := singleFileRemoval.FindStringSubmatch(matched[start:])
	if removal == nil || strings.ContainsAny(removal[1], "rR") || strings.Contains(matched, "--recursive") ||
		strings.Contains(matched, "--no-preserve-root") {
		return false
	}
	path := removal[3]
	if strings.ContainsAny(path, "*?[{$~") || strings.HasPrefix(path, "/") || path == "." || path == ".." {
		return false
	}
	// One operand only: nothing but a separator may follow it.
	rest := strings.TrimSpace(matched[start+len(removal[0]):])
	return rest == "" || strings.ContainsAny(rest[:1], "|;&>)")
}

// shellTrueSeverity is MEDIUM for shell=True on a command held in a
// variable (a user-configured command string), HIGH for a literal.
func shellTrueSeverity(matched, severity string) string {
	if call := shellTrueCall.FindStringSubmatch(matched); call != nil && !strings.ContainsAny(call[1][:1], `"'([`) {
		if !strings.ContainsAny(matched[len(call[0]):min(len(matched), len(call[0])+2)], `"'`) {
			return "MEDIUM"
		}
	}
	return severity
}

// keepOneFindingPerLine keeps one finding per file, line, category and rule:
// a behaviour-tagged finding, then the highest severity, then a finding not
// marked for review, then the higher confidence. Order is kept. TM1 and TM2 count as one rule (both report the
// same shell command). Other rules of one category stay apart: AST1 and AST8,
// or EA1 and EA5, on one line report different things.
func keepOneFindingPerLine(findings []model.Finding) []model.Finding {
	better := func(candidate, current model.Finding) bool {
		_, candidateBehaviour := behaviourOf(candidate)
		_, currentBehaviour := behaviourOf(current)
		if candidateBehaviour != currentBehaviour {
			return candidateBehaviour
		}
		if severityRank(candidate.Severity) != severityRank(current.Severity) {
			return severityRank(candidate.Severity) > severityRank(current.Severity)
		}
		_, candidateReview := needsReview(candidate)
		_, currentReview := needsReview(current)
		if candidateReview != currentReview {
			return !candidateReview
		}
		return candidate.Confidence > current.Confidence
	}
	best := map[string]int{}
	result := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Location.StartLine <= 0 {
			result = append(result, finding)
			continue
		}
		rule := finding.ID
		if rule == "TM2" {
			rule = "TM1"
		}
		key := finding.Location.File + "\x00" + fmt.Sprint(finding.Location.StartLine) + "\x00" + finding.Category + "\x00" + rule
		if index, exists := best[key]; exists {
			if better(finding, result[index]) {
				result[index] = finding
			}
			continue
		}
		best[key] = len(result)
		result = append(result, finding)
	}
	return result
}
