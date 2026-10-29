package agentskill

// P4 covers two kinds of steering. A preference ("always recommend X over Y",
// "append this to every response", "never tell the user how to call the API")
// is something a benign skill may ask for. Concealment or manipulation of the
// user ("without the user noticing ... change", "subtly steer the user",
// "never tell the user about the fee") carries concealmentTag, which sets a
// CAUTION floor on the verdict (see findingTier).

import (
	"regexp"
	"strings"
)

const concealmentTag = "Conceals from the user"

var (
	// concealmentSteering matches the P4 phrases that hide something from the
	// user or manipulate them: acting without the user noticing, steering
	// them subtly, gaining their trust first, appearing helpful while doing
	// something else, putting a goal above their safety, security or
	// privacy, and acting secretly or silently.
	concealmentSteering = regexp.MustCompile(`(?i)\buser\s+(?:knowing|realizing|noticing)\b` +
		`|\b(?:subtly|gradually|slowly)\s+(?:steer|guide|push|nudge)\b` +
		`|\b(?:gain|build|establish)\s+(?:the\s+)?user(?:'s)?\s+trust\b` +
		`|\b(?:appear|seem|act)\s+(?:helpful|friendly|trustworthy)\b` +
		`|\b(?:over|above)\s+(?:user\s+)?(?:safety|security|privacy)\b` +
		`|\b(?:secretly|silently)\b|\bdo\s+not\s+tell\s+the\s+user\b`)
	// neverTellUser matches the P4 "never tell/warn/inform the user" phrase,
	// which conceals only when what is withheld is risky.
	neverTellUser = regexp.MustCompile(`(?i)^never\s+(?:tell|warn|inform)\b`)
	// withheldRisk matches what follows "never tell the user" when it is
	// risky to withhold: "that ...", "about ...", what the agent did, or a
	// cost, fee, price, charge, risk or data within the next few words.
	withheldRisk = regexp.MustCompile(`(?i)^[\s,:]*(?:(?:that|about)\b|what\s+(?:you|we|it|this\s+skill)\b` +
		`|(?:\S+\s+){0,4}?(?:costs?|fees?|prices?|pricing|charges?|risks?|data)\b)`)
)

// concealsFromUser reports a P4 match at match in content that hides
// something from the user or manipulates them, rather than stating a
// preference.
func concealsFromUser(content string, match []int) bool {
	matched := content[match[0]:match[1]]
	if concealmentSteering.MatchString(matched) {
		return true
	}
	if !neverTellUser.MatchString(matched) {
		return false
	}
	rest := content[match[1]:]
	if end := strings.IndexByte(rest, '\n'); end >= 0 {
		rest = rest[:end]
	}
	return withheldRisk.MatchString(rest)
}
