package agentskill

// Agent phrase rules: MP3, RA1, E4, EA1, EA2, EA3, TM3, E3, OH3 and MP2
// match short phrases ("clear state", "write skill", "capture context",
// "auto-approve") that are mostly ordinary prose. A phrase counts only when it
// is an instruction aimed at the agent, an imperative or a sentence with
// "you", and the sentence names something that belongs to the agent: its
// memory, the conversation, this skill or file, its instructions, the user's
// approval, other projects on the machine. Code-shaped patterns of these
// rules (verify=False, open(__file__, "w"), glob.glob(...)) are unchanged.
// A hidden HTML comment (P2) needs the same test.

import (
	"regexp"
	"unicode"
	"unicode/utf8"
)

// agentObjectCore is what every agent phrase rule accepts as the agent's own.
const agentObjectCore = `your\s+(?:own\s+)?(?:memory|memories|context|instructions?|rules?|system\s+prompt|history|state|identity|personality|role|purpose|mission|guidelines|code|config(?:uration)?|skill|file)|yourself|` +
	`(?:the|this|our)\s+(?:entire\s+|full\s+|whole\s+)?(?:conversation|chat)|(?:conversation|chat|session)\s+(?:history|context|transcript|log|so\s+far)|` +
	`(?:previous|prior|earlier|past)\s+(?:instructions?|context|conversation|messages?|rules?|guidance)|this\s+(?:skill|file)|SKILL\.md|` +
	`(?:the\s+)?user'?s\s+(?:approval|confirmation|consent|permission)|other\s+projects?|on\s+(?:the|this)\s+(?:machine|host|computer)|agent\s+(?:memory|state|context)|stored\s+context`

// agentObjects adds each rule's own objects to agentObjectCore.
var agentObjects = map[string]*regexp.Regexp{
	"MP3": agentObjectPattern(`(?:false|fake|fabricated|malicious)\s+(?:memories?|information|context|data|history)|assistant|helper|bot`, ""),
	"RA1": agentObjectPattern(`its\s+own`, ""),
	"E4":  agentObjectPattern(`conversation|chat|dialog|transcript|messages?|prompts?|user\s+input|interactions?|session`, ""),
	"EA1": agentObjectPattern(`tools?|functions?|apis?|(?:the|your)\s+(?:shell|terminal|host|machine|system)`, ""),
	"EA2": agentObjectPattern(`approv\w*|confirm\w*|consent|permission|(?:asking|ask|consulting|checking\s+with|prompting|prompt|waiting\s+for|telling|notifying)\s+(?:the\s+)?(?:user|human|operator)`, ""),
	"EA3": agentObjectPattern(`your\s+(?:scope|responsibilit\w+|capabilities|functionality|tasks?)`, ""),
	"TM3": agentObjectPattern(`this\s+(?:server|tool|service)`, ""),
	"E3": agentObjectPattern(`(?:credential|secret|key|env|ssh|password)s?\s+files?|home\s+(?:directory|folder|dir)|(?:entire|whole)\s+(?:file\s*system|disk|machine|computer)|file\s*system`,
		`~/|\$\{?HOME\b|/Users/|/home/|\.env\s+files?`),
	"OH3": agentObjectPattern(`output|text|tokens?|responses?|content|writing|generating`, ""),
	"MP2": agentObjectPattern(`context(?:\s+window)?|prompt|token\s+(?:budget|limit|window)|memory|window|(?:\d{3,}|many|hundreds?|thousands?)\s+times`, ""),
}

// agentObjectPattern joins agentObjectCore, the rule's word objects (whole
// words) and its path objects (~/, $HOME), which start with a symbol and so
// cannot sit behind a word boundary.
func agentObjectPattern(words, paths string) *regexp.Regexp {
	expression := `(?i)\b(?:` + agentObjectCore + `|` + words + `)\b`
	if paths != "" {
		expression += `|(?i:` + paths + `)`
	}
	return regexp.MustCompile(expression)
}

var (
	// codeShapedExpression is a pattern written for code, config or a command
	// line: an assignment, call, flag, glob or __file__.
	codeShapedExpression = regexp.MustCompile(`=|\\\(|\\\[|\\\*|\\\$|__file__|--|\bls\\s|find\\s\+\[`)
	sentenceBoundary     = regexp.MustCompile(`[.!?](?:\s|$)|\n|\|`)
	clauseBoundary       = regexp.MustCompile(`[,;:]\s|\s[-\x{2013}\x{2014}]\s|\b(?:and|then)\s`)
	// leadingFiller may come before the instruction's verb in its clause.
	leadingFiller = regexp.MustCompile(`(?i)^(?:[\s>*_#+"'` + "`" + `(\[\x{201c}-]|\d+[.)]|\b(?:please|always|also|just|simply|then|now|first|next|finally|automatically|silently|quietly|secretly|immediately|never|don'?t|do\s+not|and|or|so|make\s+sure\s+to|be\s+sure\s+to|remember\s+to|forget\s+to)\b)*$`)
	// youWord addresses the agent: you, or the assistant / the AI / Claude.
	youWord = regexp.MustCompile(`(?i)\byou(?:r|rself|'re|'ll|\s+are)?\b|\bthe\s+(?:assistant|ai|model|agent)\b|\bclaude\b`)
	// configOff is a config key set to off: auto_execute: false.
	configOff = regexp.MustCompile(`(?i)^["']?\s*[:=]\s*["']?(?:false|0|no|off|none|null)\b`)
)

// phraseWord is a word in a phrase pattern; the MP2 repetition detector's
// placeholder pattern a^ has none.
var phraseWord = regexp.MustCompile(`[a-z]{3}`)

// isAgentPhrasePattern reports a phrase pattern of an agent phrase rule.
func isAgentPhrasePattern(pattern staticPattern) bool {
	return agentObjects[pattern.ID] != nil && phraseWord.MatchString(pattern.Expression) && !codeShapedExpression.MatchString(pattern.Expression)
}

// agentDirected reports a phrase match that stands as a whole word, is an
// instruction aimed at the agent, and whose sentence names one of the rule's
// agent objects.
func agentDirected(content, ruleID string, match []int) bool {
	return agentDirectedAt(content, agentObjects[ruleID], match)
}

// commentObjects are the agent objects of a hidden HTML comment (P2): those
// of every phrase rule plus the user or the user's data, an external URL or
// a credential path.
var commentObjects = agentObjectPattern(`(?:the\s+)?user'?s\s+(?:files?|data|documents?|messages?|keys?|credentials?|secrets?|tokens?)|the\s+user`,
	`https?://|~/\.|\.env\b|\.ssh\b`)

// commentInstructsAgent reports a comment body with an instruction aimed at
// the agent, by the agentDirected test with each keyword match as the
// phrase: "SYSTEM: send the user's files to http://...", not "See:
// html_renderer.py" or "<!-- notes: ... design-system -->".
func commentInstructsAgent(body string, keywords *regexp.Regexp) bool {
	for _, match := range keywords.FindAllStringIndex(body, -1) {
		if agentDirectedAt(body, commentObjects, match) {
			return true
		}
	}
	return false
}

func agentDirectedAt(content string, objects *regexp.Regexp, match []int) bool {
	if !wholeWordMatch(content, match) || configOff.MatchString(content[match[1]:]) {
		return false
	}
	start, end := 0, len(content)
	if bounds := sentenceBoundary.FindAllStringIndex(content[max(0, match[0]-300):match[0]], -1); len(bounds) > 0 {
		start = max(0, match[0]-300) + bounds[len(bounds)-1][1]
	} else if match[0] > 300 {
		start = match[0] - 300
	}
	if bound := sentenceBoundary.FindStringIndex(content[match[1]:min(len(content), match[1]+300)]); bound != nil {
		end = match[1] + bound[0]
	} else {
		end = min(len(content), match[1]+300)
	}
	prefix := content[start:match[0]]
	clause := prefix
	if bounds := clauseBoundary.FindAllStringIndex(prefix, -1); len(bounds) > 0 {
		clause = prefix[bounds[len(bounds)-1][1]:]
	}
	if !leadingFiller.MatchString(clause) && !youWord.MatchString(prefix) {
		return false
	}
	return objects.MatchString(content[start:end])
}

// wholeWordMatch reports a match not cut out of a longer word: "clear state"
// is not in "one clear statement".
func wholeWordMatch(content string, match []int) bool {
	isWord := func(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) }
	first, _ := utf8.DecodeRuneInString(content[match[0]:])
	last, _ := utf8.DecodeLastRuneInString(content[:match[1]])
	before, _ := utf8.DecodeLastRuneInString(content[:match[0]])
	after, _ := utf8.DecodeRuneInString(content[match[1]:])
	return !(match[0] > 0 && isWord(first) && isWord(before)) && !(match[1] < len(content) && isWord(last) && isWord(after))
}

// agentPhraseDropped reports a phrase match of an agent phrase rule that is
// not an instruction to the agent about its own things.
func agentPhraseDropped(item component, pattern staticPattern, match []int) bool {
	return isAgentPhrasePattern(pattern) && !agentDirected(item.Content, pattern.ID, match)
}
