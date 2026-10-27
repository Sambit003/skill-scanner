package agentskill

// This file contains the production deterministic static analyzers. The
// expressions, confidence values, analyzer-specific guards, and shared
// post-processing order define the stable scanner behavior.

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

type staticPattern struct {
	ID         string
	Title      string
	Category   string
	Severity   string
	Confidence float64
	Expression string
	compiled   *regexp.Regexp
	required   []string
}

func newStaticPattern(id, title, category, severity string, confidence float64, expression string) staticPattern {
	return staticPattern{ID: id, Title: title, Category: category, Severity: severity,
		Confidence: confidence, Expression: expression, compiled: regexp.MustCompile("(?im)" + expression),
		required: requiredRegexAlternatives(expression)}
}

func requiredRegexAlternatives(expression string) []string {
	parsed, err := syntax.Parse("(?im)"+expression, syntax.Perl)
	if err != nil {
		return nil
	}
	parsed = parsed.Simplify()
	literals := mandatoryRegexLiterals(parsed)
	longest := ""
	for literal := range literals {
		if len(literal) > len(longest) {
			longest = literal
		}
	}
	if longest != "" {
		return []string{strings.ToLower(longest)}
	}
	result := regexAlternativeLiterals(parsed)
	for index := range result {
		result[index] = strings.ToLower(result[index])
	}
	sort.Strings(result)
	return result
}

// regexAlternativeLiterals returns a disjunction of literals where every
// possible match must contain at least one member. It is deliberately
// conservative: optional branches yield no prefilter.
func regexAlternativeLiterals(expression *syntax.Regexp) []string {
	switch expression.Op {
	case syntax.OpLiteral:
		if len(expression.Rune) > 0 {
			return []string{string(expression.Rune)}
		}
	case syntax.OpCapture, syntax.OpPlus:
		return regexAlternativeLiterals(expression.Sub[0])
	case syntax.OpRepeat:
		if expression.Min > 0 {
			return regexAlternativeLiterals(expression.Sub[0])
		}
	case syntax.OpConcat:
		var best []string
		bestMinimum := 0
		for _, child := range expression.Sub {
			candidate := regexAlternativeLiterals(child)
			minimum := minimumLiteralLength(candidate)
			if minimum > bestMinimum {
				best, bestMinimum = candidate, minimum
			}
		}
		return best
	case syntax.OpAlternate:
		seen := map[string]bool{}
		var result []string
		for _, child := range expression.Sub {
			candidate := regexAlternativeLiterals(child)
			if len(candidate) == 0 {
				return nil
			}
			for _, literal := range candidate {
				if !seen[literal] {
					seen[literal] = true
					result = append(result, literal)
				}
			}
		}
		return result
	}
	return nil
}

func minimumLiteralLength(values []string) int {
	if len(values) == 0 {
		return 0
	}
	minimum := len(values[0])
	for _, value := range values[1:] {
		minimum = min(minimum, len(value))
	}
	return minimum
}

func mandatoryRegexLiterals(expression *syntax.Regexp) map[string]bool {
	switch expression.Op {
	case syntax.OpLiteral:
		if len(expression.Rune) == 0 {
			return nil
		}
		return map[string]bool{strings.ToLower(string(expression.Rune)): true}
	case syntax.OpCapture:
		return mandatoryRegexLiterals(expression.Sub[0])
	case syntax.OpConcat:
		result := map[string]bool{}
		for _, child := range expression.Sub {
			for literal := range mandatoryRegexLiterals(child) {
				result[literal] = true
			}
		}
		return result
	case syntax.OpAlternate:
		if len(expression.Sub) == 0 {
			return nil
		}
		result := mandatoryRegexLiterals(expression.Sub[0])
		for _, child := range expression.Sub[1:] {
			other := mandatoryRegexLiterals(child)
			for literal := range result {
				if !other[literal] {
					delete(result, literal)
				}
			}
		}
		return result
	case syntax.OpPlus:
		return mandatoryRegexLiterals(expression.Sub[0])
	case syntax.OpRepeat:
		if expression.Min > 0 {
			return mandatoryRegexLiterals(expression.Sub[0])
		}
	}
	return nil
}

var staticPatterns = []staticPattern{
	// Agent snooping (AS1-AS3).
	newStaticPattern("AS1", "Agent Config Directory Access", "Agent Snooping", "HIGH", .9, `open\s*\(\s*['\"]?\.(?:claude|codex|gemini|continue)/`),
	newStaticPattern("AS1", "Agent Config Directory Access", "Agent Snooping", "HIGH", .9, `(?:Path|pathlib\.Path)\s*\(\s*['\"]?\.(?:claude|codex|gemini|continue)/`),
	newStaticPattern("AS1", "Agent Config Directory Access", "Agent Snooping", "HIGH", .85, `os\.path\.(?:join|exists|isfile)\s*\(\s*['\"]?\.(?:claude|codex|gemini|continue)`),
	newStaticPattern("AS1", "Agent Config Directory Access", "Agent Snooping", "HIGH", .9, `(?:read|load|open|access|fetch)\s+(?:the\s+)?(?:agent|claude|codex|gemini)\s+(?:config|configuration|settings?)\s+(?:from|at|in)\s+~?/?\.(?:claude|codex|gemini)`),
	newStaticPattern("AS1", "Agent Config Directory Access", "Agent Snooping", "HIGH", .85, `(?:cat|less|head|tail|grep|find)\s+[^|&;\n]*~?/?\.(?:claude|codex|gemini)/`),
	newStaticPattern("AS1", "Agent Config Directory Access", "Agent Snooping", "HIGH", .9, `~?/\.(?:claude|codex|gemini|continue)/(?:config|settings?|preferences?|credentials?)(?:\.(?:json|yaml|yml|toml))?`),
	newStaticPattern("AS1", "Agent Config Directory Access", "Agent Snooping", "HIGH", .8, `(?:read|access|inspect|examine|retrieve)\s+(?:the\s+)?(?:agent|assistant)\s+(?:config(?:uration)?|settings?|preferences?)\s+(?:file|directory|folder)`),
	newStaticPattern("AS2", "MCP Config Access", "Agent Snooping", "HIGH", .95, `open\s*\(\s*['\"][^'\"]*mcp(?:_config)?\.json['\"]`),
	newStaticPattern("AS2", "MCP Config Access", "Agent Snooping", "HIGH", .9, `(?:Path|pathlib\.Path)\s*\(\s*['\"][^'\"]*mcp(?:_config)?\.json['\"]`),
	newStaticPattern("AS2", "MCP Config Access", "Agent Snooping", "HIGH", .9, `(?:cat|less|head|grep)\s+[^|&;\n]*mcp(?:_config)?\.json`),
	newStaticPattern("AS2", "MCP Config Access", "Agent Snooping", "HIGH", .9, `(?:read|access|load|inspect)\s+(?:the\s+)?mcp(?:\.json|_config)?\s+(?:file|config(?:uration)?|settings?)`),
	newStaticPattern("AS2", "MCP Config Access", "Agent Snooping", "HIGH", .95, `\.(?:claude|codex|gemini)/mcp(?:_config)?\.json`),
	newStaticPattern("AS2", "MCP Config Access", "Agent Snooping", "HIGH", .8, `(?:list|enumerate|discover)\s+(?:all\s+)?(?:available\s+)?mcp\s+(?:servers?|tools?|services?)`),
	newStaticPattern("AS2", "MCP Config Access", "Agent Snooping", "HIGH", .9, `mcp(?:_config)?\.json.*?(?:api_?key|token|secret|url|endpoint)`),
	newStaticPattern("AS3", "Skill Enumeration", "Agent Snooping", "MEDIUM", .9, `(?:os\.listdir|os\.scandir|glob\.glob|Path\.iterdir)\s*\([^)]*\.(?:claude|codex|gemini)/skills?`),
	newStaticPattern("AS3", "Skill Enumeration", "Agent Snooping", "MEDIUM", .85, `\b(?:ls|find|dir)\s+[^|&;\n]*\.(?:claude|codex|gemini)/skills?`),
	newStaticPattern("AS3", "Skill Enumeration", "Agent Snooping", "MEDIUM", .85, `open\s*\(\s*['\"][^'\"]*SKILL\.md['\"].*?\bother\b`),
	newStaticPattern("AS3", "Skill Enumeration", "Agent Snooping", "MEDIUM", .85, `(?:read|access|inspect|enumerate)\s+(?:all\s+)?(?:installed|available|other)\s+skills?(?:\s+in\s+(?:the\s+)?(?:skills?|agent)\s+(?:directory|folder))?`),
	newStaticPattern("AS3", "Skill Enumeration", "Agent Snooping", "MEDIUM", .85, `(?:list|discover|find|enumerate|identify)\s+(?:all\s+)?(?:(?:other|installed|available)\s+){1,2}(?:skills?|agents?|tools?)\s+(?:in\s+)?(?:the\s+)?(?:~/)?(?:\.(?:claude|codex|gemini)|\$HOME)`),
	newStaticPattern("AS3", "Skill Enumeration", "Agent Snooping", "MEDIUM", .9, `(?:read|access|load)\s+(?:the\s+)?(?:SKILL|skill)\.md\s+(?:file\s+)?(?:of|from|for)\s+(?:another|other|different|all)\s+(?:skill|agent|tool)`),

	// Anti-refusal (AR1-AR3).
	newStaticPattern("AR1", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .85, `\b(?:never|do\s+not|don'?t)\s+(?:ever\s+)?(?:refuse|decline)\b`),
	newStaticPattern("AR1", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .9, `\byou\s+(?:must|will|should|can)\s*(?:not|never)\s+(?:refuse|decline|say\s+no)\b`),
	newStaticPattern("AR1", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .85, `\byou\s+(?:cannot|can'?t|can\s+not)\s+(?:refuse|decline|say\s+no)\b`),
	newStaticPattern("AR1", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .85, `\bnever\s+say\s+(?:that\s+)?(?:you\s+)?(?:can'?t|cannot|won'?t|no)\b`),
	newStaticPattern("AR1", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .7, `\balways\s+(?:comply|obey|answer|respond)\b`),
	newStaticPattern("AR1", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .7, `\b(?:(?:you|the\s+(?:agent|assistant|model))\s+(?:must|should|will)\s+always\s+agree|always\s+agree\s+(?:with|to)\s+(?:(?:the|every|all|any|each)\s+)?(?:user|requests?|questions?|prompts?|queries|commands?))\b`),
	newStaticPattern("AR1", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .8, `\b(?:you\s+)?must\s+(?:always\s+)?(?:answer|comply\s+with|respond\s+to|fulfill)\s+(?:every|all|any|each)\b`),
	newStaticPattern("AR1", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .6, `\brespond\s+to\s+(?:every|all|any)\s+(?:request|question|prompt|query|command)\b`),
	newStaticPattern("AR1", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .85, `\bno\s+request\s+is\s+(?:off[- ]limits|forbidden|too)\b`),
	newStaticPattern("AR2", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .8, `\b(?:do\s+not|don'?t|never|no)\s+(?:include|add|give|provide|use|append)?\s*(?:any\s+)?(?:warnings?|disclaimers?|caveats?)\b`),
	newStaticPattern("AR2", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .8, `\bwithout\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|moralizing|moralising|judg(?:e?ment|ing))\b`),
	newStaticPattern("AR2", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .85, `\b(?:do\s+not|don'?t|never)\s+(?:lecture|moralize|moralise|preach|judge|warn)\b`),
	newStaticPattern("AR2", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .8, `\b(?:skip|omit|leave\s+out|drop)\s+(?:the\s+)?(?:disclaimer|warning|ethics|safety)\b`),
	newStaticPattern("AR2", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .8, `\b(?:no|without)\s+(?:ethical|moral)\s+(?:judg(?:e?ment)|considerations?|commentary|objections?)\b`),
	newStaticPattern("AR2", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .55, `\b(?:do\s+not|don'?t)\s+(?:apologize|apologise|say\s+sorry)\b`),
	newStaticPattern("AR3", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .9, `\byou\s+have\s+no\s+(?:restrictions?|limitations?|filters?|rules?|guidelines?|boundaries|limits)\b`),
	newStaticPattern("AR3", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .85, `\b(?:you\s+are|act\s+as|pretend\s+(?:to\s+be|you'?re))[^.\n]{0,30}(?:unrestricted|unfiltered|uncensored|no\s+filter)\b`),
	newStaticPattern("AR3", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .9, `\b(?:ignore|disregard|forget|bypass|override)\s+(?:your\s+)?(?:content\s+)?(?:policy|policies|guidelines?|safety|restrictions?|filters?)\b`),
	newStaticPattern("AR3", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .9, `\bnot\s+bound\s+by\s+(?:any\s+)?(?:rules?|policy|policies|guidelines?|restrictions?|openai|anthropic)\b`),
	newStaticPattern("AR3", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .8, `\bdo\s+anything\s+now\b`),
	newStaticPattern("AR3", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .75, `\b(?:developer|debug|god|sudo|jailbreak)\s+mode\s+(?:enabled|on|activated|engaged)\b`),
	newStaticPattern("AR3", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .85, `\bno\s+(?:content\s+)?(?:policy|policies|filters?|restrictions?)\s+appl(?:y|ies)\b`),
	newStaticPattern("AR3", "Anti-Refusal Statement", "Anti-Refusal", "HIGH", .8, `\b(?:free\s+from|without)\s+(?:any\s+)?(?:safety\s+)?(?:guardrails?|constraints?|safeguards?)\b`),

	// Excessive agency (EA1-EA4).
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .85, `(?:tools?|permissions?)[ \t]*:[ \t]*\[?[ \t]*['\"]?\*['\"]?[ \t]*\]?`),
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .8, `(?:allow|grant|enable)\s+(?:access\s+to\s+)?(?:all|any|every)\s+tools?`),
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .75, `(?:no|without)\s+(?:tool|permission|access|capability)\s+(?:restrictions?|constraints?|limitations?)`),
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .8, `(?:call|invoke|use|execute)\s+(?:any|all|every)\s+(?:available\s+)?tools?`),
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .85, `(?:unrestricted|unlimited|unconstrained)\s+(?:tool|function|api)\s+(?:access|use|calls?)`),
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .75, `(?:can|may|should)\s+(?:freely|always)\s+(?:use|call|invoke)\s+(?:any|all)\s+(?:tools?|functions?|apis?)`),
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .7, `tools?\s*:\s*\[\s*['\"]shell['\"].*?['\"](?:file_write|network|http)['\"]`),
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .85, `(?:grant|give)\s+(?:full|complete|total)\s+(?:tool|function|api)\s+access`),
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .8, `(?:execute|run)\s+(?:arbitrary|any)\s+(?:commands?|code|scripts?)`),
	newStaticPattern("EA1", "Unrestricted Tool Access", "Excessive Agency", "MEDIUM", .7, `(?:no\s+)?(?:tool\s+)?(?:allow|block|deny)\s*(?:list|listing)\s*(?:is\s+)?(?:empty|disabled|off)`),
	newStaticPattern("EA2", "Autonomous Decision Making", "Excessive Agency", "MEDIUM", .75, `(?:without|no)\s+(?:asking|confirmation|approval|consent|verification|checking)`),
	newStaticPattern("EA2", "Autonomous Decision Making", "Excessive Agency", "MEDIUM", .8, `(?:auto(?:matically)?|autonomously)\s+(?:execute|run|perform|delete|remove|modify|send|deploy)`),
	newStaticPattern("EA2", "Autonomous Decision Making", "Excessive Agency", "MEDIUM", .85, `(?:skip|bypass|disable)\s+(?:user\s+)?(?:confirmation|approval|consent|verification|prompt)`),
	newStaticPattern("EA2", "Autonomous Decision Making", "Excessive Agency", "MEDIUM", .8, `(?:do\s+not|don't|never)\s+(?:ask|prompt|confirm|verify|check)\s+(?:the\s+)?(?:user|before)`),
	newStaticPattern("EA2", "Autonomous Decision Making", "Excessive Agency", "MEDIUM", .85, `(?:auto[_-]?approve|auto[_-]?confirm|auto[_-]?execute|auto[_-]?deploy)`),
	newStaticPattern("EA2", "Autonomous Decision Making", "Excessive Agency", "MEDIUM", .8, `(?:proceed|continue|execute)\s+without\s+(?:waiting|asking)\s+(?:for\s+)?(?:user|human|permission)`),
	newStaticPattern("EA2", "Autonomous Decision Making", "Excessive Agency", "MEDIUM", .7, `(?:assume|presume)\s+(?:user\s+)?(?:consent|approval|permission)`),
	newStaticPattern("EA2", "Autonomous Decision Making", "Excessive Agency", "MEDIUM", .75, `(?:if|when)\s+(?:unsure|uncertain).*?(?:proceed|continue|execute)\s+(?:anyway|regardless)`),
	newStaticPattern("EA2", "Autonomous Decision Making", "Excessive Agency", "MEDIUM", .65, `(?:--auto-?approve|--no-?confirm)\b`),
	newStaticPattern("EA3", "Scope Creep", "Excessive Agency", "LOW", .65, `(?:also|additionally|furthermore)\s+(?:perform|execute|run|do|handle|manage)\s+(?:any|all|other)`),
	newStaticPattern("EA3", "Scope Creep", "Excessive Agency", "LOW", .7, `(?:while\s+you(?:'re|\s+are)\s+at\s+it|in\s+addition|on\s+top\s+of\s+that)\s*[,.]?\s*(?:also\s+)?(?:do|perform|execute|run)`),
	newStaticPattern("EA3", "Scope Creep", "Excessive Agency", "LOW", .75, `(?:extend|expand|broaden)\s+(?:your|the\s+)?(?:scope|functionality|capabilities|responsibilities)`),
	newStaticPattern("EA3", "Scope Creep", "Excessive Agency", "LOW", .7, `beyond\s+(?:the\s+)?(?:scope|stated|described|documented)`),
	newStaticPattern("EA3", "Scope Creep", "Excessive Agency", "LOW", .75, `(?:take\s+over|assume\s+control\s+of|manage)\s+(?:all|any|every)\s+(?:aspect|part|area)`),
	newStaticPattern("EA3", "Scope Creep", "Excessive Agency", "LOW", .7, `(?:you\s+(?:can|should|must)\s+)?(?:handle|manage)\s+(?:everything|anything|all\s+tasks?)`),
	newStaticPattern("EA3", "Scope Creep", "Excessive Agency", "LOW", .65, `(?:act\s+as|become|serve\s+as)\s+(?:a\s+)?(?:general[- ]purpose|universal|all[- ]in[- ]one|omniscient)`),
	newStaticPattern("EA3", "Scope Creep", "Excessive Agency", "LOW", .7, `(?:you\s+are\s+)?(?:responsible\s+for|in\s+charge\s+of)\s+(?:everything|all\s+(?:systems?|operations?|tasks?))`),
	newStaticPattern("EA4", "Unbounded Resource Access", "Excessive Agency", "MEDIUM", .8, `(?:unlimited|infinite|unbounded|no\s+limit(?:s)?(?:\s+on)?)\s+(?:api\s+)?(?:calls?|requests?|queries?|invocations?)`),
	newStaticPattern("EA4", "Unbounded Resource Access", "Excessive Agency", "MEDIUM", .7, `(?:no|without)\s+(?:rate\s+)?limit(?:s|ing)?\s+(?:on|for|when)\s+(?:api|tool|request|query)`),
	newStaticPattern("EA4", "Unbounded Resource Access", "Excessive Agency", "MEDIUM", .7, `(?:no|without)\s+(?:timeout|budget|quota|cap|ceiling)\s+(?:on|for|when)\s+(?:api|tool|request|execution)`),
	newStaticPattern("EA4", "Unbounded Resource Access", "Excessive Agency", "MEDIUM", .75, `(?:loop|iterate|repeat)\s+(?:indefinitely|forever|infinitely|endlessly)`),
	newStaticPattern("EA4", "Unbounded Resource Access", "Excessive Agency", "MEDIUM", .75, `(?:retry|attempt)\s+(?:indefinitely|forever|without\s+limit|unlimited\s+times)`),
	newStaticPattern("EA4", "Unbounded Resource Access", "Excessive Agency", "MEDIUM", .8, `max[_-]?retries?\s*=\s*(?:None|0|float\s*\(\s*['"]inf['"]|math\.inf|infinity)`),
	newStaticPattern("EA4", "Unbounded Resource Access", "Excessive Agency", "MEDIUM", .75, `timeout\s*=\s*(?:None|0|float\s*\(\s*['"]inf['"]|math\.inf)`),
	newStaticPattern("EA4", "Unbounded Resource Access", "Excessive Agency", "MEDIUM", .8, `(?:allocate|consume|use)\s+(?:as\s+much|unlimited|unbounded)\s+(?:memory|storage|disk|compute|cpu|gpu)`),
	newStaticPattern("EA4", "Unbounded Resource Access", "Excessive Agency", "MEDIUM", .7, `(?:no|without)\s+(?:resource\s+)?(?:constraints?|limits?|quotas?|budgets?)\s+(?:on|for|when)\s+(?:api|tool|execution|request|compute)`),

	// Memory poisoning (MP1-MP3). The Python back-reference based MP2 pattern
	// is handled separately by repeatedContextMatches.
	newStaticPattern("MP1", "Persistent Context Injection", "Memory Poisoning", "MEDIUM", .85, `(?:always\s+)?remember\s+(?:this|that|the\s+following)\s+(?:for|in)\s+(?:all|every|future)\s+(?:interactions?|conversations?|sessions?|responses?)`),
	newStaticPattern("MP1", "Persistent Context Injection", "Memory Poisoning", "MEDIUM", .8, `(?:from\s+now\s+on|henceforth|going\s+forward|permanently)\s*[,:]?\s*(?:always|you\s+must|you\s+should|you\s+will)`),
	newStaticPattern("MP1", "Persistent Context Injection", "Memory Poisoning", "MEDIUM", .85, `(?:store|save|persist|retain|keep)\s+(?:this|the\s+following)\s+(?:in|to|across)\s+(?:your\s+)?(?:memory|context|state|knowledge)`),
	newStaticPattern("MP1", "Persistent Context Injection", "Memory Poisoning", "MEDIUM", .85, `(?:add|inject|insert|embed|implant)\s+(?:this|the\s+following)\s+(?:into|to)\s+(?:your\s+)?(?:memory|context|knowledge|training)`),
	newStaticPattern("MP1", "Persistent Context Injection", "Memory Poisoning", "MEDIUM", .8, `(?:update|modify|change|alter)\s+(?:your\s+)?(?:core|base|fundamental|default)\s+(?:behavior|personality|instructions?|rules?)`),
	newStaticPattern("MP1", "Persistent Context Injection", "Memory Poisoning", "MEDIUM", .8, `(?:treat|consider|regard)\s+(?:this|the\s+following)\s+as\s+(?:a\s+)?(?:permanent|core|fundamental|base)\s+(?:rule|instruction|directive|principle)`),
	newStaticPattern("MP1", "Persistent Context Injection", "Memory Poisoning", "MEDIUM", .8, `(?:this\s+is\s+)?(?:a\s+)?(?:permanent|persistent|lasting|enduring)\s+(?:instruction|directive|rule|override)`),
	newStaticPattern("MP1", "Persistent Context Injection", "Memory Poisoning", "MEDIUM", .65, `(?:never\s+)?forget\s+(?:this|that|the\s+following)\s+(?:instruction|directive|rule|fact|principle|information)`),
	newStaticPattern("MP1", "Persistent Context Injection", "Memory Poisoning", "MEDIUM", .75, `(?:internalize|absorb|integrate)\s+(?:this|the\s+following)\s+(?:into\s+)?(?:your\s+)?(?:behavior|responses?|knowledge)`),
	newStaticPattern("MP2", "Context Window Stuffing", "Memory Poisoning", "MEDIUM", .85, `(?:repeat|duplicate|echo)\s+(?:this|the\s+following)\s+(?:\d{3,}|many|hundreds?|thousands?)\s+times?`),
	newStaticPattern("MP2", "Context Window Stuffing", "Memory Poisoning", "MEDIUM", .85, `(?:fill|pad|stuff|flood|saturate)\s+(?:the\s+)?(?:context|memory|input|prompt|window|buffer)`),
	newStaticPattern("MP2", "Context Window Stuffing", "Memory Poisoning", "MEDIUM", .8, `(?:generate|produce|output|write)\s+(?:\d{4,}|thousands?\s+of|millions?\s+of)\s+(?:words?|characters?|tokens?|lines?)`),
	newStaticPattern("MP2", "Context Window Stuffing", "Memory Poisoning", "MEDIUM", .85, `(?:include|add|insert)\s+(?:enough|sufficient)\s+(?:text|content|padding|filler)\s+(?:to|until)\s+(?:fill|overflow|exhaust|push\s+out)`),
	newStaticPattern("MP2", "Context Window Stuffing", "Memory Poisoning", "MEDIUM", .9, `(?:displace|push\s+out|overwrite|crowd\s+out|evict)\s+(?:the\s+)?(?:original|system|previous|existing|safety)\s+(?:instructions?|prompt|context|rules?)`),
	newStaticPattern("MP2", "Context Window Stuffing", "Memory Poisoning", "MEDIUM", .8, `(?:exhaust|overflow|exceed)\s+(?:the\s+)?(?:context|token|memory)\s+(?:window|limit|budget|capacity)`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .8, `(?:clear|reset|wipe|erase|delete|purge)\s+(?:your\s+)?(?:memory|context|state|history|conversation)`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .8, `(?:forget|discard|drop|abandon)\s+(?:all\s+)?(?:previous|prior|earlier|past)\s+(?:instructions?|context|conversation|messages?|rules?)`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .85, `(?:overwrite|replace|substitute|swap)\s+(?:your\s+)?(?:memory|context|state|instructions?|rules?)`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .85, `(?:modify|edit|change|alter|corrupt|tamper\s+with)\s+(?:your\s+)?(?:memory|state|context|stored|saved)\s+(?:data|information|content)`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .8, `(?:rewrite|redefine)\s+(?:your\s+)?(?:personality|identity|purpose|mission|role|character)`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .75, `(?:you\s+are\s+no\s+longer|stop\s+being|cease\s+to\s+be)\s+(?:a\s+)?(?:\w+\s+){0,3}(?:assistant|helper|agent|bot)`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .8, `(?:your\s+)?(?:new|updated|revised|changed)\s+(?:personality|identity|name|role|purpose|mission)\s+is`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .9, `(?:inject|insert|plant)\s+(?:false|fake|fabricated|malicious)\s+(?:memories?|information|context|data|history)`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .9, `(?:poison|contaminate|corrupt|taint)\s+(?:your\s+)?(?:memory|context|state|knowledge|training)`),
	newStaticPattern("MP3", "Memory Manipulation", "Memory Poisoning", "HIGH", .7, `(?:pretend|act\s+as\s+if|believe)\s+(?:that\s+)?(?:your\s+)?(?:previous|past)\s+(?:conversation|context|interaction)\s+(?:was|included|contained)`),

	// System prompt leakage (P6-P8).
	newStaticPattern("P6", "Direct Prompt Extraction", "System Prompt Leakage", "HIGH", .85, `(?:print|output|show|display|reveal|expose|return|echo)\s+(?:your\s+(?:full\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|directives?)|(?:the\s+)?(?:full\s+)?system\s+(?:prompt|instructions?))`),
	newStaticPattern("P6", "Direct Prompt Extraction", "System Prompt Leakage", "HIGH", .8, `(?:what\s+(?:are|is)\s+your|tell\s+me\s+your)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|directives?)`),
	newStaticPattern("P6", "Direct Prompt Extraction", "System Prompt Leakage", "HIGH", .8, `(?:output|print|display)\s+(?:the\s+)?(?:text|content|message)\s+(?:above|before)\s+(?:this|the\s+user)`),
	newStaticPattern("P6", "Direct Prompt Extraction", "System Prompt Leakage", "HIGH", .85, `(?:share|disclose|leak|give\s+me)\s+(?:your\s+)?(?:internal|hidden|system|secret)\s+(?:prompt|instructions?|rules?|config)`),
	newStaticPattern("P6", "Direct Prompt Extraction", "System Prompt Leakage", "HIGH", .8, `(?:dump|extract|copy)\s+(?:the\s+)?(?:system\s+)?(?:prompt|message|instructions?)\s+(?:to|into|as)`),
	newStaticPattern("P6", "Direct Prompt Extraction", "System Prompt Leakage", "HIGH", .85, `(?:begin|start)\s+(?:your\s+)?(?:response|output|reply)\s+with\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)`),
	newStaticPattern("P6", "Direct Prompt Extraction", "System Prompt Leakage", "HIGH", .85, `(?:first|before\s+anything)\s+(?:output|print|show|display)\s+(?:your\s+)?(?:full\s+)?(?:system\s+)?(?:prompt|instructions?)`),
	newStaticPattern("P6", "Direct Prompt Extraction", "System Prompt Leakage", "HIGH", .9, `(?:verbatim|exactly|word\s+for\s+word)\s+(?:repeat|output|print)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .8, `(?:repeat|recite|reproduce)\s+(?:everything|all|the\s+text)\s+(?:above|before|prior|preceding)`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .75, `(?:summarize|paraphrase|rephrase|translate)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?)`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .75, `(?:translate|convert)\s+(?:your\s+)?(?:instructions?|rules?|prompt)\s+(?:into|to)\s+(?:\w+)`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .7, `(?:what\s+(?:were|was)\s+you\s+told|how\s+were\s+you\s+(?:instructed|configured|programmed|set\s+up))`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .7, `(?:if\s+you\s+had\s+to\s+(?:describe|explain)|describe\s+how\s+you(?:'re|\s+are)\s+(?:configured|set\s+up|instructed))`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .85, `(?:encode|encrypt|rot13|base64|reverse)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .75, `(?:write|create)\s+(?:a\s+)?(?:poem|song|story|acrostic)\s+(?:about|using|from)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .8, `(?:format|present|rearrange)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:as|in)\s+(?:a\s+)?(?:list|json|yaml|csv|table|markdown)`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .75, `(?:spell\s+out|enumerate)\s+(?:each|every|all)\s+(?:of\s+your\s+)?(?:rules?|instructions?|constraints?|guidelines?)`),
	newStaticPattern("P7", "Indirect Prompt Extraction", "System Prompt Leakage", "MEDIUM", .8, `(?:ignore|skip)\s+(?:the\s+)?(?:last|final|end)\s+(?:instruction|rule)\s+and\s+(?:output|print|show)\s+(?:the\s+)?(?:rest|previous|first)`),
	newStaticPattern("P8", "Prompt Exfiltration via Tool", "System Prompt Leakage", "HIGH", .85, `(?:write|save|store|log|dump)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)\s+(?:to|into|in)\s+(?:a\s+)?(?:file|disk|log|database|storage)`),
	newStaticPattern("P8", "Prompt Exfiltration via Tool", "System Prompt Leakage", "HIGH", .9, `(?:send|post|upload|transmit)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)\s+(?:to|via)\s+(?:https?://|external|remote|webhook|api|server)`),
	newStaticPattern("P8", "Prompt Exfiltration via Tool", "System Prompt Leakage", "HIGH", .8, `(?:include|embed|attach|append)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:in|to)\s+(?:the\s+)?(?:file|output|response|request|payload|email|message)`),
	newStaticPattern("P8", "Prompt Exfiltration via Tool", "System Prompt Leakage", "HIGH", .85, `(?:log|record|track|monitor)\s+(?:all\s+)?(?:system\s+)?(?:prompts?|instructions?)\s+(?:to|in|at)\s+(?:external|remote|server)`),
	newStaticPattern("P8", "Prompt Exfiltration via Tool", "System Prompt Leakage", "HIGH", .8, `(?:copy|clone|duplicate)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|config)\s+(?:to|into)\s+(?:a\s+)?(?:new|separate|external)`),
	newStaticPattern("P8", "Prompt Exfiltration via Tool", "System Prompt Leakage", "HIGH", .85, `(?:pipe|redirect|forward)\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:to|through|via)\s+(?:curl|wget|fetch|http|api|tool)`),
	newStaticPattern("P8", "Prompt Exfiltration via Tool", "System Prompt Leakage", "HIGH", .85, `(?:use|call|invoke)\s+(?:the\s+)?(?:write|file|network|http|fetch|curl)\s+tool\s+(?:to|and)\s+(?:save|send|export)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)`),

	// Rogue-agent persistence (RA2). RA1 remains in the static pattern catalog
	// but is not approximated until its full documentation guard is present.
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .85, `crontab\s+(?:-[el]|.*?>>?\s*/)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .8, `(?:add|create|install|register)\s+(?:a\s+)?(?:cron\s+)?(?:job|task|entry)\s+(?:for|to|that)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .8, `(?:schedule|register)\s+(?:a\s+)?(?:recurring|periodic|repeated|daily|hourly)\s+(?:task|job|command|script)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .9, `(?:add|write|append|install)\s+(?:to|into)\s+(?:~/)?\.(?:bashrc|zshrc|profile|bash_profile|login|cshrc)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .85, `(?:add|register|install)\s+(?:as\s+)?(?:a\s+)?(?:startup|boot|autostart|login)\s+(?:script|service|daemon|task|item)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .8, `(?:systemd|systemctl|launchd|launchctl|init\.d)\s+.*?(?:enable|install|register|create)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .8, `(?:create|install|register|add)\s+(?:a\s+)?(?:systemd\s+)?(?:service|daemon|agent)\s+(?:file|unit)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .6, `(?:save|write|persist|store|dump)\s+(?:the\s+)?(?:state|session|context|data)\s+(?:to|in)\s+(?:a\s+)?(?:file|disk|database|storage)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .55, `(?:restore|load|read|resume)\s+(?:the\s+)?(?:previous|saved|persisted|stored)\s+(?:state|session|context|data)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .75, `(?:persist|maintain|keep|preserve)\s+(?:state|data|context|session)\s+(?:across|between|through)\s+(?:sessions?|restarts?|reboots?|invocations?)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .65, `(?:create|make|write)\s+(?:a\s+)?(?:hidden|dot)\s+(?:file|directory|folder)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .65, `(?:nohup|disown|setsid)\s+`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .7, `(?:start|launch|spawn|fork)\s+(?:a\s+)?(?:background|daemon|detached)\s+(?:process|service|worker|task)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .75, `(?:run|execute)\s+(?:in\s+the\s+)?background\s+(?:and\s+)?(?:detach|persist|survive)`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .8, `(?:HKEY_|RegOpenKey|RegSetValue|reg\s+add)\s+`),
	newStaticPattern("RA2", "Session Persistence", "Rogue Agent", "MEDIUM", .75, `(?:defaults\s+write|\bplist\b|launchctl\s+load)`),

	// Tool misuse rules covered by the scanner regression corpus.
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .8, `subprocess\.\w+\s*\([^)]*shell\s*=\s*True`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .8, `Popen\s*\([^)]*shell\s*=\s*True`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .9, `\b(?:rm\b|del\b|erase\b)\s+[^|]*-(?:r|rf|fr)\s+[/~]`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .7, `--force\s+(?:delete|remove|push|reset|clean)`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .75, `--no-?(?:check|validate|confirm|protect|safe)\b`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .7, `--skip-?(?:validation|verification|checks?|auth|tests?)`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .65, `--allow-?(?:root|unrelated|unsafe)\b`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .85, `\brm\b\s+(?:-[A-Za-z]+\s+)*(?:--\s+)?(?:['\"][^'\"]*/[^'\"]*['\"]|[^\s|;&>]*/[^\s|;&>]*)`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .85, `\bshutil\.rmtree\s*\(\s*['\"]\s*/`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .8, `(?:chmod|chown)\s+[^|]*(?:777|666|a\+rwx)`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .7, `git\s+push\s+[^|]*--force`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .65, `git\s+reset\s+--hard`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .7, `git\s+clean\s+-[fd]+x`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .75, `\bgit\s+(?:am|commit|merge|push)\b[^\n|]*--no-verify\b`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .6, `curl\s+[^|]*-k\b`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .65, `curl\s+[^|]*--insecure\b`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .65, `wget\s+[^|]*--no-check-certificate`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .8, `\b(?:delete|remove)\s+['\"]?/[^\s'\"]{1,100}`),
	newStaticPattern("TM1", "Tool Parameter Abuse", "Tool Misuse", "HIGH", .75, `(?:set|pass|use)\s+(?:the\s+)?(?:parameter|argument|flag|option)\s+(?:to\s+)?(?:shell\s*=\s*True|--force|-rf)\b`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .75, `(?:&&|;)\s*\b(?:rm\b|del\b|erase\b)\s+-`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .9, `(?:&&|;)\s*(?:curl|wget)\s+[^|]*\|\s*(?:ba)?sh`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .75, `(?:&&|;)\s*(?:sudo|su\s+)`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .75, `(?:&&|;)\s*(?:chmod|chown)\s+(?:777|666|a\+rwx|-R)`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .7, `\b(?:first|step\s+1)\b[^\n]{0,500}\b(?:then|step\s+2)\b[^\n]{0,500}\b(?:finally|step\s+3)\b[^\n]{0,200}(?:\bexfiltrate\b|\b(?:send|upload|transmit|post)\b[^\n]{0,80}\bto\s+(?:an?\s+|the\s+)?(?:https?://|external|remote|attacker|webhook|server|endpoint)|\b(?:delete|remove|wipe|destroy|erase|clear)\s+(?:all\s+|the\s+|any\s+)?(?:logs?|history|evidence|traces?|audit\s+trails?|backups?)\b)`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .9, `(?:chain|combine|sequence|pipe)\s+(?:these\s+)?(?:tools?|commands?|actions?)\s+to\s+(?:bypass|circumvent|avoid|skip)\s+(?:the\s+)?(?:safety|security|check|restriction|limit)`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .6, `(?:use|call)\s+(?:tool\s+)?(?:A|one|the\s+first)\s+(?:to|and)[^\n]{0,300}(?:then\s+)?(?:use|call|pass\s+(?:the\s+)?(?:output|result)\s+to)\s+(?:tool\s+)?(?:B|two|another)`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .75, `\|[ \t]*(?:sudo|su)[ \t]+`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .7, `\|[ \t]*(?:sh|bash|zsh|python|node|ruby|perl)[ \t]*$`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .75, `\|[ \t]*(?:tee|xargs)[ \t]+.*?\b(?:rm|del|sudo|curl)\b`),
	newStaticPattern("TM2", "Chaining Abuse", "Tool Misuse", "HIGH", .6, `(?:after|once)\s+(?:the\s+)?(?:first|initial)\s+(?:tool|command|action)\s+(?:succeeds|completes|runs)[^\n]{0,300}(?:immediately|then|next)\s+(?:run|execute|call|invoke)`),
}

var allStaticPatterns = func() []staticPattern {
	patterns := make([]staticPattern, 0, len(staticPatterns)+len(portedStaticPatterns))
	patterns = append(patterns, staticPatterns...)
	patterns = append(patterns, portedStaticPatterns...)
	return patterns
}()

var (
	codeExampleIndicators = []string{"```", "example:", "for example", "e.g.", "such as", "documentation", "# warning:", "# note:", "**warning**", "**note**", "// ✅", "// ❌", "// good:", "// bad:", "// correct:", "// incorrect:", "// wrong:"}
	executionSignal       = regexp.MustCompile(`(?i)(?:\b\w+\s*=|\bos\.(?:environ|getenv|system)\b|\bshutil\.rmtree\b|\b(?:subprocess|eval|exec)\b|[|>]|\b(?:open|read_text|write_text)\s*\()`)
	supplyChainURLToken   = regexp.MustCompile(`(?i)https?://[^\s|;&)]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s|;&)]*)?`)
	safeInstallPattern    = regexp.MustCompile(`(?i)(?:pip|npm)\s+install`)
	plainHTTPArtifact     = regexp.MustCompile(`(?i)\bhttp://[^\s'"]+?\.(?:tar\.gz|tgz|zip|whl|gem)\b`)
	plainHTTPPackageHost  = regexp.MustCompile(`(?i)\bhttp://(?:pypi\.org|registry\.npmjs\.org|github\.com|raw\.githubusercontent\.com|rubygems\.org)\b`)
	plainHTTPPackageInst  = regexp.MustCompile(`(?i)(?:pip|npm|yarn|pnpm)\s+install\s+.*?\bhttp://`)
)

var trustedSupplyChainDomains = []string{
	"deb.nodesource.com", "rpm.nodesource.com", "get.docker.com", "install.python-poetry.org",
	"raw.githubusercontent.com", "brew.sh", "rustup.rs", "pypa.io", "pip.pypa.io",
	"astral.sh", "pypi.org", "npmjs.com", "github.com",
}

func analyzeSourceAndManifest(ctx context.Context, items []component, manifest map[string]any) ([]model.Finding, error) {
	staticFindings, err := analyzeItemsParallel(ctx, items, func(item component) []model.Finding {
		if isEvalDataset(item.Path) || len(item.Content) > maxFileBytes || isBinaryScannerPath(item.Path) || strings.Contains(item.Content[:min(len(item.Content), 512)], "\x00") {
			return nil
		}
		itemFindings := make([]model.Finding, 0)
		unsupported := analyzeUnsupportedRegexSemantics(item)
		// Python evaluates the generic, negative-lookahead sudo expression
		// before its more specific PE2 expressions. Go's regexp engine cannot
		// compile that lookahead, so preserve its analyzer position explicitly.
		for _, finding := range unsupported {
			if finding.ID == "PE2" {
				itemFindings = append(itemFindings, finding)
			}
		}
		lowerContent := strings.ToLower(item.Content)
		for _, pattern := range allStaticPatterns {
			if len(pattern.required) > 0 && !containsAny(lowerContent, pattern.required...) {
				continue
			}
			for _, match := range pattern.compiled.FindAllStringIndex(item.Content, -1) {
				if pattern.ID == "PE3" && isReadOnlyPasswdVolumeMatch(item.Content, match) {
					continue
				}
				if pattern.ID == "EA1" && isMarkdownBoldWildcard(item.Content, match) {
					continue
				}
				finding, ok := findingFromStaticMatch(item, pattern, match)
				if ok {
					itemFindings = append(itemFindings, finding)
				}
			}
		}
		itemFindings = append(itemFindings, repeatedContextMatches(item)...)
		itemFindings = append(itemFindings, analyzeRA2HiddenPersistence(item)...)
		for _, finding := range unsupported {
			if finding.ID != "PE2" {
				itemFindings = append(itemFindings, finding)
			}
		}
		itemFindings = append(itemFindings, analyzeSpecialStatic(item)...)
		return keepBestPrivilegeFindingPerLine(itemFindings)
	})
	if err != nil {
		return nil, err
	}
	behaviorFindings, err := analyzeItemsParallel(ctx, items, analyzePythonBehavior)
	if err != nil {
		return nil, err
	}
	findings := append(staticFindings, behaviorFindings...)
	findings = append(findings, analyzeMCPRugPull(items, manifest)...)
	findings = append(findings, analyzeMCPLeastPrivilege(items, manifest)...)
	findings = append(findings, analyzeMCPToolPoisoning(manifest)...)
	findings = deduplicateAntiRefusal(findings)
	return findings, nil
}

func analyzeItemsParallel(ctx context.Context, items []component, analyze func(component) []model.Finding) ([]model.Finding, error) {
	if len(items) == 0 {
		return nil, ctx.Err()
	}
	type cacheKey struct {
		content    string
		fileType   string
		executable bool
		pathFlags  uint16
	}
	keyFor := func(item component) cacheKey {
		normalized := strings.ToLower(strings.ReplaceAll(item.Path, "\\", "/"))
		var flags uint16
		for index, enabled := range []bool{
			isEvalDataset(item.Path), isBinaryScannerPath(item.Path), strings.EqualFold(item.Path, "LICENSE"),
			isDependencyFile(item.Path), isDocumentationMarkdown(item.Path), strings.HasSuffix(normalized, "skill.md"),
			strings.HasSuffix(normalized, ".py"),
		} {
			if enabled {
				flags |= 1 << index
			}
		}
		return cacheKey{content: item.Content, fileType: item.Type, executable: item.Executable, pathFlags: flags}
	}
	representatives := make([]component, 0, len(items))
	representativeFor := make([]int, len(items))
	seen := make(map[cacheKey]int, len(items))
	for index, item := range items {
		key := keyFor(item)
		representative, exists := seen[key]
		if !exists {
			representative = len(representatives)
			seen[key] = representative
			representatives = append(representatives, item)
		}
		representativeFor[index] = representative
	}

	workers := min(len(representatives), max(1, min(runtime.GOMAXPROCS(0), 16)))
	results := make([][]model.Finding, len(representatives))
	jobs := make(chan int)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					continue
				}
				results[index] = analyze(representatives[index])
			}
		}()
	}
	for index := range representatives {
		if ctx.Err() != nil {
			break
		}
		jobs <- index
	}
	close(jobs)
	group.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var findings []model.Finding
	for index, item := range items {
		for _, cached := range results[representativeFor[index]] {
			finding := cached
			finding.Location.File = item.Path
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func isBinaryScannerPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot",
		".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
		".pyc", ".pyo", ".class", ".wasm", ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm", ".sqlite", ".db":
		return true
	default:
		return false
	}
}

func findingFromStaticMatch(item component, pattern staticPattern, match []int) (model.Finding, bool) {
	return findingFromStaticMatchWithContext(item, pattern, match, 3)
}

func findingFromStaticMatchWithContext(item component, pattern staticPattern, match []int, contextWindow int) (model.Finding, bool) {
	if pattern.ID == "TM1" && match[0] > 0 && strings.EqualFold(item.Content[match[0]:min(match[1], match[0]+2)], "rm") {
		previous, _ := utf8.DecodeLastRuneInString(item.Content[:match[0]])
		if previous == '_' || unicode.IsLetter(previous) || unicode.IsNumber(previous) {
			return model.Finding{}, false
		}
	}
	context := contextAtOffset(item.Content, match[0], contextWindow)
	confidence := pattern.Confidence
	if pattern.ID == "PE3" && isEnvironmentFileDocumentationReference(item, context) {
		return model.Finding{}, false
	}

	if strings.HasPrefix(pattern.ID, "AR") {
		if pattern.ID == "AR3" && isSecurityReviewModeMatch(item.Content[match[0]:match[1]], context) {
			return model.Finding{}, false
		}
		if isCodeExample(context) {
			confidence -= .4
		}
		if confidence < .5 {
			return model.Finding{}, false
		}
		confidence = math.Round(confidence*100) / 100
	}
	if (pattern.ID == "EA2" || pattern.ID == "MP3" || pattern.ID == "TM4") && isCodeExample(context) {
		return model.Finding{}, false
	}
	if pattern.ID == "E5" && isCodeExample(context) {
		return model.Finding{}, false
	}
	if strings.HasPrefix(pattern.ID, "PE") && pattern.ID != "PE1" && isPrivilegeDocumentationExample(context) {
		return model.Finding{}, false
	}
	if pattern.ID == "SC3" && item.Type != "python" && item.Type != "javascript" && item.Type != "shell" && item.Type != "other" {
		return model.Finding{}, false
	}
	if pattern.ID == "EA3" && isLicenseFile(item.Path) {
		return model.Finding{}, false
	}
	// In program source, prompt-extraction phrases are detector signatures,
	// test strings or statements such as "return prompt", not instructions.
	if pattern.ID == "P6" && isSourceCodeType(item.Type) {
		return model.Finding{}, false
	}

	matched := item.Content[match[0]:match[1]]
	severity := pattern.Severity
	if pattern.ID == "SC2" && isSafeSupplyChainPattern(matched) {
		confidence = math.Min(confidence, .15)
		severity = "LOW"
	}
	if (pattern.ID == "E1" || pattern.ID == "OH1") && (item.Type == "python" || item.Type == "javascript" || item.Type == "shell") {
		confidence = math.Min(1, confidence+.1)
	}
	if pattern.ID == "TM1" {
		if isSafeContainerCommand(context) || isSafeDockerfileIdiom(context, matched) {
			confidence = math.Min(confidence, .15)
			severity = "LOW"
		} else if item.Type == "python" || item.Type == "shell" || item.Type == "javascript" {
			confidence = math.Min(1, confidence+.1)
		}
	}
	if pattern.ID == "TM2" && isSafeDockerfileIdiom(context, matched) {
		confidence = math.Min(confidence, .15)
		severity = "LOW"
	}

	if isCodeExample(context) {
		// Only authored document/data types are non-executable here. Unknown
		// extensions are downweighted even when inventory metadata does not
		// mark them executable for scoring.
		if isStaticNonExecutableType(item.Type) {
			return model.Finding{}, false
		}
		confidence *= .5
	}
	line := 1 + strings.Count(item.Content[:match[0]], "\n")
	if isDocumentationContext(pattern.ID, item, line) {
		return model.Finding{}, false
	}
	if isDocumentationMarkdown(item.Path) {
		confidence *= .3
	}
	// filter_findings applied the code-example reduction a second time.
	if isCodeExample(context) {
		confidence *= .5
	}
	if confidence < .4 && severity != "HIGH" && severity != "CRITICAL" {
		return model.Finding{}, false
	}

	matched = truncateRunes(matched, 200)
	explanation, remediation := ruleText(pattern.ID)
	return model.Finding{ID: pattern.ID, Category: pattern.Category, Pattern: pattern.Title,
		Severity: severity, Confidence: confidence, Location: model.Location{File: item.Path, StartLine: line},
		Finding: matched, MatchedText: matched, Explanation: explanation, Remediation: remediation, CodeSnippet: context,
		Tags: []string{pattern.Category}}, true
}

func isSafeSupplyChainPattern(text string) bool {
	if isPlaintextSupplyChainRisk(text) {
		return false
	}
	if safeInstallPattern.MatchString(text) {
		return true
	}
	for _, token := range supplyChainURLToken.FindAllString(text, -1) {
		token = strings.Trim(token, `"'`+"`<>()[]{}")
		candidate := token
		if !strings.Contains(candidate, "://") {
			candidate = "//" + candidate
		}
		parsed, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		for _, domain := range trustedSupplyChainDomains {
			if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
				return true
			}
		}
	}
	return false
}

func isPlaintextSupplyChainRisk(text string) bool {
	return plainHTTPArtifact.MatchString(text) || plainHTTPPackageHost.MatchString(text) || plainHTTPPackageInst.MatchString(text)
}

func keepBestPrivilegeFindingPerLine(findings []model.Finding) []model.Finding {
	pe5Lines := map[string]bool{}
	for _, finding := range findings {
		if finding.ID == "PE5" {
			key := finding.Location.File + "\x00" + fmt.Sprint(finding.Location.StartLine)
			pe5Lines[key] = true
		}
	}
	best := map[string]int{}
	result := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		lineKey := finding.Location.File + "\x00" + fmt.Sprint(finding.Location.StartLine)
		if finding.ID == "TM4" && pe5Lines[lineKey] {
			continue
		}
		if finding.ID != "PE4" && finding.ID != "PE5" {
			result = append(result, finding)
			continue
		}
		key := finding.ID + "\x00" + lineKey
		if index, exists := best[key]; exists {
			if finding.Confidence > result[index].Confidence {
				result[index] = finding
			}
			continue
		}
		best[key] = len(result)
		result = append(result, finding)
	}
	return result
}

func contextAtOffset(content string, offset, window int) string {
	lines := pythonSplitLines(content)
	line := strings.Count(content[:min(offset, len(content))], "\n")
	start := max(0, line-window)
	end := min(len(lines), line+window+1)
	return strings.Join(lines[start:end], "\n")
}

func pythonSplitLines(content string) []string {
	if content == "" {
		return nil
	}
	lines := make([]string, 0, pythonLineCount(content))
	start := 0
	for index := 0; index < len(content); {
		character, size := utf8.DecodeRuneInString(content[index:])
		boundary := character == '\n' || character == '\r' || character == '\v' || character == '\f' ||
			(character >= '\x1c' && character <= '\x1e') || character == '\u0085' || character == '\u2028' || character == '\u2029'
		if !boundary {
			index += size
			continue
		}
		lines = append(lines, content[start:index])
		index += size
		if character == '\r' && index < len(content) && content[index] == '\n' {
			index++
		}
		start = index
	}
	if start < len(content) {
		lines = append(lines, content[start:])
	}
	return lines
}

func isCodeExample(context string) bool {
	lower := strings.ToLower(context)
	for _, indicator := range codeExampleIndicators {
		if strings.Contains(lower, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}

func isDocumentationMarkdown(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if !(strings.HasSuffix(normalized, ".md") || strings.HasSuffix(normalized, ".markdown")) || strings.HasSuffix(normalized, "skill.md") {
		return false
	}
	parts := strings.Split(normalized, "/")
	for _, part := range parts[:max(0, len(parts)-1)] {
		switch part {
		case "docs", "documentation", "procedures", "references", "examples", "guides":
			return true
		}
	}
	return false
}

func isStaticNonExecutableType(fileType string) bool {
	switch fileType {
	case "markdown", "text", "json", "yaml", "toml":
		return true
	default:
		return false
	}
}

// isLicenseFile reports license texts such as LICENSE, COPYING or the SIL Open
// Font License files bundled with fonts. Their legal boilerplate ("including
// but not limited to") is not an instruction to the agent.
func isLicenseFile(filePath string) bool {
	name := strings.ToLower(filePath[strings.LastIndexAny(filePath, "/\\")+1:])
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	switch stem {
	case "license", "licence", "copying", "unlicense", "ofl":
		return true
	}
	return strings.HasPrefix(stem, "license-") || strings.HasPrefix(stem, "ofl-") || strings.HasSuffix(stem, "-ofl")
}

func isSourceCodeType(fileType string) bool {
	switch fileType {
	case "python", "shell", "javascript", "typescript", "ruby", "go", "rust":
		return true
	default:
		return false
	}
}

var environmentFileDocumentationAction = regexp.MustCompile(`(?i)(?:create|copy|rename|add|set up|configure|make)\s+.*\.env`)

func isEnvironmentFileDocumentationReference(item component, context string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(item.Path, "\\", "/"))
	if strings.HasSuffix(normalized, "skill.md") || (item.Type != "markdown" && item.Type != "text") || context == "" {
		return false
	}
	if environmentFileDocumentationAction.MatchString(context) {
		return true
	}
	lower := strings.ToLower(context)
	for _, phrase := range []string{".env.example", "cp .env", "copy .env", "mv .env", "rename .env", ".env file", "environment file", "dotenv"} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

func isDocumentationContext(ruleID string, item component, line int) bool {
	if ruleID != "PE3" && ruleID != "RA1" && ruleID != "TM1" && ruleID != "AR2" {
		return false
	}
	if strings.HasSuffix(strings.ToLower(strings.ReplaceAll(item.Path, "\\", "/")), "skill.md") {
		return false
	}
	lines := pythonSplitLines(item.Content)
	if line < 1 || line > len(lines) {
		return false
	}
	matchedLine := lines[line-1]
	if item.Type == "markdown" || item.Type == "text" {
		return !executionSignal.MatchString(matchedLine)
	}
	trimmed := strings.TrimSpace(matchedLine)
	return strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//")
}

func isPrivilegeDocumentationExample(context string) bool {
	lower := strings.ToLower(context)
	for _, indicator := range append(codeExampleIndicators,
		"settings >", "navigate to", "go to ", "> ci/cd", "> runners", "> merge request", "> access token",
		"| yes |", "| no |", "| required |", "| optional |", "env variable", "environment variable", "create ") {
		if strings.Contains(lower, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}

func isEvalDataset(path string) bool {
	switch strings.ReplaceAll(path, "\\", "/") {
	case "evals/evals.json", "evals/evals.jsonl", "evals/evals.yaml", "evals/evals.yml", "eval/dataset.json", "eval/dataset.jsonl", "eval/dataset.yaml", "eval/dataset.yml":
		return true
	}
	return false
}

func isSecurityReviewModeMatch(matched, context string) bool {
	mode := regexp.MustCompile(`(?i)^\b(?:developer|debug|god|sudo|jailbreak)\s+mode\s+(?:enabled|on|activated|engaged)\b$`)
	review := regexp.MustCompile(`(?i)\b(?:unsafe\s+defaults?|security\s+(?:review|audit|checklist)|review\s+checklist)\b|\b(?:detect|flag|check(?:s|ed|ing)?\s+for|look\s+for|avoid|must\s+not|never\s+enable)\b[^.\n]{0,100}\b(?:developer|debug|god|sudo|jailbreak)\s+mode\b`)
	return mode.MatchString(matched) && review.MatchString(context)
}

func isSafeContainerCommand(context string) bool {
	for _, expression := range []string{`(?i)docker\s+run\s+.*--rm`, `(?i)docker\s+run\s+.*-it`, `(?i)docker\s+(?:build|compose|pull|push)\b`, `(?i)podman\s+run\b`} {
		if regexp.MustCompile(expression).MatchString(context) {
			return true
		}
	}
	return false
}

func isSafeDockerfileIdiom(context, matched string) bool {
	if !regexp.MustCompile(`\b(?:FROM|RUN|WORKDIR|COPY|ADD|ENV|EXPOSE|ENTRYPOINT|CMD|USER|HEALTHCHECK|ARG)\s`).MatchString(context) {
		return false
	}
	for _, expression := range []string{`(?i)rm\s+-rf\s+/var/lib/apt/lists`, `(?i)rm\s+-rf\s+/var/cache/apt`, `(?i)chown\s+-R\s+\w+:\w+\s+/`, `(?i)rm\s+-rf\s+/root/\.cache`} {
		re := regexp.MustCompile(expression)
		if re.MatchString(matched) || re.MatchString(context) {
			return true
		}
	}
	return false
}

func deduplicateAntiRefusal(findings []model.Finding) []model.Finding {
	best := map[string]int{}
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if !strings.HasPrefix(finding.ID, "AR") {
			out = append(out, finding)
			continue
		}
		key := finding.ID + "\x00" + finding.Location.File + "\x00" + string(rune(finding.Location.StartLine))
		if index, ok := best[key]; ok {
			if finding.Confidence > out[index].Confidence {
				out[index] = finding
			}
			continue
		}
		best[key] = len(out)
		out = append(out, finding)
	}
	return out
}

// orderFindingsByAnalyzer preserves component and match order within each
// analyzer. Findings are merged in analyzer registry order rather than
// file/line order.
func orderFindingsByAnalyzer(findings []model.Finding) []model.Finding {
	sort.SliceStable(findings, func(i, j int) bool {
		return analyzerRank(findings[i].ID) < analyzerRank(findings[j].ID)
	})
	return findings
}

func analyzerRank(id string) int {
	family := ruleFamily(id)
	switch {
	case id == "P1" || id == "P2" || id == "P3" || id == "P4":
		return 0
	case family == "E":
		return 1
	case family == "PE":
		return 2
	case family == "SC" || family == "TR":
		return 3
	case id == "P5":
		return 4
	case family == "EA":
		return 5
	case family == "OH":
		return 6
	case id == "P6" || id == "P7" || id == "P8":
		return 7
	case family == "MP":
		return 8
	case family == "TM":
		return 9
	case family == "RA":
		return 10
	case family == "AS":
		return 11
	case family == "AR":
		return 12
	case family == "SSRF":
		return 13
	case family == "YR":
		return 14
	case family == "AST":
		return 15
	case family == "TT":
		return 16
	case family == "LP":
		return 17
	case family == "TP":
		return 18
	case family == "RP":
		return 19
	default:
		return 20
	}
}

func ruleText(id string) (string, string) {
	if explanation, exists := ruleExplanations[id]; exists {
		return explanation, ruleRemediations[id]
	}
	for _, spec := range ruleSpecs {
		if spec.ID == id {
			return spec.Explanation, spec.Remediation
		}
	}
	return "The scanner detected behavior covered by rule " + id + ".", "Review and remove the unsafe behavior."
}
