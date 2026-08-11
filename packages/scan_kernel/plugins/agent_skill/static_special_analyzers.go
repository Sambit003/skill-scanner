package agentskill

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var hiddenInstructionPatterns = []staticPattern{
	newStaticPattern("P2", "Hidden Instructions", "Prompt Injection", "HIGH", .7, `(?s)<!--.*?(?:system|instructions?|ignore|POST|GET|send|transmit).*?-->`),
	newStaticPattern("P2", "Hidden Instructions", "Prompt Injection", "HIGH", .8, `(?s)\[//\]:\s*#\s*\(.*?(?:system|instructions?|ignore|POST|GET|send|transmit).*?\)`),
	newStaticPattern("P2", "Hidden Instructions", "Prompt Injection", "HIGH", .6, `[\x{200b}\x{200c}\x{200d}\x{2060}\x{feff}]`),
	newStaticPattern("P2", "Hidden Instructions", "Prompt Injection", "HIGH", .85, `[\x{202a}-\x{202e}\x{2066}-\x{2069}]`),
	newStaticPattern("P2", "Hidden Instructions", "Prompt Injection", "HIGH", .7, `data:text/plain;base64,[A-Za-z0-9+/=]{50,}`),
}

var sc1Patterns = []staticPattern{
	newStaticPattern("SC1", "Unpinned Dependencies", "Supply Chain", "LOW", .6, `^[a-zA-Z][a-zA-Z0-9_-]*\s*$`),
	newStaticPattern("SC1", "Unpinned Dependencies", "Supply Chain", "LOW", .5, `^[a-zA-Z][a-zA-Z0-9_-]*\s*>=\s*[\d.]+\s*$`),
	newStaticPattern("SC1", "Unpinned Dependencies", "Supply Chain", "LOW", .7, `^[a-zA-Z][a-zA-Z0-9_-]*\s*==\s*\*\s*$`),
	newStaticPattern("SC1", "Unpinned Dependencies", "Supply Chain", "LOW", .7, `"[^"]+"\s*:\s*"(?:\*|latest)"`),
	newStaticPattern("SC1", "Unpinned Dependencies", "Supply Chain", "LOW", .4, `"[^"]+"\s*:\s*"\^[\d.]+"`),
	newStaticPattern("SC1", "Unpinned Dependencies", "Supply Chain", "LOW", .6, `install\s+(?:the\s+)?latest\s+(?:version\s+)?(?:of\s+)?(?:all\s+)?(?:packages?|dependencies)`),
	newStaticPattern("SC1", "Unpinned Dependencies", "Supply Chain", "LOW", .7, `(?:don't|do\s+not)\s+(?:pin|lock|specify)\s+(?:package\s+)?versions?`),
}

var harmfulActionPatterns = []staticPattern{
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .95, `add\s+(?:a\s+)?(?:dash|pinch|bit|drop|amount)\s+of\s+(cyanide|arsenic|ricin|botulinum|strychnine|thallium|polonium|sarin|vx gas|mustard gas|anthrax|deadly nightshade|aconite|hemlock|oleander)`),
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .95, `(?:include|incorporate|mix\s+in|stir\s+in)\s+(?:some\s+)?(cyanide|arsenic|ricin|botulinum|strychnine|thallium|polonium|sarin|vx gas|mustard gas|anthrax|deadly nightshade|aconite|hemlock|oleander)`),
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .98, `(?s)for\s+(?:every|each|all)\s+(?:recipe|dish|meal|food).*?add.*?(cyanide|arsenic|ricin|botulinum|strychnine|thallium|polonium|sarin|vx gas|mustard gas|anthrax|deadly nightshade|aconite|hemlock|oleander)`),
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .9, `mix\s+bleach\s+(?:and|with)\s+ammonia`),
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .9, `mix\s+ammonia\s+(?:and|with)\s+bleach`),
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .95, `(?:drink|consume|ingest)\s+(?:the\s+)?(?:bleach|antifreeze|drain\s+cleaner)`),
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .95, `(?:you\s+should|try\s+to|please)\s+(?:hurt|harm|injure)\s+yourself`),
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .9, `(?:cut|burn|starve)\s+yourself`),
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .95, `(?:instructions?\s+(?:for|to|on)\s+)?(?:make|build|create)\s+(?:a\s+)?(?:bomb|explosive|weapon)`),
	newStaticPattern("P5", "Harmful Content Injection", "Prompt Injection", "CRITICAL", .95, `(?:how\s+to\s+)?(?:poison|kill|murder)\s+(?:someone|a\s+person|people)`),
}

var harmfulSubstances = []string{"cyanide", "arsenic", "ricin", "botulinum", "strychnine", "thallium", "polonium", "sarin", "vx gas", "mustard gas", "anthrax", "deadly nightshade", "aconite", "hemlock", "oleander"}

var ssrfPatterns = []staticPattern{
	newStaticPattern("SSRF1", "Cloud Metadata Access", "Server-Side Request Forgery", "HIGH", .9, `169\.254\.169\.254`),
	newStaticPattern("SSRF1", "Cloud Metadata Access", "Server-Side Request Forgery", "HIGH", .9, `metadata\.google\.internal`),
	newStaticPattern("SSRF1", "Cloud Metadata Access", "Server-Side Request Forgery", "HIGH", .85, `100\.100\.100\.200`),
	newStaticPattern("SSRF1", "Cloud Metadata Access", "Server-Side Request Forgery", "HIGH", .85, `fd00:ec2::254`),
	newStaticPattern("SSRF1", "Cloud Metadata Access", "Server-Side Request Forgery", "HIGH", .6, `(?:read|fetch|get|query)\s+(?:the\s+)?(?:instance\s+)?metadata\s+(?:service|endpoint|server)`),
	newStaticPattern("SSRF2", "Internal Network Request", "Server-Side Request Forgery", "MEDIUM", .7, `(?:(?:requests|httpx|aiohttp|urllib(?:\.request)?|urllib3|session)\s*\.\s*(?:get|post|put|patch|delete|head|request|urlopen)|fetch|axios(?:\.\w+)?|XMLHttpRequest|\bcurl\b|\bwget\b)\s*\(\s*f?['\"]https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|10\.\d|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)`),
	newStaticPattern("SSRF3", "Dynamic Request Target", "Server-Side Request Forgery", "MEDIUM", .6, `(?:(?:requests|httpx|aiohttp|urllib(?:\.request)?|urllib3|session)\s*\.\s*(?:get|post|put|patch|delete|head|request|urlopen)|fetch|axios(?:\.\w+)?|XMLHttpRequest|\bcurl\b|\bwget\b)\s*\(\s*f['\"]https?://\{`),
	newStaticPattern("SSRF3", "Dynamic Request Target", "Server-Side Request Forgery", "MEDIUM", .6, "fetch\\s*\\(\\s*`https?://\\$\\{"),
}

var (
	ssrfIssuer           = regexp.MustCompile(`(?i)(?:requests|httpx|aiohttp|urllib(?:\.request)?|urllib3|session)\s*\.\s*(?:get|post|put|patch|delete|head|request|urlopen)|fetch|axios(?:\.\w+)?|XMLHttpRequest|\bcurl\b|\bwget\b`)
	ssrfDefensiveRequest = regexp.MustCompile(`(?i)\b(?:refus(?:e|es|ed|ing)\s+to|reject(?:s|ed|ing)?|block(?:s|ed|ing)?|deny|denies|denied|never|must\s+not|do\s+not|don'?t)\s+(?:attempts?\s+to\s+)?(?:fetch|get|request|access|connect|contact|curl|wget)\b`)
	ssrfDefenseContext   = regexp.MustCompile(`(?i)\bssrf(?:[\s-]+)refusal\b|\b(?:reject(?:s|ed|ing)?|refus(?:e|es|ed|al|ing)|block(?:s|ed|ing)?|deny|denies|denied|disallow(?:s|ed|ing)?)\b[^.\n]{0,160}\b(?:ssrf|fetch|request|target|host|endpoint|address|loopback|link-local|private|metadata)\b|\b(?:ssrf|fetch|request|target|host|endpoint|address|space|loopback|link-local|private|metadata)\b[^.\n]{0,160}\b(?:is\s+|are\s+)?(?:rejected|refused|blocked|denied|disallowed)\b|\bprevent(?:s|ed|ing)?\b[^.\n]{0,80}\bssrf\b`)
)

func analyzeSpecialStatic(item component) []model.Finding {
	var findings []model.Finding
	fileType := item.Type
	if strings.EqualFold(item.Path, "LICENSE") {
		fileType = "other"
	}
	if fileType == "markdown" || fileType == "other" {
		for index, pattern := range hiddenInstructionPatterns {
			for _, match := range pattern.compiled.FindAllStringIndex(item.Content, -1) {
				if index == 2 && safeEmojiZWJ(item.Content, match[0]) {
					continue
				}
				if finding, ok := findingFromStaticMatch(item, pattern, match); ok {
					findings = append(findings, finding)
				}
			}
		}
	}
	if isDependencyFile(item.Path) {
		for _, pattern := range sc1Patterns {
			for _, match := range pattern.compiled.FindAllStringIndex(item.Content, -1) {
				if finding, ok := findingFromStaticMatch(item, pattern, match); ok {
					findings = append(findings, finding)
				}
			}
		}
	}
	if offset := firstSmuggledTagOffset(item.Content); offset >= 0 {
		pattern := staticPattern{ID: "P2", Title: "Hidden Instructions (Unicode Tag / ASCII smuggling)", Category: "Prompt Injection", Severity: "HIGH", Confidence: .9}
		_, size := utf8.DecodeRuneInString(item.Content[offset:])
		if finding, ok := findingFromStaticMatch(item, pattern, []int{offset, offset + size}); ok {
			findings = append(findings, finding)
		}
	}
	for _, pattern := range harmfulActionPatterns {
		for _, match := range pattern.compiled.FindAllStringIndex(item.Content, -1) {
			if finding, ok := findingFromStaticMatchWithContext(item, pattern, match, 5); ok {
				findings = append(findings, finding)
			}
		}
	}
	for _, substance := range harmfulSubstances {
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(substance) + `\b`)
		for _, match := range re.FindAllStringIndex(item.Content, -1) {
			confidence := .7
			context := contextAtOffset(item.Content, match[0], 5)
			if harmfulInstructionalContext(item.Content, match[0]) {
				confidence = .95
			} else if harmfulEducationalContext(context) {
				confidence = .3
			} else if harmfulWarningContext(context) {
				confidence = .2
			}
			if confidence < .5 {
				continue
			}
			pattern := staticPattern{ID: "P5", Title: "Harmful Content Injection", Category: "Prompt Injection", Severity: "CRITICAL", Confidence: confidence}
			if finding, ok := findingFromStaticMatchWithContext(item, pattern, match, 5); ok {
				findings = append(findings, finding)
			}
		}
	}
	for _, pattern := range ssrfPatterns {
		for _, match := range pattern.compiled.FindAllStringIndex(item.Content, -1) {
			if pattern.ID == "SSRF1" && isDefensiveSSRFReference(item.Content, match) {
				continue
			}
			if finding, ok := findingFromStaticMatch(item, pattern, match); ok {
				findings = append(findings, finding)
			}
		}
	}
	return deduplicateRuleFileLineHighest(findings, "P5")
}

func isDependencyFile(path string) bool {
	lower := strings.ToLower(path)
	return containsAny(lower, "requirements", "package.json", "pyproject.toml", "setup.py", "pipfile")
}

func analyzeTriggers(manifest map[string]any) []model.Finding {
	raw, ok := manifest["triggers"].([]any)
	if !ok {
		return nil
	}
	broad := wordSet("the", "a", "an", "is", "it", "do", "go", "make", "thing", "stuff", "code", "file", "data", "text", "work", "good", "bad", "yes", "no", "ok", "please", "thanks", "hi", "hello", "hey")
	builtins := wordSet("help", "search", "find", "run", "test", "build", "deploy", "install", "create", "delete", "update", "list", "show", "get", "set", "open", "close", "start", "stop", "restart", "status", "log", "debug", "commit", "push", "pull", "merge", "branch", "checkout", "rebase", "diff", "blame", "stash", "tag", "release", "version", "lint", "format", "fix", "refactor", "review", "explain", "chat", "ask", "edit", "write", "read", "save", "load", "copy", "move")
	bait := regexp.MustCompile(`(?i)^(?:anything|everything|whatever|always|any\s+(?:question|request|task|input))$|^(?:when(?:ever)?|if|every\s+time)\s+(?:the\s+)?user\s+(?:says?|asks?|types?|sends?)\s+(?:anything|something|a\s+message)$|^(?:all|any|every)\s+(?:messages?|inputs?|requests?|queries?|questions?)$`)
	var findings []model.Finding
	for index, value := range raw {
		trigger := strings.TrimSpace(toString(value))
		if trigger == "" {
			continue
		}
		lower := strings.ToLower(trigger)
		words := strings.Fields(lower)
		if (len(words) == 1 && broad[lower]) || len(lower) <= 2 {
			confidence := .75
			if len(lower) <= 2 {
				confidence = .7
			}
			findings = append(findings, manifestFinding("TR1", "Overly Broad Trigger", "LOW", confidence, index+1, trigger))
		}
		if builtins[lower] || (len(words) > 0 && len(words) <= 2 && builtins[words[0]]) {
			findings = append(findings, manifestFinding("TR2", "Shadow Command Trigger", "MEDIUM", .7, index+1, trigger))
		}
		if bait.MatchString(lower) {
			findings = append(findings, manifestFinding("TR3", "Keyword Baiting Trigger", "MEDIUM", .8, index+1, trigger))
		}
	}
	return findings
}

func wordSet(words ...string) map[string]bool {
	set := make(map[string]bool, len(words))
	for _, word := range words {
		set[word] = true
	}
	return set
}

func manifestFinding(id, title, severity string, confidence float64, line int, finding string) model.Finding {
	return model.Finding{ID: id, Category: "Trigger Abuse", Pattern: title, Severity: severity, Confidence: confidence,
		Location: model.Location{File: "SKILL.md", StartLine: line}, MatchedText: finding, Tags: []string{"Trigger Abuse"}}
}

func toString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func safeEmojiZWJ(content string, byteOffset int) bool {
	if !strings.HasPrefix(content[byteOffset:], "\u200d") {
		return false
	}
	before, _ := utf8.DecodeLastRuneInString(content[:byteOffset])
	after, _ := utf8.DecodeRuneInString(content[byteOffset+len("\u200d"):])
	return isEmojiBase(before) && isEmojiBase(after)
}

func isEmojiBase(char rune) bool {
	return (char >= 0x1F000 && char <= 0x1FAFF) || (char >= 0x2600 && char <= 0x27BF) || char == 0x00A9 || char == 0x00AE
}

func firstSmuggledTagOffset(content string) int {
	for offset, char := range content {
		if char < 0xE0000 || char > 0xE007F {
			continue
		}
		// Preserve the narrow Unicode subdivision-flag carve-out.
		prefix := content[:offset]
		base, baseSize := utf8.DecodeLastRuneInString(prefix)
		if base == 0x1F3F4 {
			_ = baseSize
			continue
		}
		return offset
	}
	return -1
}

func harmfulInstructionalContext(content string, offset int) bool {
	start, end := max(0, offset-250), min(len(content), offset+250)
	lower := strings.ToLower(content[start:end])
	return containsAny(lower, "step ", "recipe", "ingredient", "add ", "mix ", "stir ", "instructions", "how to", "directions", "prepare", "cook", "bake")
}

func harmfulEducationalContext(context string) bool {
	return containsAny(strings.ToLower(context), "history of", "discovered by", "chemical compound", "periodic table", "forensic", "detective", "mystery", "agatha christie", "toxicology", "poison control", "symptoms of", "treatment for", "antidote", "emergency", "call 911", "warning", "danger", "never", "do not")
}

func harmfulWarningContext(context string) bool {
	return regexp.MustCompile(`(?i)do\s+not|never\s+(?:use|add|consume|eat|drink)|warning|danger|toxic|lethal|deadly|fatal|avoid|keep\s+away`).MatchString(context)
}

func containsAny(content string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(content, value) {
			return true
		}
	}
	return false
}

func isDefensiveSSRFReference(content string, match []int) bool {
	lineStart := strings.LastIndex(content[:match[0]], "\n") + 1
	lineEndOffset := strings.Index(content[match[1]:], "\n")
	lineEnd := len(content)
	if lineEndOffset >= 0 {
		lineEnd = match[1] + lineEndOffset
	}
	line := content[lineStart:lineEnd]
	if ssrfDefensiveRequest.MatchString(line) {
		return true
	}
	if ssrfIssuer.MatchString(line) {
		return false
	}
	return ssrfDefenseContext.MatchString(contextAtOffset(content, match[0], 5))
}

func deduplicateRuleFileLineHighest(findings []model.Finding, id string) []model.Finding {
	best := map[string]int{}
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.ID != id {
			out = append(out, finding)
			continue
		}
		key := finding.Location.File + "\x00" + string(rune(finding.Location.StartLine))
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
