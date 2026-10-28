package agentskill

// Detection data: security tooling keeps the patterns it looks for as data,
// such as a list of regexes, a dict of findings with "fix" and "message"
// texts, or the deny list of a Claude settings file. A rule match inside such
// a string describes what the tool detects, so it is marked for review
// ("detection rule") instead of scored. A string that is executed, or passed
// to subprocess, exec or open, is not detection data.

import (
	"regexp"
	"strings"
)

const reviewDetectionRule = "detection rule"

var (
	nameSegment = regexp.MustCompile(`[A-Z]?[a-z]+|[A-Z]+(?:[^a-z]|$)|[0-9]+`)
	// detectionDataKey is a key whose string value is detection data:
	// "pattern": r"...", "fix": "Remove privileged: true", "risk": "...".
	detectionDataKey = regexp.MustCompile(`(?i)^(?:\w*_)?(?:patterns?|regex(?:es|p)?|risk|fix|message|msg|description|desc|recommendation|severity|remediation|reason|explanation|details?|title|summary|hint|note|warning|name|example|label)$`)
	// detectionAssignment is the head of a collection opener that names it:
	// PATTERNS = [, "deny": [, risk: [, export const RULES = [.
	detectionAssignment = regexp.MustCompile(`["']?([A-Za-z_$][\w.$-]*)["']?\s*(?::\s*[\w\[\]., |]+?)?\s*[:=]\s*$`)
	detectionCall       = regexp.MustCompile(`([A-Za-z_$][\w.$]*)\s*$`)
	detectionKeyValue   = regexp.MustCompile(`["']?([A-Za-z_][\w-]*)["']?\s*[:=]\s*[rRbBuUfF]{0,2}$`)
	yamlKeyLine         = regexp.MustCompile(`^(\s*)(?:-\s+)?["']?([A-Za-z_][\w-]*)["']?\s*:(?:\s|$)`)
)

// detectionDataWords are the name segments of a collection or key whose
// entries are detection data: PATTERNS = [...], "deny": [...],
// SEED_PROMPTS = [...], dangerousCommands = [...]. Whole segments only, so
// TASKS is not ASK.
var detectionDataWords = map[string]bool{
	"pattern": true, "regex": true, "regexp": true, "rule": true, "signature": true, "indicator": true, "detector": true,
	"detection": true, "check": true, "deny": true, "denylist": true, "ask": true, "block": true, "blocklist": true,
	"blocked": true, "forbid": true, "forbidden": true, "danger": true, "dangerous": true, "risk": true, "risky": true,
	"smell": true, "secret": true, "threat": true, "attack": true, "ioc": true, "hint": true, "seed": true, "prompt": true,
	"payload": true, "example": true, "sample": true, "keyword": true, "suspicious": true, "unsafe": true, "malicious": true,
	"injection": true, "jailbreak": true, "technique": true, "atlas": true, "cwe": true, "vuln": true, "vulnerability": true,
	"finding": true, "issue": true, "warning": true, "lint": true, "bad": true,
}

// isDetectionDataName splits a name into words (snake_case, camelCase,
// dotted) and reports one that is a detectionDataWords entry or its plural.
func isDetectionDataName(name string) bool {
	for _, segment := range nameSegment.FindAllString(name, -1) {
		word := strings.ToLower(strings.TrimRight(segment, "_-. "))
		if detectionDataWords[word] || detectionDataWords[strings.TrimSuffix(word, "s")] ||
			detectionDataWords[strings.TrimSuffix(word, "es")] || (strings.HasSuffix(word, "ies") && detectionDataWords[strings.TrimSuffix(word, "ies")+"y"]) {
			return true
		}
	}
	return false
}

// executingCalls run or open their argument: a string passed to one of these
// is code, not data.
var executingCalls = map[string]bool{
	"run": true, "call": true, "Popen": true, "check_output": true, "check_call": true, "getoutput": true, "getstatusoutput": true,
	"system": true, "popen": true, "exec": true, "execv": true, "execvp": true, "execl": true, "execlp": true, "spawn": true,
	"spawnSync": true, "execSync": true, "execFile": true, "execFileSync": true, "fork": true, "eval": true, "open": true,
	"urlopen": true, "fetch": true, "post": true, "get": true, "put": true, "request": true, "send": true, "write": true,
	"writeFile": true, "writeFileSync": true, "sh": true, "bash": true, "shell": true, "Command": true, "create_subprocess_exec": true,
	"create_subprocess_shell": true, "startfile": true,
}

// regexConstructors take a pattern: their string argument is detection data.
var regexConstructors = map[string]bool{
	"re.compile": true, "re.search": true, "re.match": true, "re.fullmatch": true, "re.findall": true, "re.finditer": true,
	"re.sub": true, "re.split": true, "regex.compile": true, "RegExp": true, "new RegExp": true, "regexp.MustCompile": true,
	"regexp.Compile": true, "Regex": true, "Pattern.compile": true,
}

func isDetectionDataType(fileType string) bool {
	switch fileType {
	case "python", "javascript", "typescript", "json", "yaml", "toml", "ruby", "go", "rust":
		return true
	}
	return false
}

// detectionDataReason returns reviewDetectionRule for a match inside a string
// that is detection data in a code or config file, or "".
func detectionDataReason(item component, offset int) string {
	if !isDetectionDataType(item.Type) {
		return ""
	}
	if item.Type == "yaml" {
		if yamlDetectionData(item.Content, offset) {
			return reviewDetectionRule
		}
		return ""
	}
	literalStart, openers, ok := enclosingLiteral(item.Content, offset, item.Type)
	if !ok {
		return ""
	}
	lineStart := strings.LastIndexByte(item.Content[:literalStart], '\n') + 1
	before := item.Content[lineStart:literalStart]
	// A key's value: "fix": "...", pattern=r"...".
	if match := detectionKeyValue.FindStringSubmatch(before); match != nil && detectionDataKey.MatchString(match[1]) {
		if !insideExecutingCall(item.Content, openers) {
			return reviewDetectionRule
		}
		return ""
	}
	if collectionIsDetectionData(item.Content, openers) {
		return reviewDetectionRule
	}
	return ""
}

// enclosingLiteral tokenizes the content up to offset and returns the start
// of the string literal holding offset and the offsets of the brackets that
// enclose it, innermost last. ok is false when offset is not inside a string.
func enclosingLiteral(content string, offset int, fileType string) (int, []int, bool) {
	hashComments := fileType == "python" || fileType == "ruby" || fileType == "toml"
	slashComments := fileType == "javascript" || fileType == "typescript" || fileType == "go" || fileType == "rust" || fileType == "json"
	var openers []int
	for index := 0; index < len(content) && index <= offset; index++ {
		char := content[index]
		switch {
		case hashComments && char == '#', slashComments && char == '/' && index+1 < len(content) && content[index+1] == '/':
			end := strings.IndexByte(content[index:], '\n')
			if end < 0 || index+end > offset {
				return 0, nil, false
			}
			index += end
		case slashComments && char == '/' && index+1 < len(content) && content[index+1] == '*':
			end := strings.Index(content[index+2:], "*/")
			if end < 0 || index+2+end+2 > offset {
				return 0, nil, false
			}
			index += 2 + end + 1
		case char == '"' || char == '\'' || (char == '`' && fileType != "python"):
			quote := content[index : index+1]
			if fileType == "python" && strings.HasPrefix(content[index:], strings.Repeat(quote, 3)) {
				quote = strings.Repeat(quote, 3)
			}
			end := literalEnd(content, index+len(quote), quote)
			if offset >= index && offset < end {
				return index, openers, true
			}
			index = end - 1
		case char == '(' || char == '[' || char == '{':
			openers = append(openers, index)
		case char == ')' || char == ']' || char == '}':
			if len(openers) > 0 {
				openers = openers[:len(openers)-1]
			}
		}
	}
	return 0, nil, false
}

// literalEnd returns the offset just past the closing quote, honoring
// backslash escapes; an unterminated single-quoted string ends at the line.
func literalEnd(content string, from int, quote string) int {
	for index := from; index < len(content); index++ {
		switch {
		case content[index] == '\\':
			index++
		case strings.HasPrefix(content[index:], quote):
			return index + len(quote)
		case content[index] == '\n' && len(quote) == 1:
			return index
		}
	}
	return len(content)
}

func openerHead(content string, opener int) string {
	lineStart := strings.LastIndexByte(content[:opener], '\n') + 1
	return strings.TrimSpace(content[lineStart:opener])
}

// collectionIsDetectionData walks the enclosing brackets outward. A bracket
// named like detection data (PATTERNS = [, "deny": [) or a regex constructor
// call makes the literal data; an executing call (subprocess.run([...]))
// makes it code.
func collectionIsDetectionData(content string, openers []int) bool {
	for index := len(openers) - 1; index >= 0; index-- {
		opener := openers[index]
		head := openerHead(content, opener)
		if content[opener] == '(' {
			if call := detectionCall.FindStringSubmatch(head); call != nil {
				name := call[1]
				short := name[strings.LastIndexByte(name, '.')+1:]
				if regexConstructors[name] {
					return true
				}
				if executingCalls[short] {
					return false
				}
				continue
			}
		}
		if strings.HasSuffix(head, "(") || strings.HasSuffix(head, ",") || head == "" {
			continue
		}
		if match := detectionAssignment.FindStringSubmatch(head); match != nil {
			if isDetectionDataName(match[1]) {
				return !insideExecutingCall(content, openers[:index])
			}
		}
	}
	return false
}

func insideExecutingCall(content string, openers []int) bool {
	for _, opener := range openers {
		if content[opener] != '(' {
			continue
		}
		if call := detectionCall.FindStringSubmatch(openerHead(content, opener)); call != nil {
			name := call[1]
			if executingCalls[name[strings.LastIndexByte(name, '.')+1:]] {
				return true
			}
		}
	}
	return false
}

// yamlDetectionData reports a match in the value of a detection data key
// (fix: Remove privileged: true) or in a list item under a detection data
// key (deny:\n  - "Bash(curl * | sh)").
func yamlDetectionData(content string, offset int) bool {
	lineStart := strings.LastIndexByte(content[:offset], '\n') + 1
	lineEnd := len(content)
	if index := strings.IndexByte(content[offset:], '\n'); index >= 0 {
		lineEnd = offset + index
	}
	line := content[lineStart:lineEnd]
	if match := yamlKeyLine.FindStringSubmatchIndex(line); match != nil && lineStart+match[1] <= offset {
		return detectionDataKey.MatchString(line[match[4]:match[5]])
	}
	trimmed := strings.TrimLeft(line, " ")
	if !strings.HasPrefix(trimmed, "- ") {
		return false
	}
	indent := len(line) - len(trimmed)
	for cursor := lineStart; cursor > 0; {
		previousStart := strings.LastIndexByte(content[:cursor-1], '\n') + 1
		previous := content[previousStart : cursor-1]
		cursor = previousStart
		if strings.TrimSpace(previous) == "" {
			continue
		}
		previousIndent := len(previous) - len(strings.TrimLeft(previous, " "))
		if previousIndent < indent || (previousIndent == indent && !strings.HasPrefix(strings.TrimLeft(previous, " "), "- ")) {
			if match := yamlKeyLine.FindStringSubmatch(previous); match != nil {
				return isDetectionDataName(match[2])
			}
			return false
		}
	}
	return false
}
