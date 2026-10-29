package agentskill

// Detection data: security tooling keeps the patterns it looks for as data,
// such as a list of regexes, a dict of findings with "fix" and "message"
// texts, or the deny list of a Claude settings file. A rule match inside such
// a string describes what the tool detects, so it is marked for review
// ("detection rule") instead of scored. A string that is executed, or passed
// to subprocess, exec or open, is not detection data, and neither is a tool
// definition: an agent reads a tool's name and description as instructions.

import (
	"regexp"
	"strings"
)

const reviewDetectionRule = "detection rule"

var (
	nameSegment = regexp.MustCompile(`[A-Z]?[a-z]+|[A-Z]+(?:[^a-z]|$)|[0-9]+`)
	// detectionMetadataKey is a key whose string value is always detection
	// data: "pattern": r"...", "fix": "Remove privileged: true", "risk": "...".
	detectionMetadataKey = regexp.MustCompile(`(?i)^(?:\w*_)?(?:patterns?|regex(?:es|p)?|risk|fix|remediation|recommendation|severity)$`)
	// descriptiveKey is a key whose value is detection data only next to a
	// detectionSiblingKey in the same object or call: {"check": ...,
	// "message": "..."}, but not {"name": ..., "description": "..."}.
	descriptiveKey      = regexp.MustCompile(`(?i)^(?:\w*_)?(?:description|desc|message|msg|name|title|summary|note|label|hint|details?|explanation|reason|warning|example)$`)
	detectionSiblingKey = regexp.MustCompile(`(?i)^(?:\w*_)?(?:patterns?|regex(?:es|p)?|severity|risk|fix|remediation|recommendation|check|cwe|mitre|atlas_id|tactic|category)$`)
	// toolSchemaKey marks a tool definition: {name, description, inputSchema}.
	toolSchemaKey = regexp.MustCompile(`(?i)^input_?schema$`)
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
// TASKS is not ASK. Words that also name ordinary data (prompt, payload,
// example, sample, secret) are not here: PAYLOAD = [...] may be run.
var detectionDataWords = map[string]bool{
	"pattern": true, "regex": true, "regexp": true, "rule": true, "signature": true, "indicator": true, "detector": true,
	"detection": true, "check": true, "deny": true, "denylist": true, "ask": true, "block": true, "blocklist": true,
	"blocked": true, "forbid": true, "forbidden": true, "danger": true, "dangerous": true, "risk": true, "risky": true,
	"smell": true, "threat": true, "attack": true, "ioc": true, "seed": true, "suspicious": true, "unsafe": true,
	"malicious": true, "injection": true, "jailbreak": true, "technique": true, "atlas": true, "cwe": true, "vuln": true,
	"vulnerability": true, "lint": true,
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

// toolCalls define or register a tool for an agent: @mcp.tool(...),
// server.tool(...), Tool(name=..., description=...).
var toolCalls = map[string]bool{
	"tool": true, "Tool": true, "registerTool": true, "register_tool": true, "addTool": true, "add_tool": true,
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
	if insideToolDefinition(item.Content, openers, item.Type) {
		return ""
	}
	lineStart := strings.LastIndexByte(item.Content[:literalStart], '\n') + 1
	before := item.Content[lineStart:literalStart]
	// A key's value: "fix": "...", pattern=r"...", or "message": "..." next
	// to "severity".
	if match := detectionKeyValue.FindStringSubmatch(before); match != nil {
		metadata := detectionMetadataKey.MatchString(match[1])
		if !metadata && descriptiveKey.MatchString(match[1]) && len(openers) > 0 {
			metadata = anyKey(objectKeys(item.Content, openers[len(openers)-1], item.Type), detectionSiblingKey)
		}
		if metadata {
			if !insideExecutingCall(item.Content, openers) {
				return reviewDetectionRule
			}
			return ""
		}
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

// insideToolDefinition reports a literal inside a tool registration call or
// an object with an inputSchema key, at any depth.
func insideToolDefinition(content string, openers []int, fileType string) bool {
	for _, opener := range openers {
		if content[opener] == '(' {
			if call := detectionCall.FindStringSubmatch(openerHead(content, opener)); call != nil {
				if toolCalls[call[1][strings.LastIndexByte(call[1], '.')+1:]] {
					return true
				}
			}
		}
		if anyKey(objectKeys(content, opener, fileType), toolSchemaKey) {
			return true
		}
	}
	return false
}

func anyKey(keys []string, pattern *regexp.Regexp) bool {
	for _, key := range keys {
		if pattern.MatchString(key) {
			return true
		}
	}
	return false
}

// objectKeys returns the keys directly inside the bracket at opener: dict
// and object keys ("severity": , name:) and keyword arguments (severity=).
func objectKeys(content string, opener int, fileType string) []string {
	hashComments := fileType == "python" || fileType == "ruby" || fileType == "toml"
	slashComments := fileType == "javascript" || fileType == "typescript" || fileType == "go" || fileType == "rust" || fileType == "json"
	var keys []string
	depth, entryStart := 0, opener+1
	for index := opener; index < len(content); index++ {
		switch char := content[index]; {
		case hashComments && char == '#', slashComments && char == '/' && index+1 < len(content) && content[index+1] == '/':
			if end := strings.IndexByte(content[index:], '\n'); end >= 0 {
				index += end
			} else {
				return keys
			}
		case char == '"' || char == '\'' || (char == '`' && fileType != "python"):
			quote := content[index : index+1]
			if fileType == "python" && strings.HasPrefix(content[index:], strings.Repeat(quote, 3)) {
				quote = strings.Repeat(quote, 3)
			}
			index = literalEnd(content, index+len(quote), quote) - 1
		case char == '(' || char == '[' || char == '{':
			depth++
		case char == ')' || char == ']' || char == '}':
			if depth--; depth == 0 {
				return appendEntryKey(keys, content[entryStart:index])
			}
		case char == ',' && depth == 1:
			keys = appendEntryKey(keys, content[entryStart:index])
			entryStart = index + 1
		}
	}
	return keys
}

var entryKey = regexp.MustCompile(`^\s*["']?([A-Za-z_][\w-]*)["']?\s*(?::|=[^=])`)

func appendEntryKey(keys []string, entry string) []string {
	// Skip comment lines before the key.
	for entry = strings.TrimLeft(entry, " \t\r\n"); strings.HasPrefix(entry, "#") || strings.HasPrefix(entry, "//"); entry = strings.TrimLeft(entry, " \t\r\n") {
		end := strings.IndexByte(entry, '\n')
		if end < 0 {
			return keys
		}
		entry = entry[end:]
	}
	if match := entryKey.FindStringSubmatch(entry); match != nil {
		return append(keys, match[1])
	}
	return keys
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
		key := line[match[4]:match[5]]
		return detectionMetadataKey.MatchString(key) ||
			(descriptiveKey.MatchString(key) && anyKey(yamlSiblingKeys(content, lineStart, match[4]), detectionSiblingKey))
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

// yamlSiblingKeys returns the keys of the YAML mapping holding the key that
// starts at column on the line at lineStart: lines whose key starts at the
// same column, up to the item's "- " line above and the next item below.
func yamlSiblingKeys(content string, lineStart, column int) []string {
	lines := strings.Split(content, "\n")
	current := strings.Count(content[:lineStart], "\n")
	var keys []string
	keyAt := func(line string) (string, int, bool) {
		match := yamlKeyLine.FindStringSubmatchIndex(line)
		if match == nil {
			return "", 0, false
		}
		return line[match[4]:match[5]], match[4], true
	}
	indentOf := func(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }
	if !strings.HasPrefix(strings.TrimLeft(lines[current], " "), "- ") {
		for index := current - 1; index >= 0; index-- {
			line := lines[index]
			if strings.TrimSpace(line) == "" || indentOf(line) > column {
				continue
			}
			key, keyColumn, ok := keyAt(line)
			if !ok || keyColumn != column {
				break
			}
			keys = append(keys, key)
			if indentOf(line) < column {
				break
			}
		}
	}
	for index := current + 1; index < len(lines); index++ {
		line := lines[index]
		if strings.TrimSpace(line) == "" || indentOf(line) > column {
			continue
		}
		key, keyColumn, ok := keyAt(line)
		if !ok || indentOf(line) < column {
			break
		}
		if keyColumn == column {
			keys = append(keys, key)
		}
	}
	return keys
}
