package agentskill

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	pyparser "github.com/tamnd/gopapy/parser"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// gopapy recycles its parser arena as soon as ParseFile returns. Keep parsing
// and traversal in one critical section so a concurrent parse cannot mutate
// the AST that is still being analyzed.
var pythonParserMu sync.Mutex

var astSubprocessCalls = wordSet("call", "run", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput")
var astOSExecCalls = wordSet(
	"system", "popen", "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
	"spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "posix_spawn", "posix_spawnp",
)
var astDangerousGetattrNames = wordSet("exec", "eval", "system", "popen", "__import__")

var astRuleProperties = map[string]struct {
	message    string
	severity   string
	confidence float64
}{
	"AST1": {"exec() call detected", "HIGH", .85},
	"AST2": {"eval() call detected", "HIGH", .85},
	"AST3": {"Dynamic import via __import__()", "MEDIUM", .75},
	"AST4": {"subprocess module call", "MEDIUM", .7},
	"AST5": {"os.system() or os exec-family call", "HIGH", .85},
	"AST6": {"compile() call detected", "MEDIUM", .65},
	"AST7": {"Dynamic attribute access via getattr()", "LOW", .5},
	"AST8": {"Dangerous execution chain", "CRITICAL", .95},
	"AST9": {"Reflective dangerous call via getattr() with a literal sink name", "HIGH", .85},
}

var taintCredentialSources = wordSet("os.environ.get", "os.environ", "os.getenv")
var taintFileReadSources = wordSet("open", "pathlib.Path.read_text", "pathlib.Path.read_bytes")
var taintNetworkInputSources = wordSet(
	"requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
	"httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
	"urllib.request.urlopen", "urllib.request.urlretrieve", "socket.socket.recv", "socket.socket.recvfrom",
)
var taintUserInputSources = wordSet("input", "sys.stdin.read", "sys.stdin.readline")
var taintNetworkOutputSinks = wordSet(
	"requests.post", "requests.put", "requests.patch", "requests.get",
	"httpx.post", "httpx.put", "httpx.patch", "httpx.get",
	"urllib.request.urlopen", "socket.socket.send", "socket.socket.sendall", "socket.socket.sendto",
)
var taintExecSinks = wordSet(
	"exec", "eval", "compile", "os.system", "os.popen", "subprocess.run", "subprocess.call",
	"subprocess.check_output", "subprocess.check_call", "subprocess.Popen",
)
var taintFileWriteSinks = wordSet("open", "pathlib.Path.write_text", "pathlib.Path.write_bytes", "shutil.copy", "shutil.copy2", "shutil.copyfile")

var taintRuleProperties = map[string]struct {
	severity   string
	confidence float64
}{
	"TT1": {"HIGH", .8}, "TT2": {"MEDIUM", .65}, "TT3": {"CRITICAL", .9},
	"TT4": {"HIGH", .8}, "TT5": {"CRITICAL", .9},
}

type taintedVariable struct {
	name       string
	sourceCall string
	line       int
}

func analyzePythonBehavior(item component) []model.Finding {
	if !strings.HasSuffix(item.Path, ".py") || len(item.Content) > maxFileBytes {
		return nil
	}
	pythonParserMu.Lock()
	defer pythonParserMu.Unlock()
	module, err := pyparser.ParseFile(item.Path, item.Content)
	if err != nil {
		return nil
	}
	aliases := buildPythonImportAliases(module)
	types := buildPythonTypeMap(module, aliases)
	findings := analyzePythonAST(item, module, aliases)
	findings = append(findings, analyzePythonTaint(item, module, aliases, types)...)
	return findings
}

func analyzePythonAST(item component, module *pyparser.Module, aliases map[string]string) []model.Finding {
	findings := make([]model.Finding, 0)
	pythonWalk(module, func(raw any) {
		call, ok := raw.(*pyparser.Call)
		if !ok {
			return
		}
		name := resolvePythonCallName(call, aliases)
		if name == "" {
			name = resolvePythonDynamicImportCall(call, aliases)
		}
		if name == "" {
			return
		}
		line, column := correctedPythonCallPosition(item.Content, name, call.P.Line, call.P.Col)
		endLine := pythonCallEndLine(item.Content, line, column)
		emit := func(id, override string) {
			properties := astRuleProperties[id]
			message := properties.message
			if override != "" {
				message = override
			}
			if finding, ok := pythonAnalyzerFinding(item, id, message, properties.severity, properties.confidence, line, endLine, "Dangerous Code Execution"); ok {
				findings = append(findings, finding)
			}
		}
		switch name {
		case "exec", "eval":
			if len(call.Args) > 0 {
				if source := dangerousPythonSource(call.Args[0], aliases); source != "" {
					emit("AST8", fmt.Sprintf("Dangerous chain: %s() wrapping %s", name, source))
				}
			}
			if name == "exec" {
				emit("AST1", "")
			} else {
				emit("AST2", "")
			}
		case "__import__":
			emit("AST3", "")
		case "compile":
			emit("AST6", "")
		case "getattr":
			if len(call.Args) < 2 {
				return
			}
			constant, constantArgument := call.Args[1].(*pyparser.Constant)
			if !constantArgument {
				emit("AST7", "")
				return
			}
			if value, ok := constant.Value.(string); ok && astDangerousGetattrNames[value] {
				emit("AST9", "")
			}
		default:
			if strings.HasPrefix(name, "subprocess.") && astSubprocessCalls[strings.TrimPrefix(name, "subprocess.")] {
				emit("AST4", "")
			} else if strings.HasPrefix(name, "os.") && astOSExecCalls[strings.TrimPrefix(name, "os.")] {
				emit("AST5", "")
			}
		}
	})
	return findings
}

func dangerousPythonSource(expression pyparser.Expr, aliases map[string]string) string {
	result := ""
	pythonWalk(expression, func(raw any) {
		if result != "" {
			return
		}
		call, ok := raw.(*pyparser.Call)
		if !ok {
			return
		}
		name := resolvePythonCallName(call, aliases)
		if name == "compile" || name == "__import__" || strings.HasPrefix(name, "subprocess.") || strings.HasPrefix(name, "os.") ||
			containsAny(name, "base64", "codecs", "marshal", "urllib", "requests", "httpx") {
			result = name
		}
	})
	return result
}

func analyzePythonTaint(item component, module *pyparser.Module, aliases, types map[string]string) []model.Finding {
	findings := make([]model.Finding, 0)
	tainted := map[string]taintedVariable{}
	seen := map[string]bool{}
	pythonWalk(module, func(raw any) {
		if assignment, ok := raw.(*pyparser.Assign); ok {
			source := findPythonSourceInExpression(assignment.Value, types, aliases)
			if source == "" {
				if subscript, ok := assignment.Value.(*pyparser.Subscript); ok {
					base := resolvePythonDottedName(subscript.Value)
					if base != "" {
						base = applyPythonImportAliases(base, aliases)
					}
					if taintCredentialSources[base] {
						source = base
					}
				}
			}
			if source == "" {
				if existing, ok := findTaintedInPythonExpression(assignment.Value, tainted); ok {
					source = existing.sourceCall
				}
			}
			if source != "" {
				markPythonTargets(assignment.Targets, tainted, source, assignment.P.Line)
			}
			return
		}
		call, ok := raw.(*pyparser.Call)
		if !ok {
			return
		}
		sink := resolvePythonCallNameTyped(call, types, aliases)
		if sink == "" {
			sink = resolvePythonDynamicImportCall(call, aliases)
		}
		if !isTaintSink(sink) || (sink == "open" && !pythonOpenForWrite(call)) {
			return
		}
		line := call.P.Line
		endLine := pythonCallEndLine(item.Content, call.P.Line, call.P.Col)
		emit := func(id, message string) {
			key := fmt.Sprintf("%s\x00%d", id, line)
			if seen[key] {
				return
			}
			seen[key] = true
			properties := taintRuleProperties[id]
			if finding, ok := pythonAnalyzerFinding(item, id, message, properties.severity, properties.confidence, line, endLine, "Data Flow"); ok {
				findings = append(findings, finding)
			}
		}
		for _, source := range findNestedPythonSources(call, types, aliases) {
			if source.name == "open" && source.call != nil && pythonOpenForWrite(source.call) {
				continue
			}
			rule := pickTaintRule(source.name, sink, true)
			emit(rule, fmt.Sprintf("Direct flow: %s (%s) → %s (%s)", source.name, taintSourceCategory(source.name), sink, taintSinkCategory(sink)))
		}
		for _, variable := range findTaintedPythonArguments(call, tainted) {
			rule := pickTaintRule(variable.sourceCall, sink, false)
			emit(rule, fmt.Sprintf("Tainted flow: '%s' from %s (line %d, %s) → %s (%s)",
				variable.name, variable.sourceCall, variable.line, taintSourceCategory(variable.sourceCall), sink, taintSinkCategory(sink)))
		}
	})
	return findings
}

type namedPythonCall struct {
	name string
	call *pyparser.Call
}

func findNestedPythonSources(parent *pyparser.Call, types, aliases map[string]string) []namedPythonCall {
	results := make([]namedPythonCall, 0)
	pythonWalk(parent, func(raw any) {
		call, ok := raw.(*pyparser.Call)
		if !ok || call == parent {
			return
		}
		name := resolvePythonCallNameTyped(call, types, aliases)
		if isTaintSource(name) {
			results = append(results, namedPythonCall{name: name, call: call})
		}
	})
	return results
}

func findPythonSourceInExpression(expression pyparser.Expr, types, aliases map[string]string) string {
	result := ""
	pythonWalk(expression, func(raw any) {
		if result != "" {
			return
		}
		call, ok := raw.(*pyparser.Call)
		if !ok {
			return
		}
		name := resolvePythonCallNameTyped(call, types, aliases)
		if isTaintSource(name) && !(name == "open" && pythonOpenForWrite(call)) {
			result = name
		}
	})
	return result
}

func findTaintedInPythonExpression(expression pyparser.Expr, tainted map[string]taintedVariable) (taintedVariable, bool) {
	var result taintedVariable
	found := false
	pythonWalk(expression, func(raw any) {
		if found {
			return
		}
		if name, ok := raw.(*pyparser.Name); ok {
			result, found = tainted[name.Id]
		}
	})
	return result, found
}

func findTaintedPythonArguments(call *pyparser.Call, tainted map[string]taintedVariable) []taintedVariable {
	seen := map[string]bool{}
	results := make([]taintedVariable, 0)
	pythonWalk(call, func(raw any) {
		name := ""
		switch node := raw.(type) {
		case *pyparser.Name:
			name = node.Id
		case *pyparser.Subscript:
			name = resolvePythonDottedName(node.Value)
		}
		if name == "" || seen[name] {
			return
		}
		if value, ok := tainted[name]; ok {
			seen[name] = true
			results = append(results, value)
		}
	})
	return results
}

func markPythonTargets(targets []pyparser.Expr, tainted map[string]taintedVariable, source string, line int) {
	for _, target := range targets {
		switch value := target.(type) {
		case *pyparser.Name:
			tainted[value.Id] = taintedVariable{name: value.Id, sourceCall: source, line: line}
		case *pyparser.Tuple:
			for _, element := range value.Elts {
				if name, ok := element.(*pyparser.Name); ok {
					tainted[name.Id] = taintedVariable{name: name.Id, sourceCall: source, line: line}
				}
			}
		}
	}
}

func pickTaintRule(source, sink string, direct bool) string {
	if taintCredentialSources[source] && taintNetworkOutputSinks[sink] {
		return "TT3"
	}
	if taintFileReadSources[source] && taintNetworkOutputSinks[sink] {
		return "TT4"
	}
	if (taintNetworkInputSources[source] || taintUserInputSources[source]) && taintExecSinks[sink] {
		return "TT5"
	}
	if direct {
		return "TT1"
	}
	return "TT2"
}

func taintSourceCategory(name string) string {
	switch {
	case taintCredentialSources[name]:
		return "credential/environment"
	case taintFileReadSources[name]:
		return "file read"
	case taintNetworkInputSources[name]:
		return "network input"
	case taintUserInputSources[name]:
		return "user input"
	default:
		return "data source"
	}
}

func taintSinkCategory(name string) string {
	switch {
	case taintNetworkOutputSinks[name]:
		return "network output"
	case taintExecSinks[name]:
		return "code execution"
	case taintFileWriteSinks[name]:
		return "file write"
	default:
		return "data sink"
	}
}

func isTaintSource(name string) bool {
	return taintCredentialSources[name] || taintFileReadSources[name] || taintNetworkInputSources[name] || taintUserInputSources[name]
}

func isTaintSink(name string) bool {
	return taintNetworkOutputSinks[name] || taintExecSinks[name] || taintFileWriteSinks[name]
}

func pythonOpenForWrite(call *pyparser.Call) bool {
	if len(call.Args) >= 2 {
		if mode, ok := pythonStringConstant(call.Args[1]); ok && strings.ContainsAny(mode, "wa") {
			return true
		}
	}
	for _, keyword := range call.Keywords {
		if keyword.Arg == "mode" {
			if mode, ok := pythonStringConstant(keyword.Value); ok && strings.ContainsAny(mode, "wa") {
				return true
			}
		}
	}
	return false
}

func buildPythonImportAliases(module *pyparser.Module) map[string]string {
	aliases := map[string]string{}
	pythonWalk(module, func(raw any) {
		switch node := raw.(type) {
		case *pyparser.Import:
			for _, imported := range node.Names {
				local := imported.Name
				if imported.Asname != "" {
					local = imported.Asname
				}
				aliases[local] = imported.Name
			}
		case *pyparser.ImportFrom:
			for _, imported := range node.Names {
				local := imported.Name
				if imported.Asname != "" {
					local = imported.Asname
				}
				qualified := imported.Name
				if node.Module != "" {
					qualified = node.Module + "." + imported.Name
				}
				aliases[local] = qualified
			}
		}
	})
	return aliases
}

func buildPythonTypeMap(module *pyparser.Module, aliases map[string]string) map[string]string {
	types := map[string]string{}
	record := func(target pyparser.Expr, call *pyparser.Call) {
		name, ok := target.(*pyparser.Name)
		if !ok {
			return
		}
		constructor := resolvePythonDottedName(call.Func)
		if constructor != "" {
			types[name.Id] = applyPythonImportAliases(constructor, aliases)
		}
	}
	pythonWalk(module, func(raw any) {
		switch node := raw.(type) {
		case *pyparser.Assign:
			if call, ok := node.Value.(*pyparser.Call); ok {
				for _, target := range node.Targets {
					record(target, call)
				}
			}
		case *pyparser.With:
			for _, item := range node.Items {
				if call, ok := item.ContextExpr.(*pyparser.Call); ok && item.OptionalVars != nil {
					record(item.OptionalVars, call)
				}
			}
		}
	})
	return types
}

func resolvePythonCallName(call *pyparser.Call, aliases map[string]string) string {
	name := resolvePythonDottedName(call.Func)
	if name != "" && len(aliases) > 0 {
		name = applyPythonImportAliases(name, aliases)
	}
	return name
}

func resolvePythonCallNameTyped(call *pyparser.Call, types, aliases map[string]string) string {
	name := resolvePythonDottedName(call.Func)
	if name == "" {
		return ""
	}
	if len(aliases) > 0 {
		name = applyPythonImportAliases(name, aliases)
	}
	root, rest, found := strings.Cut(name, ".")
	if found {
		if inferred := types[root]; inferred != "" {
			name = inferred + "." + rest
		}
	}
	return name
}

func resolvePythonDottedName(expression pyparser.Expr) string {
	switch node := expression.(type) {
	case *pyparser.Name:
		return node.Id
	case *pyparser.Attribute:
		prefix := resolvePythonDottedName(node.Value)
		if prefix != "" {
			return prefix + "." + node.Attr
		}
	}
	return ""
}

func applyPythonImportAliases(name string, aliases map[string]string) string {
	if alias := aliases[name]; alias != "" {
		return stripPythonBuiltins(alias)
	}
	root, rest, found := strings.Cut(name, ".")
	if found && aliases[root] != "" {
		return stripPythonBuiltins(aliases[root] + "." + rest)
	}
	return stripPythonBuiltins(name)
}

func stripPythonBuiltins(name string) string {
	if strings.HasPrefix(name, "builtins.") && strings.Count(name, ".") == 1 {
		return strings.TrimPrefix(name, "builtins.")
	}
	return name
}

func resolvePythonDynamicImportCall(call *pyparser.Call, aliases map[string]string) string {
	attribute, ok := call.Func.(*pyparser.Attribute)
	if !ok {
		return ""
	}
	moduleCall, ok := attribute.Value.(*pyparser.Call)
	if !ok {
		return ""
	}
	function := resolvePythonDottedName(moduleCall.Func)
	if function != "" && len(aliases) > 0 {
		function = applyPythonImportAliases(function, aliases)
	}
	if function != "importlib.import_module" && function != "import_module" || len(moduleCall.Args) == 0 {
		return ""
	}
	module, ok := pythonStringConstant(moduleCall.Args[0])
	if !ok {
		return ""
	}
	return module + "." + attribute.Attr
}

func pythonStringConstant(expression pyparser.Expr) (string, bool) {
	constant, ok := expression.(*pyparser.Constant)
	if !ok {
		return "", false
	}
	value, ok := constant.Value.(string)
	return value, ok
}

func pythonAnalyzerFinding(item component, id, message, severity string, confidence float64, line, endLine int, category string) (model.Finding, bool) {
	// Python source gets no example handling: "# e.g." is only a comment.
	context := contextAtLine(item.Content, line, 3)
	if confidence < .4 && severity != "HIGH" && severity != "CRITICAL" {
		return model.Finding{}, false
	}
	explanation, remediation := ruleText(id)
	matched := sourceLines(item.Content, line, endLine)
	return model.Finding{ID: id, Category: category, Pattern: message, Severity: severity, Confidence: confidence,
		Location: model.Location{File: item.Path, StartLine: line, EndLine: intPointer(endLine)}, Finding: truncate(matched, 200), MatchedText: truncate(matched, 200), Explanation: explanation,
		Remediation: remediation, CodeSnippet: context, Tags: []string{category}}, true
}

func contextAtLine(content string, line, window int) string {
	lines := pythonSplitLines(content)
	start := max(0, line-1-window)
	end := min(len(lines), line+window)
	return strings.Join(lines[start:end], "\n")
}

func sourceLines(content string, line, endLine int) string {
	lines := pythonSplitLines(content)
	if line < 1 || line > len(lines) {
		return ""
	}
	if endLine < line {
		endLine = line
	}
	endLine = min(endLine, len(lines))
	return strings.Join(lines[line-1:endLine], "\n")
}

func pythonWalk(root any, visit func(any)) {
	queue := []reflect.Value{reflect.ValueOf(root)}
	var collectChildren func(reflect.Value, *[]reflect.Value)
	collectChildren = func(value reflect.Value, children *[]reflect.Value) {
		if !value.IsValid() {
			return
		}
		if value.Kind() == reflect.Interface {
			if value.IsNil() {
				return
			}
			collectChildren(value.Elem(), children)
			return
		}
		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return
			}
			*children = append(*children, value)
			return
		}
		switch value.Kind() {
		case reflect.Struct:
			for index := 0; index < value.NumField(); index++ {
				field := value.Field(index)
				if field.CanInterface() {
					collectChildren(field, children)
				}
			}
		case reflect.Slice, reflect.Array:
			for index := 0; index < value.Len(); index++ {
				collectChildren(value.Index(index), children)
			}
		}
	}
	for len(queue) > 0 {
		value := queue[0]
		queue = queue[1:]
		if value.Kind() == reflect.Interface {
			value = value.Elem()
		}
		if value.Kind() != reflect.Pointer || value.IsNil() {
			continue
		}
		if value.CanInterface() {
			visit(value.Interface())
		}
		collectChildren(value.Elem(), &queue)
	}
}

func intPointer(value int) *int { return &value }

// pythonCallEndLine returns the line containing the closing parenthesis of the
// call that starts at the parser position. gopapy/parser exposes start
// positions only, while CPython includes end_lineno on ast.Call nodes.
func pythonCallEndLine(content string, startLine, startColumn int) int {
	if startLine < 1 {
		return 1
	}
	offset := byteOffsetForPythonPosition(content, startLine, startColumn)
	depth := 0
	seenOpen := false
	line := startLine
	quote := byte(0)
	triple := false
	escaped := false
	comment := false
	for index := offset; index < len(content); index++ {
		char := content[index]
		if char == '\n' {
			line++
			comment = false
			if quote != 0 && !triple {
				quote = 0
			}
			escaped = false
			continue
		}
		if comment {
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if triple {
				if char == quote && index+2 < len(content) && content[index+1] == quote && content[index+2] == quote {
					quote = 0
					triple = false
					index += 2
				}
			} else if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '#':
			comment = true
		case '\'', '"':
			quote = char
			triple = index+2 < len(content) && content[index+1] == char && content[index+2] == char
			if triple {
				index += 2
			}
		case '(':
			seenOpen = true
			depth++
		case ')':
			if seenOpen {
				depth--
				if depth == 0 {
					return line
				}
			}
		}
	}
	return startLine
}

func byteOffsetForPythonPosition(content string, line, column int) int {
	offset := 0
	for current := 1; current < line && offset < len(content); current++ {
		next := strings.IndexByte(content[offset:], '\n')
		if next < 0 {
			return len(content)
		}
		offset += next + 1
	}
	return min(len(content), offset+max(0, column-1))
}

func correctedPythonCallPosition(content, name string, line, column int) (int, int) {
	if line >= 1 {
		lines := pythonSplitLines(content)
		if line <= len(lines) {
			start := max(0, column-1)
			if start <= len(lines[line-1]) && strings.Contains(lines[line-1][start:], name) {
				return line, column
			}
		}
	}
	// gopapy 0.6 reports interpolation-relative positions for calls nested in
	// f-strings. Recover only an unambiguous textual occurrence; ambiguous
	// cases retain the parser position instead of guessing.
	expression := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`)
	matches := expression.FindAllStringIndex(content, 2)
	if len(matches) != 1 {
		return line, column
	}
	offset := matches[0][0]
	line = 1 + strings.Count(content[:offset], "\n")
	lineStart := strings.LastIndex(content[:offset], "\n") + 1
	return line, offset - lineStart + 1
}

func sortedStringKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
