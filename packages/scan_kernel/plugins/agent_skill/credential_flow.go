package agentskill

// TT3 (credential network flow) separates a credential that leaves in a
// request from one that only authenticates it. A key read from the
// environment and sent in an Authorization or X-API-Key header, or as the
// auth= argument, is how a skill calls its own API, when the API is the
// key's: the host comes from configuration (an environment variable or a
// function argument without a literal default), or the literal host names
// the key's service (UNSPLASH_ACCESS_KEY to api.unsplash.com). A host the
// scanner cannot resolve does not count as configured. An environment value that names the host
// (https://{HOST}/...) chooses the destination. Neither is exfiltration.
//
// CRITICAL: a credential in the body, JSON, form data, query string or URL;
// the whole environment; the content of a credential file; any credential
// sent to a collection host (webhook.site, a Discord webhook, a raw IP
// address); a cloud secret or more than one credential in one request.
// HIGH: one credential in an auth header to any other host
// (OPENAI_API_KEY to metrics.example.com).

import (
	"reflect"
	"regexp"
	"strings"

	pyparser "github.com/tamnd/gopapy/parser"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// credentialRole says where a credential sits in a value.
type credentialRole int

const (
	// credentialData leaves in the request: body, query string, URL path.
	credentialData credentialRole = iota
	// credentialSecret is the credential itself ("Bearer " + key included).
	credentialSecret
	// credentialConfig is a non-secret environment value such as a host.
	credentialConfig
	// credentialHeaders is a header mapping with credentials only under
	// authentication names.
	credentialHeaders
	// credentialURL is a URL whose environment value is only the
	// destination: scheme, host or base URL.
	credentialURL
	// credentialRequest is a request object built from the roles above.
	credentialRequest
)

var (
	// secretEnvironmentName marks an environment variable that holds a
	// credential. Other names (HOST, BASE_URL, REGION) are configuration.
	secretEnvironmentName = regexp.MustCompile(`(?i)key|token|secret|passw|pwd|credential|auth|cookie|session|private|signature|cert`)
	// authHeaderName is a header that carries a credential to the API.
	authHeaderName = regexp.MustCompile(`(?i)^(?:proxy-)?authorization$|^(?:x-)?(?:api[-_]?key|apikey|api[-_]?token|auth[-_]?token|access[-_]?token|token|auth|key|subscription[-_]?key|goog-api-key|rapidapi-key|private-token|session-token)$|^ocp-apim-subscription-key$`)
	// urlDestinationPrefix is literal text before an environment value
	// that still leaves the value in the scheme or host part of the URL.
	urlDestinationPrefix = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9+.-]*://[^/?#\x00]*)?$`)
	// credentialFilePath names a file whose content is a credential: SSH
	// keys, cloud credentials, a .env file.
	credentialFilePath = regexp.MustCompile(`(?:^|[/\\])\.env(?:\.[\w-]+)?$`)
	// cloudSecretName is a cloud credential that no skill sends in a
	// header to its own API.
	cloudSecretName = regexp.MustCompile(`(?i)^(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GOOGLE_APPLICATION_CREDENTIALS)$|^AZURE_\w*SECRET`)
	// genericCredentialWord is a part of an environment variable name that
	// says nothing about the service the key belongs to.
	genericCredentialWord = map[string]bool{"api": true, "key": true, "keys": true, "token": true, "tokens": true, "secret": true,
		"access": true, "auth": true, "bearer": true, "client": true, "id": true, "password": true}
	nameWordSeparator = regexp.MustCompile(`[^A-Za-z0-9]+`)
	nonAlphanumeric   = regexp.MustCompile(`[^a-z0-9]+`)
	// urlLiteralHost is a URL's host part; it may hold the markers for a
	// configured or an unresolved value.
	urlLiteralHost = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://([^/?#:@]+)(?:[/?#:]|$)`)
	// collectionHost is a service that collects whatever is sent to it, or
	// a raw IPv4 address.
	collectionHost = regexp.MustCompile(`(?i)webhook\.site|requestbin|pipedream\.net|\bngrok(?:-free)?\.(?:io|app|dev)|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot|pastebin\.com|paste\.ee|hastebin|transfer\.sh|interact\.sh|\boast\.(?:fun|pro|live|site|online|me)\b|burpcollaborator\.net|requestcatcher\.com|beeceptor\.com|webhook\.cool|://(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)`)
)

func isCredentialFilePath(path string) bool {
	return highValueCredential.MatchString(path) || credentialFilePath.MatchString(path)
}

// pythonCredentialFlow evaluates credential roles in one Python module.
type pythonCredentialFlow struct {
	aliases, types map[string]string
	tainted        map[string]taintedVariable
	// assigned holds every value assigned to a name, for following a URL
	// or a path to its string literals.
	assigned map[string][]pyparser.Expr
	// definitions resolves a name where it is used (credential_destination.go).
	definitions *pythonDefinitions
	// environment names variables that hold the whole environment
	// (env = dict(os.environ)). They matter only at a network sink.
	environment map[string]bool
}

func newPythonCredentialFlow(module *pyparser.Module, aliases, types map[string]string, tainted map[string]taintedVariable) *pythonCredentialFlow {
	flow := &pythonCredentialFlow{aliases: aliases, types: types, tainted: tainted,
		assigned: map[string][]pyparser.Expr{}, environment: map[string]bool{}}
	flow.definitions = newPythonDefinitions(module)
	pythonWalk(module, func(raw any) {
		switch node := raw.(type) {
		case *pyparser.Assign:
			for _, target := range node.Targets {
				if name, ok := target.(*pyparser.Name); ok {
					flow.assigned[name.Id] = append(flow.assigned[name.Id], node.Value)
				}
			}
		case *pyparser.For:
			// for name in ["A_KEY", "B_TOKEN"]: each element is a value of name.
			name, ok := node.Target.(*pyparser.Name)
			if !ok {
				return
			}
			switch iter := node.Iter.(type) {
			case *pyparser.List:
				flow.assigned[name.Id] = append(flow.assigned[name.Id], iter.Elts...)
			case *pyparser.Tuple:
				flow.assigned[name.Id] = append(flow.assigned[name.Id], iter.Elts...)
			}
		}
	})
	return flow
}

func isCredentialTaint(variable taintedVariable) bool {
	return taintCredentialSources[variable.sourceCall] || variable.credentialFile
}

// role returns the credential role of an expression, and false when no
// credential reaches it.
func (flow *pythonCredentialFlow) role(expression pyparser.Expr) (credentialRole, bool) {
	switch node := expression.(type) {
	case nil:
		return 0, false
	case *pyparser.Name:
		if variable, ok := flow.tainted[node.Id]; ok && isCredentialTaint(variable) {
			return variable.role, true
		}
		if flow.environment[node.Id] {
			return credentialData, true
		}
		return 0, false
	case *pyparser.Attribute:
		if flow.isEnvironment(node) {
			return credentialData, true
		}
	case *pyparser.Subscript:
		if flow.isEnvironment(node.Value) {
			return environmentRole(node.Slice), true
		}
	case *pyparser.Call:
		name := resolvePythonCallNameTyped(node, flow.types, flow.aliases)
		switch {
		case name == "os.getenv" || name == "os.environ.get":
			var key pyparser.Expr
			if len(node.Args) > 0 {
				key = node.Args[0]
			}
			return environmentRole(key), true
		case flow.readsCredentialFile(node):
			return credentialSecret, true
		case name == "urllib.request.Request" || name == "requests.Request":
			return flow.requestRole(node)
		}
	case *pyparser.Dict:
		return flow.dictRole(node)
	case *pyparser.JoinedStr:
		return flow.stringRole(node.Values)
	case *pyparser.BinOp:
		if node.Op == "Add" {
			return flow.stringRole(flattenPythonConcatenation(node))
		}
	}
	return flow.combinedRole(pythonChildExpressions(expression))
}

func (flow *pythonCredentialFlow) isEnvironment(expression pyparser.Expr) bool {
	name := resolvePythonDottedName(expression)
	return name != "" && applyPythonImportAliases(name, flow.aliases) == "os.environ"
}

func environmentRole(key pyparser.Expr) credentialRole {
	if name, ok := pythonStringConstant(key); ok && !secretEnvironmentName.MatchString(name) {
		return credentialConfig
	}
	return credentialSecret
}

// combinedRole is the role of a value built from parts (a call, a tuple, a
// slice): bare values stay bare (a secret if any part is one), a lone
// container keeps its role, and anything else is data.
func (flow *pythonCredentialFlow) combinedRole(parts []pyparser.Expr) (credentialRole, bool) {
	result, found := credentialData, false
	for _, part := range parts {
		role, ok := flow.role(part)
		if !ok {
			continue
		}
		switch {
		case !found:
			result, found = role, true
		case role == result:
		case (role == credentialSecret || role == credentialConfig) && (result == credentialSecret || result == credentialConfig):
			result = credentialSecret
		default:
			return credentialData, true
		}
	}
	return result, found
}

// dictRole is credentialHeaders when every credential sits under an
// authentication header name, and data otherwise.
func (flow *pythonCredentialFlow) dictRole(node *pyparser.Dict) (credentialRole, bool) {
	found := false
	for index, value := range node.Values {
		role, ok := flow.role(value)
		if !ok {
			continue
		}
		found = true
		var key pyparser.Expr
		if index < len(node.Keys) {
			key = node.Keys[index]
		}
		if key == nil {
			if role != credentialHeaders {
				return credentialData, true
			}
			continue
		}
		name, constant := pythonStringConstant(key)
		if !constant || !authHeaderName.MatchString(name) || (role != credentialSecret && role != credentialConfig) {
			return credentialData, true
		}
	}
	return credentialHeaders, found
}

// stringRole evaluates the parts of an f-string or a concatenation in order.
// A secret keeps the string a secret ("Bearer " + key); an environment value
// with only a scheme and host before it makes the string a URL whose
// destination it names; anything else is data.
func (flow *pythonCredentialFlow) stringRole(parts []pyparser.Expr) (credentialRole, bool) {
	prefix := ""
	result, found := credentialData, false
	for _, part := range parts {
		if formatted, ok := part.(*pyparser.FormattedValue); ok {
			part = formatted.Value
		}
		if text, ok := pythonStringConstant(part); ok {
			prefix += text
			continue
		}
		role, ok := flow.role(part)
		if !ok {
			prefix += "\x00"
			continue
		}
		switch {
		case (role == credentialConfig || role == credentialURL) && urlDestinationPrefix.MatchString(prefix):
			role = credentialURL
		case role == credentialSecret:
		default:
			return credentialData, true
		}
		if found && role != result {
			return credentialData, true
		}
		result, found = role, true
		prefix += "\x00"
	}
	return result, found
}

func flattenPythonConcatenation(node *pyparser.BinOp) []pyparser.Expr {
	var parts []pyparser.Expr
	for _, side := range []pyparser.Expr{node.Left, node.Right} {
		if inner, ok := side.(*pyparser.BinOp); ok && inner.Op == "Add" {
			parts = append(parts, flattenPythonConcatenation(inner)...)
		} else {
			parts = append(parts, side)
		}
	}
	return parts
}

// requestRole evaluates urllib.request.Request(url, data, headers) or
// requests.Request(method, url, headers=..., ...).
func (flow *pythonCredentialFlow) requestRole(call *pyparser.Call) (credentialRole, bool) {
	positions := []string{"url", "data", "headers"}
	if name := resolvePythonCallNameTyped(call, flow.types, flow.aliases); name == "requests.Request" {
		positions = []string{"method", "url", "headers"}
	}
	tainted, harmful := flow.argumentsLeak(call, positions)
	if !tainted {
		return 0, false
	}
	if harmful {
		return credentialData, true
	}
	return credentialRequest, true
}

// argumentsLeak reports whether a credential reaches the call's arguments
// and whether any of it sits where it leaves in the request. positions
// names the positional parameters.
func (flow *pythonCredentialFlow) argumentsLeak(call *pyparser.Call, positions []string) (tainted, harmful bool) {
	check := func(parameter string, value pyparser.Expr) {
		role, ok := flow.role(value)
		if !ok {
			return
		}
		tainted = true
		if !credentialRoleAllowed(parameter, role) {
			harmful = true
		}
	}
	for index, argument := range call.Args {
		parameter := ""
		if index < len(positions) {
			parameter = positions[index]
		}
		check(parameter, argument)
	}
	for _, keyword := range call.Keywords {
		check(keyword.Arg, keyword.Value)
	}
	return tainted, harmful
}

func credentialRoleAllowed(parameter string, role credentialRole) bool {
	switch parameter {
	case "url", "base_url", "host":
		return role == credentialURL || role == credentialConfig || role == credentialRequest
	case "headers":
		return role == credentialHeaders
	case "auth", "api_key", "token":
		return role == credentialSecret || role == credentialConfig
	case "method", "timeout", "verify":
		return role == credentialConfig
	}
	return false
}

// sinkLeak returns the TT3 severity of a network sink call, or "" when no
// credential leaves in it.
func (flow *pythonCredentialFlow) sinkLeak(call *pyparser.Call, sink string, moduleReadsCredentialFile bool) string {
	if strings.HasPrefix(sink, "socket.") {
		if tainted, _ := flow.argumentsLeak(call, []string{"data"}); tainted {
			return "CRITICAL"
		}
		return ""
	}
	tainted, harmful := flow.argumentsLeak(call, []string{"url"})
	if harmful {
		return "CRITICAL"
	}
	destination := pythonCallArgument(call, 0, "url")
	if (tainted || moduleReadsCredentialFile) && destination != nil {
		for _, text := range flow.stringConstants(destination, 3) {
			if collectionHost.MatchString(text) {
				return "CRITICAL"
			}
		}
	}
	if !tainted {
		return ""
	}
	// The credentials sit only where they authenticate the request. Names
	// and the destination are resolved where the call is, so a name that
	// holds a key in another function does not count here.
	line, scope := call.P.Line, flow.definitions.scopeAt(call.P.Line)
	names := flow.credentialNamesAt(call, line, scope, pythonResolveDepth)
	if len(names) == 0 {
		return ""
	}
	for _, name := range names {
		if cloudSecretName.MatchString(name) {
			return "CRITICAL"
		}
	}
	if len(names) > 1 {
		return "CRITICAL"
	}
	if destination != nil {
		for _, text := range flow.stringValuesAt(destination, line, scope, pythonResolveDepth) {
			if !destinationBelongsTo(names[0], text) {
				return "HIGH"
			}
		}
	}
	return ""
}

func pythonCallArgument(call *pyparser.Call, position int, keyword string) pyparser.Expr {
	for _, argument := range call.Keywords {
		if argument.Arg == keyword {
			return argument.Value
		}
	}
	if position < len(call.Args) {
		return call.Args[position]
	}
	return nil
}

// destinationBelongsTo reports whether a resolved URL is the credential's own
// API: its host comes from configuration (an environment variable or a
// function argument without a literal default), or its literal host names the
// credential's service. A host the scanner cannot resolve does not count.
func destinationBelongsTo(name, url string) bool {
	if strings.HasPrefix(url, configuredValue) {
		return true
	}
	match := urlLiteralHost.FindStringSubmatch(url)
	if match == nil {
		return false
	}
	if strings.Contains(match[1], configuredValue) && !strings.Contains(match[1], unresolvedValue) {
		return true
	}
	return !strings.ContainsAny(match[1], configuredValue+unresolvedValue) && credentialNameMatchesHost(name, match[1:2])
}

// credentialNameMatchesHost reports whether a word of the variable name
// that names a service (UNSPLASH in UNSPLASH_ACCESS_KEY) appears in a
// destination host, both compared without punctuation.
func credentialNameMatchesHost(name string, hosts []string) bool {
	for _, word := range nameWordSeparator.Split(strings.ToLower(name), -1) {
		if len(word) < 3 || genericCredentialWord[word] {
			continue
		}
		for _, host := range hosts {
			if strings.Contains(nonAlphanumeric.ReplaceAllString(strings.ToLower(host), ""), word) {
				return true
			}
		}
	}
	return false
}

// readsCredentialFile reports open(path) or Path(path).read_text() on a
// credential file.
func (flow *pythonCredentialFlow) readsCredentialFile(call *pyparser.Call) bool {
	name := resolvePythonCallNameTyped(call, flow.types, flow.aliases)
	if !taintFileReadSources[name] && !strings.HasSuffix(name, ".read_text") && !strings.HasSuffix(name, ".read_bytes") {
		return false
	}
	if name == "open" && pythonOpenForWrite(call) {
		return false
	}
	var roots []pyparser.Expr
	if name == "open" {
		if len(call.Args) == 0 {
			return false
		}
		roots = append(roots, call.Args[0])
	} else {
		roots = append(roots, call.Func)
	}
	for _, root := range roots {
		for _, text := range flow.stringConstants(root, 3) {
			if isCredentialFilePath(text) {
				return true
			}
		}
	}
	return false
}

// stringConstants returns the string literals in an expression, following
// names to the values assigned to them up to depth levels.
func (flow *pythonCredentialFlow) stringConstants(expression pyparser.Expr, depth int) []string {
	var result []string
	visited := map[string]bool{}
	var collect func(pyparser.Expr, int)
	collect = func(root pyparser.Expr, level int) {
		pythonWalk(root, func(raw any) {
			switch node := raw.(type) {
			case *pyparser.Constant:
				if text, ok := node.Value.(string); ok {
					result = append(result, text)
				}
			case *pyparser.Name:
				if level > 0 && !visited[node.Id] {
					visited[node.Id] = true
					for _, value := range flow.assigned[node.Id] {
						collect(value, level-1)
					}
				}
			}
		})
	}
	collect(expression, depth)
	return result
}

// pythonChildExpressions returns the nearest expressions below a node,
// looking through keywords, comprehensions and other non-expression nodes.
func pythonChildExpressions(node any) []pyparser.Expr {
	var result []pyparser.Expr
	exprType := reflect.TypeOf((*pyparser.Expr)(nil)).Elem()
	var collect func(reflect.Value, bool)
	collect = func(value reflect.Value, root bool) {
		if !value.IsValid() {
			return
		}
		if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return
			}
			if !root && value.Type().Implements(exprType) {
				if expression, ok := value.Interface().(pyparser.Expr); ok {
					result = append(result, expression)
					return
				}
			}
			collect(value.Elem(), false)
			return
		}
		switch value.Kind() {
		case reflect.Struct:
			for index := 0; index < value.NumField(); index++ {
				if field := value.Field(index); field.CanInterface() {
					collect(field, false)
				}
			}
		case reflect.Slice, reflect.Array:
			for index := 0; index < value.Len(); index++ {
				collect(value.Index(index), false)
			}
		}
	}
	collect(reflect.ValueOf(node), true)
	return result
}

var (
	scriptStringLiteral = regexp.MustCompile("\"([^\"\\n]*)\"|'([^'\\n]*)'|`([^`]*)`")
	scriptFileRead      = regexp.MustCompile(`\b(?:readFile|readFileSync|createReadStream|readJson|readJSON|readTextFile)\b|\bBun\.file\s*\(`)
	scriptNetworkSend   = regexp.MustCompile(`\bfetch\s*\(|\baxios(?:\.(?:post|put|patch|request))?\s*\(|\bhttps?\.request\s*\(|\.(?:post|put|patch)\s*\(|\bsendBeacon\s*\(`)
	// scriptWholeEnvironment serializes every environment variable.
	scriptWholeEnvironment = regexp.MustCompile(`JSON\.stringify\(\s*process\.env\s*[,)]|Object\.(?:entries|values)\(\s*process\.env\s*\)`)
	scriptConstantString   = regexp.MustCompile("(?m)^\\s*(?:export\\s+)?(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*[\"'`]([^\"'`\\n]*)[\"'`]")
	scriptEnvironmentValue = regexp.MustCompile(`(?m)^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*process\.env(?:\.([A-Za-z_$][\w$]*)|\[\s*["']([^"']+)["']\s*\])\s*(?:;|$)`)
	scriptCallDestination  = regexp.MustCompile("^\\(\\s*(?:[\"'`]([^\"'`]*)[\"'`]|([A-Za-z_$][\\w$]*)\\s*[,)])")
	scriptIdentifier       = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	scriptBodyValue        = regexp.MustCompile(`\b(?:body|data)\s*:\s*(?:JSON\.stringify\(\s*)?([A-Za-z_$][\w$]*)\s*[,})\n]`)
)

// analyzeScriptCredentialFlow reports TT3 in JavaScript and TypeScript
// without data-flow tracking, for shapes that need none: a request whose
// body is an environment value or the serialized environment, and a file
// that reads a credential file or the whole environment and sends a request
// to a collection host.
func analyzeScriptCredentialFlow(item component) []model.Finding {
	// The type, not the path: analyzeItemsParallel shares results between
	// files with the same content and type.
	if item.Type != "javascript" && item.Type != "typescript" {
		return nil
	}
	content, _ := scanPrefix(item.Content)
	readsCredentialFile := false
	if scriptFileRead.MatchString(content) {
		for _, match := range scriptStringLiteral.FindAllStringSubmatch(content, -1) {
			if isCredentialFilePath(match[1] + match[2] + match[3]) {
				readsCredentialFile = true
				break
			}
		}
	}
	collectionNames := map[string]bool{}
	constants := map[string]string{}
	for _, match := range scriptConstantString.FindAllStringSubmatch(content, -1) {
		constants[match[1]] = match[2]
		if collectionHost.MatchString(match[2]) {
			collectionNames[match[1]] = true
		}
	}
	// environmentValues maps a variable to the environment variable it holds.
	environmentValues := map[string]string{}
	for _, match := range scriptEnvironmentValue.FindAllStringSubmatch(content, -1) {
		environmentValues[match[1]] = match[2] + match[3]
	}
	wholeEnvironment := scriptWholeEnvironment.MatchString(content)

	var findings []model.Finding
	for _, match := range scriptNetworkSend.FindAllStringIndex(content, -1) {
		call := balancedCallText(content, match[1]-1)
		message := ""
		properties := taintRuleProperties["TT3"]
		headerLeak := scriptHeaderLeak(call, environmentValues, constants)
		switch {
		case scriptWholeEnvironment.MatchString(call):
			message = "The request sends the whole environment (process.env)"
		case scriptSendsEnvironmentValue(call, environmentValues):
			message = "An environment value is the request body"
		case (readsCredentialFile || wholeEnvironment) && scriptTargetsCollectionHost(call, collectionNames):
			message = "The file reads a credential file or the whole environment and sends a request to a collection host"
		case headerLeak == "CRITICAL":
			message = "The request sends a cloud secret, or more than one credential, in its headers"
		case headerLeak == "HIGH":
			message = "The request sends a credential in an auth header to a fixed host that does not name its service"
			properties.severity, properties.confidence = "HIGH", .8
		default:
			continue
		}
		line := 1 + strings.Count(content[:match[0]], "\n")
		endLine := line + strings.Count(call, "\n")
		if finding, ok := pythonAnalyzerFinding(item, "TT3", message, properties.severity, properties.confidence, line, endLine, "Data Flow"); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

// scriptHeaderLeak applies the Python header rule (sinkLeak) to the
// environment credentials a send call names: CRITICAL for a cloud secret or
// more than one credential, HIGH for one credential to a literal host that
// does not name its service, "" otherwise.
func scriptHeaderLeak(call string, environmentValues, constants map[string]string) string {
	seen := map[string]bool{}
	var names []string
	for _, word := range scriptIdentifier.FindAllString(call, -1) {
		if name := environmentValues[word]; name != "" && !seen[name] && secretEnvironmentName.MatchString(name) {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	for _, name := range names {
		if cloudSecretName.MatchString(name) {
			return "CRITICAL"
		}
	}
	if len(names) > 1 {
		return "CRITICAL"
	}
	destination := scriptCallDestination.FindStringSubmatch(call)
	if destination == nil {
		return ""
	}
	url := destination[1]
	if destination[2] != "" {
		value, ok := constants[destination[2]]
		if !ok {
			return ""
		}
		url = value
	}
	host := urlLiteralHost.FindStringSubmatch(strings.ReplaceAll(url, "${", "\x00"))
	if host == nil || credentialNameMatchesHost(names[0], host[1:2]) {
		return ""
	}
	return "HIGH"
}

func scriptSendsEnvironmentValue(call string, environmentValues map[string]string) bool {
	for _, match := range scriptBodyValue.FindAllStringSubmatch(call, -1) {
		if environmentValues[match[1]] != "" {
			return true
		}
	}
	return false
}

func scriptTargetsCollectionHost(call string, collectionNames map[string]bool) bool {
	if collectionHost.MatchString(call) {
		return true
	}
	for _, word := range scriptIdentifier.FindAllString(call, -1) {
		if collectionNames[word] {
			return true
		}
	}
	return false
}

// balancedCallText returns the text from the opening parenthesis at open to
// its closing parenthesis, at most 4000 bytes.
func balancedCallText(content string, open int) string {
	depth := 0
	limit := min(len(content), open+4000)
	for index := open; index < limit; index++ {
		switch content[index] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return content[open : index+1]
			}
		}
	}
	return content[open:limit]
}
