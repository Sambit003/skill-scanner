package agentskill

// Resolving a name where it is used, for the TT3 auth-header rule
// (sinkLeak): which credentials reach a request, and where it goes. A name
// resolves to its assignments earlier in the same function, else to the
// function's parameter (and its default), else to the module's assignments.
// A tuple unpacked from a call to a function in the module resolves to the
// matching element of that function's return values.

import (
	"reflect"

	pyparser "github.com/tamnd/gopapy/parser"
)

const (
	pythonResolveDepth = 4
	// configuredValue marks text that comes from configuration: an
	// environment variable or a function argument without a literal
	// default. unresolvedValue marks text the scanner cannot resolve
	// (decoded, computed, looked up).
	configuredValue = "\x01"
	unresolvedValue = "\x00"
	// stringValueLimit bounds the alternative values of one expression.
	stringValueLimit = 16
)

type pythonDefinition struct {
	value pyparser.Expr
	// index is the element of a tuple assignment's value, or -1.
	index int
	line  int
	scope *pyparser.FunctionDef
}

type pythonParameter struct {
	// defaultValue is nil when the parameter has no default.
	defaultValue pyparser.Expr
}

type pythonFunctionRange struct {
	node       *pyparser.FunctionDef
	start, end int
}

type pythonDefinitions struct {
	functions   []pythonFunctionRange
	byName      map[string]*pyparser.FunctionDef
	definitions map[string][]pythonDefinition
}

func newPythonDefinitions(module *pyparser.Module) *pythonDefinitions {
	result := &pythonDefinitions{byName: map[string]*pyparser.FunctionDef{}, definitions: map[string][]pythonDefinition{}}
	pythonWalk(module, func(raw any) {
		function, ok := raw.(*pyparser.FunctionDef)
		if !ok {
			return
		}
		end := function.P.Line
		pythonWalk(function, func(inner any) {
			end = max(end, pythonNodeLine(inner))
		})
		result.functions = append(result.functions, pythonFunctionRange{node: function, start: function.P.Line, end: end})
		result.byName[function.Name] = function
	})
	add := func(name string, value pyparser.Expr, index, line int) {
		result.definitions[name] = append(result.definitions[name], pythonDefinition{value: value, index: index, line: line, scope: result.scopeAt(line)})
	}
	pythonWalk(module, func(raw any) {
		switch node := raw.(type) {
		case *pyparser.Assign:
			for _, target := range node.Targets {
				switch target := target.(type) {
				case *pyparser.Name:
					add(target.Id, node.Value, -1, node.P.Line)
				case *pyparser.Tuple:
					for index, element := range target.Elts {
						if name, ok := element.(*pyparser.Name); ok {
							add(name.Id, node.Value, index, node.P.Line)
						}
					}
				}
			}
		case *pyparser.AnnAssign:
			if name, ok := node.Target.(*pyparser.Name); ok && node.Value != nil {
				add(name.Id, node.Value, -1, node.P.Line)
			}
		case *pyparser.For:
			name, ok := node.Target.(*pyparser.Name)
			if !ok {
				return
			}
			var elements []pyparser.Expr
			switch iter := node.Iter.(type) {
			case *pyparser.List:
				elements = iter.Elts
			case *pyparser.Tuple:
				elements = iter.Elts
			}
			for _, element := range elements {
				add(name.Id, element, -1, node.P.Line)
			}
		}
	})
	return result
}

// pythonNodeLine returns a node's line, or 0 when it has no position.
func pythonNodeLine(raw any) int {
	value := reflect.ValueOf(raw)
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0
	}
	field := value.FieldByName("P")
	if !field.IsValid() || !field.CanInterface() {
		return 0
	}
	if position, ok := field.Interface().(pyparser.Pos); ok {
		return position.Line
	}
	return 0
}

// scopeAt returns the innermost function whose body holds the line, or nil
// for module level.
func (definitions *pythonDefinitions) scopeAt(line int) *pyparser.FunctionDef {
	var scope *pyparser.FunctionDef
	size := -1
	for _, function := range definitions.functions {
		if line > function.start && line <= function.end && (size < 0 || function.end-function.start < size) {
			scope, size = function.node, function.end-function.start
		}
	}
	return scope
}

// reaching returns the assignments of name that a use on line in scope can
// see, or the parameter it names.
func (definitions *pythonDefinitions) reaching(name string, line int, scope *pyparser.FunctionDef) ([]pythonDefinition, *pythonParameter) {
	var local, module []pythonDefinition
	for _, definition := range definitions.definitions[name] {
		switch {
		case definition.scope == scope && definition.line < line:
			local = append(local, definition)
		case definition.scope == nil && (scope != nil || definition.line < line):
			module = append(module, definition)
		}
	}
	if len(local) > 0 {
		return local, nil
	}
	if scope != nil && scope.Args != nil {
		if parameter := pythonFunctionParameter(scope.Args, name); parameter != nil {
			return nil, parameter
		}
	}
	return module, nil
}

func pythonFunctionParameter(arguments *pyparser.Arguments, name string) *pythonParameter {
	positional := append(append([]*pyparser.Arg{}, arguments.PosOnly...), arguments.Args...)
	for index, argument := range positional {
		if argument.Name != name {
			continue
		}
		parameter := &pythonParameter{}
		if offset := index - (len(positional) - len(arguments.Defaults)); offset >= 0 {
			parameter.defaultValue = arguments.Defaults[offset]
		}
		return parameter
	}
	for index, argument := range arguments.KwOnly {
		if argument.Name == name {
			parameter := &pythonParameter{}
			if index < len(arguments.KwOnlyDef) {
				parameter.defaultValue = arguments.KwOnlyDef[index]
			}
			return parameter
		}
	}
	for _, argument := range []*pyparser.Arg{arguments.Vararg, arguments.Kwarg} {
		if argument != nil && argument.Name == name {
			return &pythonParameter{}
		}
	}
	return nil
}

// definitionValues returns the expressions a definition binds to its name,
// with the line and scope to resolve them in; none for a tuple element the
// scanner cannot pick out.
func (definitions *pythonDefinitions) definitionValues(definition pythonDefinition) []pythonDefinition {
	if definition.index < 0 {
		return []pythonDefinition{definition}
	}
	switch value := definition.value.(type) {
	case *pyparser.Tuple:
		if definition.index < len(value.Elts) {
			return []pythonDefinition{{value: value.Elts[definition.index], index: -1, line: definition.line, scope: definition.scope}}
		}
	case *pyparser.Call:
		if name, ok := value.Func.(*pyparser.Name); ok {
			if function := definitions.byName[name.Id]; function != nil {
				return definitions.returnValues(function, definition.index)
			}
		}
	}
	return nil
}

// returnValues returns the values a function returns (index < 0) or the
// index element of the tuples it returns.
func (definitions *pythonDefinitions) returnValues(function *pyparser.FunctionDef, index int) []pythonDefinition {
	var values []pythonDefinition
	pythonWalk(function, func(raw any) {
		statement, ok := raw.(*pyparser.Return)
		if !ok || statement.Value == nil || definitions.scopeAt(statement.P.Line) != function {
			return
		}
		value := statement.Value
		if index >= 0 {
			tuple, ok := value.(*pyparser.Tuple)
			if !ok || index >= len(tuple.Elts) {
				return
			}
			value = tuple.Elts[index]
		}
		values = append(values, pythonDefinition{value: value, index: -1, line: statement.P.Line, scope: function})
	})
	return values
}

func isPythonNoneOrEmpty(expression pyparser.Expr) bool {
	constant, ok := expression.(*pyparser.Constant)
	if !ok {
		return false
	}
	text, isString := constant.Value.(string)
	return constant.Value == nil || (isString && text == "")
}

// stringValuesAt evaluates a string expression used on line in scope to its
// possible values. configuredValue and unresolvedValue stand for parts that
// are not literal text.
func (flow *pythonCredentialFlow) stringValuesAt(expression pyparser.Expr, line int, scope *pyparser.FunctionDef, depth int) []string {
	unresolved := []string{unresolvedValue}
	if depth < 0 || expression == nil {
		return unresolved
	}
	resolve := func(definitions []pythonDefinition) []string {
		var values []string
		for _, definition := range definitions {
			for _, value := range flow.definitions.definitionValues(definition) {
				for _, text := range flow.stringValuesAt(value.value, value.line, value.scope, depth-1) {
					if len(values) < stringValueLimit {
						values = append(values, text)
					}
				}
			}
		}
		if len(values) == 0 {
			return unresolved
		}
		return values
	}
	concat := func(parts []pyparser.Expr) []string {
		values := []string{""}
		for _, part := range parts {
			if formatted, ok := part.(*pyparser.FormattedValue); ok {
				part = formatted.Value
			}
			var next []string
			for _, prefix := range values {
				for _, suffix := range flow.stringValuesAt(part, line, scope, depth) {
					if len(next) < stringValueLimit {
						next = append(next, prefix+suffix)
					}
				}
			}
			values = next
		}
		return values
	}
	// A configured value with a literal default can be either.
	configured := func(defaultValue pyparser.Expr, defaultLine int, defaultScope *pyparser.FunctionDef) []string {
		if defaultValue == nil || isPythonNoneOrEmpty(defaultValue) {
			return []string{configuredValue}
		}
		return flow.stringValuesAt(defaultValue, defaultLine, defaultScope, depth-1)
	}
	switch node := expression.(type) {
	case *pyparser.Constant:
		if text, ok := node.Value.(string); ok {
			return []string{text}
		}
	case *pyparser.JoinedStr:
		return concat(node.Values)
	case *pyparser.BinOp:
		if node.Op == "Add" {
			return concat(flattenPythonConcatenation(node))
		}
	case *pyparser.Name:
		definitions, parameter := flow.definitions.reaching(node.Id, line, scope)
		if parameter != nil {
			return configured(parameter.defaultValue, line, nil)
		}
		return resolve(definitions)
	case *pyparser.Subscript:
		if flow.isEnvironment(node.Value) {
			return []string{configuredValue}
		}
		return flow.dictValuesAt(node.Value, line, scope, depth)
	case *pyparser.Call:
		name := resolvePythonCallNameTyped(node, flow.types, flow.aliases)
		switch {
		case name == "os.getenv" || name == "os.environ.get":
			return configured(pythonCallArgument(node, 1, "default"), line, scope)
		case name == "urllib.request.Request":
			return flow.stringValuesAt(pythonCallArgument(node, 0, "url"), line, scope, depth)
		case name == "requests.Request":
			return flow.stringValuesAt(pythonCallArgument(node, 1, "url"), line, scope, depth)
		case name == "urllib.parse.urljoin" || name == "str":
			if len(node.Args) > 0 {
				return flow.stringValuesAt(node.Args[0], line, scope, depth)
			}
		}
		if function, ok := node.Func.(*pyparser.Name); ok && flow.definitions.byName[function.Id] != nil {
			return resolve(flow.definitions.returnValues(flow.definitions.byName[function.Id], -1))
		}
		if attribute, ok := node.Func.(*pyparser.Attribute); ok {
			switch attribute.Attr {
			case "format", "strip", "rstrip", "lstrip":
				return flow.stringValuesAt(attribute.Value, line, scope, depth)
			case "get":
				return flow.dictValuesAt(attribute.Value, line, scope, depth)
			}
		}
	}
	return unresolved
}

// dictValuesAt returns the values of a dict literal that an expression
// names (ENDPOINTS in ENDPOINTS.get(region) or ENDPOINTS[region]).
func (flow *pythonCredentialFlow) dictValuesAt(expression pyparser.Expr, line int, scope *pyparser.FunctionDef, depth int) []string {
	var dicts []pythonDefinition
	switch node := expression.(type) {
	case *pyparser.Dict:
		dicts = []pythonDefinition{{value: node, index: -1, line: line, scope: scope}}
	case *pyparser.Name:
		definitions, _ := flow.definitions.reaching(node.Id, line, scope)
		for _, definition := range definitions {
			dicts = append(dicts, flow.definitions.definitionValues(definition)...)
		}
	}
	var values []string
	for _, definition := range dicts {
		dict, ok := definition.value.(*pyparser.Dict)
		if !ok {
			return []string{unresolvedValue}
		}
		for _, value := range dict.Values {
			for _, text := range flow.stringValuesAt(value, definition.line, definition.scope, depth-1) {
				if len(values) < stringValueLimit {
					values = append(values, text)
				}
			}
		}
	}
	if len(values) == 0 {
		return []string{unresolvedValue}
	}
	return values
}

// credentialNamesAt returns the distinct secret environment variable names
// whose values reach an expression used on line in scope; "*" stands for a
// name the scanner cannot resolve or a credential file.
func (flow *pythonCredentialFlow) credentialNamesAt(expression pyparser.Expr, line int, scope *pyparser.FunctionDef, depth int) []string {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	addKey := func(key pyparser.Expr) {
		keys := []string{"*"}
		if key != nil {
			if constants := flow.stringConstants(key, 2); len(constants) > 0 {
				keys = constants
			}
		}
		for _, name := range keys {
			if name == "*" || secretEnvironmentName.MatchString(name) {
				add(name)
			}
		}
	}
	var visit func(pyparser.Expr, int, *pyparser.FunctionDef, int)
	visitAll := func(definitions []pythonDefinition, depth int) {
		for _, definition := range definitions {
			for _, value := range flow.definitions.definitionValues(definition) {
				visit(value.value, value.line, value.scope, depth)
			}
		}
	}
	visit = func(expression pyparser.Expr, line int, scope *pyparser.FunctionDef, depth int) {
		if depth < 0 || expression == nil {
			return
		}
		pythonWalk(expression, func(raw any) {
			switch node := raw.(type) {
			case *pyparser.Call:
				switch name := resolvePythonCallNameTyped(node, flow.types, flow.aliases); {
				case name == "os.getenv" || name == "os.environ.get":
					addKey(pythonCallArgument(node, 0, "key"))
				case flow.readsCredentialFile(node):
					add("*")
				}
				if function, ok := node.Func.(*pyparser.Name); ok && flow.definitions.byName[function.Id] != nil {
					visitAll(flow.definitions.returnValues(flow.definitions.byName[function.Id], -1), depth-1)
				}
			case *pyparser.Subscript:
				if flow.isEnvironment(node.Value) {
					addKey(node.Slice)
				}
			case *pyparser.Name:
				definitions, _ := flow.definitions.reaching(node.Id, line, scope)
				visitAll(definitions, depth-1)
			}
		})
	}
	visit(expression, line, scope, depth)
	return names
}
