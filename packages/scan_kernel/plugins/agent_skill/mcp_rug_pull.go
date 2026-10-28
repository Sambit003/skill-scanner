package agentskill

// RP1 reports an unpinned MCP server: a server whose next start runs whatever
// version the registry serves. An ordinary unpinned command such as
// "npx playwright test" is a tool the skill uses, not an MCP server, and is
// not reported here.

import (
	"path"
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var (
	// rp1MCPAdd marks a command registered as an MCP server, as in
	// "claude mcp add github -- npx -y @acme/github".
	rp1MCPAdd = regexp.MustCompile(`(?i)\bmcp[ \t]+add\b`)
	rp1MCPKey = regexp.MustCompile(`mcpServers|mcp_servers`)
	// rp1ConfigCommand and rp1ConfigArgs read a server entry written as a
	// command and an args list in JSON, TOML or YAML.
	rp1ConfigCommand = regexp.MustCompile(`(?i)["']?\bcommand["']?[ \t]*[:=][ \t]*["']?(npx|bunx|pnpx|uvx|docker)["']?[ \t]*(?:[,\n]|$)`)
	rp1ConfigArgs    = regexp.MustCompile(`["']?\bargs["']?[ \t]*[:=][ \t]*(\[[^\]]*\]|(?:\n[ \t]*-[ \t]*[^\n]*)+)`)
	rp1ConfigString  = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'([^']*)'|-[ \t]+([^\s"'][^\n]*)`)
	uvxVersionPin    = regexp.MustCompile(`==[\d.]+|@[\d.]+\b`)
)

// mcpConfigFileNames are files that hold only MCP server configuration.
var mcpConfigFileNames = map[string]bool{
	".mcp.json": true, "mcp.json": true, "mcp_config.json": true, "mcp_servers.json": true, "claude_desktop_config.json": true,
}

// dockerValueFlags take a separate value ("-e TOKEN"), which is not the image.
var dockerValueFlags = map[string]bool{
	"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true, "--mount": true, "-p": true, "--publish": true,
	"--name": true, "--network": true, "--net": true, "-w": true, "--workdir": true, "--entrypoint": true, "-u": true, "--user": true,
	"-l": true, "--label": true, "--platform": true, "--pid": true, "--cap-add": true, "--cap-drop": true, "--add-host": true,
	"-m": true, "--memory": true, "--cpus": true, "-h": true, "--hostname": true, "--restart": true, "--runtime": true,
	"--security-opt": true, "--tmpfs": true, "--device": true, "--dns": true, "--ipc": true, "--log-driver": true, "--ulimit": true,
}

// isMCPServerPackage reports a package or image named as an MCP server:
// @modelcontextprotocol/*, mcp-*, *-mcp or *-mcp-server (with "_" read as
// "-"), or an image in Docker Hub's mcp/ namespace. The bare "mcp" package is
// the Python SDK, a library; the inspector is a development tool and create-*
// packages scaffold a new server rather than run one.
func isMCPServerPackage(name string) bool {
	lower := strings.ToLower(strings.TrimRight(strings.Trim(name, "\"'`"), ".,;:)]}"))
	base := lower[strings.LastIndexByte(lower, '/')+1:]
	if at := strings.IndexAny(base, "@:="); at > 0 {
		base = base[:at]
	}
	base = strings.TrimRight(strings.ReplaceAll(base, "_", "-"), ".-")
	if base == "inspector" || base == "mcp-inspector" || strings.HasPrefix(base, "create-") {
		return false
	}
	if strings.HasPrefix(lower, "@modelcontextprotocol/") || strings.HasPrefix(lower, "mcp/") || strings.HasPrefix(lower, "docker.io/mcp/") {
		return true
	}
	return strings.HasPrefix(base, "mcp-") || strings.HasSuffix(base, "-mcp") || strings.HasSuffix(base, "-mcp-server")
}

// mcpConfigRegions returns the parts of a file that configure MCP servers: the
// whole of an MCP configuration file; in Markdown, a fenced block from its
// mcpServers key to the fence's end; in other files, from the first such key
// to the end of the file.
func mcpConfigRegions(item component) []textSpan {
	if mcpConfigFileNames[strings.ToLower(path.Base(strings.ReplaceAll(item.Path, "\\", "/")))] {
		return []textSpan{{0, len(item.Content)}}
	}
	keys := rp1MCPKey.FindAllStringIndex(item.Content, -1)
	if len(keys) == 0 {
		return nil
	}
	if item.Type != "markdown" {
		return []textSpan{{keys[0][0], len(item.Content)}}
	}
	var regions []textSpan
	for _, block := range fencedCodeBlocks(item.Content) {
		for _, key := range keys {
			if block.start <= key[0] && key[0] < block.end {
				regions = append(regions, textSpan{key[0], block.end})
				break
			}
		}
	}
	return regions
}

func insideSpans(spans []textSpan, offset int) bool {
	for _, span := range spans {
		if span.start <= offset && offset < span.end {
			return true
		}
	}
	return false
}

// dockerImage returns the image argument of "docker run|pull|create ...",
// skipping options and the values of options that take one.
func dockerImage(arguments []string) (string, int) {
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if strings.HasPrefix(argument, "-") {
			if dockerValueFlags[argument] {
				index++
			}
			continue
		}
		return strings.TrimRight(strings.Trim(argument, "\"'`"), ".,;:)]}"), index
	}
	return "", -1
}

// rp1CommandFindings reports unpinned MCP servers started by npx, bunx, pnpx,
// uvx, pip or docker. A command counts when its package is named as an MCP
// server, when it is registered with "mcp add", or when it sits in an MCP
// server configuration, including entries written as command and args.
func rp1CommandFindings(item component) []model.Finding {
	regions := mcpConfigRegions(item)
	lines := map[int]bool{}
	var findings []model.Finding
	report := func(start int, kind, matched string, confidence float64) {
		line := 1 + strings.Count(item.Content[:start], "\n")
		if lines[line] {
			return
		}
		lines[line] = true
		explanation, remediation := rp1Text(kind)
		matched = truncate(matched, 200)
		findings = append(findings, model.Finding{ID: "RP1", Category: "MCP Rug Pull", Severity: rp1Severity, Confidence: confidence,
			Location: model.Location{File: item.Path, StartLine: line}, Finding: matched, MatchedText: matched,
			Explanation: explanation, Remediation: remediation, CodeSnippet: lineSnippet(item.Content, line), Tags: []string{"ASI16"}})
	}
	lineAt := func(offset int) string {
		start := strings.LastIndexByte(item.Content[:offset], '\n') + 1
		end := len(item.Content)
		if index := strings.IndexByte(item.Content[offset:], '\n'); index >= 0 {
			end = offset + index
		}
		return item.Content[start:end]
	}
	isServer := func(start int, name string) bool {
		return isMCPServerPackage(name) || rp1MCPAdd.MatchString(lineAt(start)) || insideSpans(regions, start)
	}

	for _, command := range []struct {
		re         *regexp.Regexp
		kind       string
		confidence float64
	}{{rp1NPX, "npx", .7}, {rp1UVX, "uvx", .65}, {rp1PIP, "pip", .6}} {
		for _, match := range command.re.FindAllStringSubmatchIndex(item.Content, -1) {
			full := item.Content[match[0]:match[1]]
			rest, _, _ := strings.Cut(item.Content[match[1]:], "\n")
			name := item.Content[match[2]:match[3]]
			if strings.Contains(full, "\n") || versionPin.MatchString(full+rest) {
				continue
			}
			// pip installs MCP servers only by name; "pip install mcp" in a
			// config block is the SDK.
			if command.kind == "pip" && !isMCPServerPackage(name) {
				continue
			}
			if isServer(match[0], name) {
				report(match[0], command.kind, full, command.confidence)
			}
		}
	}
	for _, match := range rp1Docker.FindAllStringSubmatchIndex(item.Content, -1) {
		// A command in an inline code span ends at its closing backtick.
		command, _, _ := strings.Cut(item.Content[match[2]:match[3]], "`")
		arguments := strings.Fields(command)
		image, index := dockerImage(arguments)
		if image == "" || versionPin.MatchString(image) {
			continue
		}
		matched := item.Content[match[0]:match[2]] + strings.Join(arguments[:index+1], " ")
		if isServer(match[0], image) {
			report(match[0], "docker", matched, .75)
		}
	}
	for _, match := range rp1ConfigCommand.FindAllStringSubmatchIndex(item.Content, -1) {
		if !insideSpans(regions, match[0]) {
			continue
		}
		// The args list belongs to the same entry: before the next command.
		window := item.Content[match[1]:min(len(item.Content), match[1]+600)]
		if next := rp1ConfigCommand.FindStringIndex(window); next != nil {
			window = window[:next[0]]
		}
		argsMatch := rp1ConfigArgs.FindStringSubmatch(window)
		if argsMatch == nil {
			continue
		}
		var arguments []string
		for _, value := range rp1ConfigString.FindAllStringSubmatch(argsMatch[1], -1) {
			arguments = append(arguments, strings.TrimSpace(value[1]+value[2]+value[3]))
		}
		kind := strings.ToLower(item.Content[match[2]:match[3]])
		name, pinned := "", false
		switch kind {
		case "docker":
			if len(arguments) == 0 || (arguments[0] != "run" && arguments[0] != "pull" && arguments[0] != "create") {
				continue
			}
			name, _ = dockerImage(arguments[1:])
			pinned = versionPin.MatchString(name)
		default:
			for _, argument := range arguments {
				if !strings.HasPrefix(argument, "-") {
					name = argument
					break
				}
			}
			pinned = versionPin.MatchString(name) || (kind == "uvx" && uvxVersionPin.MatchString(name))
		}
		if name == "" || pinned {
			continue
		}
		if kind == "bunx" || kind == "pnpx" {
			kind = "npx"
		}
		confidence := map[string]float64{"npx": .7, "uvx": .65, "docker": .75}[kind]
		report(match[0], kind, item.Content[match[2]:match[3]]+" "+strings.Join(arguments, " "), confidence)
	}
	return findings
}

// rp1Severity is LOW for every launcher: an unpinned server is a hardening
// gap, not evidence of an attack.
const rp1Severity = "LOW"

// rp1Text explains an unpinned MCP server. Pinning defends against a
// malicious or broken future release; it says nothing bad about the current
// one. Remote MCP servers cannot be pinned and are not reported.
func rp1Text(kind string) (string, string) {
	const why = " Pinning is a defense against a malicious or broken future release; an unpinned server is not a sign that the current release is malicious."
	switch kind {
	case "uvx":
		return "This MCP server is started with uvx or uv tool run without a version, so each start runs whatever release the registry serves." + why,
			"Pin the version: uvx package-name==1.2.3"
	case "pip":
		return "This MCP server package is installed with pip without a version, so a later install can bring a different release." + why,
			"Pin the version: pip install package==1.2.3"
	case "docker":
		return "This MCP server image has no fixed tag or digest, so a later pull can run a different image." + why,
			"Pin the image: image:tag, or better image@sha256:..."
	default:
		return "This MCP server is started with npx (or bunx, pnpx) without a version, so each start runs whatever release the registry serves." + why,
			"Pin the version: npx @scope/server@1.2.3"
	}
}
