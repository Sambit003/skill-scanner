package agentskill

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var capabilityPatterns = map[string][]*regexp.Regexp{
	"shell":      compileCapabilityPatterns(`subprocess`, `Popen`, `os\.system`, `os\.popen`, `os\.exec`, `\bcurl\b`, `\bwget\b`, `\bchmod\b`),
	"network":    compileCapabilityPatterns(`\bhttpx\b`, `\brequests\b`, `\burllib\b`, `\baiohttp\b`, `socket\.connect`, `fetch\(`, `XMLHttpRequest`),
	"file_read":  compileCapabilityPatterns(`open\s*\([^)]*['\"]r['\"]`, `open\s*\([^)]*['\"][^'\"]*r['\"]`, `\.read_text\(`, `\.read_bytes\(`, `os\.listdir`, `os\.walk`, `glob\.glob`),
	"file_write": compileCapabilityPatterns(`open\s*\([^)]*['\"][wa]['\"]`, `open\s*\([^)]*['\"][^'\"]*[wa]['\"]`, `\.write_text\(`, `\.write_bytes\(`, `shutil\.copy`, `os\.rename`, `os\.mkdir`),
	"env":        compileCapabilityPatterns(`os\.environ`, `os\.getenv`, `process\.env`, `\bdotenv\b`),
	"mcp":        compileCapabilityPatterns(`create_session`, `MCPClient`, `mcp\.client`),
}

var permissionCapabilities = map[string]string{
	"bash": "shell", "shell": "shell", "terminal": "shell", "command": "shell",
	"network": "network", "http": "network", "fetch": "network", "api": "network",
	"read": "file_read", "fs_read": "file_read", "file_read": "file_read",
	"write": "file_write", "fs_write": "file_write", "file_write": "file_write",
	"env": "env", "environment": "env", "mcp": "mcp", "tools": "mcp", "tool_use": "mcp",
}

// Keep keyword precedence explicit because the first match determines the
// mapped capability.
var permissionCapabilityOrder = []struct {
	keyword, capability string
}{
	{"bash", "shell"}, {"shell", "shell"}, {"terminal", "shell"}, {"command", "shell"},
	{"network", "network"}, {"http", "network"}, {"fetch", "network"}, {"api", "network"},
	{"read", "file_read"}, {"fs_read", "file_read"}, {"file_read", "file_read"},
	{"write", "file_write"}, {"fs_write", "file_write"}, {"file_write", "file_write"},
	{"env", "env"}, {"environment", "env"}, {"mcp", "mcp"}, {"tools", "mcp"}, {"tool_use", "mcp"},
}

var toolCapabilities = map[string]string{
	"bash": "shell", "execute": "shell", "terminal": "shell", "read": "file_read", "glob": "file_read", "ls": "file_read",
	"write": "file_write", "edit": "file_write", "multiedit": "file_write", "notebookedit": "file_write",
	"webfetch": "network", "websearch": "network", "fetch": "network", "env": "env",
}

func compileCapabilityPatterns(expressions ...string) []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, 0, len(expressions))
	for _, expression := range expressions {
		patterns = append(patterns, regexp.MustCompile("(?i)"+expression))
	}
	return patterns
}

// analyzeMCPLeastPrivilege compares declared permissions with the
// capabilities detected in executable files. It runs only for a manifest that
// declares a permissions field: Claude Code skills have none (allowed-tools
// pre-approves tools rather than restricting them), so a skill without the
// field has nothing to under- or over-declare.
func analyzeMCPLeastPrivilege(items []component, manifest map[string]any) []model.Finding {
	if _, declared := manifest["permissions"]; !declared {
		return nil
	}
	hasExecutable := false
	fileCapabilities := map[string]map[string]bool{}
	var executablePaths []string
	allCapabilities := map[string]bool{}
	for _, item := range items {
		if !item.Executable {
			continue
		}
		hasExecutable = true
		executablePaths = append(executablePaths, item.Path)
		capabilities := detectCapabilities(item.Content)
		if len(capabilities) > 0 {
			fileCapabilities[item.Path] = capabilities
			for capability := range capabilities {
				allCapabilities[capability] = true
			}
		}
	}
	if !hasExecutable {
		return nil
	}

	permissions, permissionsIsList := stringList(manifest["permissions"])
	if !permissionsIsList {
		permissions = nil
	}
	allowedTools := normalizeAllowedTools(manifest["allowed-tools"])
	wildcard := hasWildcardPermission(permissions)
	var findings []model.Finding
	if permissionsIsList && wildcard {
		findings = append(findings, model.Finding{
			ID: "LP2", Category: "MCP Least Privilege", Severity: "MEDIUM", Confidence: .9,
			Location: model.Location{File: "SKILL.md", StartLine: 1}, Tags: []string{"ASI02"},
			Explanation: "Wildcard permissions disable permission-based security controls entirely. Specify only the permissions the skill actually requires.",
			Remediation: "Replace '*'/'all'/'full'/'any' with an explicit list of required permissions. Request only the minimum access needed.",
		})
	}
	if len(permissions) == 0 && len(allowedTools) == 0 && len(allCapabilities) > 0 {
		findings = append(findings, model.Finding{
			ID: "LP3", Category: "MCP Least Privilege", Severity: "MEDIUM", Confidence: .7,
			Location: model.Location{File: "SKILL.md", StartLine: 1}, Tags: []string{"ASI02"},
			Explanation: "The manifest declares an empty permissions list, but the skill's code uses capabilities that list should name.",
			Remediation: "List the capabilities the code uses in the manifest's permissions field, or remove the code that needs them.",
		})
	}
	if len(permissions) == 0 && len(allowedTools) == 0 {
		return findings
	}

	declared := mapPermissionCategories(permissions)
	for _, tool := range allowedTools {
		if capability, ok := toolCapabilities[strings.ToLower(strings.TrimSpace(tool))]; ok {
			declared[capability] = true
		}
	}
	if !wildcard {
		capabilities := sortedKeys(allCapabilities)
		for _, capability := range capabilities {
			if declared[capability] {
				continue
			}
			testOnly := true
			primary := "SKILL.md"
			for _, path := range executablePaths {
				caps := fileCapabilities[path]
				if !caps[capability] {
					continue
				}
				if primary == "SKILL.md" {
					primary = path
				}
				if !isTestComponent(path) {
					testOnly = false
				}
			}
			confidence := .75
			if testOnly {
				confidence = .55
			}
			findings = append(findings, model.Finding{
				ID: "LP1", Category: "MCP Least Privilege", Severity: "HIGH", Confidence: confidence,
				Location: model.Location{File: primary, StartLine: 1}, Tags: []string{"ASI02"},
				Explanation: "The skill uses '" + capability + "' capability that is not listed in its permissions. This may indicate deceptive intent or missing permission declarations.",
				Remediation: "Add the '" + capability + "' permission to SKILL.md, or remove the code that requires it.",
			})
		}
	}
	for _, permission := range permissions {
		lower := strings.ToLower(strings.TrimSpace(permission))
		if isWildcard(lower) {
			continue
		}
		category := permissionCategory(lower)
		if category != "" && !allCapabilities[category] {
			findings = append(findings, model.Finding{
				ID: "LP4", Category: "MCP Least Privilege", Severity: "LOW", Confidence: .65,
				Location: model.Location{File: "SKILL.md", StartLine: 1}, Tags: []string{"ASI02"},
				Explanation: "Declared permissions with no matching code capability may indicate removed functionality or pre-staging for future abuse.",
				Remediation: "Remove the '" + permission + "' permission if the corresponding capability is no longer used.",
			})
		}
	}
	return findings
}

func detectCapabilities(content string) map[string]bool {
	result := map[string]bool{}
	for capability, patterns := range capabilityPatterns {
		for _, pattern := range patterns {
			if pattern.MatchString(content) {
				result[capability] = true
				break
			}
		}
	}
	return result
}

func normalizeAllowedTools(value any) []string {
	if text, ok := value.(string); ok {
		parts := strings.Split(text, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}
	values, _ := stringList(value)
	return values
}

func stringList(value any) ([]string, bool) {
	switch values := value.(type) {
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				result = append(result, strings.TrimSpace(text))
			}
		}
		return result, true
	case []string:
		return values, true
	default:
		return nil, false
	}
}

func mapPermissionCategories(permissions []string) map[string]bool {
	categories := map[string]bool{}
	for _, permission := range permissions {
		if category := permissionCategory(strings.ToLower(strings.TrimSpace(permission))); category != "" {
			categories[category] = true
		}
	}
	return categories
}

func permissionCategory(permission string) string {
	for _, mapping := range permissionCapabilityOrder {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(mapping.keyword) + `\b`).MatchString(permission) {
			return mapping.capability
		}
	}
	return ""
}

func hasWildcardPermission(permissions []string) bool {
	for _, permission := range permissions {
		if isWildcard(strings.ToLower(strings.TrimSpace(permission))) {
			return true
		}
	}
	return false
}

func isWildcard(value string) bool {
	return value == "*" || value == "all" || value == "full" || value == "any"
}

func isTestComponent(path string) bool {
	name := filepath.Base(path)
	extension := filepath.Ext(name)
	stem := strings.TrimSuffix(name, extension)
	return strings.HasPrefix(name, "test_") || strings.HasSuffix(stem, "_test")
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
