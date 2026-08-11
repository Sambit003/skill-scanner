//go:build yara_native

package agentskill

import (
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hillu/go-yara/v4"
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

//go:embed yara_rules/*
var bundledYARARules embed.FS

type yaraSource struct {
	path, namespace, content string
}

func scanYARA(items []component, customRules string) ([]model.Finding, error) {
	sources, err := collectYARASources(customRules)
	if err != nil {
		return nil, err
	}
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	loaded := 0
	for _, source := range sources {
		// Python falls back to compiling each source separately and skips only
		// malformed files. Validate before adding so one custom rule cannot
		// invalidate all bundled rules.
		probe, probeErr := yara.NewCompiler()
		if probeErr != nil {
			return nil, probeErr
		}
		if probe.AddString(source.content, source.namespace) != nil {
			continue
		}
		if err := compiler.AddString(source.content, source.namespace); err != nil {
			return nil, fmt.Errorf("compile YARA rule %s: %w", source.path, err)
		}
		loaded++
	}
	if loaded == 0 {
		return nil, nil
	}
	rules, err := compiler.GetRules()
	if err != nil {
		return nil, err
	}
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		return nil, err
	}

	var findings []model.Finding
	for _, item := range items {
		if utf8.RuneCountInString(item.Content) > maxFileBytes {
			continue
		}
		var matches yara.MatchRules
		if err := scanner.SetCallback(&matches).ScanMem([]byte(item.Content)); err != nil {
			// Python treats a per-file YARA match error as a skipped file.
			continue
		}
		for _, match := range matches {
			if finding, ok := yaraFinding(item, match); ok {
				findings = append(findings, finding)
			}
		}
	}
	return findings, nil
}

func collectYARASources(customRules string) ([]yaraSource, error) {
	entries, err := fs.ReadDir(bundledYARARules, "yara_rules")
	if err != nil {
		return nil, err
	}
	var sources []yaraSource
	seenNamespaces := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !isYARARuleFile(entry.Name()) {
			continue
		}
		path := "yara_rules/" + entry.Name()
		raw, err := bundledYARARules.ReadFile(path)
		if err != nil {
			return nil, err
		}
		content, ok := decodeYARASource(entry.Name(), raw)
		if !ok {
			continue
		}
		namespace := uniqueYARANamespace(yaraNamespace(entry.Name()), "yara_rules", seenNamespaces)
		sources = append(sources, yaraSource{path: path, namespace: namespace, content: content})
	}

	if customRules == "" {
		return sources, nil
	}
	info, statErr := os.Stat(customRules)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return sources, nil
		}
		return nil, statErr
	}
	if !info.IsDir() {
		return sources, nil
	}
	var paths []string
	err = filepath.WalkDir(customRules, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && isYARARuleFile(entry.Name()) {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		content, ok := decodeYARASource(filepath.Base(path), raw)
		if !ok {
			continue
		}
		namespace := uniqueYARANamespace(yaraNamespace(filepath.Base(path)), filepath.Base(filepath.Dir(path)), seenNamespaces)
		sources = append(sources, yaraSource{path: path, namespace: namespace, content: content})
	}
	return sources, nil
}

func isYARARuleFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yar") || strings.HasSuffix(lower, ".yara") ||
		strings.HasSuffix(lower, ".yar.b64") || strings.HasSuffix(lower, ".yara.b64")
}

func decodeYARASource(name string, raw []byte) (string, bool) {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".yar.b64") || strings.HasSuffix(lower, ".yara.b64") {
		decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
		if err != nil || !utf8.Valid(decoded) {
			return "", false
		}
		return string(decoded), true
	}
	if !utf8.Valid(raw) {
		return "", false
	}
	return string(raw), true
}

func yaraNamespace(name string) string {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".yar.b64", ".yara.b64"} {
		if strings.HasSuffix(lower, suffix) {
			return name[:len(name)-len(suffix)]
		}
	}
	return strings.TrimSuffix(name, filepath.Ext(name))
}

func uniqueYARANamespace(namespace, parent string, seen map[string]bool) string {
	if seen[namespace] {
		namespace = parent + "/" + namespace
	}
	seen[namespace] = true
	return namespace
}

func yaraFinding(item component, match yara.MatchRule) (model.Finding, bool) {
	meta := map[string]any{}
	for _, value := range match.Metas {
		meta[value.Identifier] = value.Value
	}
	id, severity := yaraCategory(fmt.Sprint(meta["category"]))
	if override := strings.ToUpper(fmt.Sprint(meta["severity"])); isSeverity(override) {
		severity = override
	}
	confidence := .7
	if parsed, err := strconv.ParseFloat(fmt.Sprint(meta["confidence"]), 64); err == nil {
		confidence = parsed
	}
	description := ""
	if value, exists := meta["description"]; exists {
		description = fmt.Sprint(value)
	}
	message := "YARA rule '" + match.Rule + "'"
	if description != "" {
		message += ": " + description
	}
	if match.Namespace != "default" {
		message += " [" + match.Namespace + "]"
	}

	firstOffset := 0
	parts := make([]string, 0, len(match.Strings))
	for _, matched := range match.Strings {
		if firstOffset == 0 {
			firstOffset = int(matched.Offset)
		}
		parts = append(parts, string(matched.Data))
	}
	matchedText := truncateRunes(strings.Join(parts, "; "), 200)
	line := 1 + strings.Count(item.Content[:min(firstOffset, len(item.Content))], "\n")
	context := contextAtOffset(item.Content, firstOffset, 3)
	if isCodeExample(context) {
		confidence *= .5
	}
	if confidence < .4 && severity != "HIGH" && severity != "CRITICAL" {
		return model.Finding{}, false
	}
	explanation, remediation := yaraRuleText(id)
	return model.Finding{
		ID: id, Category: "YARA Match", Pattern: message, Severity: severity, Confidence: confidence,
		Location: model.Location{File: item.Path, StartLine: line}, Finding: matchedText, MatchedText: matchedText,
		Explanation: explanation, Remediation: remediation, CodeSnippet: context,
		Tags: []string{"YARA Match"},
	}, true
}

func yaraCategory(category string) (string, string) {
	switch strings.ToLower(category) {
	case "malware":
		return "YR1", "CRITICAL"
	case "webshell":
		return "YR2", "CRITICAL"
	case "cryptominer":
		return "YR3", "HIGH"
	case "hack_tool", "exploit":
		return "YR4", "HIGH"
	default:
		return "YR4", "MEDIUM"
	}
}

func isSeverity(value string) bool {
	return value == "LOW" || value == "MEDIUM" || value == "HIGH" || value == "CRITICAL"
}
