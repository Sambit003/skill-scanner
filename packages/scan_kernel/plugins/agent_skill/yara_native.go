//go:build yara_native

package agentskill

import (
	"context"
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/hillu/go-yara/v4"
	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

//go:embed yara_rules/*
var bundledYARARules embed.FS

type yaraSource struct {
	path, namespace, content string
}

func scanYARA(ctx context.Context, items []component, customRules string) ([]model.Finding, error) {
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
	type cachedYARAResult struct {
		item     component
		findings []model.Finding
	}
	// yaraFinding's example handling reads the path, type and executable bit,
	// so files share a scan only when their analysisCacheKey matches.
	cache := make(map[analysisKey]int, len(items))
	results := make([]cachedYARAResult, 0, len(items))
	resultFor := make([]int, len(items))
	for index, item := range items {
		key := analysisCacheKey(item)
		if cached, exists := cache[key]; exists {
			resultFor[index] = cached
			continue
		}
		resultFor[index] = len(results)
		cache[key] = len(results)
		results = append(results, cachedYARAResult{item: item})
	}
	workers := min(len(results), max(1, min(runtime.GOMAXPROCS(0), 16)))
	jobs := make(chan int)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			scanner, scannerErr := yara.NewScanner(rules)
			if scannerErr != nil {
				errors <- scannerErr
				return
			}
			for index := range jobs {
				if ctx.Err() != nil {
					continue
				}
				item := results[index].item
				item.Content, _ = scanPrefix(item.Content)
				var matches yara.MatchRules
				if err := scanner.SetCallback(&matches).ScanMem([]byte(item.Content)); err != nil {
					// Python treats a per-file YARA match error as a skipped file.
					continue
				}
				for _, match := range matches {
					if finding, ok := yaraFinding(item, match); ok {
						results[index].findings = append(results[index].findings, finding)
					}
				}
			}
		}()
	}
	for index := range results {
		if ctx.Err() != nil {
			break
		}
		jobs <- index
	}
	close(jobs)
	group.Wait()
	close(errors)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for err := range errors {
		return nil, err
	}
	var findings []model.Finding
	for index, item := range items {
		for _, cached := range results[resultFor[index]].findings {
			finding := cached
			finding.Location.File = item.Path
			findings = append(findings, finding)
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
	// Interpret the reported byte offset as a character index to retain stable
	// line and context handling for UTF-8 files.
	runes := []rune(item.Content)
	characterOffset := min(firstOffset, len(runes))
	prefix := string(runes[:characterOffset])
	line := 1 + strings.Count(prefix, "\n")
	context := contextAtOffset(item.Content, len(prefix), 3)
	switch exampleTreatmentAt(item, len(prefix), context, isCodeExample) {
	case exampleFenced:
		return model.Finding{}, false
	case exampleNearby:
		confidence *= exampleConfidenceFactor
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
	case "prompt_injection":
		return "YR5", "HIGH"
	default:
		return "YR4", "MEDIUM"
	}
}

func isSeverity(value string) bool {
	return value == "LOW" || value == "MEDIUM" || value == "HIGH" || value == "CRITICAL"
}
