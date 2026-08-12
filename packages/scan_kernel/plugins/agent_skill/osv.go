package agentskill

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

type dependencyCoordinate struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	File      string `json:"file"`
	Line      int    `json:"line"`
}

type fallbackVulnerability struct {
	name        string
	maxSafe     string
	description string
	confidence  float64
}

type osvVulnerability struct {
	ID       string
	Summary  string
	Severity string
	Aliases  []string
}

type frozenOSVDocument struct {
	SchemaVersion int                 `json:"schema_version"`
	Responses     []frozenOSVResponse `json:"responses"`
}

type frozenOSVResponse struct {
	Ecosystem       string             `json:"ecosystem"`
	Name            string             `json:"name"`
	Version         string             `json:"version"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
}

var requirementCoordinate = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*(?:([=<>!~]=?)\s*([\d.*]+))?`)
var packageJSONSection = regexp.MustCompile(`"(?:dependencies|devDependencies|peerDependencies)"`)
var packageJSONEntry = regexp.MustCompile(`^"([^"]+)"\s*:\s*"([^"]*)"`)
var versionParts = regexp.MustCompile(`\d+`)
var cvssVector = regexp.MustCompile(`^CVSS:[34][.\d]*/(.+)$`)

var fallbackPyPI = []fallbackVulnerability{
	{"py", "", "CVE-2022-42969 (ReDoS)", .7}, {"pycrypto", "", "CVE-2013-7459 (heap overflow, unmaintained)", .8},
	{"pyyaml", "5.4", "CVE-2020-14343 (arbitrary code execution via yaml.load)", .75}, {"urllib3", "1.26.5", "CVE-2021-33503 (ReDoS)", .7},
	{"pillow", "9.0.0", "CVE-2022-22817 (arbitrary code execution)", .7}, {"setuptools", "65.5.1", "CVE-2022-40897 (ReDoS)", .65},
	{"certifi", "2022.12.07", "CVE-2023-37920 (removed trust root)", .7}, {"requests", "2.31.0", "CVE-2023-32681 (header leak on redirect)", .65},
	{"jinja2", "3.1.3", "CVE-2024-22195 (XSS)", .7}, {"cryptography", "41.0.6", "CVE-2023-49083 (NULL dereference)", .7},
	{"django", "4.2.7", "CVE-2023-46695 (DoS)", .7}, {"flask", "2.3.2", "CVE-2023-30861 (session cookie)", .65},
	{"tornado", "6.3.3", "CVE-2023-28370 (open redirect)", .65}, {"aiohttp", "3.8.6", "CVE-2023-47627 (HTTP request smuggling)", .7},
	{"paramiko", "3.4.0", "CVE-2023-48795 (Terrapin SSH)", .75},
}

var fallbackNPM = []fallbackVulnerability{
	{"event-stream", "", "Malicious package (credential theft)", .95}, {"flatmap-stream", "", "Malicious package (cryptocurrency theft)", .95},
	{"ua-parser-js", "0.7.31", "Malicious versions (cryptominer)", .85}, {"coa", "2.0.2", "Malicious versions (credential theft)", .85},
	{"rc", "1.2.8", "Malicious versions (credential theft)", .85}, {"colors", "1.4.0", "Protestware (infinite loop)", .8},
	{"faker", "5.5.3", "Protestware (infinite loop)", .8}, {"node-ipc", "10.1.0", "Protestware (destructive payload)", .9},
	{"lodash", "4.17.21", "CVE-2021-23337 (prototype pollution)", .65},
}

var abandonedPackages = wordSet(
	"pycrypto", "nose", "optparse", "distribute", "mimetools", "multifile", "popen2", "rfc822", "sets", "sha", "md5", "commands",
	"dircache", "fpformat", "htmllib", "ihooks", "linuxaudiodev", "mhlib", "mimify", "mutex", "new", "posixfile", "pre", "regsub",
	"sgmllib", "stat", "statvfs", "stringold", "sunaudiodev", "sv", "timing", "toaiff", "user", "xmllib",
	"request", "nomnom", "optimist", "dominion", "npm-conf",
)

var popularPyPI = []string{
	"requests", "numpy", "pandas", "flask", "django", "boto3", "setuptools", "pip", "urllib3", "pyyaml", "cryptography", "pillow",
	"pydantic", "sqlalchemy", "pytest", "click", "jinja2", "httpx", "aiohttp", "fastapi", "celery", "paramiko", "beautifulsoup4", "lxml",
	"scrapy", "redis", "pymongo", "psycopg2", "matplotlib", "scipy", "scikit-learn", "tensorflow", "torch", "keras", "transformers",
	"openai", "gunicorn", "uvicorn", "rich", "typer", "black", "ruff", "mypy", "pylint", "flake8", "isort", "perseus-ctx", "mimir-mcp",
}

var popularNPM = []string{
	"express", "react", "react-dom", "next", "vue", "angular", "lodash", "axios", "moment", "chalk", "commander", "inquirer", "webpack",
	"babel", "eslint", "prettier", "typescript", "jest", "mocha", "chai", "puppeteer", "socket.io", "mongoose", "sequelize", "passport",
	"jsonwebtoken", "dotenv", "cors", "body-parser", "nodemon", "pm2",
}

func analyzeDependencies(ctx context.Context, items []component, offline bool) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, item := range items {
		coordinates := extractDependencyCoordinates(item)
		if len(coordinates) == 0 {
			continue
		}
		covered := map[string]bool{}
		osvReachable := true
		if !offline {
			var osvFindings []model.Finding
			osvFindings, covered, osvReachable = analyzeOSVCoordinates(ctx, coordinates)
			findings = append(findings, osvFindings...)
		}
		fallback := fallbackPyPI
		popular := popularPyPI
		if coordinates[0].Ecosystem == "npm" {
			fallback, popular = fallbackNPM, popularNPM
		}
		uncovered := make([]dependencyCoordinate, 0, len(coordinates))
		for _, coordinate := range coordinates {
			if !covered[normalizePackageName(coordinate.Name)] {
				uncovered = append(uncovered, coordinate)
			}
		}
		fallbackFindings := analyzeFallbackVulnerabilities(uncovered, fallback)
		findings = append(findings, fallbackFindings...)
		if !offline && !osvReachable && len(uncovered) > 0 && len(fallbackFindings) == 0 {
			findings = append(findings, supplyChainFinding("SC4", "LOW", 1, item.Path, 1,
				fmt.Sprintf("🟡 SC4: OSV.dev unreachable, using static fallback (%d packages). Results may be incomplete. Set SCAN_KERNEL_OSV_TIMEOUT to increase timeout or check network connectivity to api.osv.dev.", len(fallback)),
				"SC4 fallback active"))
		}
		for _, coordinate := range coordinates {
			normalized := normalizePackageName(coordinate.Name)
			if abandonedPackages[normalized] {
				findings = append(findings, supplyChainFinding("SC5", "MEDIUM", .75, coordinate.File, coordinate.Line,
					fmt.Sprintf("Abandoned Dependency: %s is unmaintained and no longer receives security updates", coordinate.Name), coordinate.Name))
			}
			if similar := typosquatTarget(coordinate.Name, popular); similar != "" {
				findings = append(findings, supplyChainFinding("SC6", "HIGH", .7, coordinate.File, coordinate.Line,
					fmt.Sprintf("Possible Typosquatting: '%s' resembles popular package '%s'", coordinate.Name, similar), coordinate.Name))
			}
		}
	}
	return findings
}

func extractDependencyCoordinates(item component) []dependencyCoordinate {
	lower := strings.ToLower(item.Path)
	switch {
	case strings.Contains(lower, "package.json"):
		return extractPackageJSONCoordinates(item)
	case strings.Contains(lower, "pyproject.toml"):
		return extractPyprojectCoordinates(item)
	case strings.Contains(lower, "requirements"), strings.Contains(lower, "setup.py"), strings.Contains(lower, "pipfile"):
		return extractRequirementCoordinates(item)
	default:
		return nil
	}
}

func extractRequirementCoordinates(item component) []dependencyCoordinate {
	coordinates := make([]dependencyCoordinate, 0)
	for index, raw := range strings.Split(item.Content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		match := requirementCoordinate.FindStringSubmatch(line)
		if len(match) == 0 || match[0] == "" {
			continue
		}
		version := ""
		if len(match) > 3 && match[2] != "" {
			version = match[3]
		}
		coordinates = append(coordinates, dependencyCoordinate{Name: match[1], Version: version, Ecosystem: "PyPI", File: item.Path, Line: index + 1})
	}
	return coordinates
}

func extractPackageJSONCoordinates(item component) []dependencyCoordinate {
	coordinates := make([]dependencyCoordinate, 0)
	inDependencies := false
	for index, raw := range strings.Split(item.Content, "\n") {
		line := strings.TrimSpace(raw)
		if packageJSONSection.MatchString(line) {
			inDependencies = true
			continue
		}
		if inDependencies && strings.HasPrefix(line, "}") {
			inDependencies = false
			continue
		}
		if !inDependencies {
			continue
		}
		match := packageJSONEntry.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		version := strings.TrimLeft(match[2], "^~>=<")
		if version == "" || version[0] < '0' || version[0] > '9' {
			version = ""
		}
		coordinates = append(coordinates, dependencyCoordinate{Name: match[1], Version: version, Ecosystem: "npm", File: item.Path, Line: index + 1})
	}
	return coordinates
}

func extractPyprojectCoordinates(item component) []dependencyCoordinate {
	var document map[string]any
	if _, err := toml.Decode(item.Content, &document); err != nil {
		return nil
	}
	specifications := make([]string, 0)
	appendStrings := func(raw any) {
		if values, ok := raw.([]any); ok {
			for _, value := range values {
				if text, ok := value.(string); ok {
					specifications = append(specifications, text)
				}
			}
		}
		if values, ok := raw.([]string); ok {
			specifications = append(specifications, values...)
		}
	}
	if project, ok := document["project"].(map[string]any); ok {
		appendStrings(project["dependencies"])
		if optional, ok := project["optional-dependencies"].(map[string]any); ok {
			keys := sortedAnyMapKeys(optional)
			for _, key := range keys {
				appendStrings(optional[key])
			}
		}
	}
	if groups, ok := document["dependency-groups"].(map[string]any); ok {
		for _, key := range sortedAnyMapKeys(groups) {
			appendStrings(groups[key])
		}
	}
	if build, ok := document["build-system"].(map[string]any); ok {
		appendStrings(build["requires"])
	}
	coordinates := make([]dependencyCoordinate, 0, len(specifications))
	for _, specification := range specifications {
		match := requirementCoordinate.FindStringSubmatch(specification)
		if len(match) == 0 || match[0] == "" {
			continue
		}
		version := ""
		if len(match) > 3 && (match[2] == "==" || match[2] == "<=") {
			version = match[3]
		}
		line := lineContaining(item.Content, specification)
		coordinates = append(coordinates, dependencyCoordinate{Name: match[1], Version: version, Ecosystem: "PyPI", File: item.Path, Line: line})
	}
	return coordinates
}

func sortedAnyMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func analyzeOSVCoordinates(ctx context.Context, coordinates []dependencyCoordinate) ([]model.Finding, map[string]bool, bool) {
	if fixture := strings.TrimSpace(os.Getenv("SCAN_KERNEL_OSV_FIXTURE")); fixture != "" {
		return analyzeFrozenOSVCoordinates(coordinates, fixture)
	}
	queries := make([]map[string]any, 0, len(coordinates))
	for _, coordinate := range coordinates {
		query := map[string]any{"package": map[string]string{"name": coordinate.Name, "ecosystem": coordinate.Ecosystem}}
		if coordinate.Version != "" {
			query["version"] = coordinate.Version
		}
		queries = append(queries, query)
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, map[string]bool{}, false
	}
	timeout := 30 * time.Second
	if raw := os.Getenv("SCAN_KERNEL_OSV_TIMEOUT"); raw != "" {
		if seconds, parseErr := strconv.ParseFloat(raw, 64); parseErr == nil {
			timeout = time.Duration(seconds * float64(time.Second))
		}
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, map[string]bool{}, false
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, map[string]bool{}, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, map[string]bool{}, false
	}
	var payload struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if json.NewDecoder(response.Body).Decode(&payload) != nil {
		return nil, map[string]bool{}, false
	}
	findings := make([]model.Finding, 0)
	covered := map[string]bool{}
	for index, result := range payload.Results {
		if index >= len(coordinates) || len(result.Vulns) == 0 {
			continue
		}
		coordinate := coordinates[index]
		covered[normalizePackageName(coordinate.Name)] = true
		ids := make([]string, 0, len(result.Vulns))
		for _, vulnerability := range result.Vulns {
			if vulnerability.ID != "" {
				ids = append(ids, vulnerability.ID)
			}
		}
		details := fetchOSVDetails(ctx, client, ids)
		severity := "LOW"
		for _, detail := range details {
			if severityRank(detail.Severity) > severityRank(severity) {
				severity = detail.Severity
			}
		}
		confidence := map[string]float64{"CRITICAL": .9, "HIGH": .8, "MEDIUM": .7, "LOW": .6}[severity]
		version := ""
		if coordinate.Version != "" {
			version = "==" + coordinate.Version
		}
		findings = append(findings, supplyChainFinding("SC4", severity, confidence, coordinate.File, coordinate.Line,
			fmt.Sprintf("Known Vulnerable Dependency: %s%s — %d advisory(ies): %s", coordinate.Name, version, len(details), formatOSVDetails(details)), coordinate.Name+version))
	}
	return findings, covered, true
}

func analyzeFrozenOSVCoordinates(coordinates []dependencyCoordinate, fixture string) ([]model.Finding, map[string]bool, bool) {
	raw, err := os.ReadFile(fixture)
	if err != nil {
		return nil, map[string]bool{}, false
	}
	var document frozenOSVDocument
	if json.Unmarshal(raw, &document) != nil || document.SchemaVersion != 1 {
		return nil, map[string]bool{}, false
	}
	byCoordinate := map[string][]osvVulnerability{}
	for _, response := range document.Responses {
		key := strings.ToLower(response.Ecosystem) + "\x00" + normalizePackageName(response.Name) + "\x00" + response.Version
		byCoordinate[key] = append([]osvVulnerability(nil), response.Vulnerabilities...)
	}
	findings := make([]model.Finding, 0)
	covered := map[string]bool{}
	for _, coordinate := range coordinates {
		key := strings.ToLower(coordinate.Ecosystem) + "\x00" + normalizePackageName(coordinate.Name) + "\x00" + coordinate.Version
		details := byCoordinate[key]
		if len(details) == 0 {
			continue
		}
		covered[normalizePackageName(coordinate.Name)] = true
		severity := "LOW"
		for _, detail := range details {
			if severityRank(detail.Severity) > severityRank(severity) {
				severity = strings.ToUpper(detail.Severity)
			}
		}
		confidence := map[string]float64{"CRITICAL": .9, "HIGH": .8, "MEDIUM": .7, "LOW": .6}[severity]
		version := ""
		if coordinate.Version != "" {
			version = "==" + coordinate.Version
		}
		findings = append(findings, supplyChainFinding("SC4", severity, confidence, coordinate.File, coordinate.Line,
			fmt.Sprintf("Known Vulnerable Dependency: %s%s — %d advisory(ies): %s", coordinate.Name, version, len(details), formatOSVDetails(details)), coordinate.Name+version))
	}
	return findings, covered, true
}

func fetchOSVDetails(ctx context.Context, client *http.Client, ids []string) []osvVulnerability {
	if len(ids) > 10 {
		ids = ids[:10]
	}
	results := make([]osvVulnerability, 0, len(ids))
	for _, id := range ids {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.osv.dev/v1/vulns/"+id, nil)
		if err != nil {
			results = append(results, osvVulnerability{ID: id, Severity: "HIGH"})
			continue
		}
		response, err := client.Do(request)
		if err != nil {
			results = append(results, osvVulnerability{ID: id, Severity: "HIGH"})
			continue
		}
		var raw map[string]any
		decodeErr := json.NewDecoder(response.Body).Decode(&raw)
		_ = response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 || decodeErr != nil {
			results = append(results, osvVulnerability{ID: id, Severity: "HIGH"})
			continue
		}
		results = append(results, parseOSVVulnerability(raw))
	}
	return results
}

func parseOSVVulnerability(raw map[string]any) osvVulnerability {
	result := osvVulnerability{ID: stringValue(raw["id"]), Summary: stringValue(raw["summary"]), Severity: "HIGH"}
	if result.ID == "" {
		result.ID = "UNKNOWN"
	}
	if result.Summary == "" {
		result.Summary = truncate(stringValue(raw["details"]), 200)
	}
	if aliases, ok := raw["aliases"].([]any); ok {
		for _, alias := range aliases {
			if text, ok := alias.(string); ok {
				result.Aliases = append(result.Aliases, text)
			}
		}
	}
	if database, ok := raw["database_specific"].(map[string]any); ok {
		if severity := strings.ToUpper(stringValue(database["severity"])); severity != "" {
			result.Severity = severity
			return result
		}
	}
	if affected, ok := raw["affected"].([]any); ok {
		for _, entry := range affected {
			if object, ok := entry.(map[string]any); ok {
				if ecosystem, ok := object["ecosystem_specific"].(map[string]any); ok {
					if severity := strings.ToUpper(stringValue(ecosystem["severity"])); severity != "" {
						result.Severity = severity
						return result
					}
				}
			}
		}
	}
	if entries, ok := raw["severity"].([]any); ok {
		for _, entry := range entries {
			if object, ok := entry.(map[string]any); ok {
				if severity := estimateCVSSSeverity(stringValue(object["score"])); severity != "" {
					result.Severity = severity
					return result
				}
			}
		}
	}
	return result
}

func estimateCVSSSeverity(vector string) string {
	match := cvssVector.FindStringSubmatch(vector)
	if len(match) != 2 {
		return ""
	}
	high := wordSet("AV:N", "AC:L", "PR:N", "UI:N", "S:C", "C:H", "I:H", "A:H", "AT:N", "VC:H", "VI:H", "VA:H", "SC:H", "SI:H", "SA:H")
	metrics := strings.Split(match[1], "/")
	count := 0
	for _, metric := range metrics {
		if high[metric] {
			count++
		}
	}
	if len(metrics) == 0 {
		return ""
	}
	ratio := float64(count) / float64(len(metrics))
	switch {
	case ratio >= .75:
		return "CRITICAL"
	case ratio >= .5:
		return "HIGH"
	case ratio >= .25:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func formatOSVDetails(details []osvVulnerability) string {
	labels := make([]string, 0, min(3, len(details)))
	for _, detail := range details[:min(3, len(details))] {
		label := detail.ID
		for _, alias := range detail.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				label = alias
				break
			}
		}
		if detail.Summary != "" {
			label += " (" + truncateRunes(detail.Summary, 80) + ")"
		}
		labels = append(labels, label)
	}
	result := strings.Join(labels, "; ")
	if len(details) > 3 {
		result += fmt.Sprintf(" +%d more", len(details)-3)
	}
	return result
}

func analyzeFallbackVulnerabilities(coordinates []dependencyCoordinate, database []fallbackVulnerability) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, coordinate := range coordinates {
		for _, vulnerability := range database {
			if normalizePackageName(coordinate.Name) != normalizePackageName(vulnerability.name) {
				continue
			}
			message, matched := "", coordinate.Name
			if vulnerability.maxSafe == "" {
				message = fmt.Sprintf("Known Vulnerable Dependency: %s (%s)", coordinate.Name, vulnerability.description)
			} else if coordinate.Version != "" && versionLessThan(coordinate.Version, vulnerability.maxSafe) {
				matched = coordinate.Name + "==" + coordinate.Version
				message = fmt.Sprintf("Known Vulnerable Dependency: %s (fix: >=%s, %s)", matched, vulnerability.maxSafe, vulnerability.description)
			}
			if message != "" {
				findings = append(findings, supplyChainFinding("SC4", "HIGH", vulnerability.confidence, coordinate.File, coordinate.Line, message, matched))
			}
		}
	}
	return findings
}

func supplyChainFinding(id, severity string, confidence float64, file string, line int, pattern, matched string) model.Finding {
	explanation, remediation := ruleText(id)
	return model.Finding{ID: id, Category: "Supply Chain", Pattern: pattern, Severity: severity, Confidence: confidence,
		Location: model.Location{File: file, StartLine: line}, Finding: truncate(matched, 200), MatchedText: truncate(matched, 200),
		Explanation: explanation, Remediation: remediation, Tags: []string{"Supply Chain"}}
}

func typosquatTarget(name string, popular []string) string {
	normalized := normalizePackageName(name)
	for _, candidate := range popular {
		popularName := normalizePackageName(candidate)
		if normalized == popularName {
			return ""
		}
		if len(normalized) < 3 || len(popularName) < 3 {
			continue
		}
		distance := levenshteinDistance(normalized, popularName)
		if distance <= 0 || distance > 2 || distance*3 > min(len(normalized), len(popularName)) {
			continue
		}
		return candidate
	}
	return ""
}

func levenshteinDistance(left, right string) int {
	if len(left) < len(right) {
		return levenshteinDistance(right, left)
	}
	if len(right) == 0 {
		return len(left)
	}
	previous := make([]int, len(right)+1)
	for index := range previous {
		previous[index] = index
	}
	for leftIndex := range left {
		current := []int{leftIndex + 1}
		for rightIndex := range right {
			cost := 1
			if left[leftIndex] == right[rightIndex] {
				cost = 0
			}
			current = append(current, min(current[rightIndex]+1, previous[rightIndex+1]+1, previous[rightIndex]+cost))
		}
		previous = current
	}
	return previous[len(previous)-1]
}

func normalizePackageName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

func versionLessThan(left, right string) bool {
	leftParts, rightParts := numericVersionParts(left), numericVersionParts(right)
	for index := 0; index < min(len(leftParts), len(rightParts)); index++ {
		if leftParts[index] != rightParts[index] {
			return leftParts[index] < rightParts[index]
		}
	}
	return len(leftParts) < len(rightParts)
}

func numericVersionParts(value string) []int {
	parts := versionParts.FindAllString(value, -1)
	result := make([]int, 0, len(parts))
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err == nil {
			result = append(result, number)
		}
	}
	return result
}

func severityRank(value string) int {
	return map[string]int{"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[strings.ToUpper(value)]
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func lineContaining(content, needle string) int {
	for index, line := range strings.Split(content, "\n") {
		if strings.Contains(line, needle) {
			return index + 1
		}
	}
	return 1
}
