package agentskill

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

type suppressionRule struct {
	ID      string `yaml:"id" json:"id"`
	RuleID  string `yaml:"rule_id" json:"rule_id"`
	Path    string `yaml:"path" json:"path"`
	File    string `yaml:"file" json:"file"`
	Message string `yaml:"message" json:"message"`
	Reason  string `yaml:"reason" json:"reason"`
}

type fingerprintEntry struct {
	Hash   string `yaml:"hash" json:"hash"`
	Reason string `yaml:"reason" json:"reason"`
}

type baselineFile struct {
	Version      int                `yaml:"version" json:"version"`
	Rules        []suppressionRule  `yaml:"rules" json:"rules"`
	Fingerprints []fingerprintEntry `yaml:"fingerprints" json:"fingerprints"`
}

func loadBaseline(path string) (baselineFile, error) {
	if strings.TrimSpace(path) == "" {
		return baselineFile{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return baselineFile{}, fmt.Errorf("read baseline: %w", err)
	}
	var baseline baselineFile
	if err := yamlUnmarshal(raw, &baseline); err != nil {
		return baselineFile{}, fmt.Errorf("parse baseline: %w", err)
	}
	if baseline.Version != 0 && baseline.Version != 1 {
		return baselineFile{}, fmt.Errorf("unsupported baseline version %d", baseline.Version)
	}
	for _, rule := range baseline.Rules {
		if rule.ID == "" && rule.RuleID == "" && rule.Path == "" && rule.File == "" && rule.Message == "" {
			return baselineFile{}, fmt.Errorf("baseline rule must select id, path, or message")
		}
	}
	return baseline, nil
}

func filterBaseline(findings []model.Finding, baseline baselineFile) (kept []model.Finding, suppressed []model.Finding) {
	kept = make([]model.Finding, 0, len(findings))
	suppressed = make([]model.Finding, 0)
	fingerprints := map[string]bool{}
	for _, item := range baseline.Fingerprints {
		fingerprints[item.Hash] = true
	}
	for _, finding := range findings {
		matched := fingerprints[findingFingerprint(finding)]
		for _, rule := range baseline.Rules {
			id := rule.ID
			if id == "" {
				id = rule.RuleID
			}
			path := rule.Path
			if path == "" {
				path = rule.File
			}
			if globMatch(ruleID(finding), id) && globMatch(finding.Location.File, path) && globMatch(finding.Explanation, rule.Message) {
				matched = true
				break
			}
		}
		if matched {
			suppressed = append(suppressed, finding)
		} else {
			kept = append(kept, finding)
		}
	}
	return kept, suppressed
}

func globMatch(value, pattern string) bool {
	if pattern == "" {
		return true
	}
	pattern = strings.ReplaceAll(pattern, "**", "*")
	expression := regexp.QuoteMeta(strings.ToLower(pattern))
	expression = strings.ReplaceAll(expression, `\*`, `.*`)
	expression = strings.ReplaceAll(expression, `\?`, `.`)
	matched, err := regexp.MatchString("^(?:"+expression+")$", strings.ToLower(value))
	return err == nil && matched
}

func findingFingerprint(finding model.Finding) string {
	end := ""
	if finding.Location.EndLine != nil {
		end = fmt.Sprint(*finding.Location.EndLine)
	}
	raw := strings.Join([]string{ruleID(finding), finding.Location.File, fmt.Sprint(finding.Location.StartLine), end, strings.TrimSpace(finding.Explanation)}, "|")
	digest := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(digest[:8])
}
