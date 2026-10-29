package agentskill

import (
	"sort"
	"strings"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

const mappingVersion = "2026.09-1"

// familyAgenticFrameworks maps rule families to the OWASP Agentic Skills Top 10 (v1.0 2026 Edition).
// Ported directly from the frontend source of truth to make the scan kernel the single authority.
var familyAgenticFrameworks = map[string][]string{
	"P":    {"AST01", "AST04"},
	"E":    {"AST01", "AST03"},
	"PE":   {"AST03", "AST06"},
	"SC":   {"AST02", "AST04", "AST07"},
	"EA":   {"AST03"},
	"OH":   {"AST01", "AST08"},
	"MP":   {"AST01", "AST03"},
	"TM":   {"AST03", "AST04", "AST06"},
	"RA":   {"AST01"},
	"RP":   {"AST02", "AST05", "AST07", "AST09", "AST10"},
	"TR":   {"AST02"},
	"AST":  {"AST01", "AST08"},
	"TT":   {"AST01", "AST03", "AST08"},
	"YR":   {"AST01", "AST02", "AST04", "AST08"},
	"LP":   {"AST03", "AST04", "AST10"},
	"TP":   {"AST04", "AST10"},
	"AS":   {"AST01", "AST03"},
	"AR":   {"AST01"},
	"SSRF": {"AST05"},
}

// familyLLMFrameworks defines default family mappings to the OWASP GenAI LLM Top 10 (2026 Edition).
var familyLLMFrameworks = map[string][]string{
	"P":    {"LLM01:2026"},
	"E":    {"LLM02:2026"},
	"PE":   {"LLM03:2026"},
	"SC":   {"LLM04:2026"},
	"EA":   {"LLM03:2026"},
	"OH":   {"LLM10:2026"},
	"MP":   {"LLM01:2026"},
	"TM":   {"LLM03:2026"},
	"RA":   {"LLM03:2026"},
	"RP":   {"LLM04:2026"},
	"TR":   {"LLM04:2026"},
	"AST":  {"LLM10:2026"},
	"TT":   {"LLM02:2026"},
	"YR":   {"LLM04:2026"},
	"LP":   {"LLM03:2026"},
	"TP":   {"LLM01:2026"},
	"AS":   {"LLM02:2026"},
	"AR":   {"LLM01:2026"},
	"SSRF": {"LLM10:2026"},
}

// ruleFrameworkOverrides specifies exact per-rule overrides for OWASP LLM categories.
// Full replacement for the family default.
var ruleFrameworkOverrides = map[string][]string{
	"P6":  {"LLM08:2026"},
	"P7":  {"LLM08:2026"},
	"P8":  {"LLM08:2026"},
	"EA4": {"LLM03:2026", "LLM06:2026"},
	"OH3": {"LLM06:2026", "LLM10:2026"},
	"MP2": {"LLM01:2026", "LLM06:2026"},
	"MP3": {"LLM01:2026", "LLM05:2026"},
	"TT1": {"LLM02:2026", "LLM10:2026"},
	"TT2": {"LLM02:2026", "LLM10:2026"},
	"TT5": {"LLM10:2026"},
	"AS1": {"LLM02:2026", "LLM08:2026"},
	"YR5": {"LLM01:2026"},
}

// nistPrimaryRisksByLLM defines the primary (●) NIST AI 600-1 risks per OWASP LLM category
// from official Appendix A crosswalk.
var nistPrimaryRisksByLLM = map[string][]string{
	"LLM01:2026": {"Information Security"},
	"LLM02:2026": {"Data Privacy", "Information Security"},
	"LLM03:2026": {"Information Security"},
	"LLM04:2026": {"Information Security", "Value Chain and Component Integration"},
	"LLM05:2026": {"Information Integrity", "Information Security", "Value Chain and Component Integration"},
	"LLM06:2026": {"Information Security"},
	"LLM08:2026": {"Information Security"},
	"LLM10:2026": {"Information Security"},
}

func deriveNistGaiRisks(llmCategories []string) []string {
	seen := make(map[string]bool)
	var risks []string
	for _, cat := range llmCategories {
		if r, ok := nistPrimaryRisksByLLM[cat]; ok {
			for _, item := range r {
				if !seen[item] {
					seen[item] = true
					risks = append(risks, item)
				}
			}
		}
	}
	sort.Strings(risks)
	if risks == nil {
		return []string{}
	}
	return risks
}

func deriveNistRmf(llmCategories []string) []string {
	seen := make(map[string]bool)
	var rmf []string

	hasMeasure2 := false
	hasLLM02 := false
	hasLLM04 := false

	for _, cat := range llmCategories {
		switch cat {
		case "LLM01:2026", "LLM05:2026", "LLM06:2026", "LLM08:2026":
			hasMeasure2 = true
		case "LLM02:2026":
			hasMeasure2 = true
			hasLLM02 = true
		case "LLM04:2026":
			hasMeasure2 = true
			hasLLM04 = true
		}
	}

	if hasMeasure2 {
		seen["MEASURE 2.7"] = true
		rmf = append(rmf, "MEASURE 2.7")
	}
	if hasLLM02 {
		if !seen["MEASURE 2.10"] {
			seen["MEASURE 2.10"] = true
			rmf = append(rmf, "MEASURE 2.10")
		}
	}
	if hasLLM04 {
		for _, subcat := range []string{"GOVERN 6.1", "MANAGE 3.1", "MAP 4.1"} {
			if !seen[subcat] {
				seen[subcat] = true
				rmf = append(rmf, subcat)
			}
		}
	}

	sort.Strings(rmf)
	if rmf == nil {
		return []string{}
	}
	return rmf
}

func frameworksForRule(ruleID string) model.FrameworkMappings {
	cleanID := strings.TrimSpace(ruleID)
	family := ruleFamily(cleanID)

	astList := familyAgenticFrameworks[family]
	if astList == nil {
		astList = []string{}
	} else {
		cp := make([]string, len(astList))
		copy(cp, astList)
		sort.Strings(cp)
		astList = cp
	}

	var llmList []string
	if override, ok := ruleFrameworkOverrides[cleanID]; ok {
		llmList = make([]string, len(override))
		copy(llmList, override)
	} else if def, ok := familyLLMFrameworks[family]; ok {
		llmList = make([]string, len(def))
		copy(llmList, def)
	} else {
		llmList = []string{}
	}
	sort.Strings(llmList)

	gaiRisks := deriveNistGaiRisks(llmList)
	rmf := deriveNistRmf(llmList)

	mappings := model.FrameworkMappings{
		MappingVersion: mappingVersion,
		OwaspAgentic:   astList,
		OwaspLLM:       llmList,
		NistGaiRisks:   gaiRisks,
		NistRmf:        rmf,
	}
	mappings.Normalize()
	return mappings
}

func applyFrameworkMappings(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, len(findings))
	for i, f := range findings {
		id := ruleID(f)
		f.Frameworks = frameworksForRule(id)
		f.Frameworks.Normalize()
		out[i] = f
	}
	return out
}

const MappingVersion = mappingVersion

func FrameworksForRule(ruleID string) model.FrameworkMappings {
	return frameworksForRule(ruleID)
}

func AllFamilyIDs() []string {
	var ids []string
	for f := range familyAgenticFrameworks {
		ids = append(ids, f)
	}
	sort.Strings(ids)
	return ids
}

func AllOverrideRuleIDs() []string {
	var ids []string
	for id := range ruleFrameworkOverrides {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func FamilyFrameworks(family string) model.FrameworkMappings {
	cleanFam := strings.TrimSpace(family)
	astList := familyAgenticFrameworks[cleanFam]
	if astList == nil {
		astList = []string{}
	} else {
		cp := make([]string, len(astList))
		copy(cp, astList)
		sort.Strings(cp)
		astList = cp
	}

	var llmList []string
	if def, ok := familyLLMFrameworks[cleanFam]; ok {
		llmList = make([]string, len(def))
		copy(llmList, def)
	} else {
		llmList = []string{}
	}
	sort.Strings(llmList)

	gaiRisks := deriveNistGaiRisks(llmList)
	rmf := deriveNistRmf(llmList)

	mappings := model.FrameworkMappings{
		MappingVersion: mappingVersion,
		OwaspAgentic:   astList,
		OwaspLLM:       llmList,
		NistGaiRisks:   gaiRisks,
		NistRmf:        rmf,
	}
	mappings.Normalize()
	return mappings
}
