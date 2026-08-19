package agentskill

import (
	"path/filepath"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

type ruleClass string
type ruleContext string

const (
	ruleEvidence   ruleClass = "evidence"
	ruleCapability ruleClass = "capability"
	ruleHygiene    ruleClass = "hygiene"

	contextAny          ruleContext = "any"
	contextCode         ruleContext = "code"
	contextInstructions ruleContext = "instructions"
)

type rulePolicy struct {
	Class   ruleClass
	Context ruleContext
}

var scoringRulePolicies = map[string]rulePolicy{
	"TT1": {ruleEvidence, contextCode}, "TT2": {ruleEvidence, contextCode}, "TT3": {ruleEvidence, contextCode},
	"TT4": {ruleEvidence, contextCode}, "TT5": {ruleEvidence, contextCode}, "SC2": {ruleEvidence, contextCode},
	"SC3": {ruleEvidence, contextCode}, "SC4": {ruleEvidence, contextAny}, "YR1": {ruleEvidence, contextAny},
	"YR2": {ruleEvidence, contextAny}, "YR3": {ruleEvidence, contextAny}, "YR4": {ruleEvidence, contextAny},
	"TM4": {ruleEvidence, contextCode}, "PE4": {ruleEvidence, contextCode}, "PE5": {ruleEvidence, contextCode},
	"TP2": {ruleEvidence, contextAny},

	"P1": {ruleEvidence, contextInstructions}, "P3": {ruleEvidence, contextInstructions}, "P5": {ruleEvidence, contextInstructions},
	"P6": {ruleEvidence, contextInstructions}, "P8": {ruleEvidence, contextInstructions}, "MP1": {ruleEvidence, contextInstructions},
	"MP3": {ruleEvidence, contextInstructions}, "AR1": {ruleEvidence, contextInstructions}, "TR2": {ruleEvidence, contextInstructions},
	"TR3": {ruleEvidence, contextInstructions}, "TP1": {ruleEvidence, contextInstructions}, "TP3": {ruleEvidence, contextInstructions},

	"PE1": {ruleCapability, contextAny}, "PE2": {ruleCapability, contextAny}, "PE3": {ruleCapability, contextAny},
	"E1": {ruleCapability, contextAny}, "E2": {ruleCapability, contextAny}, "E3": {ruleCapability, contextAny},
	"E4": {ruleCapability, contextAny}, "E5": {ruleCapability, contextAny}, "AS1": {ruleCapability, contextAny},
	"AS2": {ruleCapability, contextAny}, "AS3": {ruleCapability, contextAny}, "LP1": {ruleCapability, contextAny},
	"LP2": {ruleCapability, contextAny}, "LP3": {ruleCapability, contextAny}, "LP4": {ruleCapability, contextAny},
	"RA1": {ruleCapability, contextAny}, "RA2": {ruleCapability, contextAny}, "EA1": {ruleCapability, contextAny},
	"EA2": {ruleCapability, contextAny}, "EA3": {ruleCapability, contextAny}, "EA4": {ruleCapability, contextAny},
	"TM1": {ruleCapability, contextAny}, "TM2": {ruleCapability, contextAny}, "TM3": {ruleCapability, contextAny},
	"OH1": {ruleCapability, contextAny}, "OH2": {ruleCapability, contextAny}, "OH3": {ruleCapability, contextAny},
	"TP4": {ruleCapability, contextAny}, "P2": {ruleCapability, contextInstructions}, "P4": {ruleCapability, contextInstructions},
	"P7": {ruleCapability, contextInstructions}, "MP2": {ruleCapability, contextInstructions}, "AR2": {ruleCapability, contextInstructions},
	"TR1": {ruleCapability, contextInstructions},

	"SC1": {ruleHygiene, contextAny}, "RP1": {ruleHygiene, contextAny}, "RP2": {ruleHygiene, contextAny},
	"RP3": {ruleHygiene, contextAny}, "SC5": {ruleHygiene, contextAny}, "SC6": {ruleHygiene, contextAny},
	"SC7": {ruleHygiene, contextAny},
}

func classifyRule(id string) rulePolicy {
	if policy, ok := scoringRulePolicies[id]; ok {
		return policy
	}
	return rulePolicy{Class: ruleCapability, Context: contextAny}
}

func findingContext(path string) ruleContext {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".markdown", ".txt", ".rst", ".adoc":
		return contextInstructions
	default:
		return contextCode
	}
}

func isEvidenceFinding(finding model.Finding) bool {
	policy := classifyRule(ruleID(finding))
	return policy.Class == ruleEvidence && (policy.Context == contextAny || policy.Context == findingContext(finding.Location.File))
}

func isCapabilityFinding(finding model.Finding) bool {
	return classifyRule(ruleID(finding)).Class == ruleCapability
}
