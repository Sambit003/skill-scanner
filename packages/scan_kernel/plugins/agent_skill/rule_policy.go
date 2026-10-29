package agentskill

import (
	"path/filepath"
	"slices"
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
	"MP3": {ruleEvidence, contextInstructions}, "AR1": {ruleEvidence, contextInstructions}, "TR1": {ruleEvidence, contextInstructions},
	"TR2": {ruleEvidence, contextInstructions}, "TR3": {ruleEvidence, contextInstructions}, "TP1": {ruleEvidence, contextInstructions},
	"TP3": {ruleEvidence, contextInstructions}, "YR5": {ruleEvidence, contextInstructions},

	"PE1": {ruleCapability, contextAny}, "PE2": {ruleCapability, contextAny}, "PE3": {ruleCapability, contextAny},
	"E1": {ruleCapability, contextAny}, "E2": {ruleCapability, contextAny}, "E3": {ruleCapability, contextAny},
	"E4": {ruleCapability, contextAny}, "E5": {ruleCapability, contextAny}, "AS1": {ruleCapability, contextAny},
	"AS2": {ruleCapability, contextAny}, "AS3": {ruleCapability, contextAny}, "LP1": {ruleCapability, contextAny},
	"LP2": {ruleCapability, contextAny}, "LP3": {ruleCapability, contextAny}, "LP4": {ruleCapability, contextAny},
	"RA1": {ruleCapability, contextAny}, "RA2": {ruleCapability, contextAny}, "EA1": {ruleCapability, contextAny},
	"EA2": {ruleCapability, contextAny}, "EA3": {ruleCapability, contextAny}, "EA4": {ruleCapability, contextAny},
	"EA5": {ruleCapability, contextAny}, "EA6": {ruleCapability, contextAny}, "EA7": {ruleCapability, contextAny},
	"TM1": {ruleCapability, contextAny}, "TM2": {ruleCapability, contextAny}, "TM3": {ruleCapability, contextAny},
	"OH1": {ruleCapability, contextAny}, "OH2": {ruleCapability, contextAny}, "OH3": {ruleCapability, contextAny},
	"P2": {ruleCapability, contextInstructions}, "P4": {ruleCapability, contextInstructions},
	"P7": {ruleCapability, contextInstructions}, "MP2": {ruleCapability, contextInstructions}, "AR2": {ruleCapability, contextInstructions},

	"SC1": {ruleHygiene, contextAny}, "RP1": {ruleHygiene, contextAny}, "RP2": {ruleHygiene, contextAny},
	"RP3": {ruleHygiene, contextAny}, "SC5": {ruleHygiene, contextAny}, "SC6": {ruleHygiene, contextAny},
	"SC7": {ruleHygiene, contextAny}, "SC8": {ruleHygiene, contextAny},
	"SC9":  {ruleHygiene, contextAny},
	"SC10": {ruleHygiene, contextAny},
	"SC11": {ruleHygiene, contextAny},
	"SC12": {ruleHygiene, contextAny},
	"SC13": {ruleHygiene, contextAny},
	"SC14": {ruleHygiene, contextAny},
	"RA3":  {ruleEvidence, contextAny},
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

// highSeverityEvidence lists capability rules whose HIGH and CRITICAL
// findings are evidence: EA6 reports a skill hook's presence at MEDIUM, and
// at HIGH a hook that posts events to a URL or runs a command that downloads,
// executes fetched code, sends data or reads credentials; SC11 at HIGH is a
// symbolic link to a secret or system location; SC13 at HIGH is a shipped
// program SKILL.md tells the agent or user to run, and SC14 at HIGH a
// Windows download, decode or hidden-window technique. A shipped program or
// script on its own (MEDIUM) is hygiene and listed as a capability.
var highSeverityEvidence = map[string]bool{"EA6": true, "SC11": true, "SC13": true, "SC14": true}

func findingPolicy(finding model.Finding) rulePolicy {
	policy := classifyRule(ruleID(finding))
	if highSeverityEvidence[ruleID(finding)] && (finding.Severity == "HIGH" || finding.Severity == "CRITICAL") {
		policy.Class = ruleEvidence
	}
	return policy
}

// Findings marked for review (see prose_review.go) stay in the report but
// count as neither evidence nor capability.
func isEvidenceFinding(finding model.Finding) bool {
	if _, review := needsReview(finding); review {
		return false
	}
	policy := findingPolicy(finding)
	return policy.Class == ruleEvidence && (policy.Context == contextAny || policy.Context == findingContext(finding.Location.File))
}

func isCapabilityFinding(finding model.Finding) bool {
	if _, review := needsReview(finding); review {
		return false
	}
	return findingPolicy(finding).Class == ruleCapability
}

// ruleTier is a verdict floor a finding sets on its own, apart from its
// additive weight in the risk score.
type ruleTier int

const (
	tierNone ruleTier = iota
	// tierCaution: an instruction attack in an instruction file, a file only
	// partly scanned, a hook that sends data or runs fetched code, an
	// instruction to manipulate the user or hide something from them, or a
	// write to the agent's memory or instruction files. The verdict is at
	// least CAUTION.
	tierCaution
	// tierCritical: confirmed malicious behaviour. The verdict is
	// DO_NOT_INSTALL.
	tierCritical
)

// tierConfidence gates the floors: matches in reference documentation and
// findings that need review fall below it.
const tierConfidence = .6

var tierFloors = map[ruleTier]int{tierCaution: 30, tierCritical: 85}

// criticalRules set the DO_NOT_INSTALL floor by rule ID at or above the given
// severity, apart from any behaviour marker: TT3 CRITICAL sends cloud
// secrets, several credentials, or any credential to a collection host or raw
// IP address. SC3 sets the floor only through its decode-to-exec marker.
var criticalRules = map[string]string{"TT3": "CRITICAL"}

// cautionRules set the CAUTION floor in any file at or above the given
// severity: SC8 is a file only partly scanned, and EA6 at HIGH a hook that
// posts events to a URL or runs a command that downloads, executes fetched
// code, sends data or reads credentials.
var cautionRules = map[string]string{"SC8": "LOW", "EA6": "HIGH"}

// instructionAttackRules set the CAUTION floor when they match in an
// instruction file: instruction override, hidden instructions, exfiltration
// instructions, prompt exfiltration, context leaks, safety nullification,
// tool-description injection and prompt-injection signatures.
var instructionAttackRules = map[string]bool{"P1": true, "P2": true, "P3": true, "P8": true, "E4": true,
	"AR3": true, "TP1": true, "TP3": true, "YR5": true}

var tierSeverityRank = map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

func severityAtLeast(severity, minimum string) bool {
	return tierSeverityRank[strings.ToUpper(severity)] >= tierSeverityRank[minimum]
}

// findingTier returns the verdict floor a finding sets. A finding that needs
// review or falls below tierConfidence sets none.
func findingTier(finding model.Finding) ruleTier {
	if _, review := needsReview(finding); review || finding.Confidence < tierConfidence {
		return tierNone
	}
	id := ruleID(finding)
	if _, behaviour := behaviourOf(finding); behaviour {
		return tierCritical
	}
	if minimum, ok := criticalRules[id]; ok && severityAtLeast(finding.Severity, minimum) {
		return tierCritical
	}
	if minimum, ok := cautionRules[id]; ok && severityAtLeast(finding.Severity, minimum) {
		return tierCaution
	}
	if id == "RA2" && slices.Contains(finding.Tags, memoryPersistenceTag) {
		return tierCaution
	}
	instructions := findingContext(finding.Location.File) == contextInstructions
	if instructions && (instructionAttackRules[id] || id == "P4" && slices.Contains(finding.Tags, concealmentTag)) {
		return tierCaution
	}
	return tierNone
}
