package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	agentskill "gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/plugins/agent_skill"
)

type FamilyRefs struct {
	OwaspAgentic []string `json:"owasp_agentic"`
	OwaspLLM     []string `json:"owasp_llm"`
	NistGaiRisks []string `json:"nist_gai_risks"`
	NistRmf      []string `json:"nist_rmf"`
}

type GeneratedData struct {
	MappingVersion string                `json:"mapping_version"`
	Families       map[string]FamilyRefs `json:"families"`
	Overrides      map[string]FamilyRefs `json:"overrides"`
}

func main() {
	repoRoot := "."
	if len(os.Args) > 1 {
		repoRoot = os.Args[1]
	}

	// 1. Generate JSON for frontend
	families := make(map[string]FamilyRefs)
	for _, fam := range agentskill.AllFamilyIDs() {
		fw := agentskill.FamilyFrameworks(fam)
		families[fam] = FamilyRefs{
			OwaspAgentic: fw.OwaspAgentic,
			OwaspLLM:     fw.OwaspLLM,
			NistGaiRisks: fw.NistGaiRisks,
			NistRmf:      fw.NistRmf,
		}
	}

	overrides := make(map[string]FamilyRefs)
	for _, ruleID := range agentskill.AllOverrideRuleIDs() {
		fw := agentskill.FrameworksForRule(ruleID)
		overrides[ruleID] = FamilyRefs{
			OwaspAgentic: fw.OwaspAgentic,
			OwaspLLM:     fw.OwaspLLM,
			NistGaiRisks: fw.NistGaiRisks,
			NistRmf:      fw.NistRmf,
		}
	}

	genData := GeneratedData{
		MappingVersion: agentskill.MappingVersion,
		Families:       families,
		Overrides:      overrides,
	}

	jsonBytes, err := json.MarshalIndent(genData, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal JSON: %v", err)
	}

	jsonPath := filepath.Join(repoRoot, "apps", "frontend", "app", "lib", "framework-refs.generated.json")
	if err := os.MkdirAll(filepath.Dir(jsonPath), 0755); err != nil {
		log.Fatalf("failed to create dir for %s: %v", jsonPath, err)
	}
	if err := os.WriteFile(jsonPath, append(jsonBytes, '\n'), 0644); err != nil {
		log.Fatalf("failed to write %s: %v", jsonPath, err)
	}
	fmt.Printf("Wrote %s\n", jsonPath)

	// 2. Generate Compliance Evidence Document
	var doc strings.Builder
	doc.WriteString("# OWASP and NIST Framework Mapping Evidence Document\n\n")
	doc.WriteString("> [!IMPORTANT]\n")
	doc.WriteString("> **DRAFT**: Final source-text spot-check pending independent review. Internal baseline verified on 2026-09-02.\n\n")

	doc.WriteString("## 1. Version Manifest & Source Verification\n\n")
	doc.WriteString("| Framework | Pinned Version | Source URL / Record | Retrieval Date | SHA256 Checksum |\n")
	doc.WriteString("|---|---|---|---|---|\n")
	doc.WriteString("| OWASP GenAI LLM Top 10 | 2026 Final | `https://github.com/GenAI-Security-Project/GenAI-LLM-Top10` | 2026-09-02 | Resource page published 2026-08-03 |\n")
	doc.WriteString("| OWASP Agentic Skills Top 10 | v1.0 (2026 Edition) | `https://owasp.org/www-project-agentic-skills-top-10/` | 2026-09-02 | Checklist snapshot 2026-08-03 |\n")
	doc.WriteString("| NIST AI RMF | 1.0 (AI 100-1) | `https://airc.nist.gov/airmf-resources/airmf/5-sec-core/` | 2026-09-02 | `f0c8c0d75337e305b9220e10dd23b6daa69d0bbb0b20cd85445c34516330a726` |\n")
	doc.WriteString("| NIST GenAI Profile | AI 600-1 (July 2024) | `https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf` | 2026-09-02 | `bb6fb01faea3a118fdf920ba6c43bb122070b3e669940c6421c0425b943fe32d` |\n")
	fmt.Fprintf(&doc, "| Engine Mapping Version | `%s` | Scan Kernel Source of Truth | 2026-09-03 | Code-enforced completeness |\n\n", agentskill.MappingVersion)

	doc.WriteString("### AST Provenance Chain\n")
	doc.WriteString("The AST01–AST10 taxonomy is an exact match (IDs, titles, order, severity tiers) of the official **OWASP Agentic Skills Top 10, v1.0 (2026 Edition)**. Inherited via NVIDIA SkillSpector's OWASP coverage assessment (checklist snapshot 2026-08-03, 72 checks; provenance chain: commits `00cd6ab` → `a09f2f2` → `cc9a5ea`). Distinct from the sibling OWASP Top 10 for Agentic Applications (ASI 2026).\n\n")

	doc.WriteString("## 2. Rule Family Mappings\n\n")
	doc.WriteString("| Family | OWASP Agentic (AST) | OWASP GenAI LLM (2026) | NIST AI 600-1 Primary Risks | NIST AI RMF Subcategories |\n")
	doc.WriteString("|---|---|---|---|---|\n")

	familyIDs := agentskill.AllFamilyIDs()
	for _, fam := range familyIDs {
		fw := agentskill.FamilyFrameworks(fam)
		rmfStr := "*(none)*"
		if len(fw.NistRmf) > 0 {
			rmfStr = strings.Join(fw.NistRmf, ", ")
		}
		fmt.Fprintf(&doc, "| **%s** | %s | %s | %s | %s |\n",
			fam,
			strings.Join(fw.OwaspAgentic, ", "),
			strings.Join(fw.OwaspLLM, ", "),
			strings.Join(fw.NistGaiRisks, ", "),
			rmfStr,
		)
	}
	doc.WriteString("\n")

	doc.WriteString("## 3. Consolidated Rule Overrides\n\n")
	doc.WriteString("| Rule ID | OWASP LLM (2026) | NIST AI 600-1 | NIST AI RMF | Rationale & Evidence |\n")
	doc.WriteString("|---|---|---|---|---|\n")

	overrideIDs := agentskill.AllOverrideRuleIDs()
	overrideRationales := map[string]string{
		"P6":  "System prompt disclosure/extraction (LLM08 Hidden Context Exposure).",
		"P7":  "Indirect prompt extraction (LLM08 Hidden Context Exposure).",
		"P8":  "Prompt exfiltration via tool calls (LLM08 Hidden Context Exposure).",
		"EA4": "Unbounded loops/retries; meets LLM06 mitigations verbatim alongside excessive agency (LLM03 + LLM06).",
		"OH3": "Unbounded output size/rate; denial-of-service via resource exhaustion (LLM06 + LLM10).",
		"MP2": "Context stuffing/token exhaustion abuse in memory (LLM01 + LLM06).",
		"MP3": "Persistent memory-store manipulation/poisoning in agent deployments (LLM01 + LLM05).",
		"TT1": "Taint tracking with code execution and network exfiltration sinks (LLM02 + LLM10).",
		"TT2": "Variable-mediated taint flow reaching exec and network sinks (LLM02 + LLM10).",
		"TT5": "External input directly reaching execution sink without exfiltration (LLM10).",
		"AS1": "Agent configuration directory access containing instructions destined for context (LLM02 + LLM08).",
	}

	for _, ruleID := range overrideIDs {
		fw := agentskill.FrameworksForRule(ruleID)
		rmfStr := "*(none)*"
		if len(fw.NistRmf) > 0 {
			rmfStr = strings.Join(fw.NistRmf, ", ")
		}
		rationale := overrideRationales[ruleID]
		fmt.Fprintf(&doc, "| **%s** | %s | %s | %s | %s |\n",
			ruleID,
			strings.Join(fw.OwaspLLM, ", "),
			strings.Join(fw.NistGaiRisks, ", "),
			rmfStr,
			rationale,
		)
	}
	doc.WriteString("\n")

	doc.WriteString("## 4. Static Coverage & Audit Boundaries\n\n")
	doc.WriteString("| 2026 Category | Static Coverage Status | Rules / Mechanisms | Evidence & Audit Boundaries |\n")
	doc.WriteString("|---|---|---|---|---|\n")
	doc.WriteString("| LLM01 Prompt Injection | Detections present | P1–5, TP1–3, AR1–3, MP1–3 | Embedded instruction and metadata injection; no runtime adversarial evaluation. |\n")
	doc.WriteString("| LLM02 Sensitive Information Disclosure | Detections present | E1–5, TT1–4, AS1–3 | Environment, secret file, config access and data flow detection. |\n")
	doc.WriteString("| LLM03 Excessive Agency | Detections present | EA1–4, LP1–4, PE1–5, TM1–4, RA1–2 | Over-permissioning, autonomous high-impact actions, container escapes. |\n")
	doc.WriteString("| LLM04 Supply Chain | Detections present | SC1–7, RP1–3, YR1–4, TR1–3 | Unpinned dependencies, malware signatures, trigger-namespace squatting. SC4 excluded in HSBC build. |\n")
	doc.WriteString("| LLM05 Data & Model Poisoning | Partial | MP3 | Persistent memory-store poisoning in agent scope. Pre-training and fine-tuning poisoning are out of static scope. |\n")
	doc.WriteString("| LLM06 Unbounded Consumption | Partial | EA4, OH3, MP2 | Static unbounded resource markers and context stuffing patterns. No runtime latency/cost measurement. |\n")
	doc.WriteString("| LLM07 Misinformation | Not covered | *(none)* | Output factual quality and hallucination are runtime evaluation concerns. |\n")
	doc.WriteString("| LLM08 Hidden Context Exposure | Detections present | P6–8, AS1 | System prompt leakage and agent config disclosure detection. |\n")
	doc.WriteString("| LLM09 Vector & Embedding Weaknesses | Not covered | *(none)* | Requires vector database geometry/embedding analysis; agent memory attacks routed to ASI06. |\n")
	doc.WriteString("| LLM10 Improper Output Handling | Detections present | OH1–3, TT1, TT2, TT5, AST1–9, SSRF1–3 | Model/untrusted output flowing to execution sinks, AST sinks, and SSRF destinations. |\n\n")

	doc.WriteString("## 5. Ratification Log\n\n")
	doc.WriteString("- **O1 (Ratified 2026-09-03, Project Lead)**: Trim RMF subcategories strictly to crosswalk-backed entries. MEASURE 2.6 dropped everywhere; MEASURE 2.7 emitted where an LLM category maps to MEASURE 2; LLM03-only and LLM10-only emit empty `nist_rmf: []`.\n")
	doc.WriteString("- **O2 (Ratified 2026-09-02, Project Lead)**: LLM09 excluded from memory findings; agent memory is classified under LLM01/LLM05, avoiding unevidenced vector tags.\n")
	doc.WriteString("- **O3 (Ratified 2026-09-03, Project Lead)**: `TR1`–`TR3` classified under `LLM04:2026` as trigger-namespace slopsquatting / supply chain name confusion.\n")
	doc.WriteString("- **C1 (Ratified 2026-09-03, Project Lead)**: MP3 NIST primary risks use pure composition (`Information Security`, `Information Integrity`, `Value Chain and Component Integration` via LLM05).\n\n")

	doc.WriteString("## 6. Requirements Traceability\n\n")
	doc.WriteString("| Requirement | Implementation Deliverable | Status |\n")
	doc.WriteString("|---|---|---|\n")
	doc.WriteString("| OWASP Top 10 Categorization | Scan Kernel `frameworks.go`, Protocol v2, UI mappings | Complete |\n")
	doc.WriteString("| NIST AI Risk Framework Alignment | AI 600-1 and AI RMF 1.0 crosswalked subcategories | Complete |\n")
	doc.WriteString("| Exportable Security Reports | JSON, Markdown (Compliance summary), SARIF 2.1.0 (4 Taxonomies) | Complete |\n")
	doc.WriteString("| Severity-Based Risk Scoring | Scoring engine preserved untouched; orthogonality enforced | Complete |\n")
	doc.WriteString("| Remediation Recommendations | Per-rule remediation + category mitigation guidance | Complete |\n")

	docPath := filepath.Join(repoRoot, "docs", "compliance", "framework-mapping-evidence.md")
	if err := os.MkdirAll(filepath.Dir(docPath), 0755); err != nil {
		log.Fatalf("failed to create dir for %s: %v", docPath, err)
	}
	if err := os.WriteFile(docPath, []byte(doc.String()), 0644); err != nil {
		log.Fatalf("failed to write %s: %v", docPath, err)
	}
	fmt.Printf("Wrote %s\n", docPath)
}
