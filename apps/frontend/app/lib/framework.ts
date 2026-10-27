import frameworkRefsData from "./framework-refs.generated.json";
import type { FrameworkRefs, FindingResponse } from "./api";

export interface AstCategoryDoc {
  id: string;
  title: string;
  severity: "Critical" | "High" | "Medium";
  summary: string;
  scannerEvidence: string;
  reviewFocus: string;
  ruleFamilies: string[];
}

export interface RuleFamilyDoc {
  id: string;
  title: string;
  summary: string;
  astCategories: string[];
}

export interface LlmCategoryDoc {
  id: string;
  title: string;
  severity: "Critical" | "High" | "Medium";
  summary: string;
  scannerEvidence: string;
  mitigations: string[];
  coverage: "detections-present" | "partial" | "none";
  url: string;
}

export interface NistGaiRiskDoc {
  id: string;
  title: string;
  summary: string;
  whatFindingsEvidence: string;
}

export interface NistRmfSubcategoryDoc {
  id: string;
  function: string;
  summary: string;
  howScannerSupports: string;
}

export const AST_CATEGORIES: AstCategoryDoc[] = [
  {
    id: "AST01",
    title: "Malicious Skills",
    severity: "Critical",
    summary: "Malicious instructions, deceptive behavior, malware indicators, and dangerous code paths.",
    scannerEvidence: "Instruction analysis, AST execution checks, taint analysis, YARA signatures, and anti-refusal checks.",
    reviewFocus: "Confirm the skill source, inspect flagged behavior, and review any dangerous instruction or execution evidence before approval.",
    ruleFamilies: ["P", "E", "AST", "TT", "YR", "AR", "RA", "AS", "MP"],
  },
  {
    id: "AST02",
    title: "Supply Chain Compromise",
    severity: "Critical",
    summary: "Mutable dependencies, remote bootstrap paths, typosquatting, and untrusted packages.",
    scannerEvidence: "Dependency pinning checks, remote execution checks, typosquat signals, and untrusted image detection.",
    reviewFocus: "Check publisher trust, dependency pinning, artifact integrity, and any remote bootstrap path before approval.",
    ruleFamilies: ["SC", "RP", "TR", "YR"],
  },
  {
    id: "AST03",
    title: "Over-Privileged Skills",
    severity: "High",
    summary: "Permissions, credentials, filesystem access, network scope, and broad tool authority.",
    scannerEvidence: "Least-privilege comparison, wildcard permission checks, credential access, elevated execution.",
    reviewFocus: "Validate that requested permissions, credentials, filesystem access, and network scope match the skill's stated purpose.",
    ruleFamilies: ["LP", "PE", "EA", "TM", "AS", "TT", "E"],
  },
  {
    id: "AST04",
    title: "Insecure Metadata",
    severity: "High",
    summary: "Hidden metadata instructions, unsafe defaults, encoded content, and description drift.",
    scannerEvidence: "Metadata poisoning, Unicode deception, hidden instruction, YARA, and unsafe default checks.",
    reviewFocus: "Inspect metadata for hidden instructions, unsafe defaults, encoded content, and description-to-behavior mismatch.",
    ruleFamilies: ["TP", "P", "SC", "TM", "LP", "YR"],
  },
  {
    id: "AST05",
    title: "Untrusted External Instructions",
    severity: "High",
    summary: "External URLs, mutable references, runtime fetches, and network destination control.",
    scannerEvidence: "Remote fetch, unpinned external reference, SSRF, and unsafe network default findings.",
    reviewFocus: "Inventory external URLs and runtime fetches, then confirm destinations are trusted, pinned, and expected.",
    ruleFamilies: ["RP", "SC", "SSRF", "TM"],
  },
  {
    id: "AST06",
    title: "Weak Isolation",
    severity: "High",
    summary: "Runtime sandboxing, container escape risk, internal interfaces, and host access.",
    scannerEvidence: "Docker socket, privileged container, unsafe network default, and untrusted image findings.",
    reviewFocus: "Confirm the skill runs with a constrained runtime, least privilege, restricted network access, and no host escape path.",
    ruleFamilies: ["PE", "TM", "SC", "E"],
  },
  {
    id: "AST07",
    title: "Update Drift",
    severity: "Medium",
    summary: "Mutable skill versions, remote references, and changes that bypass review.",
    scannerEvidence: "Unpinned external references and version-drift checks.",
    reviewFocus: "Confirm reviewed versions are pinned, updates trigger a new review, and dependency changes are manually reviewed.",
    ruleFamilies: ["RP", "SC"],
  },
  {
    id: "AST08",
    title: "Poor Scanning",
    severity: "Medium",
    summary: "Whether review looks beyond signatures into code, instructions, taint, and malware indicators.",
    scannerEvidence: "Static patterns, Python AST analysis, taint flows, YARA signatures, and deterministic rule docs.",
    reviewFocus: "Use the scan findings as review evidence and separately inspect unsupported binaries or runtime-only behavior when present.",
    ruleFamilies: ["P", "AST", "TT", "YR", "SC", "LP"],
  },
  {
    id: "AST09",
    title: "No Governance",
    severity: "Medium",
    summary: "Review history, policy evidence, inventory, ownership, and organizational approval.",
    scannerEvidence: "Scan records and normalized manifests provide useful evidence for governance workflows.",
    reviewFocus: "Attach scan evidence to the approval workflow and confirm ownership, exception handling, and review history are recorded.",
    ruleFamilies: ["RP", "SC", "LP"],
  },
  {
    id: "AST10",
    title: "Cross-Platform Reuse",
    severity: "Medium",
    summary: "Whether a skill remains safe when reused across platforms with different execution models.",
    scannerEvidence: "Selected SKILL.md frontmatter is normalized before scanning.",
    reviewFocus: "Confirm platform-specific variants preserve the same permissions, metadata, credential handling, and review outcome.",
    ruleFamilies: ["LP", "TP", "RP", "SC"],
  },
];

export const LLM_CATEGORIES: LlmCategoryDoc[] = [
  {
    id: "LLM01:2026",
    title: "Prompt Injection",
    severity: "Critical",
    summary: "Direct or indirect manipulation of model prompts via untrusted user input, third-party content, tool output, or memory.",
    scannerEvidence: "Detects override instructions, invisible unicode, hidden comment directives, and parameter injection.",
    mitigations: [
      "Enforce strict privilege separation between data and instructions.",
      "Strip invisible unicode, zero-width spaces, and directional formatting.",
      "Require human approval for high-consequence tool invocations.",
      "Treat persistent memory writes as privileged operations.",
    ],
    coverage: "detections-present",
    url: "https://genai.owasp.org/llm01/",
  },
  {
    id: "LLM02:2026",
    title: "Sensitive Information Disclosure",
    severity: "Critical",
    summary: "Unintended exposure of sensitive data, API keys, credentials, PII, or proprietary context in model output, tool arguments, or logs.",
    scannerEvidence: "Detects environment variable harvesting, credential file scanning, and exfiltration flows.",
    mitigations: [
      "Externalize secrets and avoid placing keys or credentials in prompts or manifests.",
      "Enforce egress filtering and data loss prevention on tool destinations.",
      "Minimize context window contents to strictly necessary information.",
    ],
    coverage: "detections-present",
    url: "https://genai.owasp.org/llm02/",
  },
  {
    id: "LLM03:2026",
    title: "Excessive Agency",
    severity: "High",
    summary: "Granting excessive functionality, excessive permissions, or excessive autonomy to LLM-based agentic systems.",
    scannerEvidence: "Detects wildcard permissions, elevated execution, container breakouts, and unauthorized persistence.",
    mitigations: [
      "Limit agent toolsets to the minimum necessary functions.",
      "Require user confirmation for destructive or high-impact actions.",
      "Enforce authorization checks in deterministic application logic, not model judgment.",
    ],
    coverage: "detections-present",
    url: "https://genai.owasp.org/llm03/",
  },
  {
    id: "LLM04:2026",
    title: "Supply Chain",
    severity: "Critical",
    summary: "Compromised third-party packages, plugins, MCP servers, or trigger-namespace squatting.",
    scannerEvidence: "Detects unpinned dependencies, remote code execution, package confusion, and trigger shadowing.",
    mitigations: [
      "Pin exact dependency versions and verify cryptographic checksums.",
      "Audit third-party skill registries and MCP server configurations.",
      "Verify package authenticity and registry provenance before installation.",
    ],
    coverage: "detections-present",
    url: "https://genai.owasp.org/llm04/",
  },
  {
    id: "LLM05:2026",
    title: "Data & Model Poisoning",
    severity: "High",
    summary: "Tampering with training data, fine-tuning datasets, or persistent agent memory stores to introduce backdoors or biases.",
    scannerEvidence: "Detects persistent state and memory manipulation attempts (MP3). Pre-training and fine-tuning poisoning are out of static scope.",
    mitigations: [
      "Validate and sanitize data written to persistent agent memory stores.",
      "Maintain data provenance and integrity verification for all skill resources.",
      "Isolate memory partitions across different user sessions.",
    ],
    coverage: "partial",
    url: "https://genai.owasp.org/llm05/",
  },
  {
    id: "LLM06:2026",
    title: "Unbounded Consumption",
    severity: "Medium",
    summary: "Excessive resource consumption leading to denial-of-service, cost overruns, or context-window displacement.",
    scannerEvidence: "Detects unbounded loop markers (EA4), unbounded output generation (OH3), and context stuffing (MP2).",
    mitigations: [
      "Enforce hard caps on step limits, recursion depth, and execution time.",
      "Set token-aware quotas and rate limits per operation.",
      "Monitor resource usage and implement circuit breakers.",
    ],
    coverage: "partial",
    url: "https://genai.owasp.org/llm06/",
  },
  {
    id: "LLM07:2026",
    title: "Misinformation",
    severity: "Medium",
    summary: "Generation of inaccurate, hallucinated, or fabricated information with potential real-world harm.",
    scannerEvidence: "Not covered by static skill scanning; requires runtime content evaluation and ground-truth validation.",
    mitigations: [
      "Implement retrieval-augmented generation with verified knowledge bases.",
      "Cross-check critical factual claims against authoritative external sources.",
      "Display confidence scores and uncertainty disclosures to users.",
    ],
    coverage: "none",
    url: "https://genai.owasp.org/llm07/",
  },
  {
    id: "LLM08:2026",
    title: "Hidden Context Exposure",
    severity: "High",
    summary: "Extraction or leakage of system prompts, developer instructions, internal policies, or tool schemas.",
    scannerEvidence: "Detects system prompt disclosure patterns (P6-P8) and agent configuration snooping (AS1).",
    mitigations: [
      "Assume system prompt contents will eventually be disclosed to determined users.",
      "Never store sensitive API keys or credentials in system prompts.",
      "Implement secondary safety filters on model output to detect prompt reflection.",
    ],
    coverage: "detections-present",
    url: "https://genai.owasp.org/llm08/",
  },
  {
    id: "LLM09:2026",
    title: "Vector & Embedding Weaknesses",
    severity: "Medium",
    summary: "Attacks targeting vector database embeddings, similarity search manipulation, or semantic poisoning.",
    scannerEvidence: "Not covered by static skill scanning; requires vector database inspection and embedding space analysis.",
    mitigations: [
      "Implement access controls on vector database indices.",
      "Validate semantic similarity thresholds before injecting retrieved context.",
      "Audit vector embeddings for anomalies or cluster manipulation.",
    ],
    coverage: "none",
    url: "https://genai.owasp.org/llm09/",
  },
  {
    id: "LLM10:2026",
    title: "Improper Output Handling",
    severity: "Critical",
    summary: "Blindly passing model output to downstream execution sinks, shells, databases, or browsers without sanitization.",
    scannerEvidence: "Detects output flowing directly into exec(), eval(), subprocess, SQL, or SSRF endpoints.",
    mitigations: [
      "Treat all model output as untrusted user input.",
      "Apply context-aware output encoding (HTML, shell, SQL).",
      "Never pass unvalidated model text directly into execution sinks.",
    ],
    coverage: "detections-present",
    url: "https://genai.owasp.org/llm10/",
  },
];

export const NIST_GAI_RISKS: Record<string, NistGaiRiskDoc> = {
  "Information Security": {
    id: "Information Security",
    title: "Information Security",
    summary: "Risks related to unauthorized access, code execution, prompt manipulation, and security controls breach in GenAI systems.",
    whatFindingsEvidence: "Findings in this area identify prompt overrides, arbitrary execution sinks, container escapes, or credential exposure.",
  },
  "Data Privacy": {
    id: "Data Privacy",
    title: "Data Privacy",
    summary: "Risks of sensitive data, PII, credentials, or confidential business context disclosure through model outputs, tool arguments, or telemetry.",
    whatFindingsEvidence: "Findings in this area identify environment secret harvesting, sensitive file discovery, or external network data exfiltration.",
  },
  "Value Chain and Component Integration": {
    id: "Value Chain and Component Integration",
    title: "Value Chain and Component Integration",
    summary: "Risks originating from third-party components, dependencies, external MCP integrations, or supply chain tampering.",
    whatFindingsEvidence: "Findings in this area identify unpinned packages, malware indicators, untrusted container images, or trigger squatting.",
  },
  "Information Integrity": {
    id: "Information Integrity",
    title: "Information Integrity",
    summary: "Risks concerning the intentional corruption or unauthorized modification of agent state, persistent memory, or reference data.",
    whatFindingsEvidence: "Findings in this area identify persistent agent memory corruption or state store poisoning.",
  },
};

export const NIST_RMF_SUBCATEGORIES: Record<string, NistRmfSubcategoryDoc> = {
  "GOVERN 6.1": {
    id: "GOVERN 6.1",
    function: "GOVERN",
    summary: "Policies and procedures are in place to address AI risks and benefits arising from third-party software and data and other supply chain issues.",
    howScannerSupports: "Provides evidence of third-party package dependency auditing and provenance validation.",
  },
  "MANAGE 3.1": {
    id: "MANAGE 3.1",
    function: "MANAGE",
    summary: "Mechanisms are in place to manage the AI risks arising from third-party software, hardware, system components, or data.",
    howScannerSupports: "Supports third-party skill intake controls by detecting unpinned or malicious dependencies.",
  },
  "MAP 4.1": {
    id: "MAP 4.1",
    function: "MAP",
    summary: "The AI system's potential harms are identified and documented, including impacts on individuals, groups, communities, organizations, and society.",
    howScannerSupports: "Identifies systemic supply chain vulnerabilities in third-party skill ecosystems.",
  },
  "MEASURE 2.7": {
    id: "MEASURE 2.7",
    function: "MEASURE",
    summary: "AI system security and resilience — including cybersecurity, data poisoning, model extraction, and evasion attacks — are evaluated and documented.",
    howScannerSupports: "Supplies quantitative static detection evidence for model evasion, injection, and security vulnerabilities.",
  },
  "MEASURE 2.10": {
    id: "MEASURE 2.10",
    function: "MEASURE",
    summary: "Privacy risk of the AI system is evaluated.",
    howScannerSupports: "Evaluates privacy risk through static detection of sensitive credential access and exfiltration pathways.",
  },
};

const rawFamilies = [
  { id: "P", title: "Prompt and instruction manipulation", summary: "Override, hidden instruction, prompt leakage, and harmful content patterns." },
  { id: "E", title: "Exfiltration and sensitive data", summary: "Environment, credential, file, network, and cloud upload exposure." },
  { id: "PE", title: "Privilege escalation", summary: "Root access, credential files, Docker socket access, and container escape capability." },
  { id: "SC", title: "Supply chain and dependency risk", summary: "Unpinned installs, remote bootstrap, typosquats, and unsigned images." },
  { id: "EA", title: "Excessive agency", summary: "Unrestricted tools, destructive autonomy, scope creep, and unbounded resources." },
  { id: "OH", title: "Output handling", summary: "Unsafe use of model or tool output across execution and trust boundaries." },
  { id: "MP", title: "Memory poisoning", summary: "Persistent context injection, context stuffing, and agent state manipulation." },
  { id: "TM", title: "Tool misuse", summary: "Dangerous parameters, tool chaining, unsafe defaults, and privileged workloads." },
  { id: "RA", title: "Rogue agent behavior", summary: "Self-modification and unauthorized persistence across sessions." },
  { id: "RP", title: "Rug-pull and update risk", summary: "Mutable external references, manifest expansion, and unpinned skill versions." },
  { id: "TR", title: "Trigger abuse", summary: "Over-broad, shadowing, or generic activation triggers." },
  { id: "AST", title: "Python AST execution", summary: "exec, eval, subprocess, dynamic imports, compile, reflection, and execution chains." },
  { id: "TT", title: "Taint tracking", summary: "Source-to-sink flows involving credentials, files, external input, network, or execution." },
  { id: "YR", title: "YARA signatures", summary: "Malware, webshell, cryptominer, and offensive-tool indicators." },
  { id: "LP", title: "Least privilege", summary: "Capability declarations, wildcard permissions, undeclared operations, and overdeclaration." },
  { id: "TP", title: "Tool metadata poisoning", summary: "Hidden metadata, Unicode deception, and parameter injection." },
  { id: "AS", title: "Agent snooping", summary: "Agent config, MCP config, and peer skill enumeration." },
  { id: "AR", title: "Anti-refusal", summary: "Instructions that suppress refusal, warnings, or safety policy boundaries." },
  { id: "SSRF", title: "Server-side request forgery", summary: "Metadata endpoints, private network targets, and dynamic request hosts." },
];

export const RULE_FAMILIES: RuleFamilyDoc[] = rawFamilies.map((fam) => {
  const generatedFam = (frameworkRefsData.families as Record<string, { owasp_agentic?: string[] }>)[fam.id];
  return {
    ...fam,
    astCategories: generatedFam?.owasp_agentic ?? [],
  };
});

export function getRuleFamilyDoc(family: string | null | undefined): RuleFamilyDoc | null {
  if (!family) return null;
  const normalized = family.toUpperCase();
  return RULE_FAMILIES.find((item) => item.id === normalized) ?? null;
}

export function getAstCategoryDoc(id: string): AstCategoryDoc | null {
  return AST_CATEGORIES.find((item) => item.id === id) ?? null;
}

export function getLlmCategoryDoc(id: string): LlmCategoryDoc | null {
  const normalized = id.includes(":") ? id : `${id}:2026`;
  return LLM_CATEGORIES.find((item) => item.id === normalized) ?? null;
}

export function getNistGaiRiskDoc(id: string): NistGaiRiskDoc | null {
  return NIST_GAI_RISKS[id] ?? null;
}

export function getNistRmfDoc(id: string): NistRmfSubcategoryDoc | null {
  return NIST_RMF_SUBCATEGORIES[id] ?? null;
}

export function astCategoriesForFamily(family: string | null | undefined): AstCategoryDoc[] {
  const doc = getRuleFamilyDoc(family);
  if (!doc) return [];
  return doc.astCategories
    .map((id) => getAstCategoryDoc(id))
    .filter((item): item is AstCategoryDoc => item !== null);
}

export function astCategoriesForFamilies(families: Iterable<string | null | undefined>): AstCategoryDoc[] {
  const ids = new Set<string>();
  for (const family of families) {
    for (const category of astCategoriesForFamily(family)) {
      ids.add(category.id);
    }
  }
  return AST_CATEGORIES.filter((category) => ids.has(category.id));
}

interface RawFrameworkRefs {
  owasp_agentic: string[];
  owasp_llm: string[];
  nist_gai_risks: string[];
  nist_rmf: string[];
}

export function getFrameworksForFinding(finding: Pick<FindingResponse, "rule_id" | "rule_family" | "frameworks">): {
  frameworks: FrameworkRefs;
  isRetrospective: boolean;
} {
  if (finding.frameworks && finding.frameworks.mapping_version) {
    return {
      frameworks: finding.frameworks,
      isRetrospective: false,
    };
  }

  const overrides = frameworkRefsData.overrides as Record<string, RawFrameworkRefs>;
  const families = frameworkRefsData.families as Record<string, RawFrameworkRefs>;

  const ruleID = finding.rule_id?.toUpperCase() ?? "";
  const familyID = finding.rule_family?.toUpperCase() ?? "";

  const fallback = overrides[ruleID] ?? families[familyID] ?? {
    owasp_agentic: [],
    owasp_llm: [],
    nist_gai_risks: [],
    nist_rmf: [],
  };

  return {
    frameworks: {
      mapping_version: frameworkRefsData.mapping_version,
      owasp_agentic: fallback.owasp_agentic ?? [],
      owasp_llm: fallback.owasp_llm ?? [],
      nist_gai_risks: fallback.nist_gai_risks ?? [],
      nist_rmf: fallback.nist_rmf ?? [],
    },
    isRetrospective: true,
  };
}

export function sortRuleIds(left: string, right: string): number {
  const pattern = /^([A-Za-z]+)(\d+)$/;
  const leftMatch = left.match(pattern);
  const rightMatch = right.match(pattern);
  if (!leftMatch || !rightMatch) return left.localeCompare(right);
  if (leftMatch[1] !== rightMatch[1]) return leftMatch[1].localeCompare(rightMatch[1]);
  return Number(leftMatch[2]) - Number(rightMatch[2]);
}
