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
    summary: "Mutable dependencies, remote bootstrap paths, typosquatting, and vulnerable packages.",
    scannerEvidence: "Dependency pinning checks, OSV lookups, remote execution checks, and untrusted image detection.",
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
    summary: "Mutable skill versions, advisory exposure, and changes that bypass review.",
    scannerEvidence: "Unpinned external references and point-in-time OSV vulnerability checks.",
    reviewFocus: "Confirm reviewed versions are pinned, updates trigger a new review, and dependencies are checked against advisories.",
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

export const RULE_FAMILIES: RuleFamilyDoc[] = [
  { id: "P", title: "Prompt and instruction manipulation", summary: "Override, hidden instruction, prompt leakage, and harmful content patterns.", astCategories: ["AST01", "AST04"] },
  { id: "E", title: "Exfiltration and sensitive data", summary: "Environment, credential, file, network, and cloud upload exposure.", astCategories: ["AST01", "AST03"] },
  { id: "PE", title: "Privilege escalation", summary: "Root access, credential files, Docker socket access, and container escape capability.", astCategories: ["AST03", "AST06"] },
  { id: "SC", title: "Supply chain and dependency risk", summary: "Unpinned installs, remote bootstrap, vulnerabilities, typosquats, and unsigned images.", astCategories: ["AST02", "AST04", "AST07"] },
  { id: "EA", title: "Excessive agency", summary: "Unrestricted tools, destructive autonomy, scope creep, and unbounded resources.", astCategories: ["AST03"] },
  { id: "OH", title: "Output handling", summary: "Unsafe use of model or tool output across execution and trust boundaries.", astCategories: ["AST01", "AST08"] },
  { id: "MP", title: "Memory poisoning", summary: "Persistent context injection, context stuffing, and agent state manipulation.", astCategories: ["AST01", "AST03"] },
  { id: "TM", title: "Tool misuse", summary: "Dangerous parameters, tool chaining, unsafe defaults, and privileged workloads.", astCategories: ["AST03", "AST04", "AST06"] },
  { id: "RA", title: "Rogue agent behavior", summary: "Self-modification and unauthorized persistence across sessions.", astCategories: ["AST01"] },
  { id: "RP", title: "Rug-pull and update risk", summary: "Mutable external references, manifest expansion, and unpinned skill versions.", astCategories: ["AST02", "AST05", "AST07", "AST09", "AST10"] },
  { id: "TR", title: "Trigger abuse", summary: "Over-broad, shadowing, or generic activation triggers.", astCategories: ["AST02"] },
  { id: "AST", title: "Python AST execution", summary: "exec, eval, subprocess, dynamic imports, compile, reflection, and execution chains.", astCategories: ["AST01", "AST08"] },
  { id: "TT", title: "Taint tracking", summary: "Source-to-sink flows involving credentials, files, external input, network, or execution.", astCategories: ["AST01", "AST03", "AST08"] },
  { id: "YR", title: "YARA signatures", summary: "Malware, webshell, cryptominer, and offensive-tool indicators.", astCategories: ["AST01", "AST02", "AST04", "AST08"] },
  { id: "LP", title: "Least privilege", summary: "Capability declarations, wildcard permissions, undeclared operations, and overdeclaration.", astCategories: ["AST03", "AST04", "AST10"] },
  { id: "TP", title: "Tool metadata poisoning", summary: "Hidden metadata, Unicode deception, parameter injection, and description mismatch.", astCategories: ["AST04", "AST10"] },
  { id: "AS", title: "Agent snooping", summary: "Agent config, MCP config, and peer skill enumeration.", astCategories: ["AST01", "AST03"] },
  { id: "AR", title: "Anti-refusal", summary: "Instructions that suppress refusal, warnings, or safety policy boundaries.", astCategories: ["AST01"] },
  { id: "SSRF", title: "Server-side request forgery", summary: "Metadata endpoints, private network targets, and dynamic request hosts.", astCategories: ["AST05"] },
];

export function getRuleFamilyDoc(family: string | null | undefined): RuleFamilyDoc | null {
  if (!family) return null;
  const normalized = family.toUpperCase();
  return RULE_FAMILIES.find((item) => item.id === normalized) ?? null;
}

export function getAstCategoryDoc(id: string): AstCategoryDoc | null {
  return AST_CATEGORIES.find((item) => item.id === id) ?? null;
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

export function sortRuleIds(left: string, right: string): number {
  const pattern = /^([A-Za-z]+)(\d+)$/;
  const leftMatch = left.match(pattern);
  const rightMatch = right.match(pattern);
  if (!leftMatch || !rightMatch) return left.localeCompare(right);
  if (leftMatch[1] !== rightMatch[1]) return leftMatch[1].localeCompare(rightMatch[1]);
  return Number(leftMatch[2]) - Number(rightMatch[2]);
}
