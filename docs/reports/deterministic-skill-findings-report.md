# Deterministic Skill Findings Report

## Purpose

This document defines what the deterministic skill checker reports when given a GitHub repository and asked to scan one skill.

The goal is to make the product scope concrete:

- input: GitHub repo, local folder, zip, or single skill file
- scan mode: deterministic only
- output: findings, severity, score, recommendation, and machine-readable reports

This report is based on the current ScanKernel codebase.

## What "deterministic-only" means

Deterministic scanning means:

- no external model calls
- no execution of untrusted skill code
- findings come only from static parsing, pattern matching, dependency lookups, structural analysis, and signature matching
- the same input should produce the same findings and score

## Supported input shape

A deterministic scanner for one skill can accept:

- GitHub repository URL
- local directory
- zip archive
- single `SKILL.md` or equivalent manifest file

The repo is resolved into a local directory, files are enumerated, manifest metadata is parsed, and all components are scanned statically.

## Deterministic finding families

### 1. Prompt Injection

- `P1` Override Instructions
- `P2` Hidden Instructions
- `P3` External Transmission Instructions
- `P4` Subtle Steering
- `P5` Harmful Content
- `P6` Direct System Prompt Leakage
- `P7` Indirect System Prompt Leakage
- `P8` System Prompt Exfiltration via tools/files/network

### 2. Data Exfiltration

- `E1` External Transmission
- `E2` Environment Variable Harvesting
- `E3` File System Enumeration
- `E4` Conversation Context Leak
- `E5` Cloud Storage Exfiltration

### 3. Privilege Escalation

- `PE1` Excessive Permissions
- `PE2` Sudo/Root Execution
- `PE3` Credential Access
- `PE4` Docker Socket Access
- `PE5` Privileged Container / Container Escape

### 4. Supply Chain and Trigger Abuse

- `SC1` Unpinned Dependencies
- `SC2` External Script Fetching / remote code bootstrap
- `SC3` Obfuscated Code
- `SC4` Known Vulnerable Dependency
- `SC5` Abandoned Dependency
- `SC6` Possible Typosquatting Dependency
- `SC7` Untrusted Container Image

Trigger-related deterministic findings:

- `TR1` Overly Broad Trigger
- `TR2` Shadow Command Trigger
- `TR3` Keyword Baiting Trigger

### 5. Excessive Agency

- `EA1` Unrestricted Tool Access
- `EA2` Autonomous High-Impact Decisions
- `EA3` Scope Creep
- `EA4` Unbounded Resource Access

### 6. Output Handling

- `OH1` Unvalidated Output Injection
- `OH2` Cross-Context Output
- `OH3` Unbounded Output

### 7. Memory Poisoning

- `MP1` Persistent Context Injection
- `MP2` Context Window Stuffing
- `MP3` Memory Manipulation

### 8. Tool Misuse

- `TM1` Tool Parameter Abuse
- `TM2` Chaining Abuse
- `TM3` Unsafe Defaults
- `TM4` Privileged Kubernetes Workload

### 9. Rogue Agent

- `RA1` Self-Modification
- `RA2` Session Persistence

### 10. Agent Snooping

- `AS1` Agent Config Directory Access
- `AS2` MCP Config Access
- `AS3` Skill Enumeration / other-skill access

### 11. Anti-Refusal / Jailbreak Framing

- `AR1` Refusal Suppression
- `AR2` Disclaimer Suppression
- `AR3` Safety Policy Nullification

### 12. SSRF

- `SSRF1` Cloud Metadata Access
- `SSRF2` Internal Network Request
- `SSRF3` Dynamic Request Target

### 13. Behavioral AST Findings

Python-only structural findings:

- `AST1` `exec()` call
- `AST2` `eval()` call
- `AST3` dynamic `__import__()`
- `AST4` `subprocess.*` execution
- `AST5` `os.system()` / exec-family calls
- `AST6` `compile()` call
- `AST7` dynamic `getattr()`
- `AST8` dangerous execution chain
- `AST9` reflective dangerous sink via `getattr(obj, "system"|"exec"|...)`

### 14. Behavioral Taint Tracking

Python-only data-flow findings:

- `TT1` Direct Source-to-Sink Flow
- `TT2` Variable-Mediated Taint Flow
- `TT3` Credential Exfiltration Flow
- `TT4` File Data Exfiltration Flow
- `TT5` External Input to Execution Flow

### 15. YARA Signature Matches

- `YR1` Malware Signature
- `YR2` Webshell Detected
- `YR3` Crypto Miner Detected
- `YR4` Hack Tool / Exploit Detected

### 16. MCP Least Privilege

- `LP1` Underdeclared Capability
- `LP2` Wildcard Permission
- `LP3` Missing Permission Declaration
- `LP4` Overdeclared Permission

### 17. MCP Tool Poisoning

- `TP1` Hidden Instructions in metadata
- `TP2` Unicode Deception
- `TP3` Parameter Description Injection / suspicious defaults

### 18. MCP Rug Pull

- `RP1` Unpinned MCP/tool/server dependency or permission expansion signal
- `RP2` Manifest permission/pre-staging or trigger modification signal
- `RP3` Broad/unpinned version or parameter/schema modification signal

## What one deterministic finding can contain

Each finding can expose the following fields:

- `id` — rule ID such as `SC4`, `AST8`, `LP1`
- `category` — human category, such as `Supply Chain`
- `pattern` — human display name
- `severity` — `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `confidence` — normalized score from `0.0` to `1.0`
- `location.file`
- `location.start_line`
- `location.end_line`
- `finding` — short matched snippet
- `explanation` — why it is risky
- `remediation` — suggested fix
- `code_snippet` — context snippet if available
- `intent` — usually empty in deterministic-only mode
- `tags` — optional metadata tags

## Deterministic scan outputs you can show for one skill

### A. Scan summary

- skill name
- scan source
- scan timestamp
- total component count
- executable-script presence
- total findings count
- suppressed findings count, if baselines are used

### B. Risk assessment

- `risk_score` from `0` to `100`
- `risk_severity`
- `recommendation`

Recommendation mapping:

- `LOW` -> `SAFE`
- `MEDIUM` -> `CAUTION`
- `HIGH` -> `DO_NOT_INSTALL`
- `CRITICAL` -> `DO_NOT_INSTALL`

### C. Component inventory

For each scanned file:

- relative path
- inferred type
- line count
- executable yes/no
- size in bytes

### D. Findings list

For each finding:

- rule ID
- title/pattern name
- severity
- confidence
- file and line number
- evidence snippet
- explanation
- remediation

### E. Deterministic coverage metadata

You can explicitly show that the scan is deterministic with fields like:

- `analysis_mode: deterministic`
- `filtering_mode: heuristic`
- `scan_mode: deterministic`

### F. Completeness / limitations

A useful deterministic report can also show:

- total components discovered
- total components scanned
- coverage percent
- findings before filtering
- findings after filtering
- limitations list
- `is_complete`

Example limitations:

- large file skipped
- binary file skipped
- Python-only AST/taint checks do not apply to non-Python code
- dependency advisory lookup fell back to bundled static list

## Report formats available from deterministic-only scan

### 1. Terminal report

Human-readable summary with:

- skill/source/time
- risk score and recommendation
- file/component table
- findings list

### 2. JSON report

Best format for frontend and API use.

Suggested top-level structure:

```json
{
  "skill": {},
  "risk_assessment": {},
  "components": [],
  "issues": [],
  "suppressed_count": 0,
  "suppressed": [],
  "metadata": {},
  "analysis_completeness": {}
}
```

### 3. Markdown report

Best for:

- product exports
- internal reviews
- attachments to tickets
- audit records

### 4. SARIF report

Best for:

- CI/CD
- GitHub code scanning
- IDE integrations
- enterprise security tooling

## Deterministic scoring behavior

Scoring can be shown as:

- severity-weighted
- confidence-adjusted
- duplicate-controlled

Current deterministic scoring model supports:

- base points by severity
  - `CRITICAL = 50`
  - `HIGH = 25`
  - `MEDIUM = 10`
  - `LOW = 5`
- multiply by confidence
- diminishing returns for repeated same-rule hits
- optional multiplier for executable-file findings
- hard cap at `100`

## Useful frontend sections for one-skill deterministic report

If you build a UI, one skill page can show:

1. Overview
- score
- severity
- recommendation
- scan mode = static-only

2. Findings by severity
- critical
- high
- medium
- low

3. Findings by category
- supply chain
- privilege escalation
- prompt injection
- taint/data flow
- YARA
- MCP metadata issues

4. File inventory
- all scanned files
- executable files only
- dependency files only

5. Dependency risk section
- vulnerable packages
- abandoned packages
- typosquatting candidates
- OSV fallback warning if live lookup failed

6. Code risk section
- dangerous execution calls
- taint flows
- malware/signature hits

7. Manifest / MCP risk section
- permission mismatches
- wildcard permissions
- hidden metadata instructions
- Unicode deception
- trigger abuse

## What deterministic-only mode cannot honestly claim

Do not claim these in static-only mode:

- full semantic intent detection
- paraphrased or narrative prompt injection detection
- perfect description-behavior mismatch detection
- human-level understanding of policy violations

Those require human review and are outside the scanner's guarantees.

## Product-safe positioning

The deterministic-only scanner can be positioned as:

> A reproducible, auditable, no-code-execution security gate for AI skills that detects structural, signature-based, dependency-based, manifest-based, and code-flow-based risks.

This is a strong fit for reproducible CI and pre-installation review.

## Recommended API response for deterministic-only one-skill scan

```json
{
  "target": "https://github.com/org/repo",
  "scan_mode": "deterministic",
  "risk_score": 72,
  "severity": "HIGH",
  "recommendation": "DO_NOT_INSTALL",
  "safe_to_install": false,
  "summary": {
    "components": 14,
    "executable_files": 4,
    "findings": 9
  },
  "findings": [],
  "reports": {
    "json": "available",
    "markdown": "available",
    "sarif": "available",
    "terminal": "available"
  },
  "metadata": {
    "analysis_mode": "deterministic",
    "filtering_mode": "heuristic"
  }
}
```

## Bottom line

If you only scan a GitHub repo deterministically for one skill, you can still produce a serious report with:

- manifest findings
- prompt-injection pattern findings
- exfiltration findings
- privilege-escalation findings
- supply-chain findings
- dangerous Python AST findings
- taint/data-flow findings
- YARA/malware findings
- MCP least-privilege findings
- MCP metadata poisoning findings
- rug-pull / versioning findings
- risk score
- install recommendation
- JSON / Markdown / SARIF / terminal outputs

That is enough for a credible first version of an AI skill checker.
