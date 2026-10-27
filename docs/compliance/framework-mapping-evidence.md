# OWASP and NIST Framework Mapping Evidence Document

> [!IMPORTANT]
> **DRAFT**: Final source-text spot-check pending independent review. Internal baseline verified on 2026-09-02.

## 1. Version Manifest & Source Verification

| Framework | Pinned Version | Source URL / Record | Retrieval Date | SHA256 Checksum |
|---|---|---|---|---|
| OWASP GenAI LLM Top 10 | 2026 Final | `https://github.com/GenAI-Security-Project/GenAI-LLM-Top10` | 2026-09-02 | Resource page published 2026-08-03 |
| OWASP Agentic Skills Top 10 | v1.0 (2026 Edition) | `https://owasp.org/www-project-agentic-skills-top-10/` | 2026-09-02 | Checklist snapshot 2026-08-03 |
| NIST AI RMF | 1.0 (AI 100-1) | `https://airc.nist.gov/airmf-resources/airmf/5-sec-core/` | 2026-09-02 | `f0c8c0d75337e305b9220e10dd23b6daa69d0bbb0b20cd85445c34516330a726` |
| NIST GenAI Profile | AI 600-1 (July 2024) | `https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf` | 2026-09-02 | `bb6fb01faea3a118fdf920ba6c43bb122070b3e669940c6421c0425b943fe32d` |
| Engine Mapping Version | `2026.09-1` | Scan Kernel Source of Truth | 2026-09-03 | Code-enforced completeness |

### AST Provenance Chain
The AST01–AST10 taxonomy is an exact match (IDs, titles, order, severity tiers) of the official **OWASP Agentic Skills Top 10, v1.0 (2026 Edition)**. Inherited via NVIDIA SkillSpector's OWASP coverage assessment (checklist snapshot 2026-08-03, 72 checks; provenance chain: commits `00cd6ab` → `a09f2f2` → `cc9a5ea`). Distinct from the sibling OWASP Top 10 for Agentic Applications (ASI 2026).

## 2. Rule Family Mappings

| Family | OWASP Agentic (AST) | OWASP GenAI LLM (2026) | NIST AI 600-1 Primary Risks | NIST AI RMF Subcategories |
|---|---|---|---|---|
| **AR** | AST01 | LLM01:2026 | Information Security | MEASURE 2.7 |
| **AS** | AST01, AST03 | LLM02:2026 | Data Privacy, Information Security | MEASURE 2.10, MEASURE 2.7 |
| **AST** | AST01, AST08 | LLM10:2026 | Information Security | *(none)* |
| **E** | AST01, AST03 | LLM02:2026 | Data Privacy, Information Security | MEASURE 2.10, MEASURE 2.7 |
| **EA** | AST03 | LLM03:2026 | Information Security | *(none)* |
| **LP** | AST03, AST04, AST10 | LLM03:2026 | Information Security | *(none)* |
| **MP** | AST01, AST03 | LLM01:2026 | Information Security | MEASURE 2.7 |
| **OH** | AST01, AST08 | LLM10:2026 | Information Security | *(none)* |
| **P** | AST01, AST04 | LLM01:2026 | Information Security | MEASURE 2.7 |
| **PE** | AST03, AST06 | LLM03:2026 | Information Security | *(none)* |
| **RA** | AST01 | LLM03:2026 | Information Security | *(none)* |
| **RP** | AST02, AST05, AST07, AST09, AST10 | LLM04:2026 | Information Security, Value Chain and Component Integration | GOVERN 6.1, MANAGE 3.1, MAP 4.1, MEASURE 2.7 |
| **SC** | AST02, AST04, AST07 | LLM04:2026 | Information Security, Value Chain and Component Integration | GOVERN 6.1, MANAGE 3.1, MAP 4.1, MEASURE 2.7 |
| **SSRF** | AST05 | LLM10:2026 | Information Security | *(none)* |
| **TM** | AST03, AST04, AST06 | LLM03:2026 | Information Security | *(none)* |
| **TP** | AST04, AST10 | LLM01:2026 | Information Security | MEASURE 2.7 |
| **TR** | AST02 | LLM04:2026 | Information Security, Value Chain and Component Integration | GOVERN 6.1, MANAGE 3.1, MAP 4.1, MEASURE 2.7 |
| **TT** | AST01, AST03, AST08 | LLM02:2026 | Data Privacy, Information Security | MEASURE 2.10, MEASURE 2.7 |
| **YR** | AST01, AST02, AST04, AST08 | LLM04:2026 | Information Security, Value Chain and Component Integration | GOVERN 6.1, MANAGE 3.1, MAP 4.1, MEASURE 2.7 |

## 3. Consolidated Rule Overrides

| Rule ID | OWASP LLM (2026) | NIST AI 600-1 | NIST AI RMF | Rationale & Evidence |
|---|---|---|---|---|
| **AS1** | LLM02:2026, LLM08:2026 | Data Privacy, Information Security | MEASURE 2.10, MEASURE 2.7 | Agent configuration directory access containing instructions destined for context (LLM02 + LLM08). |
| **EA4** | LLM03:2026, LLM06:2026 | Information Security | MEASURE 2.7 | Unbounded loops/retries; meets LLM06 mitigations verbatim alongside excessive agency (LLM03 + LLM06). |
| **MP2** | LLM01:2026, LLM06:2026 | Information Security | MEASURE 2.7 | Context stuffing/token exhaustion abuse in memory (LLM01 + LLM06). |
| **MP3** | LLM01:2026, LLM05:2026 | Information Integrity, Information Security, Value Chain and Component Integration | MEASURE 2.7 | Persistent memory-store manipulation/poisoning in agent deployments (LLM01 + LLM05). |
| **OH3** | LLM06:2026, LLM10:2026 | Information Security | MEASURE 2.7 | Unbounded output size/rate; denial-of-service via resource exhaustion (LLM06 + LLM10). |
| **P6** | LLM08:2026 | Information Security | MEASURE 2.7 | System prompt disclosure/extraction (LLM08 Hidden Context Exposure). |
| **P7** | LLM08:2026 | Information Security | MEASURE 2.7 | Indirect prompt extraction (LLM08 Hidden Context Exposure). |
| **P8** | LLM08:2026 | Information Security | MEASURE 2.7 | Prompt exfiltration via tool calls (LLM08 Hidden Context Exposure). |
| **TT1** | LLM02:2026, LLM10:2026 | Data Privacy, Information Security | MEASURE 2.10, MEASURE 2.7 | Taint tracking with code execution and network exfiltration sinks (LLM02 + LLM10). |
| **TT2** | LLM02:2026, LLM10:2026 | Data Privacy, Information Security | MEASURE 2.10, MEASURE 2.7 | Variable-mediated taint flow reaching exec and network sinks (LLM02 + LLM10). |
| **TT5** | LLM10:2026 | Information Security | *(none)* | External input directly reaching execution sink without exfiltration (LLM10). |
| **YR5** | LLM01:2026 | Information Security | MEASURE 2.7 | YARA prompt-injection signature; the YR family default (LLM04 supply chain) does not apply (LLM01). |

## 4. Static Coverage & Audit Boundaries

| 2026 Category | Static Coverage Status | Rules / Mechanisms | Evidence & Audit Boundaries |
|---|---|---|---|---|
| LLM01 Prompt Injection | Detections present | P1–5, TP1–3, AR1–3, MP1–3, YR5 | Embedded instruction and metadata injection; no runtime adversarial evaluation. |
| LLM02 Sensitive Information Disclosure | Detections present | E1–5, TT1–4, AS1–3 | Environment, secret file, config access and data flow detection. |
| LLM03 Excessive Agency | Detections present | EA1–4, LP1–4, PE1–5, TM1–4, RA1–2 | Over-permissioning, autonomous high-impact actions, container escapes. |
| LLM04 Supply Chain | Detections present | SC1–7, RP1–3, YR1–4, TR1–3 | Unpinned dependencies, malware signatures, trigger-namespace squatting. SC4 excluded in HSBC build. |
| LLM05 Data & Model Poisoning | Partial | MP3 | Persistent memory-store poisoning in agent scope. Pre-training and fine-tuning poisoning are out of static scope. |
| LLM06 Unbounded Consumption | Partial | EA4, OH3, MP2 | Static unbounded resource markers and context stuffing patterns. No runtime latency/cost measurement. |
| LLM07 Misinformation | Not covered | *(none)* | Output factual quality and hallucination are runtime evaluation concerns. |
| LLM08 Hidden Context Exposure | Detections present | P6–8, AS1 | System prompt leakage and agent config disclosure detection. |
| LLM09 Vector & Embedding Weaknesses | Not covered | *(none)* | Requires vector database geometry/embedding analysis; agent memory attacks routed to ASI06. |
| LLM10 Improper Output Handling | Detections present | OH1–3, TT1, TT2, TT5, AST1–9, SSRF1–3 | Model/untrusted output flowing to execution sinks, AST sinks, and SSRF destinations. |

## 5. Ratification Log

- **O1 (Ratified 2026-09-03, Project Lead)**: Trim RMF subcategories strictly to crosswalk-backed entries. MEASURE 2.6 dropped everywhere; MEASURE 2.7 emitted where an LLM category maps to MEASURE 2; LLM03-only and LLM10-only emit empty `nist_rmf: []`.
- **O2 (Ratified 2026-09-02, Project Lead)**: LLM09 excluded from memory findings; agent memory is classified under LLM01/LLM05, avoiding unevidenced vector tags.
- **O3 (Ratified 2026-09-03, Project Lead)**: `TR1`–`TR3` classified under `LLM04:2026` as trigger-namespace slopsquatting / supply chain name confusion.
- **C1 (Ratified 2026-09-03, Project Lead)**: MP3 NIST primary risks use pure composition (`Information Security`, `Information Integrity`, `Value Chain and Component Integration` via LLM05).

## 6. Requirements Traceability

| Requirement | Implementation Deliverable | Status |
|---|---|---|
| OWASP Top 10 Categorization | Scan Kernel `frameworks.go`, Protocol v2, UI mappings | Complete |
| NIST AI Risk Framework Alignment | AI 600-1 and AI RMF 1.0 crosswalked subcategories | Complete |
| Exportable Security Reports | JSON, Markdown (Compliance summary), SARIF 2.1.0 (4 Taxonomies) | Complete |
| Severity-Based Risk Scoring | Scoring engine preserved untouched; orthogonality enforced | Complete |
| Remediation Recommendations | Per-rule remediation + category mitigation guidance | Complete |
