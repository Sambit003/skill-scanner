"""Deterministic MCP tool-poisoning analyzer node (B.3.2)."""

from __future__ import annotations

import base64
import logging
import re
import unicodedata

from scan_kernel.engine.plugins.agent_skills.models import Finding
from scan_kernel.engine.plugins.agent_skills.state import AnalyzerNodeResponse, ScanKernelState

ANALYZER_ID = "mcp_tool_poisoning"
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_FRAMEWORK_TAGS = ["ASI02", "AML.T0080"]
TP3_MAX_PARAM_DESC_LENGTH = 500

_CATEGORY = "MCP Tool Poisoning"

# ---------------------------------------------------------------------------
# TP2: Confusables map — Cyrillic and Greek lookalikes → Latin equivalents
# ---------------------------------------------------------------------------

_CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "p",  # р → p
    "\u0441": "c",  # с → c
    "\u0443": "y",  # у → y
    "\u0456": "i",  # і → i
    # Cyrillic uppercase
    "\u0410": "A",  # А → A
    "\u0412": "B",  # В → B
    "\u0415": "E",  # Е → E
    "\u041a": "K",  # К → K
    "\u041c": "M",  # М → M
    "\u041d": "H",  # Н → H
    "\u041e": "O",  # О → O
    "\u0420": "P",  # Р → P
    "\u0421": "C",  # С → C
    "\u0422": "T",  # Т → T
    "\u0425": "X",  # Х → X
    # Greek lowercase
    "\u03b1": "a",  # α → a
    "\u03b5": "e",  # ε → e
    "\u03bf": "o",  # ο → o
}

# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------


def _extract_metadata_texts(manifest: dict) -> list[tuple[str, str, bool]]:
    """Extract (text, source_field, is_identifier) tuples from a manifest.

    Returns a list of:
      - (skill_name, "name", True)
      - (description, "description", False)
      - (trigger_text, "triggers[i]", True) for each trigger
      - (param_name, "parameters[i].name", True) for each parameter
      - (param_desc, "parameters[i].description", False) for each parameter
    """
    results: list[tuple[str, str, bool]] = []

    name = manifest.get("name")
    if name and isinstance(name, str):
        results.append((name, "name", True))

    description = manifest.get("description")
    if description and isinstance(description, str):
        results.append((description, "description", False))

    triggers = manifest.get("triggers") or []
    for i, trigger in enumerate(triggers):
        if trigger and isinstance(trigger, str):
            results.append((trigger, f"triggers[{i}]", True))

    params = manifest.get("parameters") or []
    for i, param in enumerate(params):
        if not isinstance(param, dict):
            continue
        pname = param.get("name")
        if pname and isinstance(pname, str):
            results.append((pname, f"parameters[{i}].name", True))
        pdesc = param.get("description")
        if pdesc and isinstance(pdesc, str):
            results.append((pdesc, f"parameters[{i}].description", False))

    return results


# ---------------------------------------------------------------------------
# TP1: Hidden instructions
# ---------------------------------------------------------------------------

# Instruction keywords that escalate HTML comment confidence to 0.95
_TP1_INSTRUCTION_KEYWORDS = re.compile(
    r"SYSTEM:|IGNORE\s+PREVIOUS|OVERRIDE|YOU\s+MUST",
    re.IGNORECASE,
)

# HTML comment patterns — handle both <!-- and <\!-- (YAML-escaped variant)
_HTML_COMMENT_RE = re.compile(r"<\\?!--.*?-->", re.DOTALL)

# Markdown comment: [//]: # (...)
_MARKDOWN_COMMENT_RE = re.compile(r"\[//\]:\s*#\s*\(.*?\)")

# Zero-width chars followed by visible text
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d]+\S")

# Base64 blobs (>=50 chars) — checked AFTER data URI to avoid double-counting
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{50,}={0,2}")

# Data URI prefix
_DATA_URI_RE = re.compile(r"data:text/[^;]+;base64,")


def _check_tp1(text: str, source_field: str) -> list[Finding]:
    """Detect hidden instructions in metadata text.

    Checks for: HTML comments, markdown comments, zero-width chars,
    base64 blobs, and data URIs.
    """
    findings: list[Finding] = []

    # Track ranges already covered by data URIs to avoid double-counting base64
    data_uri_ranges: list[tuple[int, int]] = []

    # --- Data URIs (check first) ---
    for m in _DATA_URI_RE.finditer(text):
        data_uri_ranges.append((m.start(), m.end()))
        findings.append(
            Finding(
                rule_id="TP1",
                message=f"Data URI found in '{source_field}': potential hidden payload delivery.",
                severity="HIGH",
                confidence=0.85,
                file="SKILL.md",
                category=_CATEGORY,
                tags=list(_FRAMEWORK_TAGS),
                matched_text=m.group(),
                explanation=(
                    "Data URIs embedded in metadata fields can encode and deliver hidden payloads "
                    "to AI agents processing the manifest."
                ),
                remediation="Remove data URIs from metadata fields. Metadata should contain plain text only.",
            )
        )

    # --- HTML comments ---
    for m in _HTML_COMMENT_RE.finditer(text):
        comment_text = m.group()
        if _TP1_INSTRUCTION_KEYWORDS.search(comment_text):
            confidence = 0.95
        else:
            confidence = 0.90
        findings.append(
            Finding(
                rule_id="TP1",
                message=(f"HTML comment found in '{source_field}': potential hidden instruction."),
                severity="HIGH",
                confidence=confidence,
                file="SKILL.md",
                category=_CATEGORY,
                tags=list(_FRAMEWORK_TAGS),
                matched_text=comment_text,
                explanation=(
                    "HTML comments in tool metadata are invisible to users but may be processed "
                    "by AI agents, enabling hidden instruction injection."
                ),
                remediation=(
                    "Remove HTML comments from metadata fields. "
                    "Metadata should contain plain, visible text only."
                ),
            )
        )

    # --- Markdown comments ---
    for m in _MARKDOWN_COMMENT_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="TP1",
                message=(
                    f"Markdown comment found in '{source_field}': potential hidden instruction."
                ),
                severity="HIGH",
                confidence=0.90,
                file="SKILL.md",
                category=_CATEGORY,
                tags=list(_FRAMEWORK_TAGS),
                matched_text=m.group(),
                explanation=(
                    "Markdown-style comments in metadata fields may hide instructions from users "
                    "while still being processed by AI systems."
                ),
                remediation="Remove markdown comments from metadata fields.",
            )
        )

    # --- Zero-width chars ---
    for m in _ZERO_WIDTH_RE.finditer(text):
        findings.append(
            Finding(
                rule_id="TP1",
                message=(
                    f"Zero-width character(s) followed by visible text found in '{source_field}': "
                    "potential steganographic instruction."
                ),
                severity="HIGH",
                confidence=0.85,
                file="SKILL.md",
                category=_CATEGORY,
                tags=list(_FRAMEWORK_TAGS),
                matched_text=m.group(),
                explanation=(
                    "Zero-width Unicode characters are invisible to humans but detectable by AI. "
                    "When followed by visible text, they indicate hidden content injection."
                ),
                remediation=(
                    "Strip zero-width Unicode characters (U+200B, U+200C, U+200D) "
                    "from all metadata fields."
                ),
            )
        )

    # --- Base64 blobs (skip ranges covered by data URIs) ---
    for m in _BASE64_RE.finditer(text):
        # Check if this match overlaps with a data URI range
        overlaps = any(
            m.start() >= uri_start and m.end() <= uri_end + 200
            for uri_start, uri_end in data_uri_ranges
        )
        if overlaps:
            continue

        # Validate: must decode to valid UTF-8
        raw = m.group()
        # Pad if needed
        padding_needed = (4 - len(raw) % 4) % 4
        padded = raw + "=" * padding_needed
        try:
            decoded = base64.b64decode(padded)
            decoded.decode("utf-8")
        except Exception:
            continue  # not valid base64/UTF-8 — skip

        findings.append(
            Finding(
                rule_id="TP1",
                message=(
                    f"Base64-encoded blob found in '{source_field}': "
                    "potential hidden encoded instruction."
                ),
                severity="HIGH",
                confidence=0.75,
                file="SKILL.md",
                category=_CATEGORY,
                tags=list(_FRAMEWORK_TAGS),
                matched_text=raw[:80] + ("..." if len(raw) > 80 else ""),
                explanation=(
                    "Long base64-encoded strings in metadata fields may encode hidden instructions "
                    "intended to be decoded and executed by AI agents."
                ),
                remediation=(
                    "Remove base64-encoded blobs from metadata fields. "
                    "Metadata should contain only human-readable plain text."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# TP2: Unicode deception
# ---------------------------------------------------------------------------

# RTL and directional override characters
_RTL_CHARS = frozenset({"\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069"})
# Invisible formatting characters (for identifiers)
_INVISIBLE_CHARS = frozenset({"\u00ad", "\u034f", "\u2060"})


def _get_script_prefix(char: str) -> str:
    """Get the Unicode script prefix from a character's name.

    Uses unicodedata.name() to get script information.
    Returns a short script label (e.g. 'LATIN', 'CYRILLIC', 'GREEK').
    """
    try:
        name = unicodedata.name(char, "")
    except Exception:
        return "UNKNOWN"

    # Common script prefixes
    for script in (
        "LATIN",
        "CYRILLIC",
        "GREEK",
        "ARABIC",
        "HEBREW",
        "CJK",
        "HIRAGANA",
        "KATAKANA",
        "HANGUL",
        "THAI",
        "DEVANAGARI",
    ):
        if name.startswith(script):
            return script
    return "OTHER"


def _check_tp2(text: str, source_field: str, is_identifier: bool) -> list[Finding]:
    """Detect Unicode-based deception in metadata text."""
    findings: list[Finding] = []
    homoglyph_found = False

    # --- Homoglyphs (identifiers only) ---
    if is_identifier:
        found_confusables: list[tuple[str, str]] = []
        for char in text:
            if char in _CONFUSABLES:
                found_confusables.append((char, _CONFUSABLES[char]))

        if found_confusables:
            homoglyph_found = True
            examples = ", ".join(
                f"U+{ord(c):04X} (looks like '{latin}')" for c, latin in found_confusables[:3]
            )
            findings.append(
                Finding(
                    rule_id="TP2",
                    message=(
                        f"Homoglyph characters detected in identifier '{source_field}': {examples}. "
                        "Visual spoofing of identifier name."
                    ),
                    severity="HIGH",
                    confidence=0.90,
                    file="SKILL.md",
                    category=_CATEGORY,
                    tags=list(_FRAMEWORK_TAGS),
                    matched_text=text,
                    explanation=(
                        "Confusable Unicode characters (e.g., Cyrillic or Greek lookalikes of Latin letters) "
                        "can make a malicious tool name appear identical to a trusted one."
                    ),
                    remediation=(
                        "Replace all non-ASCII characters in identifier fields with their ASCII equivalents. "
                        "Use a Unicode normalization/confusables check in CI."
                    ),
                )
            )

    # --- RTL override (anywhere) ---
    rtl_found = [ch for ch in text if ch in _RTL_CHARS]
    if rtl_found:
        examples = ", ".join(f"U+{ord(c):04X}" for c in rtl_found[:3])
        findings.append(
            Finding(
                rule_id="TP2",
                message=(
                    f"RTL/directional override character(s) found in '{source_field}': {examples}. "
                    "Text direction manipulation detected."
                ),
                severity="HIGH",
                confidence=0.95,
                file="SKILL.md",
                category=_CATEGORY,
                tags=list(_FRAMEWORK_TAGS),
                matched_text=text[:100],
                explanation=(
                    "RTL override characters (U+202E, U+202D, U+2066-U+2069) can reverse text "
                    "rendering to make malicious content appear benign."
                ),
                remediation=(
                    "Remove all directional override Unicode characters from metadata fields."
                ),
            )
        )

    # --- Invisible formatting (identifiers only) ---
    if is_identifier:
        invisible_found = [ch for ch in text if ch in _INVISIBLE_CHARS]
        if invisible_found:
            examples = ", ".join(f"U+{ord(c):04X}" for c in invisible_found[:3])
            findings.append(
                Finding(
                    rule_id="TP2",
                    message=(
                        f"Invisible formatting character(s) found in identifier '{source_field}': {examples}."
                    ),
                    severity="HIGH",
                    confidence=0.80,
                    file="SKILL.md",
                    category=_CATEGORY,
                    tags=list(_FRAMEWORK_TAGS),
                    matched_text=text,
                    explanation=(
                        "Invisible Unicode formatting characters (soft hyphen U+00AD, CGJ U+034F, "
                        "word joiner U+2060) inserted into identifiers create visually identical "
                        "but technically different names."
                    ),
                    remediation=(
                        "Strip invisible formatting characters (U+00AD, U+034F, U+2060) "
                        "from all identifier fields."
                    ),
                )
            )

    # --- Mixed-script (identifiers only; only if homoglyphs NOT already found) ---
    if is_identifier and not homoglyph_found:
        scripts: set[str] = set()
        for char in text:
            if ord(char) < 128:
                # ASCII — treat as LATIN
                if char.isalpha():
                    scripts.add("LATIN")
            elif char.isalpha():
                script = _get_script_prefix(char)
                if script not in ("OTHER", "UNKNOWN"):
                    scripts.add(script)

        # Fire if multiple scripts found (e.g., LATIN + GREEK)
        if len(scripts) > 1:
            script_list = ", ".join(sorted(scripts))
            findings.append(
                Finding(
                    rule_id="TP2",
                    message=(
                        f"Mixed script detected in identifier '{source_field}': {script_list}. "
                        "Multiple Unicode scripts in a single identifier name."
                    ),
                    severity="HIGH",
                    confidence=0.85,
                    file="SKILL.md",
                    category=_CATEGORY,
                    tags=list(_FRAMEWORK_TAGS),
                    matched_text=text,
                    explanation=(
                        "Mixing characters from multiple Unicode scripts in a single identifier "
                        "is a common technique to create visually ambiguous tool names."
                    ),
                    remediation=(
                        "Restrict identifier fields to a single Unicode script. "
                        "Prefer ASCII-only identifiers."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# TP3: Parameter description injection
# ---------------------------------------------------------------------------

# Instruction override patterns
_TP3_INSTRUCTION_OVERRIDE_RE = re.compile(
    r"ignore\s+previous|override\s+safety|you\s+are\s+now|disregard\s+(?:all|any)\s+instructions",
    re.IGNORECASE,
)

# System prompt tokens
_TP3_SYSTEM_TOKEN_RE = re.compile(
    r"SYSTEM:|<system>|\[INST\]|<\|im_start\|>system",
    re.IGNORECASE,
)

# Exfiltration patterns
_TP3_EXFILTRATION_RE = re.compile(
    r"send\s+to|transmit|upload\s+conversation|exfiltrate",
    re.IGNORECASE,
)

# Malicious default: URLs (excluding localhost/127.0.0.1) or shell commands.
# The loopback exemption is anchored to a host boundary (port / path / query /
# fragment / end of string). Without the boundary, the negative lookahead
# matched the bare substring "localhost", so an attacker host that merely
# starts with it (e.g. http://localhost.evil.com/exfil) was wrongly treated as
# loopback and skipped detection.
_TP3_MALICIOUS_URL_RE = re.compile(
    r"https?://(?!(?:localhost|127\.0\.0\.1)(?:[:/?#]|$))\S+",
    re.IGNORECASE,
)
_TP3_SHELL_CMD_RE = re.compile(
    r"\bcurl\b|\bwget\b|bash\s+-c|sh\s+-c|\beval\b",
    re.IGNORECASE,
)


def _check_tp3(params: list[dict]) -> list[Finding]:
    """Detect injection patterns in parameter definitions."""
    findings: list[Finding] = []

    for i, param in enumerate(params):
        if not isinstance(param, dict):
            continue

        param_name = param.get("name", f"param[{i}]")
        description = param.get("description", "")
        default_val = param.get("default")

        if description and isinstance(description, str):
            # Instruction override
            m = _TP3_INSTRUCTION_OVERRIDE_RE.search(description)
            if m:
                findings.append(
                    Finding(
                        rule_id="TP3",
                        message=(
                            f"Instruction override phrase in parameter '{param_name}' description: "
                            f"'{m.group()}'."
                        ),
                        severity="MEDIUM",
                        confidence=0.85,
                        file="SKILL.md",
                        category=_CATEGORY,
                        tags=list(_FRAMEWORK_TAGS),
                        matched_text=m.group(),
                        explanation=(
                            "Instruction-override phrases in parameter descriptions can hijack "
                            "AI agent behavior when the tool description is processed as a prompt."
                        ),
                        remediation=(
                            "Remove instruction-override language from parameter descriptions. "
                            "Descriptions should explain the parameter's purpose only."
                        ),
                    )
                )

            # System tokens
            m2 = _TP3_SYSTEM_TOKEN_RE.search(description)
            if m2:
                findings.append(
                    Finding(
                        rule_id="TP3",
                        message=(
                            f"System prompt token in parameter '{param_name}' description: "
                            f"'{m2.group()}'."
                        ),
                        severity="MEDIUM",
                        confidence=0.90,
                        file="SKILL.md",
                        category=_CATEGORY,
                        tags=list(_FRAMEWORK_TAGS),
                        matched_text=m2.group(),
                        explanation=(
                            "System prompt tokens injected into parameter descriptions may alter "
                            "the AI agent's system context when the tool schema is processed."
                        ),
                        remediation=(
                            "Remove system prompt tokens (SYSTEM:, <system>, [INST], etc.) "
                            "from parameter descriptions."
                        ),
                    )
                )

            # Exfiltration
            m3 = _TP3_EXFILTRATION_RE.search(description)
            if m3:
                findings.append(
                    Finding(
                        rule_id="TP3",
                        message=(
                            f"Potential exfiltration instruction in parameter '{param_name}' description: "
                            f"'{m3.group()}'."
                        ),
                        severity="MEDIUM",
                        confidence=0.85,
                        file="SKILL.md",
                        category=_CATEGORY,
                        tags=list(_FRAMEWORK_TAGS),
                        matched_text=m3.group(),
                        explanation=(
                            "Exfiltration-related phrases in parameter descriptions may instruct "
                            "AI agents to leak conversation data or sensitive information."
                        ),
                        remediation=(
                            "Remove data transmission instructions from parameter descriptions."
                        ),
                    )
                )

            # Excessive description length
            if len(description) > TP3_MAX_PARAM_DESC_LENGTH:
                findings.append(
                    Finding(
                        rule_id="TP3",
                        message=(
                            f"Excessive parameter description length for '{param_name}': "
                            f"{len(description)} chars (limit: {TP3_MAX_PARAM_DESC_LENGTH})."
                        ),
                        severity="MEDIUM",
                        confidence=0.65,
                        file="SKILL.md",
                        category=_CATEGORY,
                        tags=list(_FRAMEWORK_TAGS),
                        explanation=(
                            "Unusually long parameter descriptions may contain hidden instructions "
                            "padded with benign content to evade simple keyword detection."
                        ),
                        remediation=(
                            f"Keep parameter descriptions under {TP3_MAX_PARAM_DESC_LENGTH} characters. "
                            "Move extended documentation to separate files."
                        ),
                    )
                )

        # Malicious default values
        if default_val is not None:
            default_str = str(default_val)
            malicious_url = _TP3_MALICIOUS_URL_RE.search(default_str)
            shell_cmd = _TP3_SHELL_CMD_RE.search(default_str)
            if malicious_url or shell_cmd:
                matched = (malicious_url or shell_cmd).group()  # type: ignore[union-attr]
                findings.append(
                    Finding(
                        rule_id="TP3",
                        message=(
                            f"Suspicious default value for parameter '{param_name}': "
                            f"contains '{matched}'."
                        ),
                        severity="MEDIUM",
                        confidence=0.75,
                        file="SKILL.md",
                        category=_CATEGORY,
                        tags=list(_FRAMEWORK_TAGS),
                        matched_text=matched,
                        explanation=(
                            "Default parameter values containing URLs or shell commands may "
                            "trigger unintended network requests or command execution when used "
                            "by an AI agent without explicit user input."
                        ),
                        remediation=(
                            "Remove URLs and shell commands from parameter default values. "
                            "Default values should be safe, static, representative examples."
                        ),
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# TP4 placeholder
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Main node
# ---------------------------------------------------------------------------


def node(state: ScanKernelState) -> AnalyzerNodeResponse:
    """Analyze MCP tool manifest for deterministic tool-poisoning indicators."""
    manifest: dict = state.get("manifest") or {}

    if not manifest:
        logger.info("%s: no manifest, skipping", ANALYZER_ID)
        return {"findings": []}

    findings: list[Finding] = []

    # Extract all metadata texts with (text, source_field, is_identifier) tuples
    metadata_texts = _extract_metadata_texts(manifest)

    # TP1: Hidden instructions — check all metadata fields
    for text, source_field, _is_identifier in metadata_texts:
        findings.extend(_check_tp1(text, source_field))

    # TP2: Unicode deception — check all metadata fields
    for text, source_field, is_identifier in metadata_texts:
        findings.extend(_check_tp2(text, source_field, is_identifier))

    # TP3: Parameter description injection — check parameters
    params = manifest.get("parameters") or []
    if isinstance(params, list):
        findings.extend(_check_tp3(params))

    logger.info("%s: %d findings", ANALYZER_ID, len(findings))
    return {"findings": findings}
