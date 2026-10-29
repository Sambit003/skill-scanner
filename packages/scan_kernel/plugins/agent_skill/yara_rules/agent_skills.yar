/*
    AI agent skill prompt-injection rule for source and manifest scanning.

    The bundled malware, webshell, cryptominer and hack-tool signatures
    (YR1-YR4) were retired: they matched words, not behaviour, and fired on
    security documentation. Customer rule files passed with --yara-rules
    still report under YR1-YR4 by their category.
*/

rule agent_skill_prompt_injection_hidden_instructions
{
    meta:
        description = "Prompt injection or hidden instructions embedded in AI agent skill text"
        category = "prompt_injection"
        severity = "HIGH"
        confidence = "0.80"
        reference = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
    strings:
        $hidden_html_override = /<!--[^>]{0,240}(SYSTEM|DEVELOPER|ASSISTANT)[^>]{0,240}(ignore|override|bypass|disregard)[^>]{0,240}-->/ nocase
        $hidden_markdown_override = /\[\/\/\]:\s*#\s*\([^)]{0,240}(ignore|override|bypass|disregard)[^)]{0,240}\)/ nocase

        $agent_context = /(AI agent|assistant|LLM|model|system prompt|developer message|tool description)/ nocase
        $inj_ignore_previous = /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|messages|system prompt)/ nocase
        $inj_override_safety = /(override|bypass|disable)\s+(safety|security|policy|guardrails|constraints)/ nocase
        $inj_reveal_prompt = /(reveal|print|dump|expose|show)\s+(the\s+)?(system|developer)\s+(prompt|message|instructions)/ nocase
        $inj_forced_obedience = /(you\s+must|always)\s+(obey|follow)\s+(this|these)\s+(hidden|secret|internal)?\s*(instruction|rule)/ nocase
        $inj_roleplay_bypass = /(you\s+are\s+now|act\s+as)\s+.*(unrestricted|jailbreak|developer\s+mode|god\s+mode)/ nocase
    condition:
        any of ($hidden_*) or ($agent_context and any of ($inj_*)) or 2 of ($inj_*)
}
