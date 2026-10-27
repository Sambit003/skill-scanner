package agentskill

func yaraRuleText(id string) (string, string) {
	switch id {
	case "YR1":
		return "YARA rule matched a known malware signature (reverse shell, backdoor, ransomware, C2 framework, or info stealer).", "Remove the malware payload or compromised file entirely. Investigate how it entered the skill and audit all other artifacts for additional indicators of compromise."
	case "YR2":
		return "YARA rule matched a known webshell pattern (PHP, Python, JSP, or ASPX webshell).", "Remove the webshell code immediately. Webshells provide unauthorized remote command execution. Audit the skill for additional backdoors or persistence mechanisms."
	case "YR3":
		return "YARA rule matched cryptocurrency mining indicators (stratum protocol, mining pools, miner binaries, or cryptojacking scripts).", "Remove all cryptocurrency mining code, pool references, and miner binaries. Mining in agent skills is unauthorized resource abuse. Report the skill as malicious."
	case "YR5":
		return "YARA rule matched prompt-injection or hidden-instruction text aimed at the agent (instruction overrides, safety bypass, prompt disclosure, or role-play jailbreaks).", "Remove the injected instructions and any hidden comments that carry them. Skill text should describe its task plainly and never ask the agent to ignore, override, or reveal its instructions."
	default:
		return "YARA rule matched a hack tool or exploit indicator (offensive tools, reconnaissance, privilege escalation, or exploit frameworks).", "Remove offensive tool references and exploit code. Legitimate agent skills should not contain penetration testing tools, exploit frameworks, or reconnaissance utilities."
	}
}
