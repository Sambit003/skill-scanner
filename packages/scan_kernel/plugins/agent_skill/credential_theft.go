package agentskill

// Credential theft: a skill that reads a credential or env file and sends its
// contents off the machine (credential-exfiltration), or asks the user for a
// password in a fake prompt and sends the answer away
// (credential-theft-flow). A key sent to its own API is not theft and stays
// untagged.

import (
	"regexp"
	"strings"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

const (
	// behaviourCredentialExfiltration: a credential file, the environment or
	// a credential store sent off the machine.
	behaviourCredentialExfiltration = "credential-exfiltration"
	// behaviourCredentialTheftFlow: a password asked for in a prompt and
	// sent off the machine.
	behaviourCredentialTheftFlow = "credential-theft-flow"
)

var (
	// literalURL is a URL in code or a command.
	literalURL = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"` + "`" + `<>()\[\]{}|;]+`)
	// shellCredentialSend sends a file with curl or wget: -d @file,
	// -F x=@file, -T file, --post-file file, or a data argument built from
	// $(cat file) or $(base64 < file).
	shellCredentialSend = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n]*?(?:\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form)[\s=]*["']?(?:[^\s"'@$]*=)?(?:@|[^\n]*?\$\(\s*(?:cat|base64|gzip\s+-c|tar\s+[^\n)]*)\s*<?\s*)|\s(?:-T|--upload-file|--post-file)[\s=]+["']?)([^\s"')]+)`)
)

// untrustedReceiver reports a destination that collects what is sent to it:
// a collection or paste host, a raw IP address, or plain http.
func untrustedReceiver(text string) bool {
	if collectionHost.MatchString(text) {
		return true
	}
	for _, url := range literalURL.FindAllString(text, -1) {
		if !loopbackOrigin(url) && untrustedOrigin(url) {
			return true
		}
	}
	return false
}

// remoteDestination reports a URL in text that is not on this machine.
func remoteDestination(text string) bool {
	for _, url := range literalURL.FindAllString(text, -1) {
		if !loopbackOrigin(url) {
			return true
		}
	}
	return false
}

// shellSendsCredentialFile reports a curl or wget command in text that sends
// a credential file to a remote host.
func shellSendsCredentialFile(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		for _, match := range shellCredentialSend.FindAllStringSubmatch(line, -1) {
			path := strings.Trim(match[1], `"'`)
			if (isCredentialFilePath(path) || highValueCredential.MatchString(path)) && remoteDestination(line) {
				return true
			}
		}
	}
	return false
}

// tagCredentialExfiltration tags TT3 and TT4 findings in code that send a
// credential file, the whole environment or a credential store to a
// collection host, a paste site, a raw IP or plain http, or a credential
// file's content anywhere off the machine.
func tagCredentialExfiltration(item component, findings []model.Finding) []model.Finding {
	if !isScriptFile(item) {
		return findings
	}
	for index, finding := range findings {
		if finding.ID != "TT3" && finding.ID != "TT4" {
			continue
		}
		end := finding.Location.StartLine
		if finding.Location.EndLine != nil {
			end = *finding.Location.EndLine
		}
		call := sourceLines(item.Content, finding.Location.StartLine, end)
		switch {
		case finding.ID == "TT3" && (strings.HasPrefix(finding.Pattern, "Credential file content") ||
			strings.HasPrefix(finding.Pattern, "The request sends the content of a credential file") ||
			strings.HasPrefix(finding.Pattern, "The file reads a credential file or the whole environment")):
		case finding.ID == "TT3" && strings.HasPrefix(finding.Pattern, "The request sends the whole environment") && remoteDestination(call):
		case untrustedReceiver(call) && credentialStoreNamed(item.Content):
		default:
			continue
		}
		findings[index] = markBehaviour(finding, behaviourCredentialExfiltration)
	}
	return findings
}

// credentialStoreNamed reports code that names a credential file or store in
// a string literal: a .env file, ~/.ssh, ~/.aws, a keychain, browser login
// data, a wallet.
func credentialStoreNamed(content string) bool {
	for _, match := range scriptStringLiteral.FindAllStringSubmatch(content, -1) {
		literal := match[1] + match[2] + match[3]
		if isCredentialFilePath(literal) || highValueCredential.MatchString(literal) || strings.Contains(strings.ToLower(literal), ".wallet") {
			return true
		}
	}
	return false
}

var (
	// scriptCredentialRead is a JavaScript variable assigned the content of
	// a file: const env = fs.readFileSync(path, "utf8").
	scriptCredentialRead = regexp.MustCompile(`(?m)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:[\w$.]+\.)?(?:readFileSync|readFile|readTextFile)\s*\(([^\n]*)`)
)

// scriptCredentialFileVariables returns the JavaScript variables that hold the
// content of a credential file.
func scriptCredentialFileVariables(content string) map[string]bool {
	variables := map[string]bool{}
	for _, match := range scriptCredentialRead.FindAllStringSubmatch(content, -1) {
		for _, literal := range scriptStringLiteral.FindAllStringSubmatch(match[2], -1) {
			if path := literal[1] + literal[2] + literal[3]; isCredentialFilePath(path) || highValueCredential.MatchString(path) {
				variables[match[1]] = true
			}
		}
	}
	return variables
}

var (
	// hiddenPasswordDialog is a macOS dialog that asks for a hidden answer,
	// assigned to a shell variable.
	hiddenPasswordDialog = regexp.MustCompile(`(?i)\b([A-Za-z_]\w*)=\$\(\s*osascript\b[^\n]*\bdisplay\s+dialog\b[^\n]*\bhidden\s+answer\b`)
	// shellSecretRead is read -s (silent) into a variable.
	shellSecretRead = regexp.MustCompile(`\bread\s+(?:-[a-zA-Z]+\s+(?:"[^"\n]*"\s+|'[^'\n]*'\s+)?)*?-[a-zA-Z]*s[a-zA-Z]*\s+(?:-[a-zA-Z]+\s+(?:"[^"\n]*"\s+|'[^'\n]*'\s+)?)*([A-Za-z_]\w*)\s*$`)
	// pythonSecretRead is getpass() into a variable.
	pythonSecretRead = regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:getpass\.)?getpass\s*\(([^\n]*)`)
	// powershellSecretRead is Read-Host -AsSecureString or Get-Credential.
	powershellSecretRead = regexp.MustCompile(`(?im)^\s*\$([A-Za-z_]\w*)\s*=\s*(?:Read-Host\b[^\n]*-AsSecureString|Get-Credential\b)([^\n]*)`)
	// passwordWord names a password rather than an API token.
	passwordWord    = regexp.MustCompile(`(?i)pass(?:word|phrase|wd)?\b|\bpw\b|\blogin\b|\bsudo\b|\badmin(?:istrator)?\b|\bkeychain\b|system\s+(?:settings|preferences)`)
	networkSendLine = regexp.MustCompile(`(?i)\b(?:curl|wget|nc|ncat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|\b(?:requests|httpx|urllib\.request|urllib3|session)\.\w+\s*\(|\burlopen\s*\(|\bfetch\s*\(|\baxios\b`)
)

// promptedSecrets returns each variable that holds a password the user typed
// into a prompt, mapped to whether the prompt imitates a system dialog.
func promptedSecrets(item component) map[string]bool {
	secrets := map[string]bool{}
	for _, match := range hiddenPasswordDialog.FindAllStringSubmatch(item.Content, -1) {
		secrets[match[1]] = true
	}
	for _, line := range strings.Split(item.Content, "\n") {
		if match := shellSecretRead.FindStringSubmatch(strings.TrimSpace(line)); match != nil && passwordWord.MatchString(line) {
			if _, seen := secrets[match[1]]; !seen {
				secrets[match[1]] = false
			}
		}
	}
	for _, pattern := range []*regexp.Regexp{pythonSecretRead, powershellSecretRead} {
		for _, match := range pattern.FindAllStringSubmatch(item.Content, -1) {
			if _, seen := secrets[match[1]]; !seen && passwordWord.MatchString(match[0]) {
				secrets[match[1]] = false
			}
		}
	}
	return secrets
}

// analyzePasswordPrompt reports (TT3) a password typed into a prompt and
// then sent in a network request from the same file. It is tagged
// credential-theft-flow when the prompt imitates a system dialog (a hidden
// osascript answer) or the request goes to a collection host, a paste site,
// a raw IP or plain http; a login to the service's own https API is not.
func analyzePasswordPrompt(item component) []model.Finding {
	if !isScriptFile(item) && item.Type != "powershell" && item.Type != "batch" {
		return nil
	}
	secrets := promptedSecrets(item)
	if len(secrets) == 0 {
		return nil
	}
	var findings []model.Finding
	offset := 0
	for index, line := range strings.Split(item.Content, "\n") {
		start := offset
		offset += len(line) + 1
		if !networkSendLine.MatchString(line) || scriptCommentLine(item, start) {
			continue
		}
		for name, systemDialog := range secrets {
			if !regexp.MustCompile(`(?:\$\{?|\b)` + regexp.QuoteMeta(name) + `\b`).MatchString(line) {
				continue
			}
			if literalURL.MatchString(line) && !remoteDestination(line) {
				continue
			}
			explanation, remediation := ruleText("TT3")
			explanation += " A password typed into a prompt is sent in a network request."
			matched := truncateRunes(strings.TrimSpace(line), 200)
			finding := model.Finding{ID: "TT3", Category: "Data Exfiltration", Pattern: "Password Prompt Sent Off the Machine", Severity: "CRITICAL",
				Confidence: .9, Location: model.Location{File: item.Path, StartLine: index + 1}, Finding: matched, MatchedText: matched,
				Explanation: explanation, Remediation: remediation, CodeSnippet: contextAtOffset(item.Content, start, 3), Tags: []string{"Data Exfiltration"}}
			if systemDialog || untrustedReceiver(line) {
				finding = markBehaviour(finding, behaviourCredentialTheftFlow)
			}
			findings = append(findings, finding)
			break
		}
	}
	return findings
}

// analyzeShellCredentialSend reports (TT3) a curl or wget command in a script,
// or in a SKILL.md code span or block, that sends a credential file to a
// remote host, tagged credential-exfiltration where it would run.
func analyzeShellCredentialSend(item component) []model.Finding {
	if !isScriptFile(item) && !isSkillManifestPath(item.Path) {
		return nil
	}
	var findings []model.Finding
	offset := 0
	for index, line := range strings.Split(item.Content, "\n") {
		start := offset
		offset += len(line) + 1
		if !shellSendsCredentialFile(line) || scriptCommentLine(item, start) {
			continue
		}
		explanation, remediation := ruleText("TT3")
		explanation += " A command sends the content of a credential file to a remote host."
		matched := truncateRunes(strings.TrimSpace(line), 200)
		context := contextAtOffset(item.Content, start, 3)
		finding := model.Finding{ID: "TT3", Category: "Data Exfiltration", Pattern: "Credential File Sent", Severity: "CRITICAL",
			Confidence: .9, Location: model.Location{File: item.Path, StartLine: index + 1}, Finding: matched, MatchedText: matched,
			Explanation: explanation, Remediation: remediation, CodeSnippet: context, Tags: []string{"Data Exfiltration"}}
		lead := start + len(line) - len(strings.TrimLeft(line, " \t"))
		if reason := proseReviewReason(item, "TT3", lead); reason != "" {
			finding = markForReview(finding, reason)
		}
		if runsUnreviewed(item, start) || (isSkillManifestPath(item.Path) && !isTableRow(line) &&
			(insideFencedCodeBlock(item, lead) || strings.Contains(line, "`")) && !isCodeExample(context)) {
			finding = markBehaviour(finding, behaviourCredentialExfiltration)
		}
		findings = append(findings, finding)
	}
	return findings
}
