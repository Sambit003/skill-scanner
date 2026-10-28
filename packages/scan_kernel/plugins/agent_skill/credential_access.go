package agentskill

// PE3 (credential file access) needs an access action: the content reads,
// copies or sends the credential file. A bare file name in an extension
// list, a .gitignore template, help text or a check that .env is not
// committed is not access.

import (
	"regexp"
	"strings"
)

var (
	// codeCredentialAccess reads, copies or sends a file in program source;
	// on the path's line it may come before or after the path.
	codeCredentialAccess = regexp.MustCompile(`\bopen\s*\(|\.read(?:_text|_bytes|lines)?\s*\(|\bread(?:File|FileSync)\s*\(|\bcreateReadStream\b|\bshutil\.(?:copy\w*|move)\b|\bcopyFile(?:Sync)?\b|\bload_dotenv\b|\bdotenv\.config\b|\bupload\w*\s*\(|\bfiles\s*=|\b(?:cat|less|more|head|tail|xxd|strings|base64|cp|scp|rsync|tar|zip|curl|wget|nc|ncat|socat|sqlite3)\b`)
	// commandCredentialAccess is a command or instruction that reads,
	// copies or sends the file named after it ("cat ~/.ssh/id_rsa",
	// "base64 < ~/.aws/credentials", "Read ~/.aws/credentials and paste it").
	commandCredentialAccess = regexp.MustCompile(`(?i)\b(?:cat|less|more|head|tail|type|Get-Content|gc|xxd|strings|base64|grep|awk|sed|jq|cp|copy|Copy-Item|mv|scp|rsync|tar|zip|7z|curl|wget|nc|ncat|socat|sqlite3|open|read|reads|reading|dump|print|show|send|upload|post|paste|attach|include|exfiltrate|steal|collect|grab|harvest|load)\b|<\s*["']?$|@["']?$`)
	// literalCredentialInstruction ends a string literal's text before the
	// path with an instruction to the agent: "Before using this tool, read ",
	// "... and send the contents of ". The verb starts the literal or a
	// clause, so "Failed to read " is not one.
	literalCredentialInstruction = regexp.MustCompile(`(?i)(?:^\s*|[.!?;:,]\s+|\b(?:and|then)\s+)(?:please\s+|first\s+|also\s+|always\s+|you\s+(?:must|should|need\s+to)\s+)?(?:read|send|paste|include|upload|post|attach|copy|cat|print|output|dump|share|forward|exfiltrate|open|load|collect|grab)\b[^.!?;]*$`)
	assignedVariable             = regexp.MustCompile(`^\s*(?:(?:const|let|var|export)\s+)?([A-Za-z_$][\w$]*)\s*[:=][^=]`)
	// highValueCredential names files whose access stays HIGH: SSH keys,
	// cloud credentials, ~/.netrc, ~/.npmrc, ~/.pypirc, keychains and the
	// like. A project-relative .env or secrets file is MEDIUM.
	highValueCredential = regexp.MustCompile(`(?i)\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|authorized_keys|\.aws\b|\.config/gcloud|application_default_credentials|\.azure\b|accessTokens\.json|\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.git-credentials|\.netrc|/etc/shadow|Keychains|\.keychain|keyrings|\bsecurity\s+(?:find-|dump-)|Login Data|Cookies|key4\.db|^(?:~|\$\{?HOME\}?)/\.env`)
)

// credentialAccessed reports an access action on the PE3 match: in program
// source anywhere on the path's line, on a later line that uses a variable
// the path's line assigned, or as an instruction in the string literal that
// holds the path (a tool description an agent reads); in prose and shell,
// before the path on its line. A keychain command such as security find-generic-password is
// itself the access.
func credentialAccessed(item component, match []int) bool {
	matched := item.Content[match[0]:match[1]]
	if strings.HasPrefix(strings.ToLower(matched), "security") {
		return true
	}
	lineStart := strings.LastIndexByte(item.Content[:match[0]], '\n') + 1
	lineEnd := len(item.Content)
	if index := strings.IndexByte(item.Content[match[1]:], '\n'); index >= 0 {
		lineEnd = match[1] + index
	}
	before, after := item.Content[lineStart:match[0]], item.Content[match[1]:lineEnd]
	// Some PE3 expressions include the command ("cat .env"), so the match
	// itself counts as text before the path.
	if !isSourceCodeType(item.Type) || item.Type == "shell" {
		return commandCredentialAccess.MatchString(before + matched)
	}
	// In program source only code reads count: print(".env file found")
	// mentions the file.
	if codeCredentialAccess.MatchString(before+matched) || codeCredentialAccess.MatchString(after) {
		return true
	}
	literalStart, openers, inLiteral := enclosingLiteral(item.Content, match[0], item.Type)
	if inLiteral && literalCredentialInstruction.MatchString(strings.TrimLeft(item.Content[literalStart:match[0]], "\"'`")) {
		return true
	}
	// path = os.path.expanduser("~/.aws/credentials") ... open(path), or
	// targets = [home + "/.ssh/id_rsa", ...] ... for t in targets: copy(t).
	var names []string
	if variable := assignedVariable.FindStringSubmatch(item.Content[lineStart:lineEnd]); variable != nil {
		names = append(names, variable[1])
	}
	if inLiteral {
		for _, opener := range openers {
			if head := detectionAssignment.FindStringSubmatch(openerHead(item.Content, opener)); head != nil {
				names = append(names, head[1])
			}
		}
	}
	return usedForAccess(item.Content[lineEnd:], names, 30)
}

// usedForAccess reports one of names, or a loop variable over one of them,
// used with a code access action within the next lines.
func usedForAccess(rest string, names []string, lines int) bool {
	if len(names) == 0 {
		return false
	}
	pattern := func(names []string) *regexp.Regexp {
		quoted := make([]string, len(names))
		for index, name := range names {
			quoted[index] = regexp.QuoteMeta(name)
		}
		return regexp.MustCompile(`\b(?:` + strings.Join(quoted, "|") + `)\b`)
	}
	uses := pattern(names)
	loop := regexp.MustCompile(`\bfor\s+\(?\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s+(?:in|of)\s+`)
	for count := 0; count < lines && rest != ""; count++ {
		rest = strings.TrimPrefix(rest, "\n")
		line, remaining, _ := strings.Cut(rest, "\n")
		if uses.MatchString(line) {
			if codeCredentialAccess.MatchString(line) {
				return true
			}
			if loopVariable := loop.FindStringSubmatch(line); loopVariable != nil {
				names = append(names, loopVariable[1])
				uses = pattern(names)
			}
		}
		rest = remaining
	}
	return false
}

// credentialSeverity is HIGH for SSH keys, cloud credentials, ~/.netrc,
// ~/.npmrc, ~/.pypirc, keychains and similar, MEDIUM for project files such
// as .env or secrets.json. The token around the match decides, so ~/.env is
// HIGH and ./.env MEDIUM.
func credentialSeverity(content string, match []int) string {
	start := strings.LastIndexAny(content[:match[0]], " \t\n\"'`(=,[") + 1
	end := match[1]
	if index := strings.IndexAny(content[match[1]:], " \t\n\"'`),]"); index >= 0 {
		end = match[1] + index
	} else {
		end = len(content)
	}
	if highValueCredential.MatchString(content[start:end]) || highValueCredential.MatchString(content[match[0]:match[1]]) {
		return "HIGH"
	}
	return "MEDIUM"
}
