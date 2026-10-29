package agentskill

import (
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
)

// secretMask replaces a secret value in finding output.
const secretMask = "***"

// maskFindingSecrets replaces secret values in the text a finding carries into
// reports and scan history (code_snippet, finding, matched_text) with ***,
// keeping key names and token-type prefixes so a reviewer can tell what was
// there. It runs after scoring and baseline filtering, so which findings
// exist, where they are and how they score never depend on it.
func maskFindingSecrets(findings []model.Finding) []model.Finding {
	for index := range findings {
		finding := &findings[index]
		code := isSourceCodePath(finding.Location.File)
		finding.CodeSnippet = maskSecrets(finding.CodeSnippet, code)
		finding.Finding = maskSecrets(finding.Finding, code)
		finding.MatchedText = maskSecrets(finding.MatchedText, code)
	}
	return findings
}

// maskSecrets masks private key blocks, known token formats, passwords in
// URLs, credentials in command-line and .netrc forms and after an
// Authorization scheme, literal values assigned to keys whose names mark them
// as secrets, and, as a backstop, high-entropy tokens on lines that mention a
// credential. code says the text comes from program source, where an unquoted
// bare name is a variable rather than a value.
func maskSecrets(text string, code bool) string {
	if text == "" {
		return text
	}
	text = maskPrivateKeyBlocks(text)
	for _, format := range secretTokenFormats {
		text = format.pattern.ReplaceAllStringFunc(text, func(token string) string {
			// Documentation keys such as AWS's AKIA...EXAMPLE stay readable.
			if strings.Contains(strings.ToLower(token), "example") || format.mixed && !hasLetterAndDigit(token) {
				return token
			}
			return format.pattern.ReplaceAllString(token, format.replacement)
		})
	}
	text = replaceSubmatch(urlPassword, text, 2, func(value string) string {
		if isPlaceholderSecret(value, true, false) {
			return value
		}
		return secretMask
	})
	for _, pattern := range credentialContexts {
		text = replaceSubmatch(pattern, text, 1, maskCredentialValue)
	}
	text = replaceSubmatch(authorizationCredential, text, 2, func(value string) string {
		if !hasLetterAndDigit(value) || isPlaceholderSecret(value, true, false) {
			return value
		}
		return secretMask
	})
	return maskHighEntropyTokens(maskSecretAssignments(text, code))
}

var (
	credentialLineWord = regexp.MustCompile(`(?i)secret|passw|token|api[-_ ]?key|credential|auth`)
	longToken          = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)
)

// maskHighEntropyTokens is a backstop for credential-looking lines: a token of
// 32 or more characters mixing upper case, lower case and digits with high
// entropy is masked when the line mentions a secret, password, token, API
// key, credential or auth.
func maskHighEntropyTokens(text string) string {
	lines := strings.Split(text, "\n")
	for index, line := range lines {
		if !credentialLineWord.MatchString(line) {
			continue
		}
		lines[index] = longToken.ReplaceAllStringFunc(line, func(token string) string {
			if strings.IndexFunc(token, unicode.IsUpper) < 0 || strings.IndexFunc(token, unicode.IsLower) < 0 ||
				strings.IndexFunc(token, unicode.IsDigit) < 0 || shannonEntropy(token) < 4 {
				return token
			}
			return secretMask
		})
	}
	return strings.Join(lines, "\n")
}

func shannonEntropy(value string) float64 {
	counts := map[rune]float64{}
	for _, char := range value {
		counts[char]++
	}
	entropy, total := 0.0, float64(len(value))
	for _, count := range counts {
		probability := count / total
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

var secretTokenFormats = []struct {
	pattern     *regexp.Regexp
	replacement string
	// mixed requires letters and digits, so generic prefixes such as "sk-"
	// leave kebab-case words alone.
	mixed bool
}{
	{regexp.MustCompile(`\b(gh[opsur])_[A-Za-z0-9]{20,}`), "${1}_***", false},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`), "github_pat_***", false},
	{regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), "${1}***", false},
	{regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{16,}`), "sk-ant-***", false},
	{regexp.MustCompile(`\b(sk|rk)_live_[A-Za-z0-9]{10,}`), "${1}_live_***", false},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`), "sk-***", true},
	{regexp.MustCompile(`\b(xox[baprs])-[A-Za-z0-9-]{10,}`), "${1}-***", false},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`), "glpat-***", false},
	{regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), "npm_***", false},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`), "AIza***", false},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), "eyJ***", false},
	{regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`), "hf_***", false},
	{regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`), "SG.***", false},
	{regexp.MustCompile(`(hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/)[A-Za-z0-9]{8,}`), "${1}***", false},
	{regexp.MustCompile(`(discord(?:app)?\.com/api/webhooks/\d+/)[A-Za-z0-9_-]{20,}`), "${1}***", false},
	{regexp.MustCompile(`\b((?:bot)?\d{6,12}):[A-Za-z0-9_-]{35}\b`), "${1}:***", false},
	{regexp.MustCompile(`(https?://)[0-9a-f]{32}(@[A-Za-z0-9.-]*sentry\.io)`), "${1}***${2}", false},
}

// credentialContexts are command-line and file forms in which a credential
// follows a fixed marker. Group 1 is the value; maskCredentialValue keeps
// quotes around it and leaves references and placeholders alone.
var credentialContexts = []*regexp.Regexp{
	// curl -u user:pass, --user=user:pass ("$USER:$PASS" never matches).
	regexp.MustCompile(`(?:^|\s)(?:-u|--user)(?:[ \t]+|=)["']?[^\s:"'$]+:([^\s"'\x60]+)`),
	// mysql -pSECRET: the password is glued to -p; a bare -p prompts, and -P
	// is the port.
	regexp.MustCompile(`\b(?:mysql|mysqladmin|mysqldump|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mariadb|mariadb-dump)\b[^\n|;&]*?[ \t]-p("[^"\n]*"|'[^'\n]*'|[^\s"'\x60]+)`),
	// --password VALUE, --token=VALUE and similar credential flags.
	regexp.MustCompile(`(?i)(?:^|\s)--(?:password|passwd|token|api-key|apikey|secret|client-secret|auth-token|access-token|api-token|secret-key)(?:=|[ \t]+)("[^"\n]*"|'[^'\n]*'|[^\s"'\x60]+)`),
	// sshpass -p VALUE
	regexp.MustCompile(`\bsshpass\b[^\n|;&]*?[ \t]-p[ \t]*("[^"\n]*"|'[^'\n]*'|[^\s"'\x60]+)`),
	// .netrc: login NAME password VALUE, on one line or the next.
	regexp.MustCompile(`\blogin[ \t]+\S+(?:[ \t]+|[ \t]*\n[ \t]*)password[ \t]+([^\s"'\x60,;]+)`),
	// Authorization: <scheme> VALUE, for token and apikey schemes as well as
	// Bearer and Basic.
	regexp.MustCompile(`(?i)\b(?:proxy-)?authorization["']?[ \t]*[:=][ \t]*["']?(?:bearer|basic|token|apikey|api-key|digest)[ \t]+([^\s"',;\x60]+)`),
}

func maskCredentialValue(value string) string {
	inner, quote := value, ""
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		inner, quote = value[1:len(value)-1], value[:1]
	}
	// Another flag, or a BuildKit secret mount spec (--secret id=npmrc,src=...),
	// is not a credential value.
	if strings.HasPrefix(inner, "-") || strings.HasPrefix(inner, "id=") || isPlaceholderSecret(inner, true, false) {
		return value
	}
	return quote + secretMask + quote
}

var (
	urlPassword             = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9+.-]*://[^\s:/@'"]+:)([^\s@/'"]+)@`)
	authorizationCredential = regexp.MustCompile(`(?i)\b(Bearer|Basic)[ \t]+([A-Za-z0-9._~+/=-]{8,})`)
	secretAssignment        = regexp.MustCompile(`(?:"([A-Za-z_][A-Za-z0-9_.-]*)"|'([A-Za-z_][A-Za-z0-9_.-]*)'|\b([A-Za-z_][A-Za-z0-9_.-]*))[ \t]*(:=|=|:)[ \t]*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|[^\s,;)}\]"'\x60\\]+)`)
	pemBegin                = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	pemEnd                  = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	pemInline               = regexp.MustCompile(`(-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)[^\n]+?(-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)`)
	pemBodyLine             = regexp.MustCompile(`^\s*[A-Za-z0-9+/=]{16,}\s*$`)
	envVariableName         = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	identifierValue         = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$`)
	shortNumber             = regexp.MustCompile(`^\d{1,6}(?:\.\d+)?$`)
)

// maskPrivateKeyBlocks keeps BEGIN/END lines of PEM private keys and masks the
// body, including a body cut off at either end of a snippet.
func maskPrivateKeyBlocks(text string) string {
	if !strings.Contains(text, "PRIVATE KEY") {
		return text
	}
	text = pemInline.ReplaceAllString(text, "${1}"+secretMask+"${2}")
	lines := strings.Split(text, "\n")
	inside := false
	for index, line := range lines {
		switch {
		case pemBegin.MatchString(line) && !pemEnd.MatchString(line):
			inside = true
		case pemEnd.MatchString(line) && !pemBegin.MatchString(line):
			if !inside {
				for previous := index - 1; previous >= 0 && pemBodyLine.MatchString(lines[previous]); previous-- {
					lines[previous] = maskWholeLine(lines[previous])
				}
			}
			inside = false
		case inside:
			lines[index] = maskWholeLine(line)
		}
	}
	return strings.Join(lines, "\n")
}

func maskWholeLine(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))] + secretMask
}

func maskSecretAssignments(text string, code bool) string {
	matches := secretAssignment.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	var masked strings.Builder
	last := 0
	for _, match := range matches {
		key := ""
		for group := 1; group <= 3; group++ {
			if match[2*group] >= 0 {
				key = text[match[2*group]:match[2*group+1]]
			}
		}
		operator := text[match[8]:match[9]]
		valueStart, valueEnd := match[10], match[11]
		value := text[valueStart:valueEnd]
		strength := secretKeyStrength(key)
		// ${NAME:?message} and ${NAME:-default} are shell expansions, not
		// assignments.
		inExpansion := strings.HasSuffix(text[:match[0]], "${") || strings.HasSuffix(text[:match[0]], "$")
		if operator == "=" && strings.HasPrefix(value, "=") || strength == secretKeyNone || inExpansion {
			continue
		}
		quoted := len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0]
		inner := value
		if quoted {
			inner = value[1 : len(value)-1]
		}
		// Inside a string literal ("PASSWORD=hunter2\n" in a test fixture) a
		// bare word is text, not a variable, even in program source.
		linePrefix := text[strings.LastIndexByte(text[:match[0]], '\n')+1 : match[0]]
		inString := strings.Count(linePrefix, `"`)%2 == 1 || strings.Count(linePrefix, `'`)%2 == 1
		if isPlaceholderSecret(inner, quoted, code && !inString) || strength == secretKeyWeak && !looksRandom(inner) {
			continue
		}
		replacement := secretMask
		if quoted {
			replacement = value[:1] + secretMask + value[:1]
		}
		masked.WriteString(text[last:valueStart])
		masked.WriteString(replacement)
		last = valueEnd
	}
	masked.WriteString(text[last:])
	return masked.String()
}

var secretKeyDenied = wordSet(
	"tokens", "tokenizer", "tokenizers", "tokenize", "tokenized", "tokenization",
	"keyword", "keywords", "keyboard", "monkey", "hotkey", "turkey",
	"author", "authors", "authored", "authoring", "authorship", "authority", "authorities",
)

const (
	secretKeyNone = iota
	// secretKeyWeak names end in "key" without a credential qualifier
	// (primary_key, data_source_key); only random-looking values are masked.
	secretKeyWeak
	secretKeyStrong
)

// Qualifiers that make a "...key" name a credential: api_key, accessKey,
// private-key, SIGNING_KEY.
var credentialKeyQualifiers = wordSet("api", "access", "secret", "private", "signing", "master", "encryption",
	"client", "app", "license", "service", "account", "subscription", "session", "deploy", "ssh", "gpg", "pgp", "rsa")

// secretKeyStrength classifies a key name by its segments (split on
// punctuation and camelCase). A segment containing secret, password, passwd,
// pwd, credential or token, starting with auth, or a qualified "key" makes it
// strong; any other "...key" makes it weak. Counters and words such as
// max_tokens, keywords and author are not secrets.
func secretKeyStrength(key string) int {
	if lower := strings.ToLower(key); lower == "pwd" || lower == "oldpwd" {
		return secretKeyNone
	}
	strength := secretKeyNone
	segments := keySegments(key)
	for index, segment := range segments {
		if secretKeyDenied[segment] {
			continue
		}
		if containsAny(segment, "secret", "password", "passwd", "pwd", "credential", "token") || strings.HasPrefix(segment, "auth") {
			return secretKeyStrong
		}
		if qualifier, isKey := strings.CutSuffix(segment, "key"); isKey {
			if qualifier == "" && index > 0 {
				qualifier = segments[index-1]
			}
			if credentialKeyQualifiers[qualifier] {
				return secretKeyStrong
			}
			strength = secretKeyWeak
		}
	}
	return strength
}

// looksRandom reports values with digits and letters, mixed case, or 20 or
// more characters, as generated keys have.
func looksRandom(value string) bool {
	return hasLetterAndDigit(value) || strings.IndexFunc(value, unicode.IsUpper) >= 0 && strings.IndexFunc(value, unicode.IsLower) >= 0 || len(value) >= 20
}

func keySegments(key string) []string {
	var segments []string
	var current []rune
	runes := []rune(key)
	flush := func() {
		if len(current) > 0 {
			segments = append(segments, strings.ToLower(string(current)))
			current = current[:0]
		}
	}
	for index, char := range runes {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			flush()
			continue
		}
		if index > 0 && unicode.IsUpper(char) {
			previous := runes[index-1]
			nextLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
			if unicode.IsLower(previous) || (unicode.IsUpper(previous) && nextLower) {
				flush()
			}
		}
		current = append(current, char)
	}
	flush()
	return segments
}

var placeholderSecretValues = wordSet(
	"password", "passwd", "secret", "token", "key", "apikey", "api_key", "pass", "none", "null", "nil",
	"true", "false", "undefined", "required", "optional", "string", "str", "int", "bool", "bytes",
	"any", "number", "object", "empty", "env", "n/a", "na", "-", "bearer", "basic", "digest",
)

// isPlaceholderSecret reports values that are not secrets: placeholders such
// as <your-key> or your-api-key-here, references such as $VAR, ${VAR},
// {{ secrets.X }}, os.environ[...] or a function call, URLs and paths, short
// numbers, environment variable names, short unquoted words, unquoted dotted
// names (tokens.access_token), and in program source an unquoted variable
// name.
func isPlaceholderSecret(value string, quoted, code bool) bool {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	switch {
	case value == "" || strings.Contains(value, secretMask) || placeholderSecretValues[lower]:
		return true
	case strings.HasPrefix(value, "$") || strings.HasPrefix(value, "%") || strings.Contains(value, "{") ||
		strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">"):
		return true
	case containsAny(lower, "your", "example", "placeholder", "changeme", "change-me", "change_me", "replace", "insert", "dummy", "redacted", "xxxx", "todo", "fixme", "..."):
		return true
	case strings.Trim(lower, lower[:1]) == "":
		return true
	case shortNumber.MatchString(value) || envVariableName.MatchString(value):
		return true
	case strings.Contains(lower, "://") || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") ||
		strings.HasPrefix(value, "../") || strings.HasPrefix(value, "~/"):
		return true
	case containsAny(filepath.Ext(lower), ".pem", ".json", ".key", ".p12", ".pfx", ".crt", ".env", ".yaml", ".yml", ".txt"):
		return true
	}
	if quoted {
		return false
	}
	// Unquoted: calls, subscripts, prefixed string literals (f"...") and
	// references to configuration objects are not values; a short plain word
	// is prose ("Key: Use the API"), not a secret.
	if strings.ContainsAny(value, "([\"'") || len(value) < 8 && strings.IndexFunc(value, func(char rune) bool { return !unicode.IsLetter(char) }) < 0 {
		return true
	}
	if identifierValue.MatchString(value) && (code || strings.Contains(value, ".")) {
		return true
	}
	return false
}

func isSourceCodePath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".rb", ".go", ".rs", ".java", ".kt", ".cs", ".php", ".swift", ".scala":
		return true
	default:
		return false
	}
}

func hasLetterAndDigit(value string) bool {
	return strings.IndexFunc(value, unicode.IsLetter) >= 0 && strings.IndexFunc(value, unicode.IsDigit) >= 0
}

// replaceSubmatch rewrites one capture group of every match with replace.
func replaceSubmatch(pattern *regexp.Regexp, text string, group int, replace func(string) string) string {
	matches := pattern.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	var output strings.Builder
	last := 0
	for _, match := range matches {
		start, end := match[2*group], match[2*group+1]
		if start < 0 {
			continue
		}
		output.WriteString(text[last:start])
		output.WriteString(replace(text[start:end]))
		last = end
	}
	output.WriteString(text[last:])
	return output.String()
}
