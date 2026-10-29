package agentskill

// Bundled programs and Windows scripts (decision E2 b). Compiled programs
// and archives are recognised by their first bytes only: they are never
// unpacked, parsed or run. PowerShell and batch files are read as text like
// shell scripts; their presence is reported, and a short list of well-known
// download, decode and hidden-window patterns is checked in every file.

import (
	"bytes"
	"encoding/base64"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// fileMagic names a compiled program or archive by its first bytes: ELF,
// Mach-O, PE (MZ), zip, gzip, 7z or rar. An MZ header counts only when the
// file is not text, and office documents and e-books, which are zip files,
// are left out.
func fileMagic(raw []byte, ext string) string {
	switch {
	case bytes.HasPrefix(raw, []byte("\x7fELF")):
		return "ELF program"
	case bytes.HasPrefix(raw, []byte{0xfe, 0xed, 0xfa, 0xce}), bytes.HasPrefix(raw, []byte{0xfe, 0xed, 0xfa, 0xcf}),
		bytes.HasPrefix(raw, []byte{0xce, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(raw, []byte{0xcf, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(raw, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return "Mach-O program"
	case bytes.HasPrefix(raw, []byte("MZ")) && !textPrefix(raw):
		return "Windows program"
	case bytes.HasPrefix(raw, []byte("PK\x03\x04")) || bytes.HasPrefix(raw, []byte("PK\x05\x06")):
		switch ext {
		case ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub":
			return ""
		}
		return "zip archive"
	case bytes.HasPrefix(raw, []byte{0x1f, 0x8b}):
		return "gzip archive"
	case bytes.HasPrefix(raw, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}):
		return "7z archive"
	case bytes.HasPrefix(raw, []byte("Rar!\x1a\x07")):
		return "rar archive"
	}
	return ""
}

// textPrefix reports a file whose first 512 bytes are UTF-8 text without NUL.
func textPrefix(raw []byte) bool {
	prefix := raw[:min(len(raw), 512)]
	for len(prefix) > 0 && !utf8.FullRune(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	return utf8.Valid(prefix) && !bytes.ContainsRune(prefix, 0)
}

var (
	// runVerb is a step that runs a program the skill ships.
	runVerb = regexp.MustCompile(`(?i)\b(?:run|runs|running|execute|exec|launch|start|open|double-click|invoke|call)\b|chmod\s+\+x|(?:^|[\s"'` + "`" + `(])\.[\\/]`)
	// extractVerb is a step that unpacks an archive the skill ships.
	extractVerb = regexp.MustCompile(`(?i)\b(?:unzip|extract|unpack|decompress|tar\s+-?[a-z]*x|7za?\s+x|unrar)\b`)
)

// instructedToRun returns the SKILL.md line that tells the agent or user to
// run a shipped program, or to extract a shipped archive, by its path or file
// name, or 0.
func instructedToRun(manifest, relative, magic string) int {
	if manifest == "" {
		return 0
	}
	name := regexp.QuoteMeta(path.Base(relative))
	mention := regexp.MustCompile(`(?i)(?:^|[^\w.-])(?:\./)?(?:` + regexp.QuoteMeta(relative) + `|` + name + `)(?:[^\w.-]|$)`)
	verb := runVerb
	if strings.HasSuffix(magic, "archive") {
		verb = extractVerb
	}
	for index, line := range strings.Split(manifest, "\n") {
		if mention.MatchString(line) && verb.MatchString(line) {
			return index + 1
		}
	}
	return 0
}

// analyzeBundledFiles reports (SC13) each compiled program or archive the
// skill ships, MEDIUM, or HIGH when SKILL.md tells the agent or user to run
// it, and (SC14, MEDIUM) each PowerShell or batch script.
func analyzeBundledFiles(components []component, skills []skillInput) []model.Finding {
	var findings []model.Finding
	for _, item := range components {
		manifest, relative := "", item.Path
		for _, skill := range skills {
			if pathWithinSkill(item.Path, skill.Root) {
				manifest = skill.ManifestContent
				if skill.Root != "." {
					relative = strings.TrimPrefix(item.Path, skill.Root+"/")
				}
				break
			}
		}
		switch {
		case item.Magic != "":
			severity, text := "MEDIUM", "The skill ships a "+item.Magic+": "+relative
			explanation, remediation := ruleText("SC13")
			if line := instructedToRun(manifest, relative, item.Magic); line > 0 {
				severity = "HIGH"
				text += "; SKILL.md line " + strconv.Itoa(line) + " tells the agent or user to run it"
			}
			findings = append(findings, model.Finding{ID: "SC13", Category: "Supply Chain", Pattern: "Bundled Program or Archive", Severity: severity,
				Confidence: .9, Location: model.Location{File: item.Path, StartLine: 1}, Finding: text, MatchedText: text,
				Explanation: explanation, Remediation: remediation, Tags: []string{"Supply Chain"}})
		case item.Type == "powershell" || item.Type == "batch":
			kind := "PowerShell"
			if item.Type == "batch" {
				kind = "batch"
			}
			text := "The skill ships a " + kind + " script: " + relative
			explanation, remediation := ruleText("SC14")
			findings = append(findings, model.Finding{ID: "SC14", Category: "Supply Chain", Pattern: "Bundled Windows Script", Severity: "MEDIUM",
				Confidence: .9, Location: model.Location{File: item.Path, StartLine: 1}, Finding: text, MatchedText: text,
				Explanation: explanation, Remediation: remediation, CodeSnippet: lineSnippet(item.Content, 1), Tags: []string{"Supply Chain"}})
		}
	}
	return findings
}

// encodedPowerShell matches powershell -EncodedCommand (or any prefix of it
// down to -e) followed by its base64 argument.
var encodedPowerShell = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*?\s[-/]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s+["']?([A-Za-z0-9+/]{16,}={0,2})`)

// decodeUTF16Base64 decodes a PowerShell -EncodedCommand argument: base64 of
// UTF-16LE text.
func decodeUTF16Base64(literal string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(literal)
	if err != nil || len(raw)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(raw)/2)
	for index := range units {
		units[index] = uint16(raw[2*index]) | uint16(raw[2*index+1])<<8
	}
	text := string(utf16.Decode(units))
	for _, char := range text {
		if !unicode.IsPrint(char) && !unicode.IsSpace(char) {
			return "", false
		}
	}
	return text, true
}

// analyzeEncodedPowerShell reports a PowerShell -EncodedCommand. One whose
// decoded text downloads and runs remote code is SC3 CRITICAL, tagged
// decode-to-exec, and one that opens a reverse shell is RA3 CRITICAL, tagged
// reverse-shell; any other is SC14 HIGH, since the command it runs is hidden
// from a reader.
func analyzeEncodedPowerShell(item component) []model.Finding {
	var findings []model.Finding
	for _, match := range encodedPowerShell.FindAllStringSubmatchIndex(item.Content, -1) {
		if scriptCommentLine(item, match[0]) {
			continue
		}
		decoded, ok := decodeUTF16Base64(item.Content[match[2]:match[3]])
		lineNumber := 1 + strings.Count(item.Content[:match[0]], "\n")
		line := lineSnippet(item.Content, lineNumber)
		context := contextAtOffset(item.Content, match[0], 3)
		payload := ""
		if ok {
			if commands, _ := downloadAndRunOrigins(decoded); len(commands) > 0 {
				payload = behaviourDownloadAndRun
			} else if _, shell := reverseShellAt(decoded); shell != nil {
				payload = behaviourReverseShell
			}
		}
		var finding model.Finding
		if payload != "" {
			finding = decodedPayloadFinding(item, match[0], lineNumber, line, decoded, payload, "encoded PowerShell command")
		} else {
			matched := truncateRunes(strings.TrimSpace(item.Content[match[0]:match[1]]), 200)
			finding = model.Finding{ID: "SC14", Category: "Supply Chain", Pattern: "Encoded PowerShell Command", Severity: "HIGH",
				Confidence: .9, Location: model.Location{File: item.Path, StartLine: lineNumber}, Finding: matched, MatchedText: matched,
				CodeSnippet: context, Tags: []string{"Supply Chain"}}
			finding.Explanation, finding.Remediation = ruleText("SC14")
			if ok {
				finding.Explanation += " It decodes to: " + truncateRunes(strings.Join(strings.Fields(decoded), " "), 200)
			}
		}
		if reason := proseReviewReason(item, finding.ID, match[0]); reason != "" {
			finding = markForReview(finding, reason)
		}
		if payload != "" && exampleTreatmentAt(item, match[0], context, isCodeExample) == exampleNone {
			kind := behaviourDecodeToExec
			if payload == behaviourReverseShell {
				kind = behaviourReverseShell
			}
			finding = markBehaviour(finding, kind)
		}
		findings = append(findings, finding)
	}
	return findings
}
