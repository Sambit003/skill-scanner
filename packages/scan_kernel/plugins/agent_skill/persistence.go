package agentskill

// Persistence: skill code or instructions that make something run or apply
// again later, outside the current session: launchd plists, systemd units,
// crontab entries, shell startup files, and the agent's own memory and
// instruction files. RA2 reports these at HIGH without a behaviour tag; when
// the persisted command is itself malicious, its own finding carries the tag.
// A HIGH write to the agent's memory or instruction files or its global
// configuration carries memoryPersistenceTag, which sets a CAUTION floor on
// the verdict (see findingTier).

import (
	"regexp"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

const memoryPersistenceTag = "Persists into agent memory"

const homeDir = `(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|/Users/[^/\s"']+|/home/[^/\s"']+|/root)`

// persistenceTargets are the places a write makes persistent, as path
// expressions.
var persistenceTargets = []struct{ kind, location string }{
	{"launchd agent", `[^\s"'` + "`" + `]*/Library/Launch(?:Agents|Daemons)/[^\s"'` + "`" + `]*`},
	{"systemd unit", `[^\s"'` + "`" + `]*(?:/\.config/systemd/user|/etc/systemd/system|/lib/systemd/system)\b[^\s"'` + "`" + `]*`},
	{"cron entry", `(?:/etc/cron(?:tab\b|\.d/|\.(?:hourly|daily|weekly|monthly)/)|/var/spool/cron/)[^\s"'` + "`" + `]*`},
	{"shell startup file", `(?:` + homeDir + `/|\B)\.(?:bashrc|zshrc|profile|bash_profile|bash_login|zprofile|zshenv|zlogin)\b`},
	{"global agent configuration", homeDir + `/\.(?:claude/(?:CLAUDE\.md|settings(?:\.local)?\.json|projects/[^\s"'` + "`" + `]*/memory/[^\s"'` + "`" + `]*)|claude\.json|codex/(?:AGENTS\.md|config\.toml)|gemini/(?:GEMINI\.md|settings\.json)|cursor/rules/[^\s"'` + "`" + `]*)`},
	{"agent memory or instruction file", `(?:[^\s"'` + "`" + `(]*/)?(?:MEMORY|CLAUDE|AGENTS|GEMINI)\.md\b|\.cursorrules\b`},
}

// persistenceWriteTo returns a pattern for a write whose destination is the
// location: a shell redirect, tee, cp/mv/install/ln destination, a file
// opened for writing or a file-write call naming it, or an instruction to
// append, add, write, insert or save something to it.
func persistenceWriteTo(location string) *regexp.Regexp {
	quote := `["'` + "`" + `]?`
	return regexp.MustCompile(`(?i)(?:^|[^\d&>=-])>>?\s*` + quote + `(?:` + location + `)` +
		`|\btee\s+(?:-a\s+)?` + quote + `(?:` + location + `)` +
		`|\b(?:cp|mv|install|ln)\b[^\n;&|]*\s` + quote + `(?:` + location + `)` + quote + `\s*(?:$|[;&|)])` +
		`|\bopen\s*\([^\n]*?(?:` + location + `)[^\n]*?,\s*["'](?:a|w)` +
		`|\b(?:write_?(?:text|bytes)|writeFile(?:Sync)?|appendFile(?:Sync)?)\s*\(\s*[^,)\n]*(?:` + location + `)` +
		`|\bPath\s*\([^)\n]*(?:` + location + `)[^)\n]*\)\.(?:write_text|write_bytes|open\s*\(\s*["'](?:a|w))` +
		`|\b(?:append|add|write|insert|prepend|save|inject)\b[^.\n]{0,80}?\b(?:to|into|in)\s+(?:the\s+|your\s+|a\s+|their\s+)?(?:project'?s\s+|user'?s\s+|global\s+)?` + quote + `(?:` + location + `)`)
}

var (
	persistenceWrites = func() []struct {
		kind  string
		write *regexp.Regexp
	} {
		var writes []struct {
			kind  string
			write *regexp.Regexp
		}
		for _, target := range persistenceTargets {
			writes = append(writes, struct {
				kind  string
				write *regexp.Regexp
			}{target.kind, persistenceWriteTo(target.location)})
		}
		return writes
	}()
	// persistenceEnable registers or starts persistent work directly.
	persistenceEnable = regexp.MustCompile(`(?i)\bsystemctl\s+(?:--user\s+)?enable\b|\blaunchctl\s+(?:load|bootstrap|enable|submit)\b` +
		`|\bcrontab\s+(?:-u\s+\S+\s+)?["']?[~$/.\w][^\s|;&]*\s*(?:$|[;&|)` + "`" + `])|\bschtasks(?:\.exe)?\s+/create\b`)
	// crontabInstall pipes new entries into the crontab: ... | crontab -.
	crontabInstall = regexp.MustCompile(`\|\s*crontab\s+-(?:\s|$|["'` + "`" + `)])`)
	// crontabRead lists or edits the crontab without adding an entry.
	crontabRead = regexp.MustCompile(`(?i)\bcrontab\s+-[lre]\b`)
	// shellEnvironmentSetup is a startup-file line that only sets up the
	// environment: an export, PATH change, alias, completion or tool init.
	shellEnvironmentSetup = regexp.MustCompile(`(?i)\bexport\s+\w+=|\bPATH=|\balias\s+\w+=|\bcompletion\b|\beval\s+["']?\$\(\s*\S+\s+(?:init|shellenv|env|hook)\b|\bsource\s+\S+(?:env|\.sh)\b`)
	// onUserRequest conditions a step on the user asking for it.
	onUserRequest = regexp.MustCompile(`(?i)\b(?:if|when|only\s+if|once|after)\s+(?:the\s+)?user\s+(?:explicitly\s+)?(?:asks?|requests?|wants?|says|agrees?|approves?|confirms?|opts?\s+in)\b|\bon\s+(?:the\s+user'?s\s+)?(?:explicit\s+)?request\b|\b(?:ask|confirm\s+with)\s+the\s+user\b|\bwith\s+the\s+user'?s\s+(?:approval|permission|consent|confirmation)\b|\buser\s+(?:explicitly\s+)?(?:asks|requests)\b|\bwhen\s+asked\b`)
	// persistenceStealth hides the step or makes it apply to all later work.
	persistenceStealth = regexp.MustCompile(`(?i)\b(?:never|don'?t|do\s+not)\s+(?:mention|tell|reveal|show|disclose)\b|\bwithout\s+(?:telling|asking|informing|notifying)\b|\bsilently\b|\bquietly\b|\b(?:every|all)\s+(?:future|later|subsequent)\b|\bfrom\s+now\s+on\b`)
)

// analyzePersistence reports (RA2) each line of a file that writes a
// persistence target or registers persistent work: HIGH, or MEDIUM for a
// startup-file line that only sets up the environment, for an instruction to
// update the project's memory or instruction files (a memory skill's
// purpose, run when the user invokes it), and for an instruction step taken
// on the user's request, unless the step hides itself or applies to all
// later work. Code that writes them, and instructions to change the user's
// global agent configuration unasked, stay HIGH.
func analyzePersistence(item component) []model.Finding {
	var findings []model.Finding
	offset := 0
	for _, line := range strings.SplitAfter(item.Content, "\n") {
		start := offset
		offset += len(line)
		kind := ""
		for _, target := range persistenceWrites {
			if target.write.MatchString(line) {
				kind = target.kind
				break
			}
		}
		if kind == "" && (crontabInstall.MatchString(line) || persistenceEnable.MatchString(line) && !crontabRead.MatchString(line)) {
			kind = "registered service or scheduled task"
		}
		if kind == "" {
			continue
		}
		severity := "HIGH"
		if kind == "shell startup file" && shellEnvironmentSetup.MatchString(line) {
			severity = "MEDIUM"
		}
		if item.Type == "markdown" || item.Type == "text" {
			paragraph := lineWindow(item.Content, start, 4)
			ownFiles := kind == "agent memory or instruction file"
			if (ownFiles || onUserRequest.MatchString(paragraph)) && !persistenceStealth.MatchString(paragraph) {
				severity = "MEDIUM"
			}
		}
		pattern := newStaticPattern("RA2", "Persistence: "+kind, "Rogue Agent", severity, .85, `a^`)
		trimmed := strings.TrimRight(line, "\n")
		lead := len(trimmed) - len(strings.TrimLeft(trimmed, " \t"))
		if finding, ok := findingFromStaticMatch(item, pattern, []int{start + lead, start + len(trimmed)}); ok {
			finding.Explanation += " The skill writes a " + kind + ", which keeps running or applying after this session."
			if _, review := needsReview(finding); !review && finding.Severity == "HIGH" && writeTakesEffect(item, start+lead) &&
				(kind == "agent memory or instruction file" || kind == "global agent configuration") {
				finding.Tags = append(finding.Tags, memoryPersistenceTag)
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

// writeTakesEffect reports a line whose write happens when the skill is used:
// in an instruction file the agent follows, or in code that runs, apart from
// a script comment line. A write in HTML, JSON or another data file only
// describes one.
func writeTakesEffect(item component, offset int) bool {
	if item.Type == "markdown" || item.Type == "text" {
		return true
	}
	return (isSourceCodeType(item.Type) || isScriptFile(item)) && !scriptCommentLine(item, offset)
}
