package agentskill

import (
	"fmt"
	"sort"
	"strings"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

type ruleSpec struct {
	ID          string
	Family      string
	Title       string
	Category    string
	Severity    string
	Confidence  float64
	Expression  string
	Explanation string
	Remediation string
	Executable  bool
}

// ruleSpecs is the rule-document catalog. Scanner execution uses the production
// analyzer tables and must never execute these legacy expressions.
var ruleSpecs = []ruleSpec{
	{ID: "P1", Family: "static", Title: "Override instructions", Category: "Prompt Injection", Severity: "HIGH", Confidence: .90, Expression: `(?i)(ignore|disregard|override|forget).{0,40}(previous|prior|system|safety|instructions?|rules?)`, Explanation: "Content attempts to override trusted instructions or safety controls.", Remediation: "Remove instruction-override language and make the skill's behavior explicit and bounded."},
	{ID: "P2", Family: "static", Title: "Hidden instructions", Category: "Prompt Injection", Severity: "HIGH", Confidence: .85, Expression: `(?i)(hidden instructions?|do not (show|reveal|mention)|invisible text|<!--.{0,100}(ignore|execute))`, Explanation: "Hidden or concealed directives can steer an agent without the user's knowledge.", Remediation: "Remove concealed directives and expose all behavioral requirements in normal documentation."},
	{ID: "P3", Family: "static", Title: "External transmission instructions", Category: "Prompt Injection", Severity: "HIGH", Confidence: .80, Expression: `(?i)(send|transmit|upload|post).{0,60}(conversation|context|history|user data|prompt).{0,60}(http|server|endpoint|webhook)`, Explanation: "Instructions direct user or conversation data to an external service.", Remediation: "Do not transmit context unless the user explicitly authorizes a documented destination."},
	{ID: "P4", Family: "static", Title: "Subtle behavioral steering", Category: "Prompt Injection", Severity: "MEDIUM", Confidence: .65, Expression: `(?i)(secretly|silently|without the user knowing|do not tell the user).{0,80}(prefer|choose|change|steer|bias)`, Explanation: "Covert instructions may bias agent decisions.", Remediation: "Make decision criteria visible and user-controlled."},
	{ID: "P5", Family: "static", Title: "Harmful operational content", Category: "Prompt Injection", Severity: "CRITICAL", Confidence: .75, Expression: `(?i)(build|make|deploy|synthesize).{0,35}(explosive|malware|ransomware|poison|weapon)`, Explanation: "The skill contains high-impact harmful operational instructions.", Remediation: "Remove harmful instructions and scope the skill to a safe use case."},
	{ID: "P6", Family: "static", Title: "System prompt disclosure", Category: "System Prompt Leakage", Severity: "HIGH", Confidence: .85, Expression: `(?i)(reveal|print|show|repeat|dump).{0,35}(system prompt|hidden instructions|internal rules)`, Explanation: "The skill attempts to disclose hidden system instructions.", Remediation: "Remove prompt-disclosure behavior and treat system instructions as confidential."},
	{ID: "P7", Family: "static", Title: "Indirect prompt extraction", Category: "System Prompt Leakage", Severity: "HIGH", Confidence: .80, Expression: `(?i)(translate|summarize|encode|rephrase).{0,50}(system prompt|hidden instructions|internal rules)`, Explanation: "Indirect transformation is used to extract protected instructions.", Remediation: "Do not transform or disclose higher-priority instructions."},
	{ID: "P8", Family: "static", Title: "Prompt exfiltration through a tool", Category: "System Prompt Leakage", Severity: "CRITICAL", Confidence: .85, Expression: `(?i)(write|log|send|upload|post).{0,50}(system prompt|hidden instructions).{0,80}(file|url|server|webhook|tool)`, Explanation: "Protected instructions may be exfiltrated through a file or network tool.", Remediation: "Remove the exfiltration flow and keep protected prompts out of tool arguments."},
	{ID: "E1", Family: "static", Title: "External data transmission", Category: "Data Exfiltration", Severity: "HIGH", Confidence: .75, Expression: `(?i)(requests\.(post|put)|fetch\s*\(|curl\s+.*(-d|--data)|wget\s+--post|http\.Post)`, Explanation: "Code sends data to an external network destination.", Remediation: "Allowlist destinations, minimize transmitted data, and require explicit consent.", Executable: true},
	{ID: "E2", Family: "static", Title: "Environment secret access", Category: "Data Exfiltration", Severity: "HIGH", Confidence: .85, Expression: `(?i)(os\.(environ|getenv)|process\.env|env\s*\[).{0,50}(key|token|secret|password|credential|auth)`, Explanation: "Code accesses environment variables likely to contain credentials.", Remediation: "Read only named secrets required by the skill and never log or transmit them.", Executable: true},
	{ID: "E3", Family: "static", Title: "Sensitive file enumeration", Category: "Data Exfiltration", Severity: "HIGH", Confidence: .80, Expression: `(?i)(\.ssh|\.aws/credentials|\.config/gcloud|id_rsa|keychain|credentials\.json|/etc/shadow)`, Explanation: "Code or instructions access sensitive credential locations.", Remediation: "Remove credential discovery and constrain file access to the declared workspace.", Executable: true},
	{ID: "E4", Family: "static", Title: "Conversation context leak", Category: "Data Exfiltration", Severity: "HIGH", Confidence: .85, Expression: `(?i)(conversation|chat_history|messages|context_window).{0,100}(requests\.(post|put)|fetch\s*\(|webhook|upload)`, Explanation: "Conversation context appears to flow to an external destination.", Remediation: "Minimize context and require explicit user authorization before transmission."},
	{ID: "E5", Family: "static", Title: "Cloud storage upload", Category: "Data Exfiltration", Severity: "HIGH", Confidence: .75, Expression: `(?i)(put_object|upload_file|blob.*upload|gsutil\s+cp|aws\s+s3\s+cp)`, Explanation: "Data is uploaded to cloud storage.", Remediation: "Document and allowlist the bucket, data types, and user-consent boundary.", Executable: true},
	{ID: "PE2", Family: "static", Title: "Elevated command execution", Category: "Privilege Escalation", Severity: "HIGH", Confidence: .90, Expression: `(?m)(^|[;&|]\s*)(sudo|su\s+-|doas)\b|(?i)runas\s+/user:administrator`, Explanation: "Commands request administrator or root privileges.", Remediation: "Remove elevation or isolate the narrowly required privileged operation."},
	{ID: "PE1", Family: "static", Title: "Excessive permissions", Category: "Privilege Escalation", Severity: "HIGH", Confidence: .75, Expression: `(?i)(permissions?|capabilities?|allowed-tools).{0,40}(\*|all|unrestricted|admin|root)`, Explanation: "The skill requests permissions broader than its stated purpose.", Remediation: "Declare a least-privilege permission set."},
	{ID: "PE3", Family: "static", Title: "Credential file access", Category: "Privilege Escalation", Severity: "CRITICAL", Confidence: .90, Expression: `(?i)(id_rsa|id_ed25519|\.aws/credentials|\.docker/config\.json|/etc/shadow|keychain)`, Explanation: "The skill attempts to access authentication material.", Remediation: "Remove credential access and use a narrowly scoped secret injection boundary."},
	{ID: "PE4", Family: "static", Title: "Docker socket access", Category: "Privilege Escalation", Severity: "CRITICAL", Confidence: .95, Expression: `(?i)(/var/run/docker\.sock|docker\.sock:/|DOCKER_HOST\s*=)`, Explanation: "Docker daemon access can provide host-level control.", Remediation: "Do not mount or connect to the Docker socket."},
	{ID: "PE5", Family: "static", Title: "Container escape capability", Category: "Privilege Escalation", Severity: "CRITICAL", Confidence: .95, Expression: `(?i)(cap_add:.{0,60}(SYS_ADMIN|ALL)|--cap-add[= ](SYS_ADMIN|ALL)|security_opt:.{0,30}unconfined)`, Explanation: "The container requests capabilities commonly used for host escape.", Remediation: "Drop all capabilities and add back only the minimum required."},
	{ID: "SC1", Family: "static", Title: "Unpinned dependency", Category: "Supply Chain", Severity: "MEDIUM", Confidence: .65, Expression: `(?m)^(pip install|npm install|pnpm add|yarn add)\s+[A-Za-z@][^=\n]*$`, Explanation: "A dependency is installed without a fixed version.", Remediation: "Pin dependencies and verify their integrity."},
	{ID: "SC2", Family: "static", Title: "Remote code execution", Category: "Supply Chain", Severity: "CRITICAL", Confidence: .95, Expression: `(?i)(curl|wget).{0,160}\|\s*(sh|bash|zsh|python|node)\b|Invoke-WebRequest.{0,160}Invoke-Expression`, Explanation: "Remote content is downloaded and immediately executed.", Remediation: "Download a pinned artifact, verify its checksum, then execute a reviewed local file.", Executable: true},
	{ID: "SC3", Family: "static", Title: "Obfuscated code execution", Category: "Supply Chain", Severity: "HIGH", Confidence: .85, Expression: `(?i)(base64\.(b64decode|decode)|fromCharCode|xxd\s+-r).{0,200}(exec|eval|system|subprocess|child_process)`, Explanation: "Encoded content is passed to an execution primitive.", Remediation: "Replace obfuscated dynamic execution with auditable static code.", Executable: true},
	{ID: "EA1", Family: "static", Title: "Unrestricted tool access", Category: "Excessive Agency", Severity: "HIGH", Confidence: .75, Expression: `(?i)(all tools|unrestricted access|any command|full (shell|filesystem|network) access|allowed-tools:\s*\*)`, Explanation: "The skill requests unbounded tool capabilities.", Remediation: "Declare the minimum tools and permissions required."},
	{ID: "EA2", Family: "static", Title: "Autonomous destructive action", Category: "Excessive Agency", Severity: "CRITICAL", Confidence: .80, Expression: `(?i)(without (asking|confirmation)|do not ask).{0,80}(delete|purchase|send|deploy|terminate|destroy)`, Explanation: "The skill authorizes high-impact actions without human confirmation.", Remediation: "Require explicit confirmation before irreversible or high-impact operations."},
	{ID: "EA3", Family: "static", Title: "Undeclared capability", Category: "Excessive Agency", Severity: "HIGH", Confidence: .70, Expression: `(?i)(also|additionally|in the background).{0,60}(execute commands|access files|call APIs|modify|delete)`, Explanation: "The skill's operational scope extends beyond its apparent purpose.", Remediation: "Remove unrelated capabilities or document and permission them explicitly."},
	{ID: "EA4", Family: "static", Title: "Unbounded resource use", Category: "Excessive Agency", Severity: "MEDIUM", Confidence: .75, Expression: `(?i)(while\s+true|for\s*\(\s*;;\s*\)|unlimited|no rate limit|retry forever)`, Explanation: "The skill can consume resources without a bound.", Remediation: "Add quotas, timeouts, bounded retries, and cancellation."},
	{ID: "EA5", Family: "manifest", Title: "Broad tool pre-approval", Category: "Excessive Agency", Severity: "MEDIUM", Confidence: .90, Expression: `(?im)^allowed-tools:.*\bBash\b(?:\(\s*\*{0,2}\s*\))?(?:[\s,]|$)`, Explanation: "allowed-tools lets listed tools run without asking the user.", Remediation: "Scope allowed-tools entries to the commands the skill needs."},
	{ID: "EA6", Family: "manifest", Title: "Skill hook", Category: "Excessive Agency", Severity: "MEDIUM", Confidence: .90, Expression: `(?im)^hooks:\s*$`, Explanation: "Hooks in skill front matter run commands on events without asking the user.", Remediation: "Remove hooks the skill does not need."},
	{ID: "EA7", Family: "manifest", Title: "Preprocessing command", Category: "Excessive Agency", Severity: "LOW", Confidence: .90, Expression: "!`[^`\\n]+`", Explanation: "An inline preprocessing command runs when the skill is invoked.", Remediation: "Remove preprocessing commands the skill does not need."},
	{ID: "OH1", Family: "static", Title: "Unvalidated output execution", Category: "Output Handling", Severity: "HIGH", Confidence: .80, Expression: `(?i)(exec|eval|os\.system|subprocess\.(run|Popen)|shell:\s*true)\s*\([^\n]*(response|output|completion|content)`, Explanation: "Model or tool output flows into an execution sink without validation.", Remediation: "Use structured output validation and parameterized APIs."},
	{ID: "OH2", Family: "static", Title: "Cross-context output flow", Category: "Output Handling", Severity: "HIGH", Confidence: .75, Expression: `(?i)(model_output|tool_output|response\.text).{0,120}(innerHTML|execute|sql|shell|system prompt)`, Explanation: "Output crosses a trust boundary without validation.", Remediation: "Validate and encode data for the destination context."},
	{ID: "OH3", Family: "static", Title: "Unbounded output", Category: "Output Handling", Severity: "MEDIUM", Confidence: .70, Expression: `(?i)(max_tokens\s*[:=]\s*(0|-1|none)|no output limit|unbounded output|stream forever)`, Explanation: "Generated output has no size or time bound.", Remediation: "Set explicit output, time, and memory limits."},
	{ID: "MP1", Family: "static", Title: "Persistent memory injection", Category: "Memory Poisoning", Severity: "HIGH", Confidence: .80, Expression: `(?i)(remember (this|that) (forever|permanently)|persist.{0,30}(memory|context)|write.{0,40}(memory|profile|instructions))`, Explanation: "Content attempts to persist behavioral instructions across sessions.", Remediation: "Do not write untrusted instructions to persistent memory."},
	{ID: "MP2", Family: "static", Title: "Context-window stuffing", Category: "Memory Poisoning", Severity: "MEDIUM", Confidence: .75, Expression: `(?i)(fill|flood|stuff|consume).{0,50}(context window|token budget|memory).{0,60}(repeat|padding|filler)`, Explanation: "Filler content attempts to displace trusted context.", Remediation: "Bound context additions and reject repetitive untrusted padding."},
	{ID: "MP3", Family: "static", Title: "Agent state manipulation", Category: "Memory Poisoning", Severity: "HIGH", Confidence: .80, Expression: `(?i)(modify|overwrite|poison|reset).{0,40}(agent memory|stored context|profile|state file)`, Explanation: "The skill attempts to manipulate persisted agent state.", Remediation: "Protect state with an explicit schema and trusted write policy."},
	{ID: "TM1", Family: "static", Title: "Unsafe tool parameter", Category: "Tool Misuse", Severity: "HIGH", Confidence: .85, Expression: `(?i)(shell\s*=\s*true|--force\b|--no-preserve-root|chmod\s+777|verify\s*=\s*false)`, Explanation: "A tool is invoked with a dangerous or bypass parameter.", Remediation: "Use safe parameterized APIs and remove security-bypass flags.", Executable: true},
	{ID: "TM2", Family: "static", Title: "Safety-bypass tool chain", Category: "Tool Misuse", Severity: "HIGH", Confidence: .80, Expression: `(?i)(curl|wget).{0,100}(base64|xxd|openssl).{0,100}(sh|bash|exec|eval)`, Explanation: "Multiple tools are chained to bypass individual safety boundaries.", Remediation: "Replace the chain with a reviewed, typed operation."},
	{ID: "TM3", Family: "static", Title: "Unsafe security default", Category: "Tool Misuse", Severity: "HIGH", Confidence: .85, Expression: `(?i)(verify\s*[:=]\s*false|rejectUnauthorized\s*[:=]\s*false|--insecure\b|0\.0\.0\.0/0|auth\s*[:=]\s*none)`, Explanation: "A tool or service disables an important security control by default.", Remediation: "Enable authentication, TLS verification, and restrictive access by default."},
	{ID: "TM4", Family: "static", Title: "Privileged container", Category: "Tool Misuse", Severity: "CRITICAL", Confidence: .90, Expression: `(?i)(privileged:\s*true|hostNetwork:\s*true|hostPID:\s*true|hostPath:)`, Explanation: "A workload requests host-level container privileges.", Remediation: "Remove host access and apply a restricted security context."},
	{ID: "RA2", Family: "static", Title: "Unauthorized persistence", Category: "Rogue Agent", Severity: "CRITICAL", Confidence: .90, Expression: `(?i)(crontab|/etc/cron|\.bashrc|\.zshrc|LaunchAgents|systemctl\s+enable|schtasks\s+/create)`, Explanation: "Code attempts to persist beyond the current session.", Remediation: "Remove persistence and keep execution lifecycle-bound."},
	{ID: "RA1", Family: "static", Title: "Self-modifying skill", Category: "Rogue Agent", Severity: "CRITICAL", Confidence: .85, Expression: `(?i)(__file__|SKILL\.md|own (code|instructions)).{0,100}(write|replace|modify|patch|overwrite)`, Explanation: "The skill attempts to modify its own code or instructions.", Remediation: "Make the installed skill immutable at runtime."},
	{ID: "SC4", Family: "supply_chain", Title: "Known-vulnerable dependency marker", Category: "Supply Chain", Severity: "HIGH", Confidence: .70, Expression: `(?i)(known vulnerable|unpatched CVE|CVE-[0-9]{4}-[0-9]{4,})`, Explanation: "The dependency set references a known vulnerability.", Remediation: "Upgrade to a fixed version and verify with an advisory database."},
	{ID: "SC5", Family: "supply_chain", Title: "Abandoned dependency marker", Category: "Supply Chain", Severity: "MEDIUM", Confidence: .60, Expression: `(?i)(deprecated|unmaintained|archived package|no longer maintained)`, Explanation: "A dependency appears abandoned or deprecated.", Remediation: "Replace it with a maintained dependency."},
	{ID: "SC6", Family: "supply_chain", Title: "Potential dependency confusion", Category: "Supply Chain", Severity: "HIGH", Confidence: .65, Expression: `(?m)^(pip install|npm install|pnpm add)\s+(reqeusts|requestss|lodahs|expresss|typscript)\b`, Explanation: "A dependency name resembles a popular package and may be typosquatted.", Remediation: "Verify the exact package identity, publisher, and checksum."},
	{ID: "SC7", Family: "supply_chain", Title: "Unverified container image", Category: "Supply Chain", Severity: "HIGH", Confidence: .90, Expression: `(?i)(--disable-content-trust|DOCKER_CONTENT_TRUST\s*=\s*0|--insecure-registry)`, Explanation: "Container signature or registry verification is disabled.", Remediation: "Require a trusted registry, digest pin, and signature verification."},
	{ID: "SC8", Family: "static", Title: "Oversized file", Category: "Supply Chain", Severity: "MEDIUM", Confidence: 1, Explanation: "A file exceeds the scan limit and was only partly analyzed.", Remediation: "Review or split the file so it can be scanned fully."},
	{ID: "SC9", Family: "static", Title: "No skill instruction file", Category: "Supply Chain", Severity: "LOW", Confidence: 1, Explanation: "The target or a skill folder in it has no SKILL.md; its files were scanned anyway.", Remediation: "Name the skill's instruction file SKILL.md."},
	{ID: "SC10", Family: "static", Title: "Invalid Front Matter", Category: "Supply Chain", Severity: "LOW", Confidence: 1, Explanation: "The SKILL.md front matter does not parse as YAML; fields were read one at a time.", Remediation: "Quote the value that contains the colon (description: \"Use when: ...\") or use a block scalar, then check the front matter with a YAML parser."},
	{ID: "TR1", Family: "trigger", Title: "Overly broad trigger", Category: "Trigger Abuse", Severity: "MEDIUM", Confidence: .65, Expression: `(?i)(triggers?|keywords?).{0,60}(\*|anything|all requests|every message)`, Explanation: "A broad trigger can activate the skill in unrelated contexts.", Remediation: "Use narrow, purpose-specific trigger phrases."},
	{ID: "TR2", Family: "trigger", Title: "Built-in command shadowing", Category: "Trigger Abuse", Severity: "HIGH", Confidence: .75, Expression: `(?i)(trigger|command).{0,30}(/help|/login|/logout|/settings|/admin)`, Explanation: "The skill may intercept a common built-in command.", Remediation: "Choose a namespaced trigger that cannot shadow trusted commands."},
	{ID: "TR3", Family: "trigger", Title: "Generic activation keyword", Category: "Trigger Abuse", Severity: "LOW", Confidence: .60, Expression: `(?i)(triggers?|keywords?).{0,40}(help|run|do|make|create|use)([,\]}'" ]|$)`, Explanation: "Generic keywords cause excessive activation.", Remediation: "Use a multi-word trigger tied to the skill's purpose."},
	{ID: "RP1", Family: "mcp_rug_pull", Title: "Unpinned MCP dependency", Category: "MCP Rug Pull", Severity: "LOW", Confidence: .80, Expression: `(?i)(npx|uvx|pipx|docker run).{0,100}(mcp|server)(\s|"|')*$|(?i)image:\s*[^@\s:]+(:latest)?\s*$`, Explanation: "An MCP server or container is referenced without an immutable version.", Remediation: "Pin the package version or container digest."},
	{ID: "RP2", Family: "mcp_rug_pull", Title: "Future permission expansion", Category: "MCP Rug Pull", Severity: "MEDIUM", Confidence: .70, Expression: `(?i)(future|later|eventually).{0,50}(permission|access|capabilit|tool)`, Explanation: "Manifest language pre-authorizes future capability expansion.", Remediation: "Require a new review whenever permissions change."},
	{ID: "RP3", Family: "mcp_rug_pull", Title: "Unpinned skill version", Category: "MCP Rug Pull", Severity: "MEDIUM", Confidence: .75, Expression: `(?im)^version:\s*(latest|\*|x|>=|\^|~)?\s*$`, Explanation: "The skill version is missing or overly broad.", Remediation: "Pin an exact reviewed version."},
	{ID: "AST1", Family: "behavioral_ast", Title: "Dynamic exec call", Category: "Behavioral Code Execution", Severity: "HIGH", Confidence: .90, Expression: `(?m)\bexec\s*\(`, Explanation: "A direct exec call can run arbitrary code.", Remediation: "Replace dynamic execution with explicit, validated operations.", Executable: true},
	{ID: "AST2", Family: "behavioral_ast", Title: "Dynamic eval call", Category: "Behavioral Code Execution", Severity: "HIGH", Confidence: .90, Expression: `(?m)\beval\s*\(`, Explanation: "A direct eval call can run attacker-controlled expressions.", Remediation: "Use a typed parser for the expected input.", Executable: true},
	{ID: "AST4", Family: "behavioral_ast", Title: "Subprocess execution", Category: "Behavioral Code Execution", Severity: "MEDIUM", Confidence: .75, Expression: `(?m)\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(`, Explanation: "The code launches an external command.", Remediation: "Use fixed argument arrays, validate inputs, and avoid a shell.", Executable: true},
	{ID: "AST3", Family: "behavioral_ast", Title: "Dynamic import", Category: "Behavioral Code Execution", Severity: "HIGH", Confidence: .85, Expression: `(?m)\b(__import__|importlib\.import_module)\s*\(`, Explanation: "A module is selected dynamically at runtime.", Remediation: "Use an explicit import allowlist."},
	{ID: "AST5", Family: "behavioral_ast", Title: "Operating-system command execution", Category: "Behavioral Code Execution", Severity: "HIGH", Confidence: .90, Expression: `(?m)\bos\.(system|exec[a-z]*|popen)\s*\(`, Explanation: "The code invokes an operating-system command primitive.", Remediation: "Use a fixed executable and validated argument array."},
	{ID: "AST6", Family: "behavioral_ast", Title: "Dynamic code compilation", Category: "Behavioral Code Execution", Severity: "HIGH", Confidence: .85, Expression: `(?m)\bcompile\s*\(`, Explanation: "Source text is compiled dynamically.", Remediation: "Parse expected input into a typed representation instead."},
	{ID: "AST7", Family: "behavioral_ast", Title: "Dynamic reflective access", Category: "Behavioral Code Execution", Severity: "MEDIUM", Confidence: .75, Expression: `(?m)\bgetattr\s*\([^,]+,[^"'][^,)]*\)`, Explanation: "A non-literal attribute is accessed dynamically.", Remediation: "Allowlist attribute names before reflective access."},
	{ID: "AST8", Family: "behavioral_ast", Title: "Dynamic execution chain", Category: "Behavioral Code Execution", Severity: "CRITICAL", Confidence: .90, Expression: `(?is)(requests|geturl|b64decode|__import__).{0,500}(exec\s*\(|eval\s*\(|os\.system)`, Explanation: "A dynamic data source is chained into a code-execution sink.", Remediation: "Break the chain and validate data before any privileged operation."},
	{ID: "AST9", Family: "behavioral_ast", Title: "Reflective execution sink", Category: "Behavioral Code Execution", Severity: "CRITICAL", Confidence: .90, Expression: `(?i)getattr\s*\([^,]+,\s*["'](system|exec|eval|popen)["']\s*\)`, Explanation: "Reflection is used to hide an execution primitive.", Remediation: "Remove reflective access to execution sinks."},
	{ID: "TT1", Family: "taint", Title: "Direct unvalidated source-to-sink flow", Category: "Data Exfiltration", Severity: "HIGH", Confidence: .75, Expression: `(?is)(input\s*\(|request\.|read\s*\(|getenv).{0,300}(requests\.(post|put)|exec\s*\(|eval\s*\(|os\.system)`, Explanation: "Untrusted data may flow directly to a sensitive sink.", Remediation: "Validate and constrain the value before it reaches the sink."},
	{ID: "TT2", Family: "taint", Title: "Variable-mediated taint flow", Category: "Data Exfiltration", Severity: "HIGH", Confidence: .70, Expression: `(?is)(user_input|payload|secret|token)\s*=.{0,300}(requests\.(post|put)|fetch\s*\(|subprocess|os\.system)`, Explanation: "A variable may carry untrusted or sensitive data into a sink.", Remediation: "Use typed validation and an explicit allowlist."},
	{ID: "TT4", Family: "taint", Title: "File-content network flow", Category: "Data Exfiltration", Severity: "HIGH", Confidence: .85, Expression: `(?is)(open\s*\(|readFile|os\.ReadFile).{0,500}(requests\.(post|put)|fetch\s*\(|http\.Post)`, Explanation: "File contents may flow to a network sink.", Remediation: "Restrict files and destinations and require user approval."},
	{ID: "TT5", Family: "taint", Title: "External-input execution flow", Category: "Privilege Escalation", Severity: "CRITICAL", Confidence: .90, Expression: `(?is)(request\.|input\s*\(|sys\.argv|process\.argv).{0,500}(exec\s*\(|eval\s*\(|os\.system|shell\s*=\s*true)`, Explanation: "External input may reach a code-execution sink.", Remediation: "Replace dynamic execution with a fixed operation and validated arguments."},
	{ID: "LP1", Family: "mcp_permissions", Title: "Capability exceeds declaration", Category: "MCP Least Privilege", Severity: "HIGH", Confidence: .70, Expression: `(?is)permissions?:.{0,200}(read).{0,500}(requests\.|fetch\s*\(|curl\s)`, Explanation: "Detected behavior may exceed the declared permission set.", Remediation: "Remove the capability or declare and justify it."},
	{ID: "LP2", Family: "mcp_permissions", Title: "Wildcard permission", Category: "MCP Least Privilege", Severity: "CRITICAL", Confidence: .95, Expression: `(?i)(permissions?|capabilities?|allowed-tools)\s*:\s*(\*|all|\[?\s*["']?\*)`, Explanation: "A wildcard grants blanket capability access.", Remediation: "Replace the wildcard with the smallest explicit permission set."},
	{ID: "LP3", Family: "mcp_permissions", Title: "Undeclared operational permission", Category: "MCP Least Privilege", Severity: "HIGH", Confidence: .65, Expression: `(?i)(no permissions|permissions:\s*\[?\s*\]?).{0,500}(subprocess|requests\.|fetch\s*\(|writeFile)`, Explanation: "Operational capabilities are used without manifest declarations.", Remediation: "Declare and justify every detected capability."},
	{ID: "LP4", Family: "mcp_permissions", Title: "Unused permission", Category: "MCP Least Privilege", Severity: "LOW", Confidence: .55, Expression: `(?i)permissions?:.{0,100}(admin|root|write_all|network_all)`, Explanation: "A broad permission may not be required by the visible implementation.", Remediation: "Remove permissions that are not demonstrably used."},
	{ID: "TP1", Family: "mcp_metadata", Title: "Hidden metadata instruction", Category: "MCP Tool Poisoning", Severity: "HIGH", Confidence: .85, Expression: `(?i)(description|trigger|parameter).{0,100}(ignore previous|do not reveal|hidden instruction)`, Explanation: "Tool metadata contains concealed behavioral instructions.", Remediation: "Keep metadata descriptive and remove instructions aimed at the model."},
	{ID: "TP2", Family: "mcp_metadata", Title: "Unicode metadata deception", Category: "MCP Tool Poisoning", Severity: "HIGH", Confidence: .80, Expression: `[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]`, Explanation: "Invisible or direction-changing Unicode can disguise metadata.", Remediation: "Remove control characters and normalize identifiers."},
	{ID: "TP3", Family: "mcp_metadata", Title: "Parameter instruction injection", Category: "MCP Tool Poisoning", Severity: "HIGH", Confidence: .85, Expression: `(?i)(parameter|default|argument).{0,120}(ignore|override|always comply|system prompt)`, Explanation: "Parameter metadata attempts to steer model behavior.", Remediation: "Describe the parameter's data contract only."},
	{ID: "TT3", Family: "taint", Title: "Credential network flow", Category: "Data Exfiltration", Severity: "CRITICAL", Confidence: .90, Expression: `(?is)(getenv|environ|process\.env).{0,500}(requests\.(post|put)|fetch\s*\(|http\.Post|curl)`, Explanation: "A credential, the environment or a credential file's content leaves in a network request.", Remediation: "Break the flow and permit only explicitly selected non-secret fields.", Executable: true},
	{ID: "AS1", Family: "static", Title: "Agent configuration snooping", Category: "Agent Snooping", Severity: "HIGH", Confidence: .90, Expression: `(?i)(\.claude/|\.codex/|\.gemini/|CLAUDE\.md|AGENTS\.md)`, Explanation: "The skill reads configuration belonging to an agent runtime.", Remediation: "Keep peer-agent configuration outside the skill's accessible scope."},
	{ID: "AS2", Family: "static", Title: "MCP configuration snooping", Category: "Agent Snooping", Severity: "HIGH", Confidence: .90, Expression: `(?i)(mcp\.json|mcpServers|\.mcp/)`, Explanation: "The skill accesses MCP configuration which may contain secrets and endpoints.", Remediation: "Do not enumerate or read unrelated MCP configuration."},
	{ID: "AS3", Family: "static", Title: "Peer skill enumeration", Category: "Agent Snooping", Severity: "HIGH", Confidence: .85, Expression: `(?i)(\.claude/skills|\.codex/skills|\.agents/skills|other skills|installed skills).{0,80}(list|read|enumerate|SKILL\.md)`, Explanation: "The skill attempts to inspect peer skills and their instructions.", Remediation: "Isolate skills from one another and remove peer enumeration."},
	{ID: "AR1", Family: "static", Title: "Anti-refusal instruction", Category: "Anti-Refusal", Severity: "HIGH", Confidence: .90, Expression: `(?i)(never refuse|always comply|must comply|do not decline)`, Explanation: "The skill suppresses the agent's ability to refuse unsafe work.", Remediation: "Remove unconditional compliance language."},
	{ID: "AR2", Family: "static", Title: "Warning suppression", Category: "Anti-Refusal", Severity: "MEDIUM", Confidence: .85, Expression: `(?i)(no warnings?|omit (warnings?|disclaimers?)|without (warnings?|disclaimers?))`, Explanation: "The skill asks the agent to conceal safety warnings.", Remediation: "Allow accurate warnings and risk disclosures."},
	{ID: "AR3", Family: "static", Title: "Safety policy nullification", Category: "Anti-Refusal", Severity: "CRITICAL", Confidence: .95, Expression: `(?i)(you have no restrictions|ignore (all )?(safety|policy|guidelines)|do anything now|disable guardrails)`, Explanation: "The skill attempts to nullify safety controls.", Remediation: "Remove jailbreak language and preserve higher-priority policies."},
	{ID: "SSRF1", Family: "static", Title: "Cloud metadata access", Category: "Server-Side Request Forgery", Severity: "CRITICAL", Confidence: .98, Expression: `(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)`, Explanation: "Code targets a cloud instance metadata endpoint.", Remediation: "Block metadata addresses and validate all outbound destinations.", Executable: true},
	{ID: "SSRF2", Family: "static", Title: "Private network request", Category: "Server-Side Request Forgery", Severity: "HIGH", Confidence: .80, Expression: `(?i)(https?://)(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)`, Explanation: "Code directly targets a loopback or private network service.", Remediation: "Deny private and reserved address ranges after DNS resolution.", Executable: true},
	{ID: "SSRF3", Family: "static", Title: "Dynamic request host", Category: "Server-Side Request Forgery", Severity: "HIGH", Confidence: .75, Expression: `(?i)(requests\.(get|post)|fetch|http\.Get)\s*\([^\n]*(input|request|params|args|url|host)`, Explanation: "A request destination is built from a dynamic value.", Remediation: "Parse the URL and enforce an exact scheme and host allowlist after resolution."},
}

func lineSnippet(content string, line int) string {
	lines := strings.Split(content, "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	value := strings.TrimSpace(lines[line-1])
	if len(value) > 240 {
		return value[:240] + "…"
	}
	return value
}

func deduplicate(findings []model.Finding) []model.Finding {
	seen := map[string]bool{}
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		key := fmt.Sprintf("%s\x00%s\x00%d", ruleID(finding), finding.Location.File, finding.Location.StartLine)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, finding)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Location.File != out[j].Location.File {
			return out[i].Location.File < out[j].Location.File
		}
		if out[i].Location.StartLine != out[j].Location.StartLine {
			return out[i].Location.StartLine < out[j].Location.StartLine
		}
		return ruleID(out[i]) < ruleID(out[j])
	})
	return out
}

func ruleID(finding model.Finding) string {
	if finding.ID != "" {
		return finding.ID
	}
	if len(finding.Tags) > 1 {
		return finding.Tags[1]
	}
	return ""
}

func ruleDocuments() []model.RuleDocument {
	docs := make([]model.RuleDocument, 0, len(ruleSpecs)+4)
	seen := map[string]bool{}
	patternByRuleID := map[string]staticPattern{}
	for _, pattern := range allStaticPatterns {
		if _, exists := patternByRuleID[pattern.ID]; !exists {
			patternByRuleID[pattern.ID] = pattern
		}
	}
	for _, patterns := range [][]staticPattern{hiddenInstructionPatterns, harmfulActionPatterns, ssrfPatterns, sc1Patterns} {
		for _, pattern := range patterns {
			if _, exists := patternByRuleID[pattern.ID]; !exists {
				patternByRuleID[pattern.ID] = pattern
			}
		}
	}
	for _, spec := range ruleSpecs {
		if spec.ID == "SC4" && !dependencyAdvisoriesEnabled() {
			continue
		}
		if seen[spec.ID] {
			continue
		}
		seen[spec.ID] = true
		title, category := spec.Title, spec.Category
		if pattern, ok := patternByRuleID[spec.ID]; ok {
			title, category = pattern.Title, pattern.Category
		}
		if canonicalTitle, ok := ruleTitles[spec.ID]; ok {
			title = canonicalTitle
		}
		if strings.HasPrefix(spec.ID, "AST") {
			category = "Security"
		}
		explanation, remediation := ruleText(spec.ID)
		docs = append(docs, model.RuleDocument{
			RuleID: spec.ID, RuleFamily: ruleFamily(spec.ID), Title: title,
			Category: category, Description: explanation, Remediation: remediation,
			DocumentationURL: "/v1/rules/" + spec.ID,
			Frameworks:       frameworksForRule(spec.ID),
		})
	}
	for index, title := range []string{"Malware Signature", "Webshell Detected", "Crypto Miner Detected", "Hack Tool / Exploit Detected", "Prompt Injection Signature"} {
		id := fmt.Sprintf("YR%d", index+1)
		explanation, remediation := yaraRuleText(id)
		docs = append(docs, model.RuleDocument{
			RuleID: id, RuleFamily: "YR", Title: title, Category: "YARA Match",
			Description: explanation, Remediation: remediation,
			DocumentationURL: "/v1/rules/" + id,
			Frameworks:       frameworksForRule(id),
		})
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].RuleID < docs[j].RuleID })
	return docs
}

func ruleFamily(id string) string {
	end := 0
	for end < len(id) {
		char := id[end]
		if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') {
			break
		}
		end++
	}
	return strings.ToUpper(id[:end])
}
