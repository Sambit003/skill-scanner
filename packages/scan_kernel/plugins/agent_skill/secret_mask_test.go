package agentskill

// Fake secrets in these tests are built by concatenation so no file contains
// a string that looks like a real credential.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var (
	fakeAlnum36 = strings.Repeat("Ab12", 9)
	fakeGitHub  = "gh" + "p_" + fakeAlnum36
	fakeAWSID   = "AK" + "IA" + "QWERTYUIOP234567"
	fakeAWSKey  = "wJalrXUtnFEMIK7MDENG" + "bPxRfiCY1234abcdQRST"
	fakeDBPass  = "Tr0ub4dor" + "-and-3"
	fakeNpmAuth = "a1b2c3d4e5f6" + "a7b8c9d0e1f2"
)

func TestMaskSecretsKnownFormats(t *testing.T) {
	for name, test := range map[string]struct{ input, want string }{
		"github ghp":      {"token " + fakeGitHub, "token ghp_***"},
		"github gho":      {"gh" + "o_" + fakeAlnum36, "gho_***"},
		"github ghs":      {"gh" + "s_" + fakeAlnum36, "ghs_***"},
		"github ghu":      {"gh" + "u_" + fakeAlnum36, "ghu_***"},
		"github ghr":      {"gh" + "r_" + fakeAlnum36, "ghr_***"},
		"github pat":      {"github" + "_pat_" + "11ABCDEFG0" + fakeAlnum36, "github_pat_***"},
		"aws akia":        {"id " + fakeAWSID + " end", "id AKIA*** end"},
		"aws asia":        {"AS" + "IA" + "QWERTYUIOP234567", "ASIA***"},
		"openai sk":       {"s" + "k-proj-" + "Ab12Cd34Ef56Gh78Ij90Kl", "sk-***"},
		"anthropic":       {"s" + "k-ant-" + "api03-" + fakeAlnum36, "sk-ant-***"},
		"stripe sk_live":  {"s" + "k_live_" + "Ab12Cd34Ef56", "sk_live_***"},
		"stripe rk_live":  {"r" + "k_live_" + "Ab12Cd34Ef56", "rk_live_***"},
		"slack":           {"xo" + "xb-" + "1234567890-abcdefghij", "xoxb-***"},
		"gitlab":          {"gl" + "pat-" + "Ab12Cd34Ef56Gh78Ij90", "glpat-***"},
		"npm":             {"np" + "m_" + fakeAlnum36, "npm_***"},
		"google":          {"AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q", "AIza***"},
		"jwt":             {"ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0." + "abcDEF123456ghi", "eyJ***"},
		"url password":    {"postgres://admin:" + fakeDBPass + "@db.internal:5432/app", "postgres://admin:***@db.internal:5432/app"},
		"env assignment":  {"AWS_SECRET_ACCESS_KEY=" + fakeAWSKey, "AWS_SECRET_ACCESS_KEY=***"},
		"quoted env":      {"DB_PASSWORD=\"" + fakeDBPass + "\"", "DB_PASSWORD=\"***\""},
		"yaml":            {"  password: " + fakeDBPass, "  password: ***"},
		"json":            {"\"api_key\": \"abc123" + "def456\"", "\"api_key\": \"***\""},
		"python literal":  {"client_secret = 'Zx81" + "Qw72Er63'", "client_secret = '***'"},
		"npmrc":           {"//registry.npmjs.org/:_authToken=" + fakeNpmAuth, "//registry.npmjs.org/:_authToken=***"},
		"authorization":   {"Authorization: Bearer abc123" + "def456ghi", "Authorization: Bearer ***"},
		"go short decl":   {"token := \"A1b2C3" + "d4E5\"", "token := \"***\""},
		"camel case":      {"apiKey: 'Q9w8e7" + "r6t5y4'", "apiKey: '***'"},
		"prefix kept":     {"GITHUB_TOKEN=" + fakeGitHub, "GITHUB_TOKEN=ghp_***"},
		"bearer in curl":  {"curl -H \"Authorization: Bearer " + fakeAlnum36 + "\" https://api.example.com", "curl -H \"Authorization: Bearer ***\" https://api.example.com"},
		"unquoted letter": {"SECRET_KEY=supersecret" + "valueonly", "SECRET_KEY=***"},
		// alirezarezvani/claude-skills session-handoff/scripts/redaction_linter.py
		"escaped newline": {"\"PASSWORD=hunter2super" + "secret\\n\"", "\"PASSWORD=***\\n\""},
	} {
		if got := maskSecrets(test.input, false); got != test.want {
			t.Errorf("%s: maskSecrets(%q)=%q, want %q", name, test.input, got, test.want)
		}
	}
}

func TestMaskSecretsPrivateKeyBlocks(t *testing.T) {
	body1, body2 := "MIIEowIBAAKCAQEA"+fakeAlnum36, "q83kZp0"+fakeAlnum36+"Lm"
	begin, end := "-----BEGIN RSA PRIVATE "+"KEY-----", "-----END RSA PRIVATE "+"KEY-----"
	block := "key = \"\"\"\n" + begin + "\n" + body1 + "\n  " + body2 + "\n" + end + "\n\"\"\""
	want := "key = \"\"\"\n" + begin + "\n***\n  ***\n" + end + "\n\"\"\""
	if got := maskSecrets(block, true); got != want {
		t.Errorf("block:\n%s\nwant:\n%s", got, want)
	}
	// A snippet that starts inside the block.
	if got, want := maskSecrets(body2+"\n"+end+"\nnext = 1", false), "***\n"+end+"\nnext = 1"; got != want {
		t.Errorf("cut block=%q, want %q", got, want)
	}
	// A snippet that ends inside the block.
	if got, want := maskSecrets("x = 1\n"+begin+"\n"+body1, false), "x = 1\n"+begin+"\n***"; got != want {
		t.Errorf("open block=%q, want %q", got, want)
	}
	inline := "PEM = \"" + begin + "\\n" + body1 + "\\n" + end + "\""
	if got, want := maskSecrets(inline, true), "PEM = \""+begin+"***"+end+"\""; got != want {
		t.Errorf("inline block=%q, want %q", got, want)
	}
}

func TestMaskSecretsKeepsReferencesAndPlaceholders(t *testing.T) {
	for _, test := range []struct {
		text string
		code bool
	}{
		{"api_key = os.environ[\"API_KEY\"]", true},
		{"api_key = os.getenv(\"API_KEY\")", true},
		{"const token = process.env.GITHUB_TOKEN;", true},
		{"api_key = get_api_key()", true},
		{"token = args.token", true},
		{"self.api_key = api_key", true},
		{"def login(password: str, token: Optional[str] = None):", true},
		{"headers = {\"Authorization\": f\"Bearer {token}\"}", true},
		{"TOKEN=$GITHUB_TOKEN", false},
		{"TOKEN=${GITHUB_TOKEN}", false},
		{"password: \"{{ secrets.DB_PASSWORD }}\"", false},
		{"API_KEY=<your-key>", false},
		{"API_KEY=your-api-key-here", false},
		{"OPENAI_API_KEY=sk-...", false},
		{"password: changeme", false},
		{"password: \"\"", false},
		{"TOKEN_ENV = \"GITHUB_TOKEN\"", false},
		{"max_tokens=1024", false},
		{"author: Jane Doe", false},
		{"keywords: [security, audit]", false},
		{"auth_url: https://auth.example.com/oauth/token", false},
		{"credentials_file: ~/.aws/credentials", false},
		{"auth_timeout: 30", false},
		{"NODE_TLS_REJECT_UNAUTHORIZED=0", false},
		{"DOCKER_CONTENT_TRUST=0", false},
		{"DATABASE_URL=postgres://app:${DB_PASS}@db.internal/app", false},
		{"Bearer tokens are short-lived.", false},
		{"Key: Use the API key from the dashboard.", false},
		{"if token == expected:", true},
		{"sk-learn-style-kebab-case-identifier-name", false},
	} {
		if got := maskSecrets(test.text, test.code); got != test.text {
			t.Errorf("maskSecrets(%q)=%q, want unchanged", test.text, got)
		}
	}
}

func TestEnvironmentFileSecretsNeverReachTheReport(t *testing.T) {
	root := t.TempDir()
	skill := filepath.Join(root, "skills", "deploy-helper")
	env := strings.Join([]string{
		"AWS_ACCESS_KEY_ID=" + fakeAWSID,
		"AWS_SECRET_ACCESS_KEY=" + fakeAWSKey,
		"GITHUB_TOKEN=" + fakeGitHub,
		"NODE_TLS_REJECT_UNAUTHORIZED=0",
		"DOCKER_CONTENT_TRUST=0",
		"DATABASE_URL=postgres://app:" + fakeDBPass + "@db.internal:5432/app",
		"DB_PASSWORD=" + fakeDBPass,
	}, "\n") + "\n"
	for name, content := range map[string]string{
		"SKILL.md": blindSpotFrontmatter + "Load .env before deploying.\n",
		".env":     env,
	} {
		if err := os.MkdirAll(skill, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(skill, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result, err := New().Scan(context.Background(), model.ScanRequest{Target: root, AssetType: "skill", Offline: true,
		OutputFormats: []string{"json", "markdown", "sarif", "terminal"}, TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(result.Findings, "TM3") {
		t.Fatalf("probe did not trigger TM3: %#v", result.Findings)
	}
	output, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		output = append(output, finding.MatchedText...)
	}
	for _, secret := range []string{fakeAWSID, fakeAWSKey, fakeGitHub, fakeDBPass} {
		if strings.Contains(string(output), secret) {
			t.Errorf("secret %q reached the scan output", secret[:6]+"...")
		}
	}
	if !strings.Contains(string(output), "AWS_SECRET_ACCESS_KEY=***") {
		t.Error("masked output should keep the key name")
	}
}

func TestMaskingLeavesFindingsAndScoresUnchanged(t *testing.T) {
	components, _, err := readComponents(testFixture(t, "malicious_skill"))
	if err != nil {
		t.Fatal(err)
	}
	components = append(components, component{Path: ".env", Type: "other", Content: "NODE_TLS_REJECT_UNAUTHORIZED=0\nGITHUB_TOKEN=" + fakeGitHub + "\nDB_PASSWORD=" + fakeDBPass + "\n"})
	findings, err := analyzeSourceAndManifest(context.Background(), components, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	before := append([]model.Finding(nil), findings...)
	after := maskFindingSecrets(append([]model.Finding(nil), findings...))
	if len(after) != len(before) {
		t.Fatalf("masking changed the finding count: %d -> %d", len(before), len(after))
	}
	masked := 0
	for index := range before {
		b, a := before[index], after[index]
		if a.ID != b.ID || !reflect.DeepEqual(a.Location, b.Location) || a.Severity != b.Severity || a.Confidence != b.Confidence ||
			a.Category != b.Category || a.Pattern != b.Pattern || !reflect.DeepEqual(a.Tags, b.Tags) {
			t.Errorf("masking changed finding %d: %#v -> %#v", index, b, a)
		}
		if a.CodeSnippet != b.CodeSnippet {
			masked++
		}
	}
	if masked == 0 {
		t.Error("expected the .env snippet to be masked")
	}
	if got, want := summarize(after, components), summarize(before, components); !reflect.DeepEqual(got, want) {
		t.Errorf("masking changed the summary: %#v -> %#v", want, got)
	}
}

func TestMaskSecretsAvoidsCorpusOverMasking(t *testing.T) {
	for _, test := range []struct {
		text string
		code bool
	}{
		// Jeffallan/claude-skills code-documenter/references/user-guides-tutorials.md
		{"const client = new Client({ accessToken: tokens.access_token });", false},
		// alirezarezvani/claude-skills pr-review-expert/SKILL.md
		{": \"${LINEAR_API_KEY:?LINEAR_API_KEY must be set}\"", false},
		// alirezarezvani/claude-skills threat-detection/scripts/threat_signal_analyzer.py
		{"\"mimikatz\": {\"tactic\": \"credential_access\", \"data_source_key\": \"credential_access\"},", true},
		// anthropics/skills claude-api/SKILL.md
		{"(OAuth tokens go on `Authorization: Bearer`, not `x-api-key:`", false},
		// AWS documentation's example access key id.
		{"Allowed: AK" + "IAIOSFODNN7EXAMPLE", false},
		{"primary_key: id", false},
	} {
		if got := maskSecrets(test.text, test.code); got != test.text {
			t.Errorf("maskSecrets(%q)=%q, want unchanged", test.text, got)
		}
	}
	// alirezarezvani/claude-skills session-handoff/scripts/redaction_linter.py:
	// an assignment inside a Python string literal is text, not code.
	if got, want := maskSecrets("    \"PASSWORD=hunter2super"+"secret\\n\"", true), "    \"PASSWORD=***\\n\""; got != want {
		t.Errorf("assignment in a string literal=%q, want %q", got, want)
	}
	// A weak "...key" name still masks a random-looking value.
	if got, want := maskSecrets("cache_key: \"Zq81"+"Xw72Ve63\"", false), "cache_key: \"***\""; got != want {
		t.Errorf("weak key with random value=%q, want %q", got, want)
	}
}

var fakePassword = "Sup3rS3" + "cretPw9"

func TestMaskSecretsCommandLineAndFileForms(t *testing.T) {
	for name, test := range map[string]struct{ input, want string }{
		"curl -u":          {"curl -u admin:" + fakePassword + " https://api.example.com", "curl -u admin:*** https://api.example.com"},
		"curl --user=":     {"curl --user='admin:" + fakePassword + "' https://api.example.com", "curl --user='admin:***' https://api.example.com"},
		"mysql -p":         {"mysql -u root -p" + fakePassword + " prod", "mysql -u root -p*** prod"},
		"mysqldump -p'":    {"mysqldump -h db -u app -p'" + fakePassword + "' app > dump.sql", "mysqldump -h db -u app -p'***' app > dump.sql"},
		"--password":       {"deploy --password " + fakePassword, "deploy --password ***"},
		"--token=":         {"cli login --token=" + fakePassword, "cli login --token=***"},
		"--api-key quoted": {"tool --api-key \"" + fakePassword + "\" run", "tool --api-key \"***\" run"},
		"--client-secret":  {"az login --client-secret " + fakePassword, "az login --client-secret ***"},
		"sshpass":          {"sshpass -p '" + fakePassword + "' ssh deploy@host", "sshpass -p '***' ssh deploy@host"},
		"netrc one line":   {"machine api.example.com login admin password " + fakePassword, "machine api.example.com login admin password ***"},
		"netrc two lines":  {"machine api.example.com\n  login admin\n  password " + fakePassword, "machine api.example.com\n  login admin\n  password ***"},
		"auth token":       {"Authorization: token " + fakePassword, "Authorization: token ***"},
		"auth apikey":      {"-H 'Authorization: ApiKey " + fakePassword + "'", "-H 'Authorization: ApiKey ***'"},
		"auth bearer word": {"Authorization: Bearer abcdefghijkl", "Authorization: Bearer ***"},
		"hugging face":     {"HF=" + "hf" + "_" + fakeAlnum36, "HF=hf_***"},
		"sendgrid":         {"SG" + ".Ab12Cd34Ef56Gh78Ij." + "Kl90Mn12Op34Qr56St78", "SG.***"},
		"slack webhook":    {"https://hooks.slack.com/services/T01ABCDEF/B02GHIJKL/" + "Ab12Cd34Ef56Gh78Ij90Kl12", "https://hooks.slack.com/services/T01ABCDEF/B02GHIJKL/***"},
		"discord webhook":  {"https://discord.com/api/webhooks/123456789012345678/" + fakeAlnum36 + "Xy_z-", "https://discord.com/api/webhooks/123456789012345678/***"},
		"telegram url":     {"https://api.telegram.org/bot123456789:" + "AAH" + "dQwlNhJ5aBcDeFgHiJkLmNoPqRsTuVw1" + "/sendMessage", "https://api.telegram.org/bot123456789:***/sendMessage"},
		"telegram bare":    {"BOT=123456789:" + "AAH" + "dQwlNhJ5aBcDeFgHiJkLmNoPqRsTuVw1", "BOT=123456789:***"},
		"sentry dsn":       {"dsn: https://" + strings.Repeat("0a1b2c3d", 4) + "@o123456.ingest.sentry.io/4504", "dsn: https://***@o123456.ingest.sentry.io/4504"},
	} {
		if got := maskSecrets(test.input, false); got != test.want {
			t.Errorf("%s: maskSecrets(%q)=%q, want %q", name, test.input, got, test.want)
		}
	}
}

func TestMaskSecretsCommandLineGuards(t *testing.T) {
	for _, text := range []string{
		"docker run -p 8080:8080 app",
		"ssh -p 2222 deploy@host",
		"mysql -h db -P 3306 -u root -p appdb",
		"mysqldump -u app -p\"$DB_PASSWORD\" app",
		"gh auth login --token-file ~/.config/gh/token",
		"docker login --password-stdin",
		"curl -u \"$USER:$PASS\" https://api.example.com",
		"curl -u admin https://api.example.com",
		"docker run -u 1000:1000 app",
		"docker build --secret id=npmrc,src=$HOME/.npmrc .",
		"deploy --token $DEPLOY_TOKEN --verbose",
		"deploy --password --interactive",
		"Authorization: token $GITHUB_TOKEN",
		"Authorization: Bearer <token>",
		"Please login with your password to continue.",
		"The admin password is hunter2X, rotate it monthly.",
		"Meeting at 12:30 about the 123456789 rollout.",
		// alirezarezvani/claude-skills: a documented .netrc placeholder.
		"> (`machine your-org.atlassian.net login user@company.com password <token>`,",
	} {
		if got := maskSecrets(text, false); got != text {
			t.Errorf("maskSecrets(%q)=%q, want unchanged", text, got)
		}
	}
}

func TestCredentialsInScriptsNeverReachTheReport(t *testing.T) {
	root := t.TempDir()
	skill := filepath.Join(root, "skills", "deploy-helper")
	credentials := []string{
		"curl -u admin:" + fakePassword + " https://api.example.com/deploy",
		"mysql -u root -p" + fakePassword + " prod < schema.sql",
		"deploy --password " + fakePassword,
		"sshpass -p '" + fakePassword + "' ssh deploy@host",
		"echo 'machine api.example.com login admin password " + fakePassword + "' > ~/.netrc",
		"curl -H 'Authorization: token " + fakePassword + "' https://api.example.com",
	}
	script := "#!/bin/sh\n"
	for _, line := range credentials {
		script += "export NODE_TLS_REJECT_UNAUTHORIZED=0\n" + line + "\n# next step\n"
	}
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"SKILL.md": blindSpotFrontmatter + "Run deploy.sh.\n", "deploy.sh": script} {
		if err := os.WriteFile(filepath.Join(skill, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result, err := New().Scan(context.Background(), model.ScanRequest{Target: root, AssetType: "skill", Offline: true,
		OutputFormats: []string{"json", "markdown", "sarif", "terminal"}, TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if countRule(result.Findings, "TM3") == 0 {
		t.Fatalf("probe did not trigger TM3: %#v", result.Findings)
	}
	output, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), fakePassword) {
		t.Errorf("a script credential reached the scan output")
	}
}

func TestMaskSecretsHighEntropyBackstop(t *testing.T) {
	random := "q7Hk2Vz9" + "Lw4Rt8Bn" + "3Xc6Mp1D" + "s5Gy0FjE"
	if got, want := maskSecrets("Use the staging token "+random+" for the deploy.", false), "Use the staging token *** for the deploy."; got != want {
		t.Errorf("backstop=%q, want %q", got, want)
	}
	for _, text := range []string{
		// No credential word on the line.
		"Build " + random + " finished.",
		// Lower-case hex (commit or content hashes) and low-entropy strings.
		"token rotated in commit 3f9c2a7e1b4d8c6f0a2e5b7d9c1f3a5e7b9d0c2e",
		"auth fixture AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1a",
	} {
		if got := maskSecrets(text, false); got != text {
			t.Errorf("maskSecrets(%q)=%q, want unchanged", text, got)
		}
	}
}
