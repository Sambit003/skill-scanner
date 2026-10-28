package model

import (
	"context"
	"encoding/json"
	"time"
)

const (
	LegacyProtocolVersion = "1"
	ProtocolVersion       = "2"
	ScanScopeSkillFiles   = "skill_files"
	ScanScopeSkillFolders = "skill_folders"
	ScanScopeRepository   = "repository"
)

type ScanRequest struct {
	Target         string   `json:"target"`
	AssetType      string   `json:"asset_type"`
	OutputFormats  []string `json:"output_formats"`
	TimeoutSeconds float64  `json:"timeout_seconds"`
	YARARulesDir   string   `json:"-"`
	BaselinePath   string   `json:"-"`
	ShowSuppressed bool     `json:"-"`
	Recursive      bool     `json:"-"`
	Offline        bool     `json:"-"`
	ScanScope      string   `json:"-"`
	IncludeReadme  bool     `json:"-"`
	// ListCapabilities moves capability findings into ScanResult.Capabilities.
	// Without it the findings keep their pre-capabilities shape, for
	// protocol clients that have not opted in.
	ListCapabilities bool `json:"-"`
}

type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   *int   `json:"end_line"`
}

type FrameworkMappings struct {
	MappingVersion string   `json:"mapping_version"`
	OwaspAgentic   []string `json:"owasp_agentic"`
	OwaspLLM       []string `json:"owasp_llm"`
	NistGaiRisks   []string `json:"nist_gai_risks"`
	NistRmf        []string `json:"nist_rmf"`
}

func (fm *FrameworkMappings) Normalize() {
	if fm.OwaspAgentic == nil {
		fm.OwaspAgentic = []string{}
	}
	if fm.OwaspLLM == nil {
		fm.OwaspLLM = []string{}
	}
	if fm.NistGaiRisks == nil {
		fm.NistGaiRisks = []string{}
	}
	if fm.NistRmf == nil {
		fm.NistRmf = []string{}
	}
}

type Finding struct {
	ID          string            `json:"id"`
	Category    string            `json:"category"`
	Pattern     string            `json:"pattern,omitempty"`
	Severity    string            `json:"severity"`
	Confidence  float64           `json:"confidence"`
	Location    Location          `json:"location"`
	Finding     string            `json:"finding,omitempty"`
	MatchedText string            `json:"-"`
	Explanation string            `json:"explanation,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	CodeSnippet string            `json:"code_snippet,omitempty"`
	Intent      string            `json:"intent,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Frameworks  FrameworkMappings `json:"frameworks"`
}

// MarshalJSON preserves the scanner's stable finding wire shape. Empty
// optional strings are represented as explicit null values rather than omitted
// keys, and intent remains null because the deterministic pipeline does not
// synthesize analyst intent.
func (finding Finding) MarshalJSON() ([]byte, error) {
	tags := finding.Tags
	if tags == nil {
		tags = []string{}
	}
	frameworks := finding.Frameworks
	frameworks.Normalize()
	type findingJSON struct {
		ID          string            `json:"id"`
		Category    string            `json:"category"`
		Pattern     *string           `json:"pattern"`
		Severity    string            `json:"severity"`
		Confidence  float64           `json:"confidence"`
		Location    Location          `json:"location"`
		Finding     *string           `json:"finding"`
		Explanation *string           `json:"explanation"`
		Remediation *string           `json:"remediation"`
		CodeSnippet *string           `json:"code_snippet"`
		Intent      *string           `json:"intent"`
		Tags        []string          `json:"tags"`
		Frameworks  FrameworkMappings `json:"frameworks"`
	}
	return json.Marshal(findingJSON{
		ID: finding.ID, Category: finding.Category, Pattern: optionalString(finding.Pattern), Severity: finding.Severity,
		Confidence: finding.Confidence, Location: finding.Location, Finding: optionalString(finding.Finding),
		Explanation: optionalString(finding.Explanation), Remediation: optionalString(finding.Remediation),
		CodeSnippet: optionalString(finding.CodeSnippet), Intent: optionalString(finding.Intent), Tags: tags,
		Frameworks: frameworks,
	})
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

type Summary struct {
	RiskScore          int            `json:"risk_score"`
	VulnerabilityScore int            `json:"vulnerability_score"`
	ExposureScore      float64        `json:"exposure_score"`
	Severity           string         `json:"severity"`
	Recommendation     string         `json:"recommendation"`
	SafeToInstall      bool           `json:"safe_to_install"`
	FindingsCount      int            `json:"findings_count"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	FindingsByCategory map[string]int `json:"findings_by_category"`
	ScannerVersion     string         `json:"scanner_version"`
	ScanMode           string         `json:"scan_mode"`
	ScanScope          string         `json:"scan_scope,omitempty"`
	IncludeReadme      *bool          `json:"include_readme,omitempty"`
}

type Report struct {
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
}

// Capability is something the scanned skill can do, such as running shell
// commands or reading environment variables. Capabilities are listed apart
// from findings: they are not counted as findings, and the risk score is the
// same with or without the list.
type Capability struct {
	RuleID   string   `json:"rule_id"`
	Label    string   `json:"label"`
	Location Location `json:"location"`
	Snippet  string   `json:"snippet,omitempty"`
}

type ScanResult struct {
	Kind         string            `json:"kind"`
	Summary      Summary           `json:"summary"`
	Findings     []Finding         `json:"findings"`
	Capabilities []Capability      `json:"capabilities,omitempty"`
	Reports      map[string]Report `json:"reports"`
}

type RuleDocument struct {
	RuleID           string            `json:"rule_id"`
	RuleFamily       string            `json:"rule_family"`
	Title            string            `json:"title"`
	Category         string            `json:"category"`
	Description      string            `json:"description"`
	Remediation      string            `json:"remediation"`
	DocumentationURL string            `json:"documentation_url"`
	Frameworks       FrameworkMappings `json:"frameworks"`
}

type PluginDescriptor struct {
	ID                  string   `json:"id"`
	Aliases             []string `json:"aliases"`
	Version             string   `json:"version"`
	SupportedExtensions []string `json:"supported_extensions"`
}

type AssetPlugin interface {
	Descriptor() PluginDescriptor
	Scan(context.Context, ScanRequest) (ScanResult, error)
	Rules() []RuleDocument
}

type BuildInfo struct {
	Version         string   `json:"version"`
	Commit          string   `json:"commit"`
	BuildTime       string   `json:"build_time"`
	GoVersion       string   `json:"go_version"`
	ProtocolVersion string   `json:"protocol_version"`
	Target          string   `json:"target"`
	Plugins         []string `json:"plugins"`
	YARAMode        string   `json:"yara_mode"`
	YARAVersion     string   `json:"yara_version"`
	YARAModules     []string `json:"yara_modules"`
}

func Timeout(request ScanRequest) time.Duration {
	return time.Duration(request.TimeoutSeconds * float64(time.Second))
}
