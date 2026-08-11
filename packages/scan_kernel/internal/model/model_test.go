package model

import (
	"encoding/json"
	"testing"
)

func TestFindingJSONPreservesNullableFields(t *testing.T) {
	raw, err := json.Marshal(Finding{
		ID: "LP3", Category: "MCP Least Privilege", Severity: "MEDIUM", Confidence: .7,
		Location: Location{File: "SKILL.md", StartLine: 1}, Tags: []string{"ASI02"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"pattern", "finding", "explanation", "remediation", "code_snippet", "intent"} {
		value, exists := payload[field]
		if !exists || value != nil {
			t.Errorf("%s=%#v exists=%v, want explicit null", field, value, exists)
		}
	}
	location := payload["location"].(map[string]any)
	if value, exists := location["end_line"]; !exists || value != nil {
		t.Errorf("end_line=%#v exists=%v, want explicit null", value, exists)
	}
}
