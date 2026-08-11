package buildinfo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDistributionMetadataExcludesInternalValidationFields(t *testing.T) {
	payload, err := json.Marshal(Current([]string{"agent_skill"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, internalField := range []string{"parity_reference", "parity_certified"} {
		if strings.Contains(string(payload), internalField) {
			t.Fatalf("distribution metadata contains internal parity marker %q: %s", internalField, payload)
		}
	}
}
