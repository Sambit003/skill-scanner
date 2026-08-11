package protocol_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/bundle"
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/protocol"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(source), "..", "..", "testdata", name)
}

func execute(t *testing.T, request map[string]any) (protocol.Envelope, int) {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Execute(context.Background(), bundle.Registry(), raw)
}

func TestProtocolSmoke(t *testing.T) {
	envelope, code := execute(t, map[string]any{"operation": "scan", "protocol_version": "1", "target": fixture(t, "safe_skill"),
		"asset_type": "skill", "output_formats": []string{"json", "sarif"}, "timeout_seconds": 10})
	if code != 0 || !envelope.OK {
		t.Fatalf("scan failed: code=%d envelope=%+v", code, envelope)
	}
	raw, err := json.Marshal(envelope)
	if err != nil || !json.Valid(raw) {
		t.Fatalf("invalid envelope: %v", err)
	}
}

func TestContractRejectsInvalidRequests(t *testing.T) {
	requests := [][]byte{
		[]byte(`{"operation":"list_rules","protocol_version":"1","extra":true}`),
		[]byte(`{"operation":"scan","protocol_version":"1","target":"x","asset_type":"skill","output_formats":["json","json"],"timeout_seconds":10}`),
		[]byte(`{"operation":"scan","protocol_version":"2","target":"x","asset_type":"skill","output_formats":["json"],"timeout_seconds":10}`),
	}
	for _, request := range requests {
		envelope, code := protocol.Execute(context.Background(), bundle.Registry(), request)
		if code != 2 || envelope.OK || envelope.Error == nil || envelope.Error.Code != "INVALID_REQUEST" {
			t.Fatalf("expected INVALID_REQUEST for %s: code=%d envelope=%+v", request, code, envelope)
		}
	}
}

func TestMetadataOperations(t *testing.T) {
	list, code := execute(t, map[string]any{"operation": "list_rules", "protocol_version": "1"})
	if code != 0 || !list.OK {
		t.Fatalf("list_rules failed: %+v", list)
	}
	rule, code := execute(t, map[string]any{"operation": "get_rule", "protocol_version": "1", "rule_id": "P1"})
	if code != 0 || !rule.OK {
		t.Fatalf("get_rule failed: %+v", rule)
	}
}

func TestServeWritesOnlyEnvelope(t *testing.T) {
	request := bytes.NewBufferString(`{"operation":"list_rules","protocol_version":"1"}`)
	var output, diagnostic bytes.Buffer
	if code := protocol.Serve(context.Background(), bundle.Registry(), request, &output, &diagnostic); code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	decoder := json.NewDecoder(&output)
	var envelope protocol.Envelope
	if err := decoder.Decode(&envelope); err != nil || !envelope.OK {
		t.Fatalf("decode response: %v %+v", err, envelope)
	}
}
