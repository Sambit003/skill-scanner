package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/engine"
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

type rawRequest struct {
	Operation       string   `json:"operation"`
	ProtocolVersion string   `json:"protocol_version"`
	Target          string   `json:"target,omitempty"`
	AssetType       string   `json:"asset_type,omitempty"`
	OutputFormats   []string `json:"output_formats,omitempty"`
	TimeoutSeconds  float64  `json:"timeout_seconds,omitempty"`
	RuleID          string   `json:"rule_id,omitempty"`
}

type Envelope struct {
	ProtocolVersion string         `json:"protocol_version"`
	OK              bool           `json:"ok"`
	Result          any            `json:"result,omitempty"`
	Error           *ProtocolError `json:"error,omitempty"`
}

type ProtocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func Execute(parent context.Context, registry *engine.Registry, raw []byte) (Envelope, int) {
	request, err := decode(raw)
	if err != nil {
		return failure("INVALID_REQUEST", err.Error()), 2
	}
	switch request.Operation {
	case "list_rules":
		return success(map[string]any{"kind": "rules", "items": registry.Rules()}), 0
	case "get_rule":
		rule, exists := registry.Rule(request.RuleID)
		if !exists {
			return failure("INVALID_REQUEST", "rule documentation is not available"), 2
		}
		return success(map[string]any{"kind": "rule", "rule": rule}), 0
	case "scan":
		ctx, cancel := context.WithTimeout(parent, time.Duration(request.TimeoutSeconds*float64(time.Second)))
		defer cancel()
		result, err := registry.Scan(ctx, model.ScanRequest{Target: request.Target, AssetType: request.AssetType,
			OutputFormats: request.OutputFormats, TimeoutSeconds: request.TimeoutSeconds})
		if err == nil {
			return success(result), 0
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return failure("TIMEOUT", "Scanner execution timed out"), 3
		}
		if strings.Contains(err.Error(), "no plugin compiled") {
			return failure("UNSUPPORTED_ASSET_TYPE", err.Error()), 2
		}
		return failure("SCAN_FAILED", err.Error()), 3
	default:
		return failure("INVALID_REQUEST", fmt.Sprintf("unsupported operation %q", request.Operation)), 2
	}
}

func Serve(ctx context.Context, registry *engine.Registry, input io.Reader, output, diagnostic io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(input, 10*1024*1024+1))
	if err != nil {
		return write(output, failure("INVALID_REQUEST", err.Error()), 2)
	}
	if len(raw) > 10*1024*1024 {
		return write(output, failure("INVALID_REQUEST", "request exceeds 10 MiB"), 2)
	}
	envelope, exitCode := Execute(ctx, registry, raw)
	if exitCode == 3 && envelope.Error != nil {
		fmt.Fprintf(diagnostic, "ScanKernel execution failed: %s\n", envelope.Error.Message)
	}
	return write(output, envelope, exitCode)
}

func decode(raw []byte) (rawRequest, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request rawRequest
	if err := decoder.Decode(&request); err != nil {
		return rawRequest{}, fmt.Errorf("invalid JSON request: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return rawRequest{}, errors.New("request must contain exactly one JSON value")
	}
	if request.ProtocolVersion != model.ProtocolVersion {
		return rawRequest{}, fmt.Errorf("protocol_version must be %q", model.ProtocolVersion)
	}
	switch request.Operation {
	case "scan":
		if strings.TrimSpace(request.Target) == "" || strings.TrimSpace(request.AssetType) == "" {
			return rawRequest{}, errors.New("scan requires non-empty target and asset_type")
		}
		if request.TimeoutSeconds <= 0 || request.TimeoutSeconds > 3600 {
			return rawRequest{}, errors.New("timeout_seconds must be greater than 0 and at most 3600")
		}
		if len(request.OutputFormats) == 0 {
			return rawRequest{}, errors.New("output_formats must not be empty")
		}
		seen := map[string]bool{}
		for _, format := range request.OutputFormats {
			if seen[format] || (format != "json" && format != "markdown" && format != "sarif" && format != "terminal") {
				return rawRequest{}, fmt.Errorf("invalid or duplicate output format %q", format)
			}
			seen[format] = true
		}
		if request.RuleID != "" {
			return rawRequest{}, errors.New("scan does not accept rule_id")
		}
	case "list_rules":
		if request.Target != "" || request.AssetType != "" || request.OutputFormats != nil || request.TimeoutSeconds != 0 || request.RuleID != "" {
			return rawRequest{}, errors.New("list_rules accepts only operation and protocol_version")
		}
	case "get_rule":
		if strings.TrimSpace(request.RuleID) == "" {
			return rawRequest{}, errors.New("get_rule requires rule_id")
		}
		if request.Target != "" || request.AssetType != "" || request.OutputFormats != nil || request.TimeoutSeconds != 0 {
			return rawRequest{}, errors.New("get_rule accepts only operation, protocol_version, and rule_id")
		}
	default:
		return rawRequest{}, fmt.Errorf("unsupported operation %q", request.Operation)
	}
	return request, nil
}

func success(result any) Envelope {
	return Envelope{ProtocolVersion: model.ProtocolVersion, OK: true, Result: result}
}

func failure(code, message string) Envelope {
	return Envelope{ProtocolVersion: model.ProtocolVersion, OK: false, Error: &ProtocolError{Code: code, Message: message}}
}

func write(output io.Writer, envelope Envelope, exitCode int) int {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(envelope); err != nil {
		return 3
	}
	return exitCode
}
