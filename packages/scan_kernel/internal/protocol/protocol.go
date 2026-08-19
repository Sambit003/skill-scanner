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
	ScanScope       *string  `json:"scan_scope,omitempty"`
	IncludeReadme   *bool    `json:"include_readme,omitempty"`
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
	errorVersion := model.ProtocolVersion
	var versionProbe struct {
		ProtocolVersion string `json:"protocol_version"`
	}
	if json.Unmarshal(raw, &versionProbe) == nil && (versionProbe.ProtocolVersion == model.LegacyProtocolVersion || versionProbe.ProtocolVersion == model.ProtocolVersion) {
		errorVersion = versionProbe.ProtocolVersion
	}
	request, err := decode(raw)
	if err != nil {
		return failure(errorVersion, "INVALID_REQUEST", err.Error()), 2
	}
	switch request.Operation {
	case "list_rules":
		return success(request.ProtocolVersion, map[string]any{"kind": "rules", "items": registry.Rules()}), 0
	case "get_rule":
		rule, exists := registry.Rule(request.RuleID)
		if !exists {
			return failure(request.ProtocolVersion, "INVALID_REQUEST", "rule documentation is not available"), 2
		}
		return success(request.ProtocolVersion, map[string]any{"kind": "rule", "rule": rule}), 0
	case "scan":
		ctx, cancel := context.WithTimeout(parent, time.Duration(request.TimeoutSeconds*float64(time.Second)))
		defer cancel()
		scope, includeReadme := model.ScanScopeRepository, true
		if request.ProtocolVersion == model.ProtocolVersion {
			scope, includeReadme = *request.ScanScope, *request.IncludeReadme
		}
		result, err := registry.Scan(ctx, model.ScanRequest{Target: request.Target, AssetType: request.AssetType,
			OutputFormats: request.OutputFormats, TimeoutSeconds: request.TimeoutSeconds,
			ScanScope: scope, IncludeReadme: includeReadme})
		if err == nil {
			if request.ProtocolVersion == model.LegacyProtocolVersion {
				result.Summary.ScanScope = ""
				result.Summary.IncludeReadme = nil
			}
			return success(request.ProtocolVersion, result), 0
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return failure(request.ProtocolVersion, "TIMEOUT", "Scanner execution timed out"), 3
		}
		if strings.Contains(err.Error(), "no plugin compiled") {
			return failure(request.ProtocolVersion, "UNSUPPORTED_ASSET_TYPE", err.Error()), 2
		}
		return failure(request.ProtocolVersion, "SCAN_FAILED", err.Error()), 3
	default:
		return failure(request.ProtocolVersion, "INVALID_REQUEST", fmt.Sprintf("unsupported operation %q", request.Operation)), 2
	}
}

func Serve(ctx context.Context, registry *engine.Registry, input io.Reader, output, diagnostic io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(input, 10*1024*1024+1))
	if err != nil {
		return write(output, failure(model.ProtocolVersion, "INVALID_REQUEST", err.Error()), 2)
	}
	if len(raw) > 10*1024*1024 {
		return write(output, failure(model.ProtocolVersion, "INVALID_REQUEST", "request exceeds 10 MiB"), 2)
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
	if request.ProtocolVersion != model.LegacyProtocolVersion && request.ProtocolVersion != model.ProtocolVersion {
		return rawRequest{}, fmt.Errorf("protocol_version must be %q or %q", model.LegacyProtocolVersion, model.ProtocolVersion)
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
		if request.ProtocolVersion == model.LegacyProtocolVersion {
			if request.ScanScope != nil || request.IncludeReadme != nil {
				return rawRequest{}, errors.New("protocol v1 scan does not accept scan_scope or include_readme")
			}
		} else {
			if request.ScanScope == nil || request.IncludeReadme == nil {
				return rawRequest{}, errors.New("protocol v2 scan requires scan_scope and include_readme")
			}
			if *request.ScanScope != model.ScanScopeSkillFiles && *request.ScanScope != model.ScanScopeSkillFolders && *request.ScanScope != model.ScanScopeRepository {
				return rawRequest{}, fmt.Errorf("invalid scan_scope %q", *request.ScanScope)
			}
			if *request.ScanScope == model.ScanScopeSkillFiles && *request.IncludeReadme {
				return rawRequest{}, errors.New("include_readme is not applicable to skill_files scope")
			}
		}
	case "list_rules":
		if request.Target != "" || request.AssetType != "" || request.OutputFormats != nil || request.TimeoutSeconds != 0 || request.RuleID != "" || request.ScanScope != nil || request.IncludeReadme != nil {
			return rawRequest{}, errors.New("list_rules accepts only operation and protocol_version")
		}
	case "get_rule":
		if strings.TrimSpace(request.RuleID) == "" {
			return rawRequest{}, errors.New("get_rule requires rule_id")
		}
		if request.Target != "" || request.AssetType != "" || request.OutputFormats != nil || request.TimeoutSeconds != 0 || request.ScanScope != nil || request.IncludeReadme != nil {
			return rawRequest{}, errors.New("get_rule accepts only operation, protocol_version, and rule_id")
		}
	default:
		return rawRequest{}, fmt.Errorf("unsupported operation %q", request.Operation)
	}
	return request, nil
}

func success(version string, result any) Envelope {
	return Envelope{ProtocolVersion: version, OK: true, Result: result}
}

func failure(version, code, message string) Envelope {
	return Envelope{ProtocolVersion: version, OK: false, Error: &ProtocolError{Code: code, Message: message}}
}

func write(output io.Writer, envelope Envelope, exitCode int) int {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(envelope); err != nil {
		return 3
	}
	return exitCode
}
