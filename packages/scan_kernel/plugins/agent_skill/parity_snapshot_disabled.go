//go:build !parity

package agentskill

import "gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"

func writeParitySnapshot(*preparedInput) error { return nil }

func writeParityScoringSnapshot([]model.Finding) error { return nil }
