//go:build !yara_native

package agentskill

import (
	"context"
	"fmt"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

// The development build has no YARA engine. The built-in YR1-YR4 signatures
// were retired (offensive tool names are a LOW note, SC12); custom rule files
// need a native-YARA build, which release bundles enable with yara_native.
func scanYARA(ctx context.Context, items []component, customRules string) ([]model.Finding, error) {
	if customRules != "" {
		return nil, fmt.Errorf("custom YARA rules require a native-YARA build")
	}
	return nil, ctx.Err()
}
