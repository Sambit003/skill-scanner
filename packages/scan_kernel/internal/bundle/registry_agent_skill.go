//go:build !custom_plugins || plugin_agent_skill

package bundle

import (
	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
	agentskill "gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/plugins/agent_skill"
)

func compiledPlugins() []model.AssetPlugin { return []model.AssetPlugin{agentskill.New()} }
