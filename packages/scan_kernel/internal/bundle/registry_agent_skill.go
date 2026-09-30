//go:build !custom_plugins || plugin_agent_skill

package bundle

import (
	"github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/model"
	agentskill "github.com/Sambit003/skill-scanner/packages/scan_kernel/plugins/agent_skill"
)

func compiledPlugins() []model.AssetPlugin { return []model.AssetPlugin{agentskill.New()} }
