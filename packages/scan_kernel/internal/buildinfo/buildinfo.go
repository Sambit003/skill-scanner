package buildinfo

import (
	"runtime"
	"sort"

	"gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/model"
)

var (
	Version   = "1.0.0"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func Current(pluginIDs []string) model.BuildInfo {
	plugins := append([]string(nil), pluginIDs...)
	sort.Strings(plugins)
	mode, yaraVersion, modules := yaraDetails()
	return model.BuildInfo{
		Version:         Version,
		Commit:          Commit,
		BuildTime:       BuildTime,
		GoVersion:       runtime.Version(),
		ProtocolVersion: model.ProtocolVersion,
		Target:          runtime.GOOS + "/" + runtime.GOARCH,
		Plugins:         plugins,
		YARAMode:        mode,
		YARAVersion:     yaraVersion,
		YARAModules:     modules,
	}
}
