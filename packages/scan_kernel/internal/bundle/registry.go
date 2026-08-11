package bundle

import "gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/engine"

func Registry() *engine.Registry { return engine.New(compiledPlugins()...) }
