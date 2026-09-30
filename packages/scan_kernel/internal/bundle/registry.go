package bundle

import "github.com/Sambit003/skill-scanner/packages/scan_kernel/internal/engine"

func Registry() *engine.Registry { return engine.New(compiledPlugins()...) }
