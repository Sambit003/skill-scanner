package agentskill

import "gopkg.in/yaml.v3"

func yamlUnmarshal(raw []byte, target any) error { return yaml.Unmarshal(raw, target) }
