package agentskill

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

func yamlUnmarshal(raw []byte, target any) error { return yaml.Unmarshal(raw, target) }

// yamlSequenceLines returns the 1-based line of each entry in the sequence
// under a top-level mapping key, skipping the blank entries that
// manifestStringList drops so the lines stay aligned with that list.
func yamlSequenceLines(raw []byte, key string) []int {
	var document yaml.Node
	if yaml.Unmarshal(raw, &document) != nil || len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	root := document.Content[0]
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != key || root.Content[index+1].Kind != yaml.SequenceNode {
			continue
		}
		var lines []int
		for _, entry := range root.Content[index+1].Content {
			var value any
			if entry.Decode(&value) == nil && strings.TrimSpace(fmt.Sprint(value)) != "" {
				lines = append(lines, entry.Line)
			}
		}
		return lines
	}
	return nil
}
