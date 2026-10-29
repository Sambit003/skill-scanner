package agentskill

import (
	"fmt"
	"regexp"
	"strconv"
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

// frontmatterRoot returns the top-level mapping of a SKILL.md front matter.
// Node lines are SKILL.md lines because frontmatterYAML starts on line 1.
// Front matter that is not valid YAML falls back to lenientFrontmatterRoot,
// so hooks and allowed-tools are still checked.
func frontmatterRoot(content string) *yaml.Node {
	block, ok := frontmatterYAML(content)
	if !ok {
		return nil
	}
	if root, err := yamlMapping(block); err == nil {
		return root
	}
	return lenientFrontmatterRoot(block)
}

// yamlMapping parses text as a YAML document whose root is a mapping.
func yamlMapping(text string) (*yaml.Node, error) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(text), &document); err != nil {
		return nil, err
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("front matter is not a mapping")
	}
	return document.Content[0], nil
}

// frontmatterTopLevelKey matches a line that starts a top-level front matter
// entry: an unindented key followed by a colon.
var frontmatterTopLevelKey = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]*)\s*:(?:\s|$)`)

// lenientFrontmatterRoot parses front matter that is not valid YAML one
// top-level entry at a time, keeping SKILL.md line numbers. An entry that
// does not parse on its own, such as "description: Use when: x", becomes a
// plain string of the text after its first colon.
func lenientFrontmatterRoot(block string) *yaml.Node {
	lines := strings.Split(block, "\n")
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for start := 0; start < len(lines); {
		key := frontmatterTopLevelKey.FindStringSubmatch(lines[start])
		if key == nil {
			start++
			continue
		}
		end := start + 1
		for end < len(lines) && !frontmatterTopLevelKey.MatchString(lines[end]) {
			end++
		}
		entry := strings.Join(lines[start:end], "\n")
		if parsed, err := yamlMapping(strings.Repeat("\n", start) + entry); err == nil && len(parsed.Content) == 2 {
			root.Content = append(root.Content, parsed.Content...)
		} else {
			value := strings.Join(strings.Fields(strings.SplitN(entry, ":", 2)[1]), " ")
			root.Content = append(root.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key[1], Line: start + 1, Column: 1},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Line: start + 1, Column: len(key[0]) + 1})
		}
		start = end
	}
	return root
}

// yamlErrorLine reads the line number from a yaml.v3 error message.
var yamlErrorLine = regexp.MustCompile(`\bline (\d+):`)

// frontmatterSyntaxError returns the line and message of a front matter
// block that is present but does not parse as YAML.
func frontmatterSyntaxError(content string) (int, string, bool) {
	block, ok := frontmatterYAML(content)
	if !ok {
		return 0, "", false
	}
	var document yaml.Node
	err := yaml.Unmarshal([]byte(block), &document)
	if err == nil {
		return 0, "", false
	}
	line := 1
	if match := yamlErrorLine.FindStringSubmatch(err.Error()); match != nil {
		if number, convErr := strconv.Atoi(match[1]); convErr == nil && number > 0 {
			line = number
		}
	}
	return line, err.Error(), true
}

// mappingEntry returns the key and value nodes for key in a mapping node, or
// nils when the node is not a mapping or has no such key.
func mappingEntry(node *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index], node.Content[index+1]
		}
	}
	return nil, nil
}
