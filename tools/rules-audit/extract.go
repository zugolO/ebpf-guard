// Command rules-audit extracts every rule from a rules directory into JSON,
// preserving the YAML source line of each rule's `id:` so an audit table can
// cite file:line evidence.
//
// Usage:
//
//	go run ./tools/rules-audit <rules-dir> <out.json>
//
// It is intentionally a plain YAML reader (not the product loader): the point
// is to see what the file says, including conditions the product would reject.
// Wave 7, item 1 (revision 7.0) reproducibility method; see
// docs/rules-audit-2026-09-27.md.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// RuleRec is one rule as written in YAML.
type RuleRec struct {
	ID         string   `json:"id"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Name       string   `json:"name"`
	EventType  string   `json:"event_type"`
	Severity   string   `json:"severity"`
	Condition  any      `json:"condition"`
	Conditions any      `json:"conditions"`
	CondGroup  any      `json:"condition_group"`
	Exceptions any      `json:"exceptions"`
	Tags       []string `json:"tags"`
}

func nodeToAny(n *yaml.Node) any {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			return nodeToAny(n.Content[0])
		}
		return nil
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = nodeToAny(n.Content[i+1])
		}
		return m
	case yaml.SequenceNode:
		s := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			s = append(s, nodeToAny(c))
		}
		return s
	case yaml.ScalarNode:
		var v any
		if err := n.Decode(&v); err == nil {
			return v
		}
		return n.Value
	}
	return nil
}

func findKey(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return findKey(n.Content[0], key)
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
	}
	return nil
}

func scalarStr(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	return n.Value
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: rules-audit <rules-dir> <out.json>")
		os.Exit(2)
	}
	dir, out := os.Args[1], os.Args[2]

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read dir %s: %v\n", dir, err)
		os.Exit(1)
	}
	names := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext == ".yaml" || ext == ".yml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	recs := map[string]*RuleRec{}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", name, err)
			continue
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", name, err)
			continue
		}
		rulesNode := findKey(&doc, "rules")
		if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range rulesNode.Content {
			idNode := findKey(item, "id")
			if idNode == nil {
				continue
			}
			id := idNode.Value
			m, _ := nodeToAny(item).(map[string]any)
			rec := &RuleRec{ID: id, File: name, Line: idNode.Line}
			if m != nil {
				rec.Name, _ = m["name"].(string)
				rec.EventType, _ = m["event_type"].(string)
				rec.Severity, _ = m["severity"].(string)
				rec.Condition = m["condition"]
				rec.Conditions = m["conditions"]
				rec.CondGroup = m["condition_group"]
				rec.Exceptions = m["exceptions"]
				if tags, ok := m["tags"].([]any); ok {
					for _, t := range tags {
						rec.Tags = append(rec.Tags, fmt.Sprintf("%v", t))
					}
				}
			}
			if _, dup := recs[id]; dup {
				fmt.Fprintf(os.Stderr, "DUPLICATE id %s in %s\n", id, name)
			}
			recs[id] = rec
		}
	}

	f, err := os.Create(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", out, err)
		os.Exit(1)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", " ")
	if err := enc.Encode(recs); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%s: %d rules -> %s\n", dir, len(recs), out)
}
