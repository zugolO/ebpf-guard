// Package rulesembed provides embedded filesystem access to the built-in
// detection rule YAML files for zero-config deployments.
//
// The //go:embed directive below works because this file lives inside the
// rules/ directory, making "*.yaml" a valid relative path (no "..").
package rulesembed

import (
	"embed"
	"io/fs"
	"sort"
)

// FS embeds all .yaml rule files in the rules/ directory at compile time.
//
//go:embed *.yaml
var FS embed.FS

// LoadAll reads all embedded YAML rule files and returns them as a
// map of filename → content.
func LoadAll() (map[string][]byte, error) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		return nil, err
	}
	result := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := fs.ReadFile(FS, entry.Name())
		if err != nil {
			return nil, err
		}
		result[entry.Name()] = data
	}
	return result, nil
}

// List returns sorted filenames of all embedded rule files.
func List() []string {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}
