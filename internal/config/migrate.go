package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// IssueSeverity classifies how severe a compatibility problem is.
type IssueSeverity string

const (
	// IssueSeverityDeprecated means the field still loads but will be removed in a future version.
	IssueSeverityDeprecated IssueSeverity = "deprecated"
	// IssueSeverityRemoved means the field is no longer recognised and has no effect.
	IssueSeverityRemoved IssueSeverity = "removed"
)

// Issue represents a single config compatibility problem found by CheckConfigFile.
type Issue struct {
	Severity IssueSeverity
	Field    string
	Message  string
}

// CheckConfigFile reads the YAML config at path and returns any compatibility
// issues found by comparing field names against the migrations manifest.
func CheckConfigFile(path string) ([]Issue, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return checkConfigBytes(raw)
}

func checkConfigBytes(raw []byte) ([]Issue, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if doc == nil {
		doc = make(map[string]interface{})
	}

	var issues []Issue
	for _, m := range Migrations {
		for _, change := range m.Changes {
			if !yamlPathExists(doc, change.Field) {
				continue
			}
			switch change.Transform {
			case TransformRename:
				issues = append(issues, Issue{
					Severity: IssueSeverityDeprecated,
					Field:    change.Field,
					Message:  fmt.Sprintf("deprecated, renamed to %s (since %s)", change.NewField, change.Since),
				})
			case TransformRemove:
				issues = append(issues, Issue{
					Severity: IssueSeverityRemoved,
					Field:    change.Field,
					Message:  fmt.Sprintf("removed since %s: %s", change.Since, change.Reason),
				})
			}
		}
	}
	return issues, nil
}

// MigrateConfigFile applies all known migrations up to targetVersion to the
// config at inPath and writes the result to outPath.
//
// Note: YAML comments are not preserved in the migrated output because the
// document is round-tripped through a generic map.
func MigrateConfigFile(inPath, targetVersion, outPath string) error {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	out, err := migrateConfigBytes(raw, targetVersion)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func migrateConfigBytes(raw []byte, targetVersion string) ([]byte, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if doc == nil {
		doc = make(map[string]interface{})
	}

	applied := false
	for _, m := range Migrations {
		if m.To > targetVersion {
			continue
		}
		for _, change := range m.Changes {
			switch change.Transform {
			case TransformRename:
				if v, ok := yamlGetPath(doc, change.Field); ok {
					yamlDeletePath(doc, change.Field)
					yamlSetPath(doc, change.NewField, v)
				}
			case TransformRemove:
				yamlDeletePath(doc, change.Field)
			}
		}
		doc["config_version"] = m.To
		applied = true
	}

	if !applied {
		return nil, fmt.Errorf("no migrations found for target version %q", targetVersion)
	}

	return yaml.Marshal(doc)
}

// yamlPathExists reports whether the dot-separated path exists in doc.
func yamlPathExists(doc map[string]interface{}, dotPath string) bool {
	_, ok := yamlGetPath(doc, dotPath)
	return ok
}

// yamlGetPath returns the value at the dot-separated path.
func yamlGetPath(doc map[string]interface{}, dotPath string) (interface{}, bool) {
	segments := strings.Split(dotPath, ".")
	current := doc
	for i, seg := range segments {
		v, ok := current[seg]
		if !ok {
			return nil, false
		}
		if i == len(segments)-1 {
			return v, true
		}
		next, ok := v.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current = next
	}
	return nil, false
}

// yamlDeletePath removes the field at the dot-separated path.
func yamlDeletePath(doc map[string]interface{}, dotPath string) {
	segments := strings.Split(dotPath, ".")
	current := doc
	for i, seg := range segments {
		if i == len(segments)-1 {
			delete(current, seg)
			return
		}
		next, ok := current[seg].(map[string]interface{})
		if !ok {
			return
		}
		current = next
	}
}

// yamlSetPath sets the value at the dot-separated path, creating intermediate maps as needed.
func yamlSetPath(doc map[string]interface{}, dotPath string, value interface{}) {
	segments := strings.Split(dotPath, ".")
	current := doc
	for i, seg := range segments {
		if i == len(segments)-1 {
			current[seg] = value
			return
		}
		next, ok := current[seg].(map[string]interface{})
		if !ok {
			next = make(map[string]interface{})
			current[seg] = next
		}
		current = next
	}
}
