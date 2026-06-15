package correlator

import (
	"path/filepath"
	"testing"
)

func TestValidateAllRuleFiles(t *testing.T) {
	files, _ := filepath.Glob("../../rules/*.yaml")
	if len(files) == 0 {
		t.Fatal("no rule files found")
	}
	for _, f := range files {
		f := f
		t.Run(filepath.Base(f), func(t *testing.T) {
			t.Parallel()
			_, err := LoadRulesFromFile(f)
			if err != nil {
				t.Errorf("validation failed: %v", err)
			}
		})
	}
}
