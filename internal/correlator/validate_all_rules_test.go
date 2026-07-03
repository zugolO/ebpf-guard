package correlator

import (
	"path/filepath"
	"testing"
)

func TestValidateAllRuleFiles(t *testing.T) {
	files, _ := filepath.Glob("../../rules/*.yaml")
	// Sub-directory rulesets that are loaded on demand rather than from the
	// default rules directory (e.g. the ai_sandbox semantic ruleset).
	sub, _ := filepath.Glob("../../rules/ai-agent/*.yaml")
	files = append(files, sub...)
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
