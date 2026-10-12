package correlator

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const tolerantGoodRule = `rules:
  - id: %s
    name: %s
    event_type: syscall
    severity: warning
    condition:
      field: comm
      op: eq
      values: ["x"]
`

func writeRuleFile(t *testing.T, dir, name, id string) {
	t.Helper()
	body := []byte(fmt.Sprintf(tolerantGoodRule, id, id))
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Один битый файл из N — загружено N−1, битый назван; строгий загрузчик по-прежнему
// отвечает ошибкой (тесты и `rules check` обязаны видеть дефект).
func TestW85_RuleLoader_OneBadFileOfNLoadsTheRest(t *testing.T) {
	dir := t.TempDir()
	const n = 5
	for i := 0; i < n; i++ {
		writeRuleFile(t, dir, "ok"+string(rune('a'+i))+".yaml", "ok_"+string(rune('a'+i)))
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("rules: [ {id: x, \n  :::not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, failed, err := LoadRulesFromDirTolerant(dir)
	if err != nil {
		t.Fatalf("каталог читаем, ошибки быть не должно: %v", err)
	}
	if len(rules) != n {
		t.Fatalf("загружено %d правил, want %d (N−1 файлов)", len(rules), n)
	}
	if len(failed) != 1 || failed[0].File != "bad.yaml" || failed[0].Err == nil {
		t.Fatalf("пропущенные: %+v", failed)
	}
	if _, err := LoadRulesFromDir(dir); err == nil {
		t.Fatal("строгий загрузчик промолчал о битом файле")
	}
}

// Файл, провалившийся валидацией (не YAML-ошибка), тоже пропускается.
func TestW85_RuleLoader_ValidationFailureSkipsOnlyThatFile(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "good.yaml", "good_1")
	invalid := "rules:\n  - id: inv_1\n    name: no event type\n    condition:\n      field: comm\n      op: eq\n      values: [\"x\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "invalid.yaml"), []byte(invalid), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, failed, _ := LoadRulesFromDirTolerant(dir)
	if len(rules) != 1 || rules[0].ID != "good_1" || len(failed) != 1 || failed[0].File != "invalid.yaml" {
		t.Fatalf("rules=%d failed=%+v", len(rules), failed)
	}
}

// Дубль id между файлами: поздний файл пропущен целиком, ранний держит id.
func TestW85_RuleLoader_CrossFileDuplicateSkipsTheLaterFile(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.yaml", "same_id")
	writeRuleFile(t, dir, "b.yaml", "same_id")
	writeRuleFile(t, dir, "c.yaml", "other_id")
	rules, failed, _ := LoadRulesFromDirTolerant(dir)
	if len(rules) != 2 || len(failed) != 1 || failed[0].File != "b.yaml" {
		t.Fatalf("rules=%d failed=%+v", len(rules), failed)
	}
	if err := ValidateFull(rules); err != nil {
		t.Fatalf("итоговый набор должен проходить полную валидацию: %v", err)
	}
}

// AppleDouble ._x.yaml не читается ни одним из загрузчиков (даже без ошибки).
func TestW85_RuleLoader_AppleDoubleIsIgnored(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "real.yaml", "real_1")
	if err := os.WriteFile(filepath.Join(dir, "._real.yaml"), []byte{0x00, 0x05, 0x16, 0x07, 0x00, 0x02}, 0o644); err != nil {
		t.Fatal(err)
	}
	rules, failed, err := LoadRulesFromDirTolerant(dir)
	if err != nil || len(rules) != 1 || len(failed) != 0 {
		t.Fatalf("tolerant: rules=%d failed=%+v err=%v", len(rules), failed, err)
	}
	rules, err = LoadRulesFromDir(dir)
	if err != nil || len(rules) != 1 {
		t.Fatalf("strict: rules=%d err=%v", len(rules), err)
	}
}

func TestW85_RuleLoader_UnreadableDirectoryIsStillAnError(t *testing.T) {
	if _, _, err := LoadRulesFromDirTolerant(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("несуществующий каталог должен дать ошибку")
	}
}
