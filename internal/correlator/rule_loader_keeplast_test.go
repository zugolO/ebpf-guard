package correlator

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// №557 (решение владельца 13.10): при горячей перезагрузке файл, ставший плохим, не
// снимает свои правила — держится последняя удачная версия этого файла.

func ruleIDs(rules []Rule) map[string]bool {
	m := make(map[string]bool, len(rules))
	for _, r := range rules {
		m[r.ID] = true
	}
	return m
}

func writeRaw(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Сценарий владельца: файл сломан на перезагрузке → правила живы; починен → новая версия.
func TestW85_RuleLoader_KeepLast_BrokenOnReloadKeepsRules_FixedTakesNewVersion(t *testing.T) {
	dir := t.TempDir()
	cache := NewRuleFileCache()
	writeRuleFile(t, dir, "a.yaml", "a_v1")
	writeRuleFile(t, dir, "b.yaml", "b_v1")

	// старт: оба файла хороши, кэш наполнен
	rules, failed, err := LoadRulesFromDirKeepLast(dir, cache)
	if err != nil || len(failed) != 0 || len(rules) != 2 {
		t.Fatalf("старт: rules=%d failed=%+v err=%v", len(rules), failed, err)
	}

	// файл ломается
	writeRaw(t, dir, "b.yaml", "rules: [ :::")
	rules, failed, _ = LoadRulesFromDirKeepLast(dir, cache)
	ids := ruleIDs(rules)
	if !ids["a_v1"] || !ids["b_v1"] || len(rules) != 2 {
		t.Fatalf("после поломки b.yaml правила b_v1 должны жить: %v", ids)
	}
	if len(failed) != 1 || failed[0].File != "b.yaml" || !failed[0].Stale || failed[0].Err == nil {
		t.Fatalf("ошибка должна остаться и быть помечена Stale: %+v", failed)
	}

	// держится и на следующей перезагрузке, пока файл не починен
	rules, failed, _ = LoadRulesFromDirKeepLast(dir, cache)
	if len(rules) != 2 || len(failed) != 1 || !failed[0].Stale {
		t.Fatalf("повторная перезагрузка: rules=%d failed=%+v", len(rules), failed)
	}

	// файл починен — НОВАЯ версия, не старая
	writeRuleFile(t, dir, "b.yaml", "b_v2")
	rules, failed, _ = LoadRulesFromDirKeepLast(dir, cache)
	ids = ruleIDs(rules)
	if len(failed) != 0 || !ids["b_v2"] || ids["b_v1"] || len(rules) != 2 {
		t.Fatalf("после починки ждали b_v2 без b_v1: ids=%v failed=%+v", ids, failed)
	}

	// и после починки держаться больше нечем: следующая поломка держит уже b_v2
	writeRaw(t, dir, "b.yaml", "rules: [ :::")
	rules, _, _ = LoadRulesFromDirKeepLast(dir, cache)
	if ids = ruleIDs(rules); !ids["b_v2"] || ids["b_v1"] {
		t.Fatalf("держаться должна последняя УДАЧНАЯ версия b_v2: %v", ids)
	}
}

// Валидационный провал (а не синтаксис) держится так же.
func TestW85_RuleLoader_KeepLast_ValidationFailureAlsoKeeps(t *testing.T) {
	dir := t.TempDir()
	cache := NewRuleFileCache()
	writeRuleFile(t, dir, "a.yaml", "a_v1")
	LoadRulesFromDirKeepLast(dir, cache)
	writeRaw(t, dir, "a.yaml", "rules:\n  - id: a_v1\n    name: no event type\n    condition:\n      field: comm\n      op: eq\n      values: [\"x\"]\n")
	rules, failed, _ := LoadRulesFromDirKeepLast(dir, cache)
	if len(rules) != 1 || rules[0].ID != "a_v1" || len(failed) != 1 || !failed[0].Stale {
		t.Fatalf("rules=%d failed=%+v", len(rules), failed)
	}
	// удержанная версия — исходная, а не битая
	if rules[0].EventType == 0 {
		t.Fatalf("удержалась битая версия (EventType не задан): %+v", rules[0])
	}
}

// Старт (пустой кэш) и файл, плохой с самого начала: пропуск, как раньше.
func TestW85_RuleLoader_KeepLast_StartupWithBadFileSkipsIt(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "a.yaml", "a_v1")
	writeRaw(t, dir, "bad.yaml", "rules: [ :::")
	rules, failed, _ := LoadRulesFromDirKeepLast(dir, NewRuleFileCache())
	if len(rules) != 1 || len(failed) != 1 || failed[0].File != "bad.yaml" || failed[0].Stale {
		t.Fatalf("rules=%d failed=%+v", len(rules), failed)
	}
	// nil-кэш (тесты, `rules check`) — то же самое
	rules, failed, _ = LoadRulesFromDirKeepLast(dir, nil)
	if len(rules) != 1 || len(failed) != 1 || failed[0].Stale {
		t.Fatalf("nil-кэш: rules=%d failed=%+v", len(rules), failed)
	}
}

// Удалённый файл не «держится»: исчезновение — намеренное действие, а не поломка.
func TestW85_RuleLoader_KeepLast_DeletedFileIsNotHeld(t *testing.T) {
	dir := t.TempDir()
	cache := NewRuleFileCache()
	writeRuleFile(t, dir, "a.yaml", "a_v1")
	writeRuleFile(t, dir, "b.yaml", "b_v1")
	LoadRulesFromDirKeepLast(dir, cache)
	if err := os.Remove(filepath.Join(dir, "b.yaml")); err != nil {
		t.Fatal(err)
	}
	rules, failed, _ := LoadRulesFromDirKeepLast(dir, cache)
	if len(rules) != 1 || len(failed) != 0 {
		t.Fatalf("удалённый b.yaml не должен жить: rules=%d failed=%+v", len(rules), failed)
	}
	// пересоздан плохим — старой версии уже нет
	writeRaw(t, dir, "b.yaml", "rules: [ :::")
	rules, failed, _ = LoadRulesFromDirKeepLast(dir, cache)
	if len(rules) != 1 || len(failed) != 1 || failed[0].Stale {
		t.Fatalf("после удаления кэш файла должен быть забыт: rules=%d failed=%+v", len(rules), failed)
	}
}

// Удержанные правила не должны дублировать id, уже занятые другим файлом.
func TestW85_RuleLoader_KeepLast_HeldVersionCannotCollideWithAnotherFile(t *testing.T) {
	dir := t.TempDir()
	cache := NewRuleFileCache()
	writeRuleFile(t, dir, "a.yaml", "x_id")
	writeRuleFile(t, dir, "b.yaml", "b_v1")
	LoadRulesFromDirKeepLast(dir, cache)
	// b ломается, а a занимает ЕГО id — удержать b_v1 нельзя, но b_v1 и не было у a; делаем так:
	writeRuleFile(t, dir, "a.yaml", "b_v1") // a теперь владеет b_v1
	writeRaw(t, dir, "b.yaml", "rules: [ :::")
	rules, failed, _ := LoadRulesFromDirKeepLast(dir, cache)
	if err := ValidateFull(rules); err != nil {
		t.Fatalf("итоговый набор обязан проходить валидацию: %v", err)
	}
	if len(rules) != 1 || len(failed) != 1 || failed[0].Stale {
		t.Fatalf("столкновение id: rules=%d failed=%+v", len(rules), failed)
	}
}

// Кэши разных каталогов с одноимёнными файлами не смешиваются.
func TestW85_RuleLoader_KeepLast_SameFileNameInOtherDirIsNotHeld(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	cache := NewRuleFileCache()
	writeRuleFile(t, d1, "a.yaml", "a_v1")
	LoadRulesFromDirKeepLast(d1, cache)
	writeRaw(t, d2, "a.yaml", "rules: [ :::")
	rules, failed, _ := LoadRulesFromDirKeepLast(d2, cache)
	if len(rules) != 0 || len(failed) != 1 || failed[0].Stale {
		t.Fatalf("чужой каталог: rules=%d failed=%+v", len(rules), failed)
	}
}

// Удержанный набор — свежий разбор: правила не делят память с прошлой загрузкой
// (наложение настроек дописывает исключения в срезы правил).
func TestW85_RuleLoader_KeepLast_HeldRulesAreFreshlyParsed(t *testing.T) {
	dir := t.TempDir()
	cache := NewRuleFileCache()
	writeRuleFile(t, dir, "a.yaml", "a_v1")
	first, _, _ := LoadRulesFromDirKeepLast(dir, cache)
	first[0].Exceptions = append(first[0].Exceptions, RuleException{})
	writeRaw(t, dir, "a.yaml", "rules: [ :::")
	held, failed, _ := LoadRulesFromDirKeepLast(dir, cache)
	if len(failed) != 1 || !failed[0].Stale || len(held) != 1 {
		t.Fatalf("held=%d failed=%+v", len(held), failed)
	}
	if len(held[0].Exceptions) != 0 {
		t.Fatalf("удержанное правило несёт мутацию прошлого набора: %+v", held[0].Exceptions)
	}
}

// Мутация-страж: если удержание отключить, сценарий владельца ОБЯЗАН покраснеть.
// (Ручная проверка мутации описана в plan.md; тест — на случай, если кто-то вернёт обнуление.)
func TestW85_RuleLoader_KeepLast_ScenarioIsNotVacuous(t *testing.T) {
	dir := t.TempDir()
	cache := NewRuleFileCache()
	writeRuleFile(t, dir, "a.yaml", fmt.Sprintf("a_%d", 1))
	LoadRulesFromDirKeepLast(dir, cache)
	writeRaw(t, dir, "a.yaml", "rules: [ :::")
	withCache, _, _ := LoadRulesFromDirKeepLast(dir, cache)
	withoutCache, _, _ := LoadRulesFromDirKeepLast(dir, nil)
	if len(withCache) != 1 || len(withoutCache) != 0 {
		t.Fatalf("удержание должно ОТЛИЧАТЬ кэш от его отсутствия: с=%d без=%d", len(withCache), len(withoutCache))
	}
}
