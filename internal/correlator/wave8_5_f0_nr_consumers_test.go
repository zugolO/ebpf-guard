package correlator

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Волна 8.5, F0(а), правило волны 3: отбор номера в ядре (F1) не включается,
// пока не известен КАЖДЫЙ потребитель Syscall.Nr — иначе профайлер теряет вход
// молча. Сторож обходит исходники (без _test.go и сгенерированных *_bpf_gen.go)
// и сверяет функции, читающие поле Nr, со списком ниже. Новый потребитель вне
// списка — красный тест: его надо разобрать (что он потеряет, когда номер
// отфильтрован в ядре) и дописать сюда вместе с решением в plan.md (8.5 F0).
var w85KnownNrConsumers = map[string]string{
	// Живой путь агента — теряют вход при отборе в ядре.
	"internal/correlator/rules.go|getFieldValueCached":        "правила: поле nr",
	"internal/profiler/profile.go|recordSyscallEventLocked":   "EWMA-профиль (anomaly), включён",
	"internal/profiler/anomaly.go|analyzeSyscallBehavior":     "EWMA-скоринг (anomaly), включён",
	"internal/profiler/sequence.go|Update":                    "Марков, включён профилем balanced",
	"internal/profiler/driftbaseline.go|driftSignatureTarget": "база дрейфа, включена",
	"internal/profiler/allowlist.go|Record":                   "deny-unknown, на стенде выключен",
	"internal/profiler/allowlist.go|Check":                    "deny-unknown, на стенде выключен",
	"internal/drift/detector.go|record":                       "детектор дрейфа контейнера, на стенде выключен",
	"internal/drift/detector.go|checkDrift":                   "детектор дрейфа контейнера, на стенде выключен",
	"internal/exporter/prometheus.go|RecordSyscallNR":         "прибор 8.5.1: считает ПОСЛЕ кольца",
	"internal/collector/syscall.go|readLoop":                  "proc.args только для 59/322",
	"internal/collector/syscall.go|parseEvent":                "зеркало ядерного allowlist номеров",
	"internal/policy/rego_enabled.go|eventToInput":            "Rego: только события алертов",
	// Инфраструктура F1/F2: поле Nr — номер предиката или счётчика ядра, а не
	// Syscall.Nr живого события; записаны, чтобы сторож оставался красным на
	// НАСТОЯЩИЙ новый читатель.
	"cmd/ebpf-guard/kernelpred.go|Apply":                       "F1: контроллер предикатов (Nr предиката)",
	"cmd/ebpf-guard/kernelpred.go|decide":                      "F1: контроллер предикатов (Nr предиката)",
	"cmd/ebpf-guard/kernelpred.go|drain":               "F2: слив счётчиков ядра (Nr счётчика)",
	"cmd/ebpf-guard/kernelpred.go|predNrs":                     "F1: контроллер предикатов (Nr предиката)",
	"internal/bpf/syscall_counts.go|Poll":                      "F2: читатель счётчиков ядра (Nr ключа карты)",
	"internal/bpf/syscall_pred.go|EncodeSyscallPred":           "F1: запись карты предикатов (Nr предиката)",
	"internal/bpf/syscall_pred.go|SetSyscallPredicates":        "F1: запись карты предикатов (Nr предиката)",
	"internal/profiler/kernelcounts.go|IngestSyscallCounts":    "F2: счётчики ядра → EWMA-профиль (поле Nr счётчика, не события)",
	"internal/correlator/kernelpred.go|DeriveKernelPredicates": "F1: вывод предикатов; Nr — номер предиката, а не поле события",
	"internal/bpf/events.go|ParseSyscallEventInto":             "разбор кольца (производитель)",
	"internal/bpf/events.go|ToTypesEvent":                      "разбор кольца (производитель)",
	// Офлайн/CLI — живой поток агента не читают.
	"internal/autolearn/learner.go|Ingest":            "ebpf-guard learn: профиль из живого потока",
	"internal/tui/rule_builder.go|rbGetFieldValue":    "TUI",
	"internal/tui/rule_builder.go|extractEventFields": "TUI",
	"internal/tui/rule_builder.go|formatEventDesc":    "TUI",
	"internal/wasm/plugin.go|SerializeEvent":          "валидация wasm-плагина",
}

func TestW85_F0_NrConsumersAreKnown(t *testing.T) {
	root := "../.."
	fset := token.NewFileSet()
	found := map[string]bool{}
	for _, dir := range []string{"internal", "cmd", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, "_bpf_gen.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if ok && sel.Sel.Name == "Nr" {
						found[filepath.ToSlash(rel)+"|"+fn.Name.Name] = true
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	var unknown, stale []string
	for k := range found {
		if _, ok := w85KnownNrConsumers[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	for k := range w85KnownNrConsumers {
		if !found[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(unknown)
	sort.Strings(stale)
	for _, k := range unknown {
		t.Errorf("новый потребитель Syscall.Nr вне инвентаря 8.5 F0: %s", k)
	}
	for _, k := range stale {
		t.Errorf("запись инвентаря 8.5 F0 больше не читает Nr (переименована или удалена): %s", k)
	}
}
