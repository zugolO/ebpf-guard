package profstage

import (
	"bytes"
	"runtime/pprof"
	"strings"
	"testing"
)

func goroutineDump(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&b, 1); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Метка стадии стоит на горутине после Set, меняется следующей стадией и
// снимается Clear. Выключенный пакет метку не ставит (мутация: Set без проверки
// флага краснит третий шаг).
func TestSetClearAndDisabled(t *testing.T) {
	Enable(true)
	defer Enable(false)

	Set(Rego)
	if d := goroutineDump(t); !strings.Contains(d, `"stage":"rego"`) {
		t.Fatalf("метка rego не стоит:\n%s", d)
	}
	Set(DispatchStore)
	if d := goroutineDump(t); !strings.Contains(d, `"stage":"dispatch_store"`) || strings.Contains(d, `"stage":"rego"`) {
		t.Fatalf("стадия не заменилась:\n%s", d)
	}
	Clear()
	if d := goroutineDump(t); strings.Contains(d, `"stage":`) {
		t.Fatalf("метка не снята:\n%s", d)
	}

	Enable(false)
	Set(Rego)
	if d := goroutineDump(t); strings.Contains(d, `"stage":`) {
		t.Fatalf("выключенный пакет поставил метку:\n%s", d)
	}
}

func TestEveryStageHasName(t *testing.T) {
	seen := map[string]Stage{}
	for s := Stage(1); s < stageCount; s++ {
		n := s.String()
		if n == "" || n == "unknown" || n == "none" {
			t.Fatalf("стадия %d без имени", s)
		}
		if prev, dup := seen[n]; dup {
			t.Fatalf("имя %q у стадий %d и %d", n, prev, s)
		}
		seen[n] = s
	}
}

func BenchmarkSetDisabled(b *testing.B) {
	Enable(false)
	for i := 0; i < b.N; i++ {
		Set(Rules)
	}
}

func BenchmarkSetEnabled(b *testing.B) {
	Enable(true)
	defer Enable(false)
	for i := 0; i < b.N; i++ {
		Set(Rules)
	}
}
