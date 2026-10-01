#!/usr/bin/env bash
# wave8-heap-pair-fixtures.sh — фикстуры разбора пары heap-снимков (item 1 волны 8.1).
# Настоящие pprof-профили порождает маленькая Go-программа: функция growRetained
# УДЕРЖИВАЕТ 30 МиБ между снимками, churn — аллоцирует и отпускает. Разбор обязан
# поставить первую в inuse-разность, вторую — в alloc-разность и НЕ в inuse.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d /tmp/w8heap.XXXXXX); trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { echo "  OK    $1"; }
bad() { echo "  FAIL  $1"; FAIL=1; }
command -v go >/dev/null || { echo "go нет — фикстуры не исполнимы"; exit 2; }

mkdir -p "$T/gen" && cat > "$T/gen/main.go" <<'GO'
package main

import (
	"os"
	"runtime"
	"runtime/pprof"
)

var keep [][]byte
var sink []byte

//go:noinline
func growRetained() { for i := 0; i < 30; i++ { keep = append(keep, make([]byte, 1<<20)) } }

//go:noinline
func churn() { for i := 0; i < 200; i++ { sink = make([]byte, 1<<20) }; sink = nil }

func snap(p string) {
	runtime.GC()
	f, _ := os.Create(p)
	_ = pprof.Lookup("heap").WriteTo(f, 0)
	_ = f.Close()
}

func main() {
	runtime.MemProfileRate = 1
	snap(os.Args[1])
	growRetained()
	churn()
	snap(os.Args[2])
}
GO
(cd "$T/gen" && go run main.go "$T/snap1.pprof" "$T/snap2.pprof") || { echo "генератор профилей не отработал"; exit 2; }
mk() { # <файл> <rss> <heap_alloc> <alloc_total>
    printf 'process_resident_memory_bytes %s\ngo_memstats_heap_alloc_bytes %s\ngo_memstats_heap_inuse_bytes %s\ngo_memstats_heap_idle_bytes 1000\ngo_memstats_heap_released_bytes 10\ngo_memstats_alloc_bytes_total %s\n' "$2" "$3" "$3" "$4" > "$1"
}
mk "$T/metrics1.txt" 100000000 40000000 1000000000
mk "$T/metrics2.txt" 131457280 71457280 1300000000

out=$(W8_MODE=analyze W8_ART="$T" bash "$HERE/wave8-heap-pair.sh" 2>&1)
S="$T/heap-pair-summary.txt"
[ -s "$S" ] && ok "сводка написана" || bad "сводки нет: $out"
grep -q "delta_mib process_resident_memory_bytes = 30.00" "$S" && ok "дельта RSS в МиБ из двух снимков метрик (30,00)" || bad "дельта RSS: $(grep delta_mib.*resident "$S")"
grep -q "delta_mib go_memstats_alloc_bytes_total = 286.10" "$S" && ok "дельта alloc_bytes_total (286,10 МиБ)" || bad "дельта alloc_total: $(grep alloc_bytes_total "$S")"
grep -q "growRetained" "$T/heap-diff-inuse.txt" && ok "удерживающая функция growRetained стоит в inuse-разности" || bad "growRetained нет в inuse-разности"
grep -q "churn" "$T/heap-diff-alloc.txt" && ok "churn стоит в alloc-разности" || bad "churn нет в alloc-разности"
# парный негатив: churn отпускает память — в inuse-разности ему не место
if grep -q "main.churn" "$T/heap-diff-inuse.txt"; then bad "churn попал в inuse-разность — мусор принят за удержанное"; else ok "churn в inuse-разности НЕТ (мусор не удержан)"; fi
# входы: нет снимка — класс, а не пустая сводка
rm -f "$T/snap2.pprof"
W8_MODE=analyze W8_ART="$T" bash "$HERE/wave8-heap-pair.sh" >/dev/null 2>&1
grep -q "^class=нет_входа_snap2.pprof" "$T/heap-pair-summary.txt" && ok "нет второго снимка — class=нет_входа_snap2.pprof" || bad "нет второго снимка: $(cat "$T/heap-pair-summary.txt")"
W8_MODE=run W8_TOKEN="" W8_ART="$T/x" bash "$HERE/wave8-heap-pair.sh" >/dev/null 2>&1
grep -q "^class=нет_токена" "$T/x/heap-pair-summary.txt" && ok "без токена — class=нет_токена, не сеть вслепую" || bad "без токена: $(cat "$T/x/heap-pair-summary.txt" 2>&1)"
echo
[ "$FAIL" -eq 0 ] && { echo "wave8-heap-pair-fixtures: расхождений 0"; exit 0; }
echo "wave8-heap-pair-fixtures: ЕСТЬ РАСХОЖДЕНИЯ"; exit 1
