#!/bin/bash
# Фикстуры эмиттера ночи закрытия 8.2 (w82-close-report.sh): метки 8.2.1, 8.2.5.
#
# Форма входа — как у живых файлов стенда (server-logs/w82-dovodka: samples.tsv
# «сек байты», metrics с HELP/TYPE и лейблами collector/queue/reason, манифест и
# снимки алертов как в collect-2.9.4, строка recall гейта как в night-3),
# а не придуманная ([[self-test-fixtures-miss-live-log-shape]]). Архивы стенда в git
# не лежат, поэтому строки воспроизведены здесь.
#
# Каждый случай проверяет вердиктное слово метки И класс; «ок» обязан дать
# ДОСТИГНУТО, иначе фикстура, которая только краснеет, не отличит эмиттер,
# способный лишь на НЕИЗМЕРИМ ([[verdict-line-that-can-only-say-unmeasurable]]).
# Мутация: BUDGET_MIB=90 на «ок» обязана дать ПРОВАЛЕН 8.2.1.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
E="$HERE/w82-close-report.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { echo "  OK    $*"; }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

# samples <файл> <от> <до> <база_МиБ> <пик_МиБ> <сек_пика> — 10 Гц, «%.1f байты».
samples() {
    awk -v a="$2" -v b="$3" -v base="$4" -v pk="$5" -v ps="$6" 'BEGIN {
        for (t = a; t <= b + 1e-9; t += 0.1) {
            v = (t >= ps - 0.05 && t <= ps + 0.05) ? pk : base
            printf "%.1f %d\n", t, v * 1048576 } }' > "$1"
}
metrics() {   # metrics <файл> <protected> <ringbuf_full fileaccess>
    cat > "$1" <<EOF
# HELP ebpf_guard_events_dropped_by_queue_total Dropped events by collector and the priority queue they were routed to (protected = high priority, bulk = low priority).
# TYPE ebpf_guard_events_dropped_by_queue_total counter
ebpf_guard_events_dropped_by_queue_total{collector="fileaccess",queue="bulk"} 0
ebpf_guard_events_dropped_by_queue_total{collector="fileaccess",queue="protected"} $2
ebpf_guard_events_dropped_by_queue_total{collector="syscall",queue="protected"} 0
# HELP ebpf_guard_events_dropped_total Dropped events by collector and reason.
# TYPE ebpf_guard_events_dropped_total counter
ebpf_guard_events_dropped_total{collector="fileaccess",reason="ringbuf_full"} $3
ebpf_guard_events_dropped_total{collector="fileaccess",reason="ringbuf_to_router"} 0
ebpf_guard_events_dropped_total{collector="syscall",reason="ringbuf_full"} 0
EOF
}

# Базовый «ок»: старт 95,5 на 4,4 с (доводка, w82-dovb-1), атаки 104,4 на 586,1 (w82-dovb-attack).
mkcase() {
    local d="$T/$1"; mkdir -p "$d/run" "$d/att"
    samples "$d/run/samples.tsv" 3.4 89.5 84 95.5 4.4
    samples "$d/att/samples.tsv" 0.0 1200.0 96 104.4 586.1
    echo "590.2" > "$d/att/t-att1"
    echo 0 > "$d/att/restarts.txt"
    metrics "$d/att/m-pre.txt" 0 0
    metrics "$d/att/m-att1.txt" 0 0
    cat > "$d/att/attack-manifest.json" <<'EOF'
[{"category":"transit","comm":"docker-proxy","timestamp":"2026-08-20T21:47:25+00:00","transit":true},{"category":"sqlmap","comm":"sqlmap","timestamp":"2026-08-20T21:47:35+00:00"},{"category":"bruteforce","comm":"curl","timestamp":"2026-08-20T21:54:32+00:00"}]
EOF
    echo '[{"id":"old-1","rule_id":"x","comm":"curl","severity":"warning"}]' > "$d/att/baseline-alerts-20261012_060000.json"
    echo '[{"id":"old-1","rule_id":"x","comm":"curl","severity":"warning"},{"id":"drift_new_exec_critical-1787262959648166675-198894-105993","rule_id":"drift_new_exec_critical","comm":"sqlmap","severity":"critical"},{"id":"n2","rule_id":"owasp_bruteforce","comm":"curl","severity":"warning"}]' > "$d/att/final-alerts-20261012_060000.json"
    printf '\033[0;32m[PASS]\033[0m recall по манифесту: 13/13 = 1.000 (все категории манифеста пойманы)\n' > "$d/gate.txt"
    echo "    w82_alloc_bench_test.go:198: ДОСТИГНУТО: 8.2.3 ДОСТИГНУТО (поток 360 Б/событие, 4.1 аллокаций/событие против ≤ 380; микс ночи №4, 80000 событий, поставляемые правила)" > "$d/a2.txt"
}
run() { local d="$T/$1"; shift; env RUN="$d/run" ATT="$d/att" INV="" GATE="$d/gate.txt" A2="$d/a2.txt" "$@" bash "$E" 2>&1; }
# expect <вывод> <метка> <слово> [подстрока класса] <имя случая>
expect() {
    local out="$1" lbl="$2" word="$3" sub="$4" name="$5" line
    line=$(printf '%s\n' "$out" | grep -aE "^[^ ]+: $lbl ")
    if printf '%s' "$line" | grep -q "$lbl $word" && { [ -z "$sub" ] || printf '%s' "$line" | grep -qF -- "$sub"; }; then
        ok "$name: $lbl $word${sub:+ ($sub)}"
    else
        bad "$name: ждали «$lbl $word${sub:+ … $sub}», получили «${line:-нет строки}»"
    fi
}

mkcase ok; o=$(run ok)
expect "$o" 8.2.1 ДОСТИГНУТО "пик 104.4" "ок"
expect "$o" 8.2.5 ДОСТИГНУТО "" "ок"
expect "$o" 8.2.3 ДОСТИГНУТО "" "ок (A2 с префиксом go test)"
expect "$o" 8.2.2 НЕИЗМЕРИМ "нет каталога инвентаря" "ок без INV"

o=$(run ok BUDGET_MIB=90)
expect "$o" 8.2.1 ПРОВАЛЕН "> 90" "мутация порога"

mkcase short; samples "$T/short/run/samples.tsv" 3.4 40.0 84 95.5 4.4; o=$(run short)
expect "$o" 8.2.1 НЕИЗМЕРИМ "< 60" "старт < 60 с"

mkcase cut; echo "1300.0" > "$T/cut/att/t-att1"; o=$(run cut)
expect "$o" 8.2.1 НЕИЗМЕРИМ "обрываются" "сэмплы атак короче пакета"

mkcase oom; echo 1 > "$T/oom/att/restarts.txt"; echo OOMKilled > "$T/oom/att/last-state.txt"; o=$(run oom)
expect "$o" 8.2.1 ПРОВАЛЕН "OOMKilled" "рестарт контейнера"

mkcase norst; rm "$T/norst/att/restarts.txt"; o=$(run norst)
expect "$o" 8.2.1 НЕИЗМЕРИМ "restarts.txt" "нет restarts.txt"

mkcase loss; metrics "$T/loss/att/m-att1.txt" 7 0; o=$(run loss)
expect "$o" 8.2.5 ПРОВАЛЕН "потери protected 7" "потери protected"

mkcase rbf; metrics "$T/rbf/att/m-att1.txt" 0 12; o=$(run rbf)
expect "$o" 8.2.5 ПРОВАЛЕН "ringbuf_full 12" "ringbuf_full выше базы"

mkcase noser; grep -v ringbuf_full "$T/noser/att/m-att1.txt" > "$T/noser/x" && mv "$T/noser/x" "$T/noser/att/m-att1.txt"; o=$(run noser)
expect "$o" 8.2.5 НЕИЗМЕРИМ "ringbuf_full нет" "нет серии ringbuf_full (пустота ≠ 0)"

mkcase miss; echo '[{"id":"old-1","rule_id":"x","comm":"curl"},{"id":"n2","rule_id":"y","comm":"curl"}]' > "$T/miss/att/final-alerts-20261012_060000.json"; o=$(run miss)
expect "$o" 8.2.5 ПРОВАЛЕН "recall пода 1/2" "recall пода"

mkcase gfail; printf '\033[0;31m[FAIL]\033[0m recall по манифесту: 12/13 = 0.923 (ожидалось 1.000; не пойманы: ssrf)\n' > "$T/gfail/gate.txt"; o=$(run gfail)
expect "$o" 8.2.5 ПРОВАЛЕН "гейта хоста FAIL" "recall гейта хоста"

mkcase gnone; : > "$T/gnone/gate.txt"; o=$(run gnone)
expect "$o" 8.2.5 НЕИЗМЕРИМ "нет gate.txt" "нет гейта"

# Половины независимы: потери И нет гейта — провал называет (а) и печатает неизмеримость (в).
mkcase both; metrics "$T/both/att/m-att1.txt" 3 0; : > "$T/both/gate.txt"; o=$(run both)
expect "$o" 8.2.5 ПРОВАЛЕН "неизмеримо также" "независимые половины"

mkcase noa2; : > "$T/noa2/a2.txt"; o=$(run noa2)
expect "$o" 8.2.3 НЕИЗМЕРИМ "нет вердиктной строки" "нет A2"

echo ""
[ "$FAIL" -eq 0 ] && echo "w82-close-report fixtures: все случаи прошли" || echo "w82-close-report fixtures: FAIL=$FAIL"
exit "$FAIL"
