#!/bin/bash
# Фикстуры night-report.sh (ЗАМЕР №3). Каждая ветка вердикта — своя синтетическая
# ночь; снимки пишутся в форме /metrics агента. Запуск с mac, стенд не нужен.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
R="$HERE/night-report.sh"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { echo "  OK    $*"; }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

# _night <каталог> <часов> <выпущено/ч> <лимитер/ч> <дедуп/ч> [опции key=val ...]
#   vol8=N        — объём часа 8 (дедуп-слой) вместо обычного
#   e8=N          — выпущено в час 8
#   restart_at=N  — сменить process_start_time_seconds с снимка N
#   empty_at=N    — снимок N пустой
#   attack_at=N   — +1 инцидент attack на снимке N
#   no_attack=1   — серии attack нет вовсе
#   rss_grow=N    — RSS растёт на N МиБ за час (иначе плоский с колебанием)
#   no_store=1    — store-size.tsv не писать
#   zero_h2=1     — объём часа 2 нулевой
_night() {
    local d="$1" H="$2" E="$3" RL="$4" DD="$5"; shift 5
    local vol8="" e8="" restart_at=-1 empty_at=-1 attack_at=-1 no_attack=0 rss_grow=0 no_store=0 zero_h2=0 kv
    for kv in "$@"; do eval "local ${kv%%=*}=${kv#*=}"; done
    mkdir -p "$d/snapshots"
    local n e=0 r=0 dd=0 att=0 start=1900000000 h es rs ds rss f
    for n in $(seq 0 $(( H * 12 ))); do
        if [ "$n" -gt 0 ]; then
            h=$(( (n - 1) / 12 + 1 ))
            es=$E; rs=$RL; ds=$DD
            [ "$h" -eq 8 ] && [ -n "$e8" ] && es=$e8
            [ "$h" -eq 8 ] && [ -n "$vol8" ] && ds=$vol8
            [ "$h" -eq 2 ] && [ "$zero_h2" = 1 ] && { es=0; rs=0; ds=0; }
            e=$(( e + es / 12 )); r=$(( r + rs / 12 )); dd=$(( dd + ds / 12 ))
        fi
        [ "$n" -eq "$attack_at" ] && att=$(( att + 1 ))
        [ "$restart_at" -ge 0 ] && [ "$n" -ge "$restart_at" ] && start=1900009999
        rss=$(( (300 + (rss_grow * n / 12) + (n % 3)) * 1048576 ))
        f=$(printf '%s/snapshots/metrics-%04d.txt' "$d" "$n")
        if [ "$n" -eq "$empty_at" ]; then : > "$f"; continue; fi
        {
            echo "# HELP ebpf_guard_alerts_total x"
            echo "ebpf_guard_alerts_total{rule_id=\"a\",severity=\"warning\"} $(( e / 2 ))"
            echo "ebpf_guard_alerts_total{rule_id=\"b\",severity=\"critical\"} $(( e - e / 2 ))"
            echo "ebpf_guard_alerts_ratelimited_by_rule_total{rule_id=\"a\"} $r"
            echo "ebpf_guard_alerts_dedup_dropped_total $dd"
            [ "$no_attack" = 1 ] || echo "ebpf_guard_incidents_total{verdict=\"attack\"} $att"
            echo "ebpf_guard_incidents_total{verdict=\"suspicious\"} 7"
            echo "process_start_time_seconds $start"
            echo "process_resident_memory_bytes $rss"
            echo "go_memstats_heap_alloc_bytes $(( rss / 3 ))"
            echo "go_memstats_heap_inuse_bytes $(( rss / 2 ))"
            echo "go_memstats_heap_idle_bytes $(( rss / 4 ))"
            echo "go_memstats_heap_released_bytes $(( rss / 8 ))"
        } > "$f"
        [ "$no_store" = 1 ] || printf '2026-10-02T00:00:00Z\t%s\t%s\t%s\n' "$n" $(( 1048576 * (10 + n) )) 0 >> "$d/snapshots/store-size.tsv"
    done
}
_case() { local name="$1"; shift; rm -rf "$T/$name"; _night "$T/$name" "$@"; bash "$R" "$T/$name" 300 < /dev/null 2>&1; }
_need() { local what="$1" out="$2"; shift 2; local s; for s in "$@"; do
    printf '%s' "$out" | grep -qF -- "$s" || { bad "$what: нет «${s}»"; return; }; done; ok "$what"; }
_forbid() { local what="$1" out="$2"; shift 2; local s; for s in "$@"; do
    printf '%s' "$out" | grep -qF -- "$s" && { bad "$what: есть запрещённое «${s}»"; return; }; done; ok "$what"; }

echo "[ночь ровная, 9 часов]"
o=$(_case flat 9 120 120 600)
_need "P1-19 ровный — ДОСТИГНУТО с суммой трёх слоёв" "$o" "ДОСТИГНУТО: 3.P1-19" "часа 8 = 840 алертов" "часа 2 = 840 алертов" "отношение 1.000"
_need "память ровная — ИЗМЕРЕНО, не монотонный" "$o" "ИЗМЕРЕНО: 3.MEM" "не_монотонный"
_need "attack на idle 0 — ДОСТИГНУТО" "$o" "ДОСТИГНУТО: 3.ATTACK"
_need "стор — НЕИЗМЕРИМ по построению с величиной" "$o" "НЕИЗМЕРИМ: 3.STORE НЕИЗМЕРИМ по построению" "МиБ/ч"

echo "[выпущено упёрлось в лимитер, рост ушёл в дедуп]"
o=$(_case limiter 9 120 120 600 vol8=1200)
_need "рост в дедупе — ПРОВАЛЕН, хотя «выпущено» ровное" "$o" "ПРОВАЛЕН: 3.P1-19" "часа 8 = 1440 алертов"

echo "[рост в пределах 20%]"
o=$(_case edge 9 120 0 0 e8=144)
_need "ровно 1.20 — ДОСТИГНУТО (граница включительно)" "$o" "ДОСТИГНУТО: 3.P1-19" "отношение 1.200"

echo "[память растёт монотонно]"
o=$(_case grow 9 120 0 600 rss_grow=12)
_need "рост RSS — монотонный, наклон ≈12 МиБ/ч" "$o" "монотонный_рост" "RSS наклон 12.00 МиБ/ч"

echo "[рестарт в часе 8]"
o=$(_case restart 9 120 0 600 restart_at=90)
_need "рестарт — НЕИЗМЕРИМ с классом часа" "$o" "НЕИЗМЕРИМ: 3.P1-19" "8:рестарт"
_need "attack через рестарт — НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ: 3.ATTACK"
_forbid "рестарт не даёт ДОСТИГНУТО P1-19" "$o" "ДОСТИГНУТО: 3.P1-19"

echo "[пустой снимок на границе часа 2]"
o=$(_case empty 9 120 0 600 empty_at=24)
_need "пустой снимок — НЕИЗМЕРИМ, а не ноль" "$o" "НЕИЗМЕРИМ: 3.P1-19" "2:снимок_пуст"

echo "[ночь короче 8 часов]"
o=$(_case short 5 120 0 600)
_need "5 часов — НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: полных часов 5"

echo "[инцидент attack ночью]"
o=$(_case attack 9 120 0 600 attack_at=50)
_need "attack +1 — ПРОВАЛЕН" "$o" "ПРОВАЛЕН: 3.ATTACK" "за ночь 1"

echo "[серии attack нет]"
o=$(_case noattack 9 120 0 600 no_attack=1)
_need "нет серии — НЕИЗМЕРИМ, не 0" "$o" "НЕИЗМЕРИМ: 3.ATTACK" "нет серии ≠ 0"
_forbid "нет серии не даёт ДОСТИГНУТО" "$o" "ДОСТИГНУТО: 3.ATTACK"

echo "[час 2 нулевой]"
o=$(_case zero2 9 120 0 600 zero_h2=1)
_need "нулевой час 2 — отношение не определено" "$o" "НЕИЗМЕРИМ: 3.P1-19" "отношение не определено"

echo "[стор не снят]"
o=$(_case nostore 9 120 0 600 no_store=1)
_need "нет store-size — НЕИЗМЕРИМ с причиной" "$o" "STORE_DB не задан"

echo "[каталога снимков нет]"
o=$(bash "$R" "$T/nothing" 300 < /dev/null 2>&1)
_need "нет каталога — НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ: 3.*"

echo
[ "$FAIL" -eq 0 ] && { echo "night-report-fixtures: расхождений 0"; exit 0; }
echo "night-report-fixtures: ЕСТЬ РАСХОЖДЕНИЯ ($FAIL)"; exit 1
