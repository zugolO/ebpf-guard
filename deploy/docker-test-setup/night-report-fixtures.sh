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
#   cg=plateau|grow|saw|none — cgroup-mem.tsv: anon выходит на плато / растёт
#                   линейно / пилит вокруг плато так же, как в ночи №4 (находка
#                   №524: две точки на границах часов давали там класс,
#                   противоположный данным) / прибора нет вовсе — метка 8.1.1
#   cg_peak=N     — пик memory.current, МиБ (по умолчанию 231 — ниже лимита чарта)
#   drops=N       — потери очереди protected за ночь (метка 8.1.2)
#   no_hwm=1      — серий ebpf_guard_queue_depth_hwm нет (прибор очередей не предъявлен)
#   no_dropseries=1 — серии потерь очереди нет вовсе
_night() {
    local d="$1" H="$2" E="$3" RL="$4" DD="$5"; shift 5
    local vol8="" e8="" restart_at=-1 empty_at=-1 attack_at=-1 no_attack=0 rss_grow=0 no_store=0 zero_h2=0 kv
    local cg=none cg_peak=231 drops=0 no_hwm=0 no_dropseries=0
    for kv in "$@"; do eval "local ${kv%%=*}=${kv#*=}"; done
    mkdir -p "$d/snapshots"
    for kv in "$@"; do :; done
    [ "$cg" = none ] || printf 'timestamp\tn\tcurrent\tanon\tfile\tslab\tpagetables\tkernel_stack\tsock\tmax\n' > "$d/snapshots/cgroup-mem.tsv"
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
            if [ "$no_dropseries" != 1 ]; then
                echo "ebpf_guard_events_dropped_by_queue_total{collector=\"syscall\",queue=\"protected\"} $(( drops * n / (H * 12) ))"
                echo "ebpf_guard_events_dropped_total{collector=\"syscall\",reason=\"ringbuf_to_router\"} $(( drops * n / (H * 12) ))"
            fi
            if [ "$no_hwm" != 1 ]; then
                echo "ebpf_guard_queue_depth_hwm{queue=\"event_high\"} $(( n % 5 ))"
                echo "ebpf_guard_queue_depth_hwm{queue=\"event_low\"} $(( n % 9 ))"
                echo "ebpf_guard_queue_capacity{queue=\"event_high\"} 16384"
                echo "ebpf_guard_queue_capacity{queue=\"event_low\"} 16384"
            fi
        } > "$f"
        [ "$no_store" = 1 ] || printf '2026-10-02T00:00:00Z\t%s\t%s\t%s\n' "$n" $(( 1048576 * (10 + n) )) 0 >> "$d/snapshots/store-size.tsv"
        if [ "$cg" != none ]; then
            # anon: прогрев — логарифмическое насыщение (рост в первые часы, плато
            # к концу); накопление — линейный рост теми же МиБ/ч до конца.
            local an_mib cur_mib
            if [ "$cg" = plateau ]; then
                an_mib=$(awk -v n="$n" 'BEGIN { printf "%.0f", 100 + 40 * (1 - exp(-n / 24.0)) }')
            elif [ "$cg" = saw ]; then
                # Пила ночи №4: размах ~8 МиБ, период ~2 часа, слабый дрейф.
                # Час 1 ложится около впадины, час 8 около гребня — ровно та
                # пара точек, на которой первая версия классификатора сказала
                # «НАКОПЛЕНИЕ» траектории, кончившей ниже своего начала.
                an_mib=$(awk -v n="$n" 'BEGIN { printf "%.1f", 125 + 4 * sin(n / 3.8) + 0.004 * n }')
            else
                an_mib=$(awk -v n="$n" 'BEGIN { printf "%.0f", 100 + 0.35 * n }')
            fi
            cur_mib=$(awk -v p="$cg_peak" -v a="$an_mib" 'BEGIN { printf "%.0f", p - 40 + a - 100 }')
            # В байты переводит awk, а не $(( )): величина пилы дробная, и
            # целочисленная арифметика bash на ней падает молча для всего среза.
            printf '2026-10-02T00:00:00Z\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$n" \
                "$(awk -v v="$cur_mib" 'BEGIN { printf "%.0f", v * 1048576 }')" \
                "$(awk -v v="$an_mib" 'BEGIN { printf "%.0f", v * 1048576 }')" \
                2097152 1234567 1437696 1114112 0 max >> "$d/snapshots/cgroup-mem.tsv"
        fi
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

echo "[8.1.1: anon насыщается — прогрев]"
o=$(_case cgflat 9 120 0 600 cg=plateau)
_need "насыщение — класс прогрев (рост замедляется)" "$o" "ИЗМЕРЕНО: 8.1.1" "класс прогрев"
_forbid "замедляющийся рост не читается как накопление" "$o" "класс НАКОПЛЕНИЕ"
_need "печатает тренд, разброс и чистое изменение" "$o" "тренд за окно" "против разброса остатков" "чистое изменение"
_need "пик current сравнён с лимитом чарта" "$o" "против лимита чарта 256.0 МиБ" "запас"
_forbid "8.1.1 никогда не ДОСТИГНУТО" "$o" "ДОСТИГНУТО: 8.1.1"

echo "[8.1.1: anon растёт до конца — накопление]"
o=$(_case cggrow 9 120 0 600 cg=grow)
_need "линейный рост — класс НАКОПЛЕНИЕ" "$o" "ИЗМЕРЕНО: 8.1.1" "класс НАКОПЛЕНИЕ"
_forbid "монотонный рост не уходит в плато (класс обязан быть достижим)" "$o" "накоплением не называется"

echo "[8.1.1: пила ночи №4 — накоплением НЕ называется (находка №524)]"
o=$(_case cgsaw 9 120 0 600 cg=saw)
_need "пила — класс плато/колебание" "$o" "ИЗМЕРЕНО: 8.1.1" "накоплением не называется"
_forbid "пила не читается как накопление" "$o" "класс НАКОПЛЕНИЕ"
_need "разброс остатков и развороты названы" "$o" "против разброса остатков" "разворотов знака"

echo "[8.1.1: пик выше лимита чарта]"
o=$(_case cgover 9 120 0 600 cg=plateau cg_peak=300)
_need "перебор назван перебором" "$o" "перебор"
_forbid "перебор не печатается как запас" "$o" "— запас"

echo "[8.1.1: прибора cgroup нет]"
o=$(_case cgnone 9 120 0 600)
_need "нет tsv — НЕИЗМЕРИМ с причиной, не ноль" "$o" "НЕИЗМЕРИМ: 8.1.1" "cgroup-mem.tsv не снят"
_forbid "нет прибора — нет ИЗМЕРЕНО" "$o" "ИЗМЕРЕНО: 8.1.1"

echo "[8.1.1: ночь короче часа прогрева плюс часа точек]"
o=$(_case cgshort 1 120 0 600 cg=plateau)
_need "1 час — НЕИЗМЕРИМ, но пик напечатан" "$o" "НЕИЗМЕРИМ: 8.1.1" "пик memory.current"
_forbid "коротким окном класс не выносится" "$o" "ИЗМЕРЕНО: 8.1.1"

echo "[8.1.2: потерь нет, прибор очередей предъявлен]"
o=$(_case drop0 9 120 0 600 cg=plateau)
_need "ноль с прибором — ДОСТИГНУТО" "$o" "ДОСТИГНУТО: 8.1.2" "прибор очередей предъявлен"

echo "[8.1.2: потерь нет, но прибора очередей нет]"
o=$(_case drop0nohwm 9 120 0 600 no_hwm=1)
_need "ноль без прибора — НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ: 8.1.2" "прибор очередей не предъявлен"
_forbid "ноль без прибора не даёт ДОСТИГНУТО" "$o" "ДОСТИГНУТО: 8.1.2"

echo "[8.1.2: потери есть]"
o=$(_case drops 9 120 0 600 drops=667)
_need "потери — ПРОВАЛЕН с величиной и разрезом по часам" "$o" "ПРОВАЛЕН: 8.1.2" "за ночь 667" "час 1: protected +"

echo "[8.1.2: серии потерь нет вовсе]"
o=$(_case dropnoseries 9 120 0 600 no_dropseries=1)
_need "нет серии — НЕИЗМЕРИМ, не 0" "$o" "НЕИЗМЕРИМ: 8.1.2" "нет серии ≠ 0"
_forbid "нет серии не даёт ДОСТИГНУТО" "$o" "ДОСТИГНУТО: 8.1.2"

echo "[8.1.2: рестарт внутри ночи]"
o=$(_case droprestart 9 120 0 600 drops=10 restart_at=90)
_need "рестарт — НЕИЗМЕРИМ (дельта через рестарт)" "$o" "НЕИЗМЕРИМ: 8.1.2"

echo
[ "$FAIL" -eq 0 ] && { echo "night-report-fixtures: расхождений 0"; exit 0; }
echo "night-report-fixtures: ЕСТЬ РАСХОЖДЕНИЯ ($FAIL)"; exit 1
