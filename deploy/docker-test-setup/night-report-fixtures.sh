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
#   cg_step=N     — с среза N anon выше на cg_step_mib МиБ (ступенька ночи H:
#                   dpkg-шторм в последний час, уровень не возвращается)
#   cg_step_mib=M — высота ступеньки, МиБ (по умолчанию 40)
#   drops=N       — потери очереди protected за ночь (метка 8.1.2)
#   no_hwm=1      — серий ebpf_guard_queue_depth_hwm нет (прибор очередей не предъявлен)
#   no_dropseries=1 — серии потерь очереди нет вовсе
#   vols=h:v,h:v  — объём часа h (дедуп-слой, АЛЕРТОВ/ч) вместо обычного — метка 3.P1-19
#   units=h:s:d:u,… — старт юнита u в час h через s секунд от начала часа, длится d с
#                   (node-units.tsv); без units — журнал юнитов снят и пуст
#   no_units=1    — node-units.tsv не писать вовсе (журнал не снят)
# Время снимка n — 2026-10-07T23:00:00Z + 300·n в форме store-size.tsv живого
# архива (20261007T230000Z): эмиттер 3.P1-19 сопоставляет часы журналу юнитов
# по этой колонке, и прежняя константа «2026-10-02T00:00:00Z» (не та форма)
# давала бы НЕИЗМЕРИМ на каждой фикстуре.
_FIX_T0=1791414000
_fix_ts() { awk -v t="$1" 'BEGIN {
    z = int(t / 86400) + 719468; era = int(z / 146097); doe = z - era * 146097
    yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
    y = yoe + era * 400; doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100)); mp = int((5 * doy + 2) / 153)
    d = doy - int((153 * mp + 2) / 5) + 1; m = mp + (mp < 10 ? 3 : -9); if (m <= 2) y++
    s = t % 86400; printf "%04d%02d%02dT%02d%02d%02dZ", y, m, d, int(s / 3600), int(s % 3600 / 60), s % 60 }'; }
_night() {
    local d="$1" H="$2" E="$3" RL="$4" DD="$5"; shift 5
    local vol8="" e8="" restart_at=-1 empty_at=-1 attack_at=-1 no_attack=0 rss_grow=0 no_store=0 zero_h2=0 kv
    local cg=none cg_peak=231 cg_step=-1 cg_step_mib=40 drops=0 no_hwm=0 no_dropseries=0
    local vols="" units="" no_units=0 u uh us ud un
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
            case ",$vols," in *",$h:"*) ds=$(printf '%s' ",$vols," | sed "s/.*,$h:\([0-9]*\),.*/\1/");; esac
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
        [ "$no_store" = 1 ] || printf '%s\t%s\t%s\t%s\n' "$(_fix_ts $(( _FIX_T0 + 300 * n )))" "$n" $(( 1048576 * (10 + n) )) 0 >> "$d/snapshots/store-size.tsv"
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
            [ "$cg_step" -ge 0 ] && [ "$n" -ge "$cg_step" ] && an_mib=$(awk -v a="$an_mib" -v m="$cg_step_mib" 'BEGIN { printf "%.1f", a + m }')
            cur_mib=$(awk -v p="$cg_peak" -v a="$an_mib" 'BEGIN { printf "%.0f", p - 40 + a - 100 }')
            # В байты переводит awk, а не $(( )): величина пилы дробная, и
            # целочисленная арифметика bash на ней падает молча для всего среза.
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(_fix_ts $(( _FIX_T0 + 300 * n )))" "$n" \
                "$(awk -v v="$cur_mib" 'BEGIN { printf "%.0f", v * 1048576 }')" \
                "$(awk -v v="$an_mib" 'BEGIN { printf "%.0f", v * 1048576 }')" \
                2097152 1234567 1437696 1114112 0 max >> "$d/snapshots/cgroup-mem.tsv"
        fi
    done
    if [ "$no_units" != 1 ]; then
        : > "$d/node-units.tsv"
        for u in $(printf '%s' "$units" | tr ',' ' '); do
            IFS=: read -r uh us ud un <<< "$u"
            printf '%s\t%s\t%s\n' $(( _FIX_T0 + (uh - 1) * 3600 + us )) $(( _FIX_T0 + (uh - 1) * 3600 + us + ud )) "$un" >> "$d/node-units.tsv"
        done
    fi
}
_case() { local name="$1"; shift; rm -rf "$T/$name"; _night "$T/$name" "$@"; bash "${RR:-$R}" "$T/$name" 300 < /dev/null 2>&1; }
_need() { local what="$1" out="$2"; shift 2; local s; for s in "$@"; do
    printf '%s' "$out" | grep -qF -- "$s" || { bad "$what: нет «${s}»"; return; }; done; ok "$what"; }
_forbid() { local what="$1" out="$2"; shift 2; local s; for s in "$@"; do
    printf '%s' "$out" | grep -qF -- "$s" && { bad "$what: есть запрещённое «${s}»"; return; }; done; ok "$what"; }

echo "[ночь ровная, 9 часов, юнитов ноды нет]"
o=$(_case flat 9 120 120 600)
_need "P1-19 ровный — ДОСТИГНУТО с классом ПЛАТО и суммой трёх слоёв" "$o" "ДОСТИГНУТО: 3.P1-19 ДОСТИГНУТО (класс ПЛАТО" "последний фоновый час 9 = 840 алертов против первого 2 = 840" "отношение 1.000" "фоновых часов 8"
_need "час 1 — прогрев, не фон" "$o" "1 прогрев 840; 2 фон 840"
_need "пустой журнал юнитов назван" "$o" "стартов юнитов ноды за окно 0"
_need "память ровная — ИЗМЕРЕНО, не монотонный" "$o" "ИЗМЕРЕНО: 3.MEM" "не_монотонный"
_need "attack на idle 0 — ДОСТИГНУТО" "$o" "ДОСТИГНУТО: 3.ATTACK"
_need "стор — НЕИЗМЕРИМ по построению с величиной" "$o" "НЕИЗМЕРИМ: 3.STORE НЕИЗМЕРИМ по построению" "МиБ/ч"

echo "[3.P1-19: фон нарастает, рост ушёл в дедуп — «выпущено» ровное]"
o=$(_case grow119 9 120 120 600 vols=9:3000)
_need "нарастание фона — ПРОВАЛЕН с классом НАРАСТАНИЕ" "$o" "ПРОВАЛЕН: 3.P1-19 ПРОВАЛЕН (класс НАРАСТАНИЕ" "последний фоновый час 9 = 3240 алертов против первого 2 = 840"
_forbid "нарастание не читается плато" "$o" "ДОСТИГНУТО: 3.P1-19"

echo "[3.P1-19: таймер в часе 8 — 16 000 алертов, фон ровный (форма ночи H2)]"
o=$(_case timer8 9 120 120 600 vols=8:16000 units=8:600:60:apt-daily-upgrade.service,8:700:5:man-db.service)
_need "таймерный час метку не решает — ДОСТИГНУТО ПЛАТО" "$o" "ДОСТИГНУТО: 3.P1-19 ДОСТИГНУТО (класс ПЛАТО" "последний фоновый час 9 = 840" "фоновых часов 7"
_need "час 8 назван событием с юнитами" "$o" "8 событие[apt-daily-upgrade.service man-db.service] 16236"
_need "цена события напечатана по срезам с вычетом фона" "$o" "цена события ноды 06:10:00–06:11:45 [apt-daily-upgrade.service man-db.service]: срезы 86…88 (600 с)" "фон ≈140 → цена 2566 алертов"
_need "без NIGHT_PREV это сказано" "$o" "прошлая ночь не задана (NIGHT_PREV)"

echo "[3.P1-19: таймер в часе 2 прячет нарастание фона — старая метка сказала бы ДОСТИГНУТО]"
o=$(_case timer2 9 120 120 600 vols=2:16000,9:3000 units=2:1800:30:apt-daily.service)
_need "нарастание видно мимо таймерного часа 2" "$o" "ПРОВАЛЕН: 3.P1-19 ПРОВАЛЕН (класс НАРАСТАНИЕ" "против первого 3 = 840"

echo "[3.P1-19: все часы таймерные]"
o=$(_case alltimer 9 120 120 600 units=2:60:5:a.service,3:60:5:b.service,4:60:5:c.service,5:60:5:d.service,6:60:5:e.service,7:60:5:f.service,8:60:5:g.service,9:60:5:h.service)
_need "фоновых часов 0 — НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: фоновых часов 0"
_forbid "без фона вердикта нет" "$o" "ДОСТИГНУТО: 3.P1-19" "ПРОВАЛЕН: 3.P1-19"
o=$(_case onebg 9 120 120 600 units=2:60:5:a.service,3:60:5:b.service,4:60:5:c.service,5:60:5:d.service,6:60:5:e.service,7:60:5:f.service,8:60:5:g.service)
_need "один фоновый час — НЕИЗМЕРИМ (нарастанию нужно два)" "$o" "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: фоновых часов 1"

echo "[3.P1-19: журнал юнитов не снят]"
o=$(_case nounits 9 120 120 600 no_units=1)
_need "нет node-units.tsv — НЕИЗМЕРИМ, а не «все часы фоновые»" "$o" "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: журнал стартов юнитов ноды не снят"
_forbid "нет журнала — нет вердикта" "$o" "ДОСТИГНУТО: 3.P1-19" "ПРОВАЛЕН: 3.P1-19"

echo "[3.P1-19: тишина ночи — 12 → 24 алерта, отношение 2, но в пределах счёта]"
o=$(_case noise119 9 0 0 12 vols=9:24)
_need "рост в пределах счётного шума — ДОСТИГНУТО с названной причиной" "$o" "ДОСТИГНУТО: 3.P1-19 ДОСТИГНУТО (класс ПЛАТО — рост в пределах счётного шума" "отношение 2.000" "счётного шума 2·√(F+L) = 12.0"
o=$(_case noise119b 9 0 0 12 vols=9:36)
_need "12 → 36 — разность 24 сверх шума 13,9 — НАРАСТАНИЕ" "$o" "ПРОВАЛЕН: 3.P1-19 ПРОВАЛЕН (класс НАРАСТАНИЕ"

echo "[3.P1-19: цена того же юнита прошлой ночи]"
rm -rf "$T/prev119"; _night "$T/prev119" 9 120 120 600 vols=8:4000 units=8:600:60:apt-daily-upgrade.service
o=$(rm -rf "$T/cur119"; _night "$T/cur119" 9 120 120 600 vols=8:16000 units=8:600:60:apt-daily-upgrade.service; NIGHT_PREV="$T/prev119" bash "$R" "$T/cur119" 300 < /dev/null 2>&1)
_need "цена прошлой ночи напечатана у того же юнита" "$o" "прошлая ночь: apt-daily-upgrade.service=" "(06:10:00–06:11:00)"
rm -rf "$T/prev119m"; _night "$T/prev119m" 9 120 120 600 vols=8:4000 units=8:600:60:apt-daily-upgrade.service,8:700:5:man-db.service
o=$(NIGHT_PREV="$T/prev119m" bash "$R" "$T/cur119" 300 < /dev/null 2>&1)
_need "цена прошлой ночи из слитого события названа событием" "$o" "(06:10:00–06:11:45, событие из 2 юнитов)"
o=$(NIGHT_PREV="$T/flat" bash "$R" "$T/cur119" 300 < /dev/null 2>&1)
_need "юнита не было прошлой ночью — «нет»" "$o" "прошлая ночь: apt-daily-upgrade.service=нет"
rm -f "$T/flat/node-units.tsv"; o=$(NIGHT_PREV="$T/flat" bash "$R" "$T/cur119" 300 < /dev/null 2>&1)
_need "прошлая ночь без журнала — сказано, цены не сравниваются" "$o" "без node-units.tsv — цены не сравниваются"

echo "[память растёт монотонно]"
o=$(_case grow 9 120 0 600 rss_grow=12)
_need "рост RSS — монотонный, наклон ≈12 МиБ/ч" "$o" "монотонный_рост" "RSS наклон 12.00 МиБ/ч"

echo "[рестарт в часе 8]"
o=$(_case restart 9 120 0 600 restart_at=90)
_need "час рестарта из фона вынут и назван" "$o" "8 рестарт; 9 фон" "фоновых часов 7"
_need "attack через рестарт — НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ: 3.ATTACK"

echo "[пустой снимок на границе часа 2]"
o=$(_case empty 9 120 0 600 empty_at=24)
_need "пустой снимок — часы по обе стороны вынуты, а не ноль" "$o" "2 снимок_пуст; 3 снимок_пуст" "фоновых часов 6"

echo "[ночь короче 8 часов]"
o=$(_case short 5 120 0 600)
_need "5 часов — четыре фоновых, вердикт выносится" "$o" "ДОСТИГНУТО: 3.P1-19" "фоновых часов 4"
o=$(_case short2 2 120 0 600)
_need "2 часа — один фоновый, НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: фоновых часов 1"

echo "[инцидент attack ночью]"
o=$(_case attack 9 120 0 600 attack_at=50)
_need "attack +1 — ПРОВАЛЕН" "$o" "ПРОВАЛЕН: 3.ATTACK" "за ночь 1"

echo "[серии attack нет]"
o=$(_case noattack 9 120 0 600 no_attack=1)
_need "нет серии — НЕИЗМЕРИМ, не 0" "$o" "НЕИЗМЕРИМ: 3.ATTACK" "нет серии ≠ 0"
_forbid "нет серии не даёт ДОСТИГНУТО" "$o" "ДОСТИГНУТО: 3.ATTACK"

echo "[час 2 нулевой]"
o=$(_case zero2 9 120 0 600 zero_h2=1)
_need "нулевой первый фоновый час — отношение не определено, рост сверх шума" "$o" "ПРОВАЛЕН: 3.P1-19 ПРОВАЛЕН (класс НАРАСТАНИЕ" "отношение не определено"

echo "[стор не снят]"
o=$(_case nostore 9 120 0 600 no_store=1)
_need "нет store-size — НЕИЗМЕРИМ с причиной" "$o" "STORE_DB не задан"
_need "нет времени снимков — 3.P1-19 НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: у снимков нет времени"

echo "[каталога снимков нет]"
o=$(bash "$R" "$T/nothing" 300 < /dev/null 2>&1)
_need "нет каталога — НЕИЗМЕРИМ" "$o" "НЕИЗМЕРИМ: 3.*"

echo "[8.1.1: anon насыщается — прогрев]"
o=$(_case cgflat 9 120 0 600 cg=plateau)
_need "насыщение — ДОСТИГНУТО с классом ПРОГРЕВ" "$o" "ДОСТИГНУТО: 8.1.1" "класс ПРОГРЕВ"
_forbid "замедляющийся рост не читается как накопление" "$o" "класс НАКОПЛЕНИЕ" "ПРОВАЛЕН: 8.1.1"
_need "печатает тренд, разброс и чистое изменение" "$o" "тренд за окно" "против разброса остатков" "чистое изменение"
_need "пик current сравнён с лимитом чарта" "$o" "против лимита чарта 256.0 МиБ" "запас"
_need "без ступенек это сказано" "$o" "ступенек нет"
_forbid "вердиктное слово — класс, не ИЗМЕРЕНО" "$o" "ИЗМЕРЕНО: 8.1.1"

echo "[8.1.1: anon растёт до конца — накопление]"
o=$(_case cggrow 9 120 0 600 cg=grow)
_need "линейный рост — ПРОВАЛЕН с классом НАКОПЛЕНИЕ" "$o" "ПРОВАЛЕН: 8.1.1" "класс НАКОПЛЕНИЕ"
_forbid "монотонный рост не уходит в плато (класс обязан быть достижим)" "$o" "накоплением не называется" "ДОСТИГНУТО: 8.1.1"

echo "[8.1.1: пила ночи №4 — накоплением НЕ называется (находка №524)]"
o=$(_case cgsaw 9 120 0 600 cg=saw)
_need "пила — ДОСТИГНУТО с классом ПЛАТО/колебание" "$o" "ДОСТИГНУТО: 8.1.1" "накоплением не называется"
_forbid "пила не читается как накопление" "$o" "класс НАКОПЛЕНИЕ"
_forbid "пила не читается как ступенька" "$o" "ступенек 1" "ступенек 2"
_need "разброс остатков и развороты названы" "$o" "против разброса остатков" "разворотов знака"

echo "[8.1.1: плато со ступенькой в последний час — ночь H]"
o=$(_case cgstep 9 120 0 600 cg=saw cg_step=100)
_need "ступенька вынесена из класса — ПЛАТО по участку до неё" "$o" "ДОСТИГНУТО: 8.1.1" "класс ПЛАТО" "ступенек 1 (срез 100: +40" "класс считан по участку срезов 12…99"
_need "уровень после ступеньки напечатан" "$o" "уровень anon на конец окна"

echo "[8.1.1: накопление со ступенькой — ступенька не прячет рост]"
o=$(_case cggrowstep 9 120 0 600 cg=grow cg_step=100)
_need "рост до ступеньки — ПРОВАЛЕН" "$o" "ПРОВАЛЕН: 8.1.1" "класс НАКОПЛЕНИЕ" "ступенек 1"

echo "[8.1.1: ступенька сразу после прогрева — участок короток]"
o=$(_case cgstepearly 2 120 0 600 cg=saw cg_step=18)
_need "оба участка короче часа — НЕИЗМЕРИМ с названными ступеньками" "$o" "НЕИЗМЕРИМ: 8.1.1" "ступенек 1"
_forbid "коротким участком класс не выносится" "$o" "ДОСТИГНУТО: 8.1.1" "ПРОВАЛЕН: 8.1.1"

echo "[8.1.1: пик выше лимита чарта]"
o=$(_case cgover 9 120 0 600 cg=plateau cg_peak=300)
_need "перебор назван перебором" "$o" "перебор"
_forbid "перебор не печатается как запас" "$o" "— запас"

echo "[8.1.1: прибора cgroup нет]"
o=$(_case cgnone 9 120 0 600)
_need "нет tsv — НЕИЗМЕРИМ с причиной, не ноль" "$o" "НЕИЗМЕРИМ: 8.1.1" "cgroup-mem.tsv не снят"
_forbid "нет прибора — нет класса" "$o" "ДОСТИГНУТО: 8.1.1" "ПРОВАЛЕН: 8.1.1"

echo "[8.1.1: ночь короче часа прогрева плюс часа точек]"
o=$(_case cgshort 1 120 0 600 cg=plateau)
_need "1 час — НЕИЗМЕРИМ, но пик напечатан" "$o" "НЕИЗМЕРИМ: 8.1.1" "пик memory.current"
_forbid "коротким окном класс не выносится" "$o" "ДОСТИГНУТО: 8.1.1" "ПРОВАЛЕН: 8.1.1"

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

echo "[3.P1-19: мутации эмиттера обязаны краснить фикстуры]"
# Мутация ложится на копию эмиттера; не легла (sed промахнулся) — это FAIL, а не
# зелёная мутация: иначе правка текста эмиттера молча выключила бы проверку.
_mutant() { local name="$1" expr="$2"; sed "$expr" "$R" > "$T/mut-$name.sh"
    cmp -s "$R" "$T/mut-$name.sh" && { bad "мутация $name не легла (шаблон sed не совпал)"; return 1; }; return 0; }
if _mutant noev 's/if (cs\[c\] < T\[b\] \&\& ce\[c\] + grace > T\[a\])/if (0)/'; then
    o=$(RR="$T/mut-noev.sh" _case mtimer2 9 120 120 600 vols=2:16000,9:3000 units=2:1800:30:apt-daily.service)
    printf '%s' "$o" | grep -qF "ПРОВАЛЕН: 3.P1-19 ПРОВАЛЕН (класс НАРАСТАНИЕ" \
        && bad "мутация «события юнитов не вынимают часы» — фикстура таймера 2 всё ещё ПРОВАЛЕН" \
        || ok "мутация «события юнитов не вынимают часы» краснит фикстуру таймера 2"
fi
if _mutant nonoise 's/grow = (L > 1.2 \* F) \&\& (L - F > noise)/grow = (L > 1.2 * F)/'; then
    o=$(RR="$T/mut-nonoise.sh" _case mnoise 9 0 0 12 vols=9:24)
    printf '%s' "$o" | grep -qF "рост в пределах счётного шума" \
        && bad "мутация «без счётного шума» — фикстура тишины всё ещё ПЛАТО" \
        || ok "мутация «без счётного шума» краснит фикстуру тишины"
fi
if _mutant nowarm 's/if (h == 1)       hc\[h\] = "прогрев"/if (0) hc[h] = "прогрев"/'; then
    o=$(RR="$T/mut-nowarm.sh" _case mflat 9 120 120 600)
    printf '%s' "$o" | grep -qF "1 прогрев 840; 2 фон 840" \
        && bad "мутация «час 1 в фоне» — фикстура ровной ночи всё ещё зовёт час 1 прогревом" \
        || ok "мутация «час 1 в фоне» краснит фикстуру ровной ночи"
fi

echo
[ "$FAIL" -eq 0 ] && { echo "night-report-fixtures: расхождений 0"; exit 0; }
echo "night-report-fixtures: ЕСТЬ РАСХОЖДЕНИЯ ($FAIL)"; exit 1
