#!/bin/bash
# Фикстуры w88-load-report.py (метки 8.8.2, 8.8.3, 8.8.4, 8.8.Н): синтетические лестницы с известными потерями контрольных и простоем ноды.
#   w88-load-report-fixtures.sh            — фикстуры
#   w88-load-report-fixtures.sh --mutate   — мутации эмиттера обязаны покраснить фикстуры
# Лестница фикстуры: ступень 0 (калибровка r0 = 2 события на операцию, 2 контрольных), ёмкость 10 000 оп/с без потерь, далее
# ступени с реальными дропами. Параметры ступени: ops, proc (соб./с обработано), drops, idle (доля простоя ноды), lost (событий
# недосчитано у каждого контрольного), plost/page (8.8.3: событий недосчитано у зонда w88p и верхняя граница корзины его возраста, с).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
MODE=${1:-}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fails=$((fails + 1)); }

cat > "$T/build.py" <<'PY'
import json, os, sys
out, spec = sys.argv[1], json.loads(sys.argv[2])
R0, DT, CTL_RATE = 2, 60, 100
for i, s in enumerate(spec, 1):
    d = f"{out}/step-{i:02d}-{s['name']}"
    os.makedirs(d)
    w = lambda f, t: open(f"{d}/{f}", "w").write(t)
    w("a.t", "1000.0\n"); w("b.t", f"{1000 + DT}.0\n"); w("c.t", f"{1000 + DT + 5}.0\n")
    w("step-start.t", "1000.0\n"); w("step-end.t", f"{1000 + DT}.0\n")
    proc, drops = s["proc"] * DT, s["drops"]
    def prom(ev, dr, age, seen, pseen, pn):
        t = f'ebpf_guard_events_total{{type="file"}} {ev}\nebpf_guard_events_dropped_total{{reason="ring"}} {dr}\nebpf_guard_ingest_event_age_seconds_count {age}\n'
        for k in (1, 2):
            t += f'ebpf_guard_load_probe_events_total{{probe="w88c{k}"}} {seen[k]}\n'
        t += f'ebpf_guard_load_probe_events_total{{probe="w88p"}} {pseen}\n'
        for le in ("0.05", "0.1", "0.25", "+Inf"):
            n = pn if le == "+Inf" or float(le) >= s.get("page", 0.05) else 0
            t += f'ebpf_guard_load_probe_event_age_seconds_bucket{{probe="w88p",le="{le}"}} {n}\n'
        return t
    sent = CTL_RATE * DT
    lk = s.get("lostk", [s["lost"], s["lost"]])
    seen_c = {k: sent * R0 - lk[k - 1] for k in (1, 2)}
    pseen = sent * R0 - s.get("plost", 0)
    w("a.prom", prom(0, 0, 0, {1: 0, 2: 0}, 0, 0))
    w("b.prom", prom(proc, drops, proc, {1: 0, 2: 0}, 0, pseen))
    w("c.prom", prom(proc, drops, proc, seen_c, pseen, pseen))
    total = 24000   # 4 ядра × 60 с × 100 тиков
    idle = int(total * s["idle"])
    w("a.cpu", "cpu  0 0 0 0 0 0 0 0 0 0\n"); w("b.cpu", f"cpu  {total - idle} 0 0 {idle} 0 0 0 0 0 0\n")
    w("a.ticks", "0\n"); w("b.ticks", f"{int(s.get('agent', 1.0) * DT * 100)}\n")
    for g in range(1, s.get("gp", 1) + 1):
        json.dump({"ops_total": s["ops"] * DT / s.get("gp", 1), "elapsed_s": DT, "connect_errors": 0, "cpu_self_s": 30.0, "cpu_children_s": 10.0},
                  open(f"{d}/gen.json.{g}", "w"))
    for k in (1, 2):
        json.dump({"ops_total": sent}, open(f"{d}/ctl.{k}.json", "w"))
    json.dump({"ops_total": sent}, open(f"{d}/probe.json", "w"))
PY

# base: калибровка, ёмкость, 2×, прочее задаётся case-ом
S0='{"name":"0","ops":100,"proc":200,"drops":0,"idle":0.9,"lost":0}'
S1='{"name":"10000","ops":10000,"proc":10000,"drops":0,"idle":0.6,"lost":0}'
run() { # run <имя> <ступени-через-запятую> [role] — печатает строки 8.8.2/8.8.4/8.8.Н
    rm -rf "$T/$1"; mkdir -p "$T/$1"
    python3 "$T/build.py" "$T/$1" "[$2]" || { echo "builder failed"; return 1; }
    cp "$HERE/w87-e6-table.py" "$T/" 2> /dev/null
    python3 "${REPORT:-$HERE/w88-load-report.py}" "$T/$1" role=host cpu_limit=0.5 2>&1 | grep -aE '^8\.8\.(2|3|4|Н)(\([^)]*\))? '
}
# 2× ступень: дропы ≥ 1% (потолок достигнут), плато 1.0
two() { echo "{\"name\":\"20000\",\"ops\":20000,\"proc\":10000,\"drops\":${1:-50000},\"idle\":${2:-0.4},\"lost\":${3:-0}}"; }

has() { grep -aqE "$2" <<< "$1"; }

# 1. ноль потерь на 2× — PASS
o=$(run clean "$S0,$S1,$(two 50000 0.4 0)"); has "$o" '^8\.8\.4 host: PASS' && ok "ноль потерь на 2×: 8.8.4 PASS" || { bad "ноль потерь на 2×"; echo "$o"; }
# 2. одно потерянное событие (0,01%) — PASS по порогу 0,1% (волна 9); «0 событий» справочно FAIL
o=$(run lose1 "$S0,$S1,$(two 50000 0.4 1)"); has "$o" '^8\.8\.4 host: PASS.*прежний 0\.5% — PASS' && has "$o" '^8\.8\.4\(0\) host: FAIL.*20000/w88c1: 1' && ok "1 событие: 8.8.4 PASS по 0,1%, 8.8.4(0) FAIL" || { bad "1 событие"; echo "$o"; }
# 2в–2д. заход C волны 9: счёт процесса квантуется шагом 2 на любой ступени (вызов рантайма Go = enter+exit) — эталон — ПОЛ
#   по ступеням без реальных дропов, общий для контрольных; первая ступень как эталон давала «потерю 2» без потери.
J0='{"name":"0","ops":100,"proc":200,"drops":0,"idle":0.9,"lost":0,"lostk":[-2,0]}'
J1='{"name":"10000","ops":10000,"proc":10000,"drops":0,"idle":0.6,"lost":0,"lostk":[0,-2]}'
o=$(run jitter "$J0,$J1,$(two 50000 0.4 0)"); has "$o" '^8\.8\.4\(0\) host: PASS' && has "$o" 'по первой чистой ступени \(до захода C\): худшая 2 соб' && ok "дрожание базы ±2: 8.8.4(0) PASS, старая калибровка — 2 соб. справочно" || { bad "дрожание базы"; echo "$o"; }
o=$(run below "$J0,$J1,$(two 50000 0.4 2)"); has "$o" '^8\.8\.4\(0\) host: FAIL.*20000/w88c[12]: 2' && ok "недосчёт 2 ниже пола: 8.8.4(0) FAIL" || { bad "ниже пола"; echo "$o"; }
# ступень с дропами < 1% не калибрует пол: там контрольные потеряли 6, на 2× — 4 (ниже пола чистых ступеней)
SD='{"name":"15000","ops":15000,"proc":10000,"drops":3000,"idle":0.5,"lost":6}'
o=$(run caldrop "$S0,$S1,$SD,$(two 50000 0.4 4)"); has "$o" '^8\.8\.4\(0\) host: FAIL.*: 4' && has "$o" 'без реальных дропов: 0,10000 ' && ok "ступень с дропами не входит в калибровку пола" || { bad "калибровка по дропам"; echo "$o"; }
# 2б. 0,2% — FAIL по 0,1%, прежний 0,5% справочно PASS
o=$(run mid "$S0,$S1,$(two 50000 0.4 24)"); has "$o" '^8\.8\.4 host: FAIL.*прежний 0\.5% — PASS' && ok "0,2%: FAIL по 0,1%, 0,5% справочно PASS" || { bad "0,2%"; echo "$o"; }
# 3. 0,6% — FAIL и по прежнему порогу
o=$(run big "$S0,$S1,$(two 50000 0.4 72)"); has "$o" '^8\.8\.4 host: FAIL.*прежний 0\.5% — FAIL' && ok "0,6%: FAIL, справочно FAIL" || { bad "0,6%"; echo "$o"; }
# 4. потери на 2.5× при чистых 2× — окно 2×, не 2,5×: PASS
S25='{"name":"25000","ops":25000,"proc":10000,"drops":80000,"idle":0.35,"lost":200}'
o=$(run window "$S0,$S1,$(two 50000 0.4 0),$S25"); has "$o" '^8\.8\.4 host: PASS' && ok "потери на 2,5× не судятся при чистых 2×" || { bad "окно 2×"; echo "$o"; }
# 5. ящик занят (простой 5%) на 2×-ступени — НЕИЗМЕРИМ, а не FAIL; 8.8.Н печатает число
o=$(run sat "$S0,$S1,$(two 50000 0.05 300)"); has "$o" '^8\.8\.4 host: НЕИЗМЕРИМ.*простой ноды 5\.0%' && has "$o" '^8\.8\.Н host: НЕИЗМЕРИМ.*минимальный простой ноды 5\.0%' && ok "простой 5%: 8.8.4 НЕИЗМЕРИМ с числом, 8.8.Н НЕИЗМЕРИМ (стенд насыщен)" || { bad "насыщение"; echo "$o"; }
# 6. простой 12% (≥ 10%) — судится: FAIL
o=$(run unsat "$S0,$S1,$(two 50000 0.12 300)"); has "$o" '^8\.8\.4 host: FAIL' && ok "простой 12%: судится" || { bad "простой 12%"; echo "$o"; }
# 7. нет ступени около 2× (10 000 → 40 000 = 4×) — НЕИЗМЕРИМ
S4='{"name":"40000","ops":40000,"proc":10000,"drops":200000,"idle":0.3,"lost":500}'
o=$(run far "$S0,$S1,$S4"); has "$o" '^8\.8\.4 host: НЕИЗМЕРИМ.*\[1,5; 2,5\]' && ok "нет ступени около 2×: НЕИЗМЕРИМ" || { bad "нет 2×"; echo "$o"; }
# 8. 8.8.2: коллапс на ступени с простором — FAIL; тот же коллапс при простое 5% — НЕИЗМЕРИМ
COL='{"name":"60000","ops":60000,"proc":4000,"drops":600000,"idle":%s,"lost":0}'
o=$(run col "$S0,$S1,$(two 50000 0.4 0),$(printf "$COL" 0.3)"); has "$o" '^8\.8\.2 host: FAIL' && ok "8.8.2: коллапс при простое 30% — FAIL" || { bad "8.8.2 коллапс"; echo "$o"; }
o=$(run colsat "$S0,$S1,$(two 50000 0.4 0),$(printf "$COL" 0.05)"); has "$o" '^8\.8\.2 host: НЕИЗМЕРИМ.*простой ноды 5\.0%' && ok "8.8.2: коллапс при простое 5% — НЕИЗМЕРИМ с числом" || { bad "8.8.2 насыщение"; echo "$o"; }
# 10. справка 8.8.Т печатается с числами ступеней
o=$(run tab "$S0,$S1,$(two 50000 0.4 0)" ; python3 "${REPORT:-$HERE/w88-load-report.py}" "$T/tab" role=host cpu_limit=0.5 | grep -a '^8\.8\.Т'); has "$o" '^8\.8\.Т host: СПРАВКА.*20000: 20,000 оп/с → 10,000 соб\./с, дропы' && ok "8.8.Т: справка со ступенями" || { bad "8.8.Т"; echo "$o"; }
# 11–14. 8.8.3 (protected-зонд): порог плана 0 событий, окно (ёмкость, 2×ёмкость], p99 ≤ 100 мс
o=$(run pclean "$S0,$S1,$(two 50000 0.4 0)"); has "$o" '^8\.8\.3 host: PASS.*порог плана — 0 событий' && ok "8.8.3: зонд без потерь на 2× — PASS" || { bad "8.8.3 чисто"; echo "$o"; }
P1='{"name":"20000","ops":20000,"proc":10000,"drops":50000,"idle":0.4,"lost":0,"plost":1}'
o=$(run plose1 "$S0,$S1,$P1"); has "$o" '^8\.8\.3 host: FAIL.*справочно по прежнему порогу 0\.5%: PASS.*потеряно 1 соб' && ok "8.8.3: 1 событие зонда — FAIL, 0,5% справочно PASS" || { bad "8.8.3 одно событие"; echo "$o"; }
P25='{"name":"25000","ops":25000,"proc":10000,"drops":80000,"idle":0.35,"lost":0,"plost":300}'
o=$(run pwin "$S0,$S1,$(two 50000 0.4 0),$P25"); has "$o" '^8\.8\.3 host: PASS.*\(10,000, 20,000\]' && ok "8.8.3: потери зонда на 2,5× не судятся (окно 2×)" || { bad "8.8.3 окно"; echo "$o"; }
PA='{"name":"20000","ops":20000,"proc":10000,"drops":50000,"idle":0.4,"lost":0,"page":0.25}'
o=$(run page "$S0,$S1,$PA"); has "$o" '^8\.8\.3 host: FAIL.*p99 возраста 250 мс' && ok "8.8.3: p99 250 мс — FAIL" || { bad "8.8.3 p99"; echo "$o"; }
# 15–16. 8.8.1: на ступенях без потерь degraded при сбросе по замыслу (уровень сторожа 1) — не нарушение; без сброса — FAIL
p881() { # p881 <имя> <уровень сторожа> — лестница без потерь и poll.tsv: degraded весь шаг
    run "$1" "$S0,$S1" > /dev/null
    for t in $(seq 1000 2 1060); do printf '%s\tdegraded\t0\t0\t%s\t1\n' "$t" "$2"; done > "$T/$1/poll.tsv"
    python3 "${REPORT:-$HERE/w88-load-report.py}" "$T/$1" role=host cpu_limit=0.5 2>&1 | grep -a '^8\.8\.1 '
}
o=$(p881 shed 1); has "$o" '^8\.8\.1 host: PASS.*сбросе по замыслу' && ok "8.8.1: degraded при сбросе по замыслу — PASS" || { bad "8.8.1 сброс"; echo "$o"; }
o=$(p881 noshed 0); has "$o" '^8\.8\.1 host: FAIL.*сброса нет, но не healthy' && ok "8.8.1: degraded без потерь и без сброса — FAIL" || { bad "8.8.1 ложная тревога"; echo "$o"; }
# 17–20. заход C волны 9: 8.8.2(ц) — цена события за потолком ≤ 1,1× первой потери; 8.8.3(а) — p99 только для ×1
C1='{"name":"30000","ops":30000,"proc":9000,"drops":90000,"idle":0.4,"lost":0,"agent":0.95}'
o=$(run price1 "$S0,$S1,$(two 50000 0.4 0),$C1"); has "$o" '^8\.8\.2\(ц\) host: PASS.*30000=105\.6 \(1\.06×\)' && ok "8.8.2(ц): цена +6% — PASS" || { bad "8.8.2(ц) PASS"; echo "$o"; }
C2='{"name":"30000","ops":30000,"proc":8000,"drops":90000,"idle":0.4,"lost":0,"agent":1.0}'
o=$(run price2 "$S0,$S1,$(two 50000 0.4 0),$C2"); has "$o" '^8\.8\.2\(ц\) host: FAIL.*30000: 125\.0 мкс \(1\.25×\)' && ok "8.8.2(ц): цена +25% — FAIL" || { bad "8.8.2(ц) FAIL"; echo "$o"; }
PA8='{"name":"20000","ops":20000,"proc":10000,"drops":50000,"idle":0.4,"lost":0,"page":0.25,"gp":8}'
o=$(run page8 "$S0,$S1,$PA8"); has "$o" '^8\.8\.3 host: FAIL.*p99' && has "$o" '^8\.8\.3\(а\) host: PASS.*генераторов 8: p99 возраста не судится' && ok "8.8.3(а): ×8 с p99 250 мс — PASS, 8.8.3 FAIL" || { bad "8.8.3(а) ×8"; echo "$o"; }
o=$(run page1 "$S0,$S1,$PA"); has "$o" '^8\.8\.3\(а\) host: FAIL.*генераторов 1: ×1' && ok "8.8.3(а): ×1 с p99 250 мс — FAIL" || { bad "8.8.3(а) ×1"; echo "$o"; }
PL8='{"name":"20000","ops":20000,"proc":10000,"drops":50000,"idle":0.4,"lost":0,"plost":3,"gp":8}'
o=$(run plose8 "$S0,$S1,$PL8"); has "$o" '^8\.8\.3\(а\) host: FAIL' && ok "8.8.3(а): потеря зонда на ×8 — FAIL" || { bad "8.8.3(а) потеря ×8"; echo "$o"; }
# 9. плато без коллапса — PASS
o=$(run plat "$S0,$S1,$(two 50000 0.4 0)"); has "$o" '^8\.8\.2 host: PASS' && ok "8.8.2: плато PASS" || { bad "8.8.2 плато"; echo "$o"; }

if [ "$MODE" = "--mutate" ]; then
    echo "── мутации эмиттера ──"
    mutate() { # mutate <имя> <sed-выражение> <ожидаем-красным-фикстур>
        cp "$HERE/w88-load-report.py" "$T/mut.py"; cp "$HERE/w87-e6-table.py" "$T/"
        sed -i.bak "$2" "$T/mut.py"; cmp -s "$T/mut.py" "$HERE/w88-load-report.py" && { bad "мутация '$1' не изменила файл"; return; }
        n=$(REPORT="$T/mut.py" bash "$0" 2>&1 | grep -c '^FAIL')
        [ "$n" -ge "$3" ] && ok "мутация '$1' краснит $n фикстур" || bad "мутация '$1' краснит только $n (< $3)"
    }
    mutate "пол 8.8.4 — первая ступень (до захода C)" 's/r0, cal_cls, cal_names = ratios(kind)/r0, cal_cls, cal_names = ratios_first(kind), "x", []/' 1
    mutate "пол — максимум, а не минимум" 's/floor = min(min(v) for v in per.values())/floor = max(max(v) for v in per.values())/' 1
    mutate "калибровка по ступеням с дропами" 's/if n and n\["drops"\] == 0\]/if n and n.get("loss_frac", 1) < LOSS_STEP_FRAC]/' 1
    mutate "8.8.4(0) молчит" 's/lines.append(verdict("8.8.4(0)", role, (not ev_bad) if judged else None,/lines.append(verdict("8.8.4(0)", role, True,/' 1
    mutate "8.8.2(ц) порог раздут" 's/^PRICE_RISE_MAX = 1.1 /PRICE_RISE_MAX = 1e9 /' 1
    mutate "8.8.3(а) судит p99 на ×N" 's/multi = gen_procs > 1/multi = False/' 1
    mutate "8.8.3(а) прощает потери на ×N" 's/ok_a = (len(bad) - len(bad_p99) == 0) if multi else (not bad)/ok_a = True if multi else (not bad)/' 1
    mutate "порог 8.8.4 раздут" 's/^CTL_LOSS_MAX_FRAC = 0.001/CTL_LOSS_MAX_FRAC = 1e9/' 2
    mutate "насыщение не судится" 's/^NODE_IDLE_MIN = 0.10/NODE_IDLE_MIN = 0.0/' 2
    mutate "окно 2× заменено на самую дальнюю" 's/ctl_step = min(cand)\[1\]/ctl_step = max(cand)[1]/' 1
    mutate "8.8.2 насыщение молчит" 's/elif sat_r and any/elif False and any/' 1
    mutate "справочный порог выключен" 's/"PASS" if worst <= CTL_LOSS_REF else "FAIL"/"FAIL"/' 1
    mutate "справочный порог 8.8.3 выключен" 's/("PASS" if worst <= PROBE_LOSS_REF else "FAIL")/"FAIL"/' 1
    mutate "8.8.1 сброс прощает всё" 's/deg_noshed = \[rows\[i\]\[0\] for i in idx if rows\[i\]\[1\] != "healthy" and not shedding(rows\[i\])\]/deg_noshed = []/' 1
    mutate "порог 8.8.3 раздут" 's/^PROBE_LOSS_MAX_EVENTS = 1.0/PROBE_LOSS_MAX_EVENTS = 1e9/' 1
    mutate "окно 8.8.3 — 2,5×" 's/^PROBE_WINDOW_MAX = 2.0/PROBE_WINDOW_MAX = 2.5/' 1
    mutate "p99 8.8.3 не судится" 's/^PROBE_P99_MAX = 0.1/PROBE_P99_MAX = 1e9/' 1
fi
echo "итого: $fails красных"; [ "$fails" -eq 0 ]
