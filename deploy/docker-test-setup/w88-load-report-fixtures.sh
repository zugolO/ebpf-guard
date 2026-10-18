#!/bin/bash
# Фикстуры w88-load-report.py (метки 8.8.2, 8.8.4, 8.8.Н): синтетические лестницы с известными потерями контрольных и простоем ноды.
#   w88-load-report-fixtures.sh            — фикстуры
#   w88-load-report-fixtures.sh --mutate   — мутации эмиттера обязаны покраснить фикстуры
# Лестница фикстуры: ступень 0 (калибровка r0 = 2 события на операцию, 2 контрольных), ёмкость 10 000 оп/с без потерь, далее
# ступени с реальными дропами. Параметры ступени: ops, proc (соб./с обработано), drops, idle (доля простоя ноды), lost (событий
# недосчитано у каждого контрольного).
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
    def prom(ev, dr, age, seen):
        t = f'ebpf_guard_events_total{{type="file"}} {ev}\nebpf_guard_events_dropped_total{{reason="ring"}} {dr}\nebpf_guard_ingest_event_age_seconds_count {age}\n'
        for k in (1, 2):
            t += f'ebpf_guard_load_probe_events_total{{probe="w88c{k}"}} {seen[k]}\n'
        return t
    sent = CTL_RATE * DT
    seen_c = {k: sent * R0 - s["lost"] for k in (1, 2)}
    w("a.prom", prom(0, 0, 0, {1: 0, 2: 0}))
    w("b.prom", prom(proc, drops, proc, {1: 0, 2: 0}))
    w("c.prom", prom(proc, drops, proc, seen_c))
    total = 24000   # 4 ядра × 60 с × 100 тиков
    idle = int(total * s["idle"])
    w("a.cpu", "cpu  0 0 0 0 0 0 0 0 0 0\n"); w("b.cpu", f"cpu  {total - idle} 0 0 {idle} 0 0 0 0 0 0\n")
    w("a.ticks", "0\n"); w("b.ticks", f"{int(s.get('agent', 1.0) * DT * 100)}\n")
    json.dump({"ops_total": s["ops"] * DT, "elapsed_s": DT, "connect_errors": 0, "cpu_self_s": 30.0, "cpu_children_s": 10.0},
              open(f"{d}/gen.json.1", "w"))
    for k in (1, 2):
        json.dump({"ops_total": sent}, open(f"{d}/ctl.{k}.json", "w"))
PY

# base: калибровка, ёмкость, 2×, прочее задаётся case-ом
S0='{"name":"0","ops":100,"proc":200,"drops":0,"idle":0.9,"lost":0}'
S1='{"name":"10000","ops":10000,"proc":10000,"drops":0,"idle":0.6,"lost":0}'
run() { # run <имя> <ступени-через-запятую> [role] — печатает строки 8.8.2/8.8.4/8.8.Н
    rm -rf "$T/$1"; mkdir -p "$T/$1"
    python3 "$T/build.py" "$T/$1" "[$2]" || { echo "builder failed"; return 1; }
    cp "$HERE/w87-e6-table.py" "$T/" 2> /dev/null
    python3 "${REPORT:-$HERE/w88-load-report.py}" "$T/$1" role=host cpu_limit=0.5 2>&1 | grep -aE '^8\.8\.(2|4|Н) '
}
# 2× ступень: дропы ≥ 1% (потолок достигнут), плато 1.0
two() { echo "{\"name\":\"20000\",\"ops\":20000,\"proc\":10000,\"drops\":${1:-50000},\"idle\":${2:-0.4},\"lost\":${3:-0}}"; }

has() { grep -aqE "$2" <<< "$1"; }

# 1. ноль потерь на 2× — PASS
o=$(run clean "$S0,$S1,$(two 50000 0.4 0)"); has "$o" '^8\.8\.4 host: PASS' && ok "ноль потерь на 2×: 8.8.4 PASS" || { bad "ноль потерь на 2×"; echo "$o"; }
# 2. одно потерянное событие — FAIL по порогу плана (0), прежний порог 0,5% справочно PASS
o=$(run lose1 "$S0,$S1,$(two 50000 0.4 1)"); has "$o" '^8\.8\.4 host: FAIL' && has "$o" 'справочно по прежнему порогу 0\.5%: PASS' && ok "1 событие: FAIL по плану, 0,5% справочно PASS" || { bad "1 событие"; echo "$o"; }
# 3. 0,6% — FAIL и по прежнему порогу
o=$(run big "$S0,$S1,$(two 50000 0.4 72)"); has "$o" '^8\.8\.4 host: FAIL' && has "$o" 'справочно по прежнему порогу 0\.5%: FAIL' && ok "0,6%: FAIL, справочно FAIL" || { bad "0,6%"; echo "$o"; }
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
    mutate "порог 8.8.4 раздут" 's/^CTL_LOSS_MAX_EVENTS = 1.0/CTL_LOSS_MAX_EVENTS = 1e9/' 2
    mutate "насыщение не судится" 's/^NODE_IDLE_MIN = 0.10/NODE_IDLE_MIN = 0.0/' 2
    mutate "окно 2× заменено на самую дальнюю" 's/ctl_step = min(cand)\[1\]/ctl_step = max(cand)[1]/' 1
    mutate "8.8.2 насыщение молчит" 's/elif sat_r and any/elif False and any/' 1
    mutate "справочный порог выключен" 's/"PASS" if worst <= CTL_LOSS_REF else "FAIL"/"FAIL"/' 1
fi
echo "итого: $fails красных"; [ "$fails" -eq 0 ]
