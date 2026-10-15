#!/bin/bash
# Волна 8.6, заход B, шаг 7: смок ВТОРЫМ агентом — база (A-end) против нового бинаря, тот же стенд, друг за другом:
#   для каждой роли (base, new): idle-окно IDLE_S с CPU агента (дельта process_cpu_seconds_total, с/с) и профилем pprof
#   (G4: SyscallCountReader.Poll), затем пакет атак (recall по comm, наборы сработавших правил).
#   Потом тождество детекта новый-против-базы (w85-e1-identity.sh).
# Рабочий ebpf-guard-test НЕ трогается и НЕ останавливается (решение владельца: не перезапускать); пакет идёт рядом
# с ним — оба агента видят события пакета, но алерты второго читаются из ЕГО API. Ориентир, не вердикт.
#   w86-b-pack.sh <SRC_BASE> <SRC_NEW> <OUT> [IDLE_S=300]
set -u
BASE=${1:?SRC_BASE}; NEW=${2:?SRC_NEW}; OUT=${3:?OUT}; IDLE=${4:-300}
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
export PATH=$PATH:/usr/local/go/bin
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
trap 'sa_stop 2> /dev/null; echo "агентов после: $(ps -eo cmd | grep -c "[e]bpf-guard --config")"' EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"
echo "[$(date -u +%FT%TZ)] w86-b-pack base=$(cat $BASE/GIT-HEAD) new=$(cat $NEW/GIT-HEAD) idle=${IDLE}s"
mval() { sa_metrics | grep -a "^$1 " | awk '{print $2}'; }

role() { # <base|new> <SRC>
    local r=$1 src=$2 d="$OUT/$1"; mkdir -p "$d"
    sa_start "$src" /root/w86-b-run-$r 19251 || die "агент $r не поднялся"
    echo "[$r] pid=$SA_PID бинарь $(sha256sum $src/build/ebpf-guard | cut -c1-12) правил: $(grep -ac 'rules loaded\|loaded rules' /root/w86-b-run-$r/agent.log)"
    sleep 60   # settle: старт и прогрев
    # --- idle-окно: CPU агента и профиль ---------------------------------------------------------
    local c0 t0 c1 t1
    c0=$(mval process_cpu_seconds_total); t0=$(date +%s.%N)
    curl -s --max-time $((IDLE+60)) -H "Authorization: Bearer $SA_TOKEN" "$SA_API/debug/pprof/profile?seconds=$((IDLE-10))" > "$d/cpu.pprof"
    sleep 10
    c1=$(mval process_cpu_seconds_total); t1=$(date +%s.%N)
    awk -v c0="$c0" -v c1="$c1" -v t0="$t0" -v t1="$t1" -v r="$r" 'BEGIN { printf "[%s] idle: cpu %.3f с за %.0f с = %.4f с/с\n", r, c1-c0, t1-t0, (c1-c0)/(t1-t0) }' | tee "$d/idle-cpu.txt"
    sa_metrics > "$d/m-idle.txt"
    ( cd /root && go tool pprof -top -cum -nodecount=40 "$src/build/ebpf-guard" "$d/cpu.pprof" 2> /dev/null | head -60 > "$d/pprof-top.txt" )
    go tool pprof -top -focus='SyscallCountReader' -nodecount=5 "$src/build/ebpf-guard" "$d/cpu.pprof" 2> /dev/null | sed -n 1,10p > "$d/pprof-poll.txt"
    go tool pprof -top -cum -focus='RuleEngine..EvaluateInto' -nodecount=3 "$src/build/ebpf-guard" "$d/cpu.pprof" 2> /dev/null | sed -n 4,9p > "$d/pprof-eval.txt"
    # --- пакет атак ---------------------------------------------------------------------------------
    sa_metrics > "$d/m0.txt"
    local A="$src/deploy/docker-test-setup/attacks"
    ls "$A/attack-results" 2> /dev/null | sort > "$d/results-before.lst"
    ( cd "$A" && EBPF_GUARD_API="$SA_API" EBPF_GUARD_TOKEN="$SA_TOKEN" SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$d/attacks.log" 2>&1; echo "rc=$?" > "$d/attacks.rc" )
    sleep 30
    sa_metrics > "$d/m1.txt"
    curl -s --max-time 60 -H "Authorization: Bearer $SA_TOKEN" "$SA_API/api/v1/incidents?limit=1000" > "$d/incidents.json"
    cp "$A/attack-manifest.json" "$d/" 2> /dev/null
    ls "$A/attack-results" 2> /dev/null | sort | comm -13 "$d/results-before.lst" - > "$d/results-new.lst"
    for f in $(grep -E '^(baseline|final)-alerts-.*\.json$' "$d/results-new.lst"); do cp "$A/attack-results/$f" "$d/"; done
    cp /root/w86-b-run-$r/agent.log "$d/agent.log"
    echo "[$r] recall по comm: $(ATT=$d bash "$HERE/w85-close-report.sh" recall)" | tee "$d/recall.txt"
    sa_stop
    sleep 5
}
role base "$BASE"
role new "$NEW"
echo "== тождество детекта (новый против базы)"
bash "$HERE/w85-e1-identity.sh" "$(ls $OUT/new/final-alerts-*.json | tail -1)" "$(ls $OUT/base/final-alerts-*.json | tail -1)" "$OUT/new/attack-manifest.json" | tee "$OUT/identity.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
