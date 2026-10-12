#!/bin/bash
# Фикстуры вердикта w85-f3-smoke.sh (режим verdict — чистая функция над снимками) и мутации.
#   w85-f3-smoke-fixtures.sh [--mutate]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${F3S:-$HERE/w85-f3-smoke.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fails=$((fails + 1)); }
# mkd <имя> p=<счёт P> q=<счёт Q|none> pa=<алертов P> qa=<алертов Q> shape=formatted|plain drop=<файл>
mkd() {
    local n=$1; shift; local N=200 p=400 q=none pa=1 qa=1 shape=formatted drop=""
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local D=$T/$n; mkdir -p "$D"
    echo "$N" > "$D/n.txt"; echo "111 222" > "$D/pids.txt"
    python3 - "$D" "$p" "$q" "$pa" "$qa" "$shape" <<'PY'
import json, sys
D, p, q, pa, qa, shape = sys.argv[1:7]
rows = [{"tgid": 999, "nr": 9, "n": 12345}]            # чужая запись другого номера
def row(tgid, n): return {"key": {"tgid": tgid, "nr": 321}, "value": {"n": int(n), "cgroup_id": 1, "comm": [0]}}
ents = [{"key": {"tgid": 999, "nr": 9}, "value": {"n": 5}}, row(111, p)]
if q != "none": ents.append(row(222, q))
out = [({"formatted": e} if shape == "formatted" else e) for e in ents]
json.dump(out, open(D + "/counts.json", "w"))
al = []
al += [{"rule_id": "rootkit_bpf_prog_load_suspicious", "pid": 111, "comm": "python3"}] * int(pa)
al += [{"rule_id": "rootkit_bpf_prog_load_suspicious", "pid": 222, "comm": "python3"}] * int(qa)
al += [{"rule_id": "rootkit_bpf_prog_load_suspicious", "pid": 333, "comm": "python3"}]   # чужой pid не засчитывается
json.dump({"alerts": al}, open(D + "/alerts.json", "w"))
PY
    [ -n "$drop" ] && rm -f "$D/$drop"
    echo "$D"
}
want() { local out; out=$(bash "$SCRIPT" verdict "$2" 2>&1); if echo "$out" | grep -aqE "$3"; then ok "$1"; else bad "$1 — нет «${3}»"; echo "$out" | sed 's/^/    | /' | head -8; fi; }
want good        "$(mkd good)"                       '^ДОСТИГНУТО: F3 .*= 2×200'
want good-plain  "$(mkd plain shape=plain)"          '^ДОСТИГНУТО: F3 '
want p-short     "$(mkd pshort p=398)"               '^ПРОВАЛЕН: F3 .*не исключены точно \(счёт 398'
want p-over      "$(mkd pover p=402)"                '^ПРОВАЛЕН: F3 .*не исключены точно \(счёт 402'
want q-excluded  "$(mkd qex q=400)"                  '^ПРОВАЛЕН: F3 .*чужого процесса служебные исключены \(400\)'
want p-no-alert  "$(mkd pna pa=0)"                   '^ПРОВАЛЕН: F3 .*cmd 5 от «агента» не дал алерта'
want q-no-alert  "$(mkd qna qa=0)"                   '^ПРОВАЛЕН: F3 .*cmd 5 от чужого процесса не дал алерта'
want no-counts   "$(mkd nc drop=counts.json)"        '^НЕИЗМЕРИМ: F3 .*нет counts\.json'
want no-n        "$(mkd nn drop=n.txt)"              '^НЕИЗМЕРИМ: F3 .*нет n\.txt'
if [ "${1:-}" = "--mutate" ]; then
    echo "== мутации"
    mut() { local n=$1 expr=$2 m=$T/mut-$1.sh; sed -e "$expr" "$SCRIPT" > "$m"
        cmp -s "$m" "$SCRIPT" && { bad "мутация $n не изменила скрипт"; return; }
        if F3S=$m bash "$0" 2>&1 | grep -q '^FAIL'; then ok "мутация $n покраснила фикстуры"; else bad "мутация $n ПРОШЛА"; fi; }
    mut exact-count   's/\[ "\$pn" = \$((2 \* N)) \] || fail=/true || fail=/'
    mut foreign-zero  's/\[ "\$qn" = 0 \] || fail=/true || fail=/'
    mut agent-alert   's/\[ "\${pa:-0}" -ge 1 \] || fail=/true || fail=/'
    mut foreign-alert 's/\[ "\${qa:-0}" -ge 1 \] || fail=/true || fail=/'
    mut absent-zero   's/for f in counts.json alerts.json pids.txt; do \[ -s "\$D\/\$f" \] || cls=.*; done/true/'
fi
echo "-- fails=$fails"; [ "$fails" = 0 ]
