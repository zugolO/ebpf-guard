#!/bin/bash
# Фикстуры w85-u1-smoke.sh: подставной API (python3) и подставная проба вместо systemd-run.
#   w85-u1-smoke-fixtures.sh            — фикстуры
#   w85-u1-smoke-fixtures.sh --mutate   — мутации скрипта обязаны покраснуть
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${U1S:-$HERE/w85-u1-smoke.sh}
T=$(mktemp -d); SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; rm -rf "$T"; }; trap cleanup EXIT
fails=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fails=$((fails + 1)); }
cat > "$T/srv.py" <<'PY'
import http.server, sys
port, series = int(sys.argv[1]), sys.argv[2]
st = {"res": 10, "unres": 5, "full": 3, "top": 7}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/bump"):
            q = dict(p.split("=") for p in self.path.split("?")[1].split("&"))
            for k in st: st[k] += int(q.get(k, 0))
            self.send_response(200); self.end_headers(); return
        lines = ['ebpf_guard_systemd_unit_lookups_total{result="resolved"} %d' % st["res"],
                 'ebpf_guard_systemd_unit_lookups_total{result="unresolved"} %d' % st["unres"],
                 'ebpf_guard_systemd_unit_lookups_total{result="no_resolver"} 0']
        if series != "nofull": lines.append("ebpf_guard_systemd_unit_scans_total %d" % st["full"])
        if series != "notop": lines.append("ebpf_guard_systemd_unit_top_scans_total %d" % st["top"])
        self.send_response(200); self.end_headers(); self.wfile.write(("\n".join(lines) + "\n").encode())
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
# runu <имя> <порт> <серии: all|notop|nofull> <проба: bump-запрос или FAIL>
runu() {
    python3 "$T/srv.py" "$2" "$3" & SRV=$!
    for i in 1 2 3 4 5 6 7 8 9 10; do curl -s -o /dev/null "http://127.0.0.1:$2/" && break; sleep 0.3; done
    if [ "$4" = FAIL ]; then export U1_PROBE_CMD='echo "systemd-run: boom" >&2; false'
    else export U1_PROBE_CMD="curl -s 'http://127.0.0.1:$2/bump?$4' > /dev/null"; fi
    sed 's/^sleep 25$/sleep 0.5/' "$SCRIPT" > "$T/s-$1.sh"
    bash "$T/s-$1.sh" "127.0.0.1:$2" tok "$1" > "$T/$1.out" 2>&1
    kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=""; unset U1_PROBE_CMD
}
want() { if grep -aqE "$2" "$T/$1.out"; then ok "$1"; else bad "$1 — нет «${2}»"; sed 's/^/    | /' "$T/$1.out" | head -8; fi; }
runu good 18911 all 'res=3&top=1';             want good    '^ДОСТИГНУТО: U1/good .*resolved \+3 .*полных сканов 0, сканов верхнего уровня 1'
runu zero 18912 all 'res=0&top=1';             want zero    '^ПРОВАЛЕН: U1/zero .*resolved не вырос'
runu full 18913 all 'res=3&full=2';            want full    '^ПРОВАЛЕН: U1/full .*полных сканов 2 > 0'
runu notop 18914 notop 'res=3';                want notop   '^НЕИЗМЕРИМ: U1/notop .*нет серии ebpf_guard_systemd_unit_top_scans_total'
runu nofull 18915 nofull 'res=3';              want nofull  '^НЕИЗМЕРИМ: U1/nofull .*нет серии ebpf_guard_systemd_unit_scans_total'
runu probefail 18916 all FAIL;                 want probefail '^НЕИЗМЕРИМ: U1/probefail .*проба не стартовала'
if [ "${1:-}" = "--mutate" ]; then
    echo "== мутации"
    mut() { local n=$1 expr=$2 m=$T/mut-$1.sh; sed -e "$expr" "$SCRIPT" > "$m"
        cmp -s "$m" "$SCRIPT" && { bad "мутация $n не изменила скрипт"; return; }
        if U1S=$m bash "$0" 2>&1 | grep -q '^FAIL'; then ok "мутация $n покраснила фикстуры"; else bad "мутация $n ПРОШЛА"; fi; }
    mut resolved-check 's/elif \[ \$((R1 - R0)) -lt 1 \]; then/elif false; then/'
    mut full-scans     's/elif \[ \$((S1 - S0)) -gt "\$MAXFULL" \]; then/elif false; then/'
    mut absent-as-zero 's/\[ -n "\$(val "\$D\/before.txt" "ebpf_guard_\$m")" \] || {/true || {/'
fi
echo "-- fails=$fails"; [ "$fails" = 0 ]
