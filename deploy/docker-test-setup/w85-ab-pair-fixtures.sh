#!/bin/bash
# Фикстуры w85-ab-pair.sh: локальный подставной API (python3 http.server) с переключателем
# предикатов и счётчиком anomaly_detection. Режимы подставного сервера: ok, refuse (POST true не
# меняет состояние), stuck (POST false не даёт off_config).
#   w85-ab-pair-fixtures.sh            — фикстуры
#   w85-ab-pair-fixtures.sh --mutate   — мутации скрипта обязаны покраснить фикстуры
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${PAIR:-$HERE/w85-ab-pair.sh}
T=$(mktemp -d); SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; rm -rf "$T"; }; trap cleanup EXIT
fails=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fails=$((fails + 1)); }

cat > "$T/srv.py" <<'PY'
import http.server, sys, json
mode, port = sys.argv[1], int(sys.argv[2])
st = {"on": True, "anom": 0}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        st["anom"] += 10 if not st["on"] else 9
        state = "active" if st["on"] else "off_config"
        body = ('ebpf_guard_kernel_predicate_state{state="%s"} 1\n'
                'ebpf_guard_alert_volume_by_event_type_total{event_type="syscall",rule_id="anomaly_detection"} %d\n') % (state, st["anom"])
        self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); want = json.loads(self.rfile.read(n))["enabled"]
        changed = st["on"] != want
        if mode == "refuse" and want: changed = False
        elif mode == "stuck" and not want: changed = False
        else: st["on"] = want
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps({"enabled": st["on"], "changed": changed}).encode())
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
runcase() { # runcase <имя> <режим сервера> <порт>
    python3 "$T/srv.py" "$2" "$3" & SRV=$!
    for i in 1 2 3 4 5 6 7 8 9 10; do curl -s -o /dev/null "http://127.0.0.1:$3/metrics" && break; sleep 0.3; done
    API=http://127.0.0.1:$3 TOKEN=t bash "$SCRIPT" "$T/$1" 2 > "$T/$1.log" 2>&1
    kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=""
}
runcase good ok 18901
if grep -q '^done' "$T/good/DONE" 2>/dev/null && [ -s "$T/good/m-a0.txt" ] && [ -s "$T/good/m-ab.txt" ] && [ -s "$T/good/m-b1.txt" ]; then ok "ok: три снимка и done"; else bad "ok: нет done/снимков ($(cat "$T/good/DONE" 2>/dev/null))"; fi
grep -q 'off_config' "$T/good/m-ab.txt" && grep -q 'active' "$T/good/m-b1.txt" && ok "ok: m-ab при off_config, m-b1 при active" || bad "ok: состояния на границах"
out=$(AB_DIR="$T/good" bash "$HERE/w85-close-report.sh" ab 2>&1)
echo "$out" | grep -aqE '^(ДОСТИГНУТО|ПРОВАЛЕН): 8\.5\.3 ' && ok "ok: эмиттер ab читает выход скрипта" || { bad "эмиттер не вынес вердикт по выходу скрипта"; echo "$out" | head -8; }
runcase refuse refuse 18902
grep -q '^die: переключатель не сменил состояние' "$T/refuse/DONE" 2>/dev/null && ok "refuse: die" || bad "refuse: нет die ($(cat "$T/refuse/DONE" 2>/dev/null))"
runcase stuck stuck 18903
grep -q '^die: после POST false' "$T/stuck/DONE" 2>/dev/null && ok "stuck: die до окна A" || bad "stuck: нет die ($(cat "$T/stuck/DONE" 2>/dev/null))"

if [ "${1:-}" = "--mutate" ]; then
    echo "== мутации"
    mut() {
        local n=$1 expr=$2 m=$T/mut-$1.sh
        if [ "${expr#perl:}" != "$expr" ]; then perl -0pe "${expr#perl:}" "$SCRIPT" > "$m"; else sed -e "$expr" "$SCRIPT" > "$m"; fi
        cmp -s "$m" "$SCRIPT" && { bad "мутация $n не изменила скрипт"; return; }
        if PAIR=$m bash "$0" 2>&1 | grep -q '^FAIL'; then ok "мутация $n покраснила фикстуры"; else bad "мутация $n ПРОШЛА — прибор не ловит"; fi
    }
    mut no-changed-check 's/^grep -Eq .*sw-true.json" || die.*/true/'
    mut no-state-check   's/st=\$(state); \[ "\$st" = off_config \] || die.*/true/'
    mut unequal-windows  'perl:s/sleep "\$WIN"/sleep 1/'
fi
echo "-- fails=$fails"; [ "$fails" = 0 ]
