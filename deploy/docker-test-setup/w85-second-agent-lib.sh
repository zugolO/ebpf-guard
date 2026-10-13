#!/bin/bash
# Библиотека смоков волны 8.5: второй агент на стенде. Рабочий ebpf-guard-test не трогается.
#   source w85-second-agent-lib.sh
#   sa_start <SRC> <RUN> <PORT> [RULES_DIR]  — конфиг из SRC/deploy/docker-test-setup/config-test.yaml со СВОИМИ портом,
#       стором, аудитом, состоянием профиля, токенами и каталогом правил (по умолчанию SRC/rules); unix_socket и
#       observer_exclude выключены (сокет и файл observer-pid иначе общие с рабочим). Выставляет SA_PID, SA_TOKEN, SA_API.
#   sa_stop                                  — останавливает его
#   sa_metrics                               — /metrics второго агента
# Ждёт «syscall: collector enabled» до 60 с; умер — «AGENT DIED» и код 3.
SA_TOKEN=w85u1smoketoken0123456789abcdef012
sa_start() {
    local SRC=$1 RUN=$2 PORT=$3 RULES=${4:-$1/rules}
    rm -rf "$RUN"; mkdir -p "$RUN"
    python3 - "$RUN" "$RULES" "$SRC/deploy/docker-test-setup/config-test.yaml" "$PORT" <<'PY'
import sys
run, rules, base, port = sys.argv[1:5]
s = open(base).read()
def sub(old, new):
    global s
    assert old in s, old
    s = s.replace(old, new, 1)
sub('bind_address: "0.0.0.0:19090"', 'bind_address: "127.0.0.1:%s"' % port)
sub('path: /var/lib/ebpf-guard/profiler-state.json', 'path: %s/profiler-state.json' % run)
sub('path: "/var/lib/ebpf-guard/test-events.db"', 'path: "%s/events.db"' % run)
sub('audit_log: "/var/log/ebpf-guard/audit.jsonl"', 'audit_log: "%s/audit.jsonl"' % run)
sub('path: "/opt/ebpf-guard/rules/"', 'path: "%s/"' % rules.rstrip('/'))
sub('hot_reload: true', 'hot_reload: false')
sub('admin_token: ""', 'admin_token: "w85u1smoketoken0123456789abcdef012"')
sub('viewer_token: ""', 'viewer_token: "w85u1viewertoken0123456789abcdef01"')
sub('unix_socket:\n    enabled: true', 'unix_socket:\n    enabled: false')
sub('observer_exclude:\n    enabled: true', 'observer_exclude:\n    enabled: false')
open(run + '/config.yaml', 'w').write(s)
PY
    SA_API=http://127.0.0.1:$PORT
    (cd "$RUN" && setsid nohup "$SRC/build/ebpf-guard" --config "$RUN/config.yaml" --log-level=info > "$RUN/agent.log" 2>&1 < /dev/null & echo $! > "$RUN/pid")
    SA_PID=$(cat "$RUN/pid")
    local i
    for i in $(seq 1 60); do
        grep -q "syscall: collector enabled" "$RUN/agent.log" 2>/dev/null && break
        kill -0 "$SA_PID" 2>/dev/null || { echo "AGENT DIED"; tail -20 "$RUN/agent.log"; return 3; }
        sleep 1
    done
    sleep 8
}
sa_metrics() { curl -s --max-time 10 -H "Authorization: Bearer $SA_TOKEN" "$SA_API/metrics"; }
sa_stop() { kill "$SA_PID" 2>/dev/null; sleep 2; kill -9 "$SA_PID" 2>/dev/null; return 0; }
