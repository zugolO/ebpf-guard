#!/bin/bash
# Библиотека смоков волны 8.5: второй агент на стенде. Рабочий ebpf-guard-test не трогается.
#   source w85-second-agent-lib.sh
#   sa_start <SRC> <RUN> <PORT> [RULES_DIR]  — конфиг из SRC/deploy/docker-test-setup/config-test.yaml со СВОИМИ портом,
#       стором, аудитом, состоянием профиля, токенами и каталогом правил (по умолчанию SRC/rules); unix_socket и
#       observer_exclude выключены (сокет и файл observer-pid иначе общие с рабочим). Выставляет SA_PID, SA_TOKEN, SA_API.
#   SA_PROC_TABLE=off — выключить таблицу процессов ядра (тот же бинарь, прежний путь трекера).
#   SA_CFG_PATCH=<скрипт.py> — после генерации конфига: python3 <скрипт.py> <config.yaml> (роли пар A/B, O1).
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
import os
if os.environ.get('SA_PROC_TABLE') == 'off':
    # таблица процессов выключена конфигом: тот же бинарь на прежнем пути трекера (Go-карты и /proc) — вторая половина A/B
    assert s.count('\nbpf:\n') == 1, 'в конфиге нет единственной секции bpf:'
    s = s.replace('\nbpf:\n', '\nbpf:\n  proc_table:\n    enabled: false\n', 1)
open(run + '/config.yaml', 'w').write(s)
PY
    if [ -n "${SA_CFG_PATCH:-}" ]; then python3 "$SA_CFG_PATCH" "$RUN/config.yaml" "$SRC" || { echo "CFG PATCH FAIL"; return 5; }; fi
    SA_API=http://127.0.0.1:$PORT
    # без setsid и без «&&» перед nohup: `cd && cmd &` уводит в фон ВСЮ цепочку, и $! — pid подоболочки. setsid форкает, и $! становится pid обёртки, а не агента (найдено на часе cmd 3: pid второго агента
    # в сводке был на единицу меньше настоящего, и его вызовы bpf() не попали в итог). Отсоединение — nohup и
    # перенаправления; скрипты-вызыватели сами запущены отсоединённо.
    (cd "$RUN"; nohup "$SRC/build/ebpf-guard" --config "$RUN/config.yaml" --log-level=info > "$RUN/agent.log" 2>&1 < /dev/null & echo $! > "$RUN/pid")
    SA_PID=$(cat "$RUN/pid")
    local i
    for i in $(seq 1 60); do
        grep -q "syscall: collector enabled" "$RUN/agent.log" 2>/dev/null && break
        kill -0 "$SA_PID" 2>/dev/null || { echo "AGENT DIED"; tail -20 "$RUN/agent.log"; return 3; }
        sleep 1
    done
    sleep 8
    # тождество pid: тот, что агент сам назвал в журнале, обязан совпасть с SA_PID (иначе всё, что считается «по pid агента», слепо)
    local logged
    logged=$(grep -a '"msg":"correlator: self-exclusion filter"' "$RUN/agent.log" | head -1 | sed -n 's/.*"self_pid":\([0-9]*\).*/\1/p')
    if [ -n "$logged" ] && [ "$logged" != "$SA_PID" ]; then
        echo "PID MISMATCH: журнал агента self_pid=$logged, SA_PID=$SA_PID"; kill "$logged" 2> /dev/null; return 4
    fi
}
sa_metrics() { curl -s --max-time 10 -H "Authorization: Bearer $SA_TOKEN" "$SA_API/metrics"; }
sa_stop() { kill "$SA_PID" 2>/dev/null; sleep 2; kill -9 "$SA_PID" 2>/dev/null; return 0; }
