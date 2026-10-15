#!/bin/bash
# Волна 8.6, заход B, Д14а / №563: смок блокирующей половины LSM вторым агентом.
# Запуск на стенде (detached): setsid nohup bash w86-lsm-smoke.sh < /dev/null > /var/lib/w86lsm/run.log 2>&1 &
# Рабочий ebpf-guard-test не трогается; второй агент — свой порт/стор/правила
# (w86-second-agent.sh). Итог — /var/lib/w86lsm/result.txt, маркер — DONE.
#
# Контроли (решение владельца 15.10: kill → EPERM вычеркнут, file_open по EACCES):
#   c1 open канарейки              → EACCES + lsm_audit(deny,file_open) + lsm_block +1
#   c2 connect на :19777           → отказ (EPERM) + lsm_audit(deny,socket_connect)
#   c3 task_kill (SIGCONT)         → проходит, в журнале аудит task_kill, deny нет
#   c4 соседние файл/порт/сигнал   → проходят
#   c5 после остановки агента      → блок снят (канарейка/порт открыты, ссылок нет)
# + цена хуков: kernel.bpf_stats_enabled, run_cnt/run_time_ns по программам за 60 с.
set -u
OUT=/var/lib/w86lsm
CAN=$OUT/canary
SRC=/root/w86-src
SA=$SRC/deploy/docker-test-setup/w86-second-agent.sh
NAME=lsm
PORT=19192
TOK=w86admin$PORT
mkdir -p "$OUT" "$CAN"
R=$OUT/result.txt
: > "$R"
log() { echo "$*" | tee -a "$R"; }

echo blocked > "$CAN/blocked.txt"
echo neighbour > "$CAN/neighbour.txt"

# слушатели — настоящие процессы python3 (comm=python3), не шебанг-обёртки
python3 - <<'PY' &
import socket, time
ls = []
for p in (19777, 19778):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", p)); s.listen(64); ls.append(s)
time.sleep(3600)
PY
LISTENER=$!
trap 'kill $LISTENER 2>/dev/null; [ -n "${SLEEPER:-}" ] && kill $SLEEPER 2>/dev/null' EXIT
sleep 1

# контроль: сырой syscall, errno печатается числом
ctl_open() { python3 - "$1" <<'PY'
import os, sys, ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
fd = libc.syscall(ctypes.c_long(257), ctypes.c_long(-100), ctypes.c_char_p(sys.argv[1].encode()), ctypes.c_long(0), ctypes.c_long(0))
print("OK" if fd >= 0 else "ERRNO=%d" % ctypes.get_errno())
PY
}
ctl_connect() { python3 - "$1" <<'PY'
import socket, sys, errno
s = socket.socket(); s.settimeout(3)
try:
    s.connect(("127.0.0.1", int(sys.argv[1]))); print("OK")
except OSError as e:
    print("ERRNO=%d" % e.errno)
PY
}
metric() { curl -s -H "Authorization: Bearer $TOK" "http://127.0.0.1:$PORT/metrics" | grep -E "$1" | head -${2:-3}; }
lsm_links() { bpftool link show 2>/dev/null | grep -c "lsm" ; }
lsm_progs() { bpftool prog show 2>/dev/null | grep -cE "type lsm|lsm_(file_open|socket_conn|task_kill|kernel)" ; }

log "== w86 lsm smoke $(date -u +%FT%TZ) kernel=$(uname -r) lsm=$(cat /sys/kernel/security/lsm)"
log "workers: $(ps -eo pid,cmd | grep -c '[e]bpf-guard --config')  (рабочий агент + возможные вторые)"

# --- фаза 0: до агента -------------------------------------------------------
P0_LINKS=$(lsm_links); P0_PROGS=$(lsm_progs)
log "before: lsm links=$P0_LINKS progs=$P0_PROGS"
log "c0 до агента: open canary=$(ctl_open $CAN/blocked.txt) connect19777=$(ctl_connect 19777) connect19778=$(ctl_connect 19778)"

# --- фаза 1: второй агент с block_backend: lsm -------------------------------
bash "$SA" config $NAME $PORT enforcement.enabled=true enforcement.dry_run=false enforcement.block_backend=lsm \
  "enforcement.lsm_path_blocklist=[$CAN/blocked.txt]" "enforcement.network_blocklist={subnets: [], ports: [19777]}" \
  >> $OUT/agent-config.log 2>&1
bash "$SA" start $NAME >> $OUT/agent-start.log 2>&1
for i in $(seq 1 60); do curl -s -o /dev/null "http://127.0.0.1:$PORT/health" && break; sleep 1; done
sleep 8
AGENT_PID=$(cat /root/w86/$NAME/agent.pid)
log "agent pid=$AGENT_PID (self_pid в журнале: $(grep -o 'self_pid=[0-9]*' /root/w86/$NAME/agent.log | head -1))"
log "after start: lsm links=$(lsm_links) progs=$(lsm_progs)  (ждём +3 блокирующих хука к $P0_LINKS)"
bpftool link show 2>/dev/null | grep -E "lsm" >> $OUT/links-with-agent.txt
log "collector_up{lsm}: $(metric 'ebpf_guard_collector_up\{collector="lsm"\}' 1)"
log "lsm_block (до): $(metric 'ebpf_guard_enforcement_actions_total\{action="lsm_block"\}' 1)"
grep -E "lsm|kmod" /root/w86/$NAME/agent.log | cut -c1-260 | head -20 >> $OUT/agent-lsm-log.txt

AUDIT=/root/w86/$NAME/state/audit.jsonl
A0=$(wc -l < $AUDIT 2>/dev/null || echo 0)

# --- фаза 2: контроли --------------------------------------------------------
sleep 30 & SLEEPER=$!
sleep 1
C1=$(ctl_open $CAN/blocked.txt); C1B=$(cat $CAN/blocked.txt 2>&1 | head -1)
C2=$(ctl_connect 19777)
kill -CONT $SLEEPER; C3RC=$?; sleep 0.5; kill -0 $SLEEPER 2>/dev/null && C3ALIVE=alive || C3ALIVE=dead
C4A=$(ctl_open $CAN/neighbour.txt); C4B=$(ctl_connect 19778)
sleep 12   # поток ядро → кольцо → журнал

log "c1 open canary: $C1  (cat: $C1B)   ожидается ERRNO=13"
log "c2 connect 19777: $C2   ожидается ERRNO=1 (EPERM)"
log "c3 kill -CONT: rc=$C3RC target=$C3ALIVE   ожидается rc=0 alive (task_kill — только аудит)"
log "c4 соседние: open neighbour=$C4A connect19778=$C4B   ожидается OK OK"
log "lsm_block (после): $(metric 'ebpf_guard_enforcement_actions_total\{action="lsm_block"\}' 1)"
log "lsm_blocks_total: $(metric 'ebpf_guard_lsm_blocks_total' 8 | tr '\n' ' ')"
tail -n +$((A0+1)) $AUDIT 2>/dev/null > $OUT/audit-new.jsonl
log "audit: новых записей $(wc -l < $OUT/audit-new.jsonl)"
log "audit deny file_open: $(grep -c '"hook":"file_open"' $OUT/audit-new.jsonl)  deny socket_connect: $(grep -c '"hook":"socket_connect"' $OUT/audit-new.jsonl)  task_kill: $(grep -c '"hook":"task_kill"' $OUT/audit-new.jsonl)"
grep -E '"hook":"(file_open|socket_connect)"' $OUT/audit-new.jsonl | head -4 | cut -c1-260 >> $R
grep -E '"hook":"task_kill"' $OUT/audit-new.jsonl | grep -E "\"target_pid\":$SLEEPER" | head -2 | cut -c1-260 >> $R

# --- фаза 3: цена хуков в ядре ----------------------------------------------
sysctl -qw kernel.bpf_stats_enabled=1
snap() { bpftool -j prog show 2>/dev/null | python3 -c '
import json, sys
for p in json.load(sys.stdin):
    n = p.get("name", "")
    if n in ("lsm_file_open", "lsm_socket_conn", "lsm_task_kill", "lsm_kernel_modu", "lsm_kernel_read"):
        print(n, p.get("run_cnt", 0), p.get("run_time_ns", 0))
'; }
snap > $OUT/stats-0.txt; T0=$(date +%s)
sleep 60
snap > $OUT/stats-1.txt; T1=$(date +%s)
sysctl -qw kernel.bpf_stats_enabled=0
python3 - $OUT/stats-0.txt $OUT/stats-1.txt $((T1-T0)) <<'PY' | tee -a $R
import sys
a = {l.split()[0]: tuple(map(int, l.split()[1:])) for l in open(sys.argv[1])}
b = {l.split()[0]: tuple(map(int, l.split()[1:])) for l in open(sys.argv[2])}
dt = int(sys.argv[3])
for n in sorted(b):
    if n not in a: continue
    dc, dn = b[n][0]-a[n][0], b[n][1]-a[n][1]
    print("cost %-16s calls=%d (%.1f/s) ns/call=%.0f cpu=%.4f%% of one core" % (n, dc, dc/dt, dn/max(dc,1), 100.0*dn/1e9/dt))
PY

# --- фаза 4: остановка → блок снят ------------------------------------------
bash "$SA" stop $NAME >> $OUT/agent-stop.log 2>&1
sleep 3
C5A=$(ctl_open $CAN/blocked.txt); C5B=$(ctl_connect 19777)
log "c5 после остановки: open canary=$C5A connect19777=$C5B  ожидается OK OK; lsm links=$(lsm_links) progs=$(lsm_progs) (ждём $P0_LINKS / $P0_PROGS)"
log "DONE $(date -u +%FT%TZ)"
touch $OUT/DONE
