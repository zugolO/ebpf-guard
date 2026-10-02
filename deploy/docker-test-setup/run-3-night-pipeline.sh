#!/bin/bash
# run-3-night-pipeline.sh — ЗАМЕР №3: idle на всю ночь + атаки утром.
# Он же первый вход волны 8.1: почасовые heap-профили и траектория памяти
# на неподвижной базе шума (волны 6.4 и 7 закрыты, аллоулист больше не двигается).
#
# Исполняется НА СТЕНДЕ одним отцепленным процессом; ожидать финиша локально,
# заходить по ssh один раз после маркера ([[waiting-loop-must-not-ssh-into-window]]).
#
# ЧТО МЕРИТ (plan.md, «ЗАМЕР №3»):
#   3.P1-19  объём часа 8 против часа 2 (сумма трёх слоёв подавления);
#   3.MEM    траектория RSS/heap по часам — вход 8.1, порог не назначается;
#   3.ATTACK инциденты verdict="attack" на idle;
#   3.STORE  рост файла SQLite (приёмка 4.5 по построению НЕИЗМЕРИМА за ночь);
#   утром    run-all-attacks.sh + run-gate.sh — приёмка гейтов волн 2/3/5 как есть.
#
# ЧЕГО НЕ ДЕЛАЕТ. GOMEMLIMIT не задаётся: ночь меряет стенд в его режиме GC, item 5
# волны 8.1 (лимит чарта) — отдельный заход ([[run-intent-must-be-declared]]).
# Рестарта P0-3 в конце idle нет: атаки утром идут на ТОМ ЖЕ процессе, иначе
# память утра несравнима с ночью ([[ab-toggle-measures-the-restart]]).
#
# die — ТОЛЬКО для неизмеримого прогона ([[die-only-for-unmeasurable-run]]): два
# агента, не тот бинарь, не тот аллоулист. Провал атак или гейта ночь не убивает.
#
# Вход: EXPECT_NR (обязателен — число номеров аллоулиста, которое агент обязан
#       напечатать в monitored_syscalls), IDLE_SECS (умолчание 32400 = 9 ч),
#       NIGHT_SKIP_ATTACKS=1 (только idle), NIGHT_ART (умолчание /var/lib/night-3).
set -u
SETUP="${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}"
REPO="$(cd "$SETUP/../.." && pwd)"
SERVICE="${SERVICE:-ebpf-guard-test.service}"
API="${NIGHT_API:-http://localhost:19090}"
DB="${NIGHT_DB:-/var/lib/ebpf-guard/test-events.db}"
ART="${NIGHT_ART:-/var/lib/night-3}"
IDLE_SECS="${IDLE_SECS:-32400}"
EXPECT_NR="${EXPECT_NR:?EXPECT_NR не задан — аллоулист прогона объявляется, а не угадывается}"
LOG="/root/run-3-night-pipeline.log"
MARK="/root/PIPELINE-3-NIGHT-DONE"
START_FILE="/root/agent-start-3-night.txt"
export PATH=$PATH:/usr/local/go/bin

rm -f "$MARK"
exec >>"$LOG" 2>&1
say() { echo "[$(date -u +%FT%TZ)] $*"; }
die() { say "СТОП (прогон неизмерим): $*"; echo "die: $*" > "$MARK"; exit 1; }
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)
_curl() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$@"; }

say "=== ЗАМЕР №3 стартовал; git $(git -C "$REPO" rev-parse --short HEAD) ==="
rm -rf "$ART"; mkdir -p "$ART" || die "не создать $ART"

# ── [1] преflight: что меряем ──────────────────────────────────────────────
n_agents=$(ps -eo cmd | grep -c "[e]bpf-guard --config")
[ "$n_agents" -eq 1 ] || die "агентов $n_agents, а не 1"
bin="$REPO/build/ebpf-guard"
"$bin" version > "$ART/binary-version.txt" 2>&1
grep -q 'rego=true' "$ART/binary-version.txt" || die "бинарь без тега rego"
[ -n "$TOKEN" ] || die "нет admin-токена"
free_kb=$(df -Pk /var/lib | awk 'NR == 2 { print $4 }')
[ "${free_kb:-0}" -gt 2097152 ] || die "свободно ${free_kb} КиБ на /var/lib — ночной стор и профили не поместятся"
say "преflight: агент один, бинарь rego, свободно $((free_kb / 1024)) МиБ"

# ── [2] стор с нуля и рестарт ──────────────────────────────────────────────
# Стор не удаляется, а откладывается: файл предыдущих замеров остаётся рядом.
systemctl stop "$SERVICE"
ts=$(date -u +%Y%m%dT%H%M%SZ)
for f in "$DB" "$DB-wal" "$DB-shm"; do [ -e "$f" ] && mv "$f" "$f.pre-3-night-$ts"; done
date -u +%FT%TZ > "$START_FILE"
systemctl start "$SERVICE"
ready=0
for i in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$API/health")" = "200" ] && { ready=1; break; }
    sleep 2
done
[ "$ready" -eq 1 ] || die "агент не ответил /health 200 за 120 с после рестарта"
pid=$(systemctl show -p MainPID --value "$SERVICE")
sha_file=$(sha256sum "$bin" | cut -d' ' -f1); sha_proc=$(sha256sum "/proc/$pid/exe" | cut -d' ' -f1)
{ echo "sha256=$sha_file"; echo "sha256_proc=$sha_proc"; echo "pid=$pid"; echo "git=$(git -C "$REPO" rev-parse HEAD)"; } > "$ART/binary-identity.txt"
[ "$sha_file" = "$sha_proc" ] || die "sha процесса ${sha_proc:0:16} ≠ sha файла ${sha_file:0:16}"
n_agents=$(ps -eo cmd | grep -c "[e]bpf-guard --config")
[ "$n_agents" -eq 1 ] || die "после рестарта агентов $n_agents"
sleep 10
got_nr=$(journalctl -u "$SERVICE" --since "$(date -d "$(cat "$START_FILE")" '+%F %T')" --no-pager -o cat \
    | grep -a '"collector":"syscall"' | grep -o '"monitored_syscalls":[0-9]*' | tail -1 | cut -d: -f2)
[ "$got_nr" = "$EXPECT_NR" ] || die "monitored_syscalls в журнале = ${got_nr:-НЕ НАПЕЧАТАН}, объявлено $EXPECT_NR"
say "агент поднят: pid $pid, sha ${sha_file:0:16}, monitored_syscalls=$got_nr (объявлено $EXPECT_NR)"

# ── [3] ночь ───────────────────────────────────────────────────────────────
say "idle: ${IDLE_SECS} с, срез 300 с, heap каждый час, стор stat'ом"
( cd "$SETUP" && OUT_DIR="$ART/idle" DURATION="$IDLE_SECS" INTERVAL=300 NO_RESTART=1 \
    HEAP_EVERY=12 STORE_DB="$DB" SERVICE="$SERVICE" bash ./idle-run.sh ) > "$ART/idle-run.out" 2>&1
say "idle закончен (rc=$?)"
pid_now=$(systemctl show -p MainPID --value "$SERVICE")
[ "$pid_now" = "$pid" ] || say "ВНИМАНИЕ: MainPID сменился за ночь ($pid → $pid_now) — 3.ATTACK/3.MEM это назовут"

# ── [4] отчёт ночи — ДО атак, чтобы его не трогало утро ────────────────────
bash "$SETUP/night-report.sh" "$ART/idle" 300 > "$ART/night-report.txt" 2>&1
cat "$ART/night-report.txt"

# ── [5] утро: атаки и гейт как есть ────────────────────────────────────────
if [ "${NIGHT_SKIP_ATTACKS:-0}" != 1 ]; then
    export IDLE_METRICS_START="$ART/idle/metrics-start.txt" IDLE_METRICS_END="$ART/idle/metrics-end.txt"
    export IDLE_STATE_END="$ART/idle/state-end.json"
    export IDLE_ALERTS_START="$ART/idle/alerts-start.json" IDLE_ALERTS_END="$ART/idle/alerts-end.json"
    export IDLE_INCIDENTS_START="$ART/idle/incidents-start.json" IDLE_INCIDENTS_END="$ART/idle/incidents-end.json"
    export EBPF_GUARD_TOKEN="$TOKEN"
    say "атаки: run-all-attacks.sh"
    ( cd "$SETUP/attacks" && bash ./run-all-attacks.sh ) > "$ART/attacks.txt" 2>&1
    say "атаки закончены (rc=$?)"
    say "гейт: run-gate.sh"
    ( cd "$SETUP/attacks" && bash ./run-gate.sh ) > "$ART/gate.txt" 2>&1
    say "гейт закончен (rc=$?)"
    [ -d "$SETUP/attacks/attack-results" ] && cp -r "$SETUP/attacks/attack-results" "$ART/attacks-results" 2>/dev/null
else
    say "атаки пропущены (NIGHT_SKIP_ATTACKS=1)"
fi

# ── [6] снимки ПОСЛЕ всего: журнал, финальная куча, метрики ────────────────
_curl "$API/metrics" > "$ART/metrics-final.txt"
_curl "$API/debug/pprof/heap" > "$ART/heap-final.pprof"
journalctl -u "$SERVICE" --since "$(date -d "$(cat "$START_FILE")" '+%F %T')" --no-pager -o cat > "$ART/journal-agent-3-night.log"
cp "$SETUP/config-test.yaml" "$ART/config-test.yaml"
cp "$START_FILE" "$ART/"
cp "$0" "$ART/" 2>/dev/null; cp "$SETUP/night-report.sh" "$ART/"
tar czf /root/collect-3-night.tgz -C "$(dirname "$ART")" "$(basename "$ART")"
say "=== ЗАМЕР №3 закончен; архив /root/collect-3-night.tgz ($(du -h /root/collect-3-night.tgz | cut -f1)) ==="
echo "done $(date -u +%FT%TZ)" > "$MARK"
