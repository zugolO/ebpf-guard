#!/bin/bash
# w86-night-set.sh — ПОСТАВИТЬ ночь закрытия 8.6: отложенный старт ПО ЧАСАМ СТЕНДА (по умолчанию 22:57 UTC), отцепленный от
# ssh через setsid nohup (НЕ systemd-run и НЕ at: пакет атак уйдёт в другой cgroup). Запускается НА СТЕНДЕ.
#   w86-night-set.sh                      — ставит ночь; печатает pid отложенного процесса, время старта, ожидаемый конец
#   NIGHT_START_UTC=HH:MM[:SS]            — другое время старта
#   NIGHT_DAY=today|tomorrow              — день старта (по умолчанию today; если время уже прошло — отказ, не гадаем)
#   NIGHT_CMD="touch /root/x"             — проверка механизма вместо пайплайна
# Окружение пайплайна — одним местом, ниже. Ожидаемый конец = старт + idle + EST_AFTER_IDLE_SECS (контроли 8.5.2/8.4.x, атаки и гейт,
# контроли правил и цепочки, ≥ 5 прогонов пода) — оценка по репетиции, печатается как оценка.
set -eu
START=${NIGHT_START_UTC:-22:57:00}
DAY=${NIGHT_DAY:-today}
SETUP=${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}
BASE=${W85_BASE:-/root/w85-base}
W86=${W86_BASE:-/root/w86-base}
EXPECT_NR=${EXPECT_NR:-36}
IDLE_SECS=${IDLE_SECS:-43200}
EST_AFTER_IDLE_SECS=${EST_AFTER_IDLE_SECS:-13500}
LAUNCH=/root/night-8.6-at.sh
target=$(date -u -d "$DAY $START" +%s); now=$(date +%s)
[ "$target" -gt "$now" ] || { echo "die: старт $DAY $START UTC уже прошёл (сейчас $(date -u +%FT%T))"; exit 1; }
[ -n "${NIGHT_CMD:-}" ] || {
    for f in "$BASE/idle-8.2" "$BASE/final-incidents-20261012_070020.json" "$W86/idle-8.5" "$W86/pod-attack-8.5" "$W86/host-final-alerts-8.5.json" /root/w86-b-out/events.jsonl; do
        [ -e "$f" ] || { echo "die: нет базы $f"; exit 1; }
    done
    [ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || { echo "die: агентов не один"; exit 1; }
}
CMD=${NIGHT_CMD:-"cd $SETUP && EXPECT_NR=$EXPECT_NR NIGHT_TAG=8.6-night IDLE_SECS=$IDLE_SECS NIGHT_PREV=$W86/idle-8.5 BASE_IDLE_82=$BASE/idle-8.2 W86_BASE=$W86 BASE_INC=$BASE/final-incidents-20261012_070020.json POD_RUNS_N=5 bash ./run-8.6-night-pipeline.sh"}
cat > "$LAUNCH" <<EOS
#!/bin/bash
# отложенный старт ночи закрытия 8.6; поставлен $(date -u +%FT%TZ), старт $DAY $START UTC (epoch $target)
echo \$\$ > /root/night-8.6-at.pid
now=\$(date +%s); [ \$now -lt $target ] && sleep \$(( $target - now ))
echo "[\$(date -u +%FT%TZ)] старт ночи" > /root/night-8.6-started.txt
$CMD
EOS
chmod +x "$LAUNCH"; rm -f /root/night-8.6-started.txt /root/night-8.6-at.pid
( setsid nohup bash "$LAUNCH" > /root/night-8.6.log 2>&1 < /dev/null & )
for i in 1 2 3 4 5 6 7 8 9 10; do [ -s /root/night-8.6-at.pid ] && break; sleep 1; done
pid=$(cat /root/night-8.6-at.pid 2> /dev/null)
[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || { echo "die: отложенный процесс не жив"; exit 2; }
echo "pid=$pid sid=$(ps -o sid= -p $pid | tr -d ' ') старт=$(date -u -d @$target +%FT%TZ) ожидаемый конец≈$(date -u -d @$((target + IDLE_SECS + EST_AFTER_IDLE_SECS)) +%FT%TZ) (оценка: idle $((IDLE_SECS / 3600)) ч + $((EST_AFTER_IDLE_SECS / 60)) мин контролей, атак, гейта и 5 прогонов пода)"
echo "{ pid=$pid, start_epoch=$target }" > /root/night-8.6-set.txt
echo "команда: $CMD"
ps -o pid,sid,etimes,stat,cmd -p $pid
