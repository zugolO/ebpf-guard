#!/bin/bash
# w9-night-set.sh — ПОСТАВИТЬ ночь закрытия 9: отложенный старт ПО ЧАСАМ СТЕНДА (по умолчанию 22:57 UTC), отцепленный от
# ssh через setsid nohup (НЕ systemd-run и НЕ at: пакет атак уйдёт в другой cgroup). Запускается НА СТЕНДЕ.
#   w87-night-set.sh                      — ставит ночь; печатает pid отложенного процесса, время старта, ожидаемый конец
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
W87D=${W87_BASE86:-/root/w87-data86}
EXPECT_NR=${EXPECT_NR:-36}
IDLE_SECS=${IDLE_SECS:-43200}
EST_AFTER_IDLE_SECS=${EST_AFTER_IDLE_SECS:-27600}   # 8.7: 20 400 + пара 8.8.7 (≈ 70 мин) + лестница В6 (≈ 50 мин)
LAUNCH=/root/night-9-at.sh
W9B87=${W9_BASE87:-/var/lib/night-9-night}
ABSRC=${AB_BASE_SRC:-/root/w9b-src}
target=$(date -u -d "$DAY $START" +%s); now=$(date +%s)
[ "$target" -gt "$now" ] || { echo "die: старт $DAY $START UTC уже прошёл (сейчас $(date -u +%FT%T))"; exit 1; }
[ -n "${NIGHT_CMD:-}" ] || {
    for f in "$BASE/idle-8.2" "$BASE/final-incidents-20261012_070020.json" "$W86/idle-8.5" "$W86/pod-attack-8.5" "$W86/host-final-alerts-8.5.json" "$W87D/pod-run" "$W87D/idle" "$W87D/host-final-alerts-8.6.json" /root/w86-b-out/events.jsonl "$W9B87/idle" "$W9B87/attack-manifest-host.json" "$ABSRC/build/ebpf-guard"; do
        [ -e "$f" ] || { echo "die: нет базы $f"; exit 1; }
    done
    [ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || { echo "die: агентов не один"; exit 1; }
}
CMD=${NIGHT_CMD:-"cd $SETUP && EXPECT_NR=$EXPECT_NR NIGHT_TAG=9-night IDLE_SECS=$IDLE_SECS NIGHT_PREV=$W87D/idle W9_BASE87=$W9B87 AB_BASE_SRC=$ABSRC BASE_IDLE_82=$BASE/idle-8.2 W86_BASE=$W86 W87_BASE86=$W87D BASE_INC=$BASE/final-incidents-20261012_070020.json POD_RUNS_N=5 bash ./run-9-night-pipeline.sh"}
cat > "$LAUNCH" <<EOS
#!/bin/bash
# отложенный старт ночи закрытия 9; поставлен $(date -u +%FT%TZ), старт $DAY $START UTC (epoch $target)
echo \$\$ > /root/night-9-at.pid
now=\$(date +%s); [ \$now -lt $target ] && sleep \$(( $target - now ))
echo "[\$(date -u +%FT%TZ)] старт ночи" > /root/night-9-started.txt
$CMD
EOS
chmod +x "$LAUNCH"; rm -f /root/night-9-started.txt /root/night-9-at.pid
( setsid nohup bash "$LAUNCH" > /root/night-9.log 2>&1 < /dev/null & )
for i in 1 2 3 4 5 6 7 8 9 10; do [ -s /root/night-9-at.pid ] && break; sleep 1; done
pid=$(cat /root/night-9-at.pid 2> /dev/null)
[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || { echo "die: отложенный процесс не жив"; exit 2; }
echo "pid=$pid sid=$(ps -o sid= -p $pid | tr -d ' ') старт=$(date -u -d @$target +%FT%TZ) ожидаемый конец≈$(date -u -d @$((target + IDLE_SECS + EST_AFTER_IDLE_SECS)) +%FT%TZ) (оценка: idle $((IDLE_SECS / 3600)) ч + $((EST_AFTER_IDLE_SECS / 60)) мин: пара 8.8.7, окно block/mutex, контроли, атаки, гейт, лестница В6 и 5 прогонов пода по ≈ 58 мин)"
echo "{ pid=$pid, start_epoch=$target }" > /root/night-9-set.txt
echo "команда: $CMD"
ps -o pid,sid,etimes,stat,cmd -p $pid
