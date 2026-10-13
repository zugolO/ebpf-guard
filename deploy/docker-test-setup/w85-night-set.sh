#!/bin/bash
# w85-night-set.sh — ПОСТАВИТЬ ночь закрытия 8.5: отложенный старт на 22:57 UTC сегодняшней даты ПО ЧАСАМ СТЕНДА, отцепленный от
# ssh через setsid (НЕ systemd-run и НЕ at: пакет атак уйдёт в другой cgroup). Запускается НА СТЕНДЕ.
#   w85-night-set.sh           — ставит ночь; печатает pid отложенного процесса, время старта, ожидаемый конец
#   NIGHT_START_UTC=HH:MM[:SS] — другое время старта (для проверки механизма: NIGHT_CMD="touch /root/x" — вместо пайплайна)
# Окружение пайплайна — одним местом, ниже. Если старт сегодня уже прошёл — отказ (не гадаем про завтра).
set -eu
START=${NIGHT_START_UTC:-22:57:00}
SETUP=${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}
BASE=${W85_BASE:-/root/w85-base}
EXPECT_NR=${EXPECT_NR:-36}
LAUNCH=/root/night-8.5-at.sh
target=$(date -u -d "today $START" +%s); now=$(date +%s)
[ "$target" -gt "$now" ] || { echo "die: старт $START UTC сегодня уже прошёл (сейчас $(date -u +%T))"; exit 1; }
PRIOR=""
for r in $BASE/d1-prior/run-*; do [ -d "$r/pod-run" ] && [ -d "$r/pod-attack" ] && PRIOR="$PRIOR $r/pod-run:$r/pod-attack"; done
[ -n "${NIGHT_CMD:-}" ] || {
    for f in "$BASE/idle-8.2" "$BASE/pod-attack-8.2" "$BASE/final-incidents-20261012_070020.json"; do [ -e "$f" ] || { echo "die: нет базы $f"; exit 1; }; done
    [ "$(echo $PRIOR | wc -w)" -ge 5 ] || { echo "die: прогонов пода для медианы ${PRIOR:+$(echo $PRIOR | wc -w)}${PRIOR:-0} < 5 (каталоги $BASE/d1-prior/run-*)"; exit 1; }
}
CMD=${NIGHT_CMD:-"cd $SETUP && EXPECT_NR=$EXPECT_NR NIGHT_TAG=8.5-night NIGHT_PREV=$BASE/idle-8.2 BASE_IDLE=$BASE/idle-8.2 BASE_ATT=$BASE/pod-attack-8.2 BASE_INC=$BASE/final-incidents-20261012_070020.json D1_PRIOR_RUNS=\"${PRIOR# }\" AB_SECS=3600 bash ./run-8.5-night-pipeline.sh"}
cat > "$LAUNCH" <<EOS
#!/bin/bash
# отложенный старт ночи закрытия 8.5; поставлен $(date -u +%FT%TZ), старт $START UTC (epoch $target)
echo \$\$ > /root/night-8.5-at.pid
now=\$(date +%s); [ \$now -lt $target ] && sleep \$(( $target - now ))
echo "[\$(date -u +%FT%TZ)] старт ночи" > /root/night-8.5-started.txt
$CMD
EOS
chmod +x "$LAUNCH"; rm -f /root/night-8.5-started.txt /root/night-8.5-at.pid
( setsid nohup bash "$LAUNCH" > /root/night-8.5.log 2>&1 < /dev/null & )
for i in 1 2 3 4 5 6 7 8 9 10; do [ -s /root/night-8.5-at.pid ] && break; sleep 1; done
pid=$(cat /root/night-8.5-at.pid 2> /dev/null)
[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || { echo "die: отложенный процесс не жив"; exit 2; }
echo "pid=$pid sid=$(ps -o sid= -p $pid | tr -d ' ') старт=$(date -u -d @$target +%FT%TZ) ожидаемый конец≈$(date -u -d @$((target + 11*3600)) +%FT%TZ) (≈ 8 ч idle + пара A/B 2 ч + атаки и гейт + под)"
echo "{ pid=$pid, start_epoch=$target }" > /root/night-8.5-set.txt
echo "команда: $CMD"
ps -o pid,sid,etimes,cmd -p $pid
