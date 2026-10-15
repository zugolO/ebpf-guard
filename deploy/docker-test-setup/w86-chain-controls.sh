#!/bin/bash
# Волна 8.6, заход C, Д12: положительный контроль ЦЕПОЧКИ — K прогонов nginx→bash→curl с МГНОВЕННЫМ bash
# (bash порождает curl в фоне и выходит), в окне атак против РАБОЧЕГО агента ночи. Эмиттер 8.5.5 судит долю
# инцидентов с process_chain на ЭТИХ инцидентах (корень nginx), N ≥ 5 (w86-close-report.sh chain).
# nginx — копия dash под этим именем (comm = имя ФАЙЛА), bash — копия bash: настоящие процессы, не шебанг.
# Корень контроля — comm «nginx»: на стенде настоящего nginx нет, инциденты с таким корнем — только эти.
#   w86-chain-controls.sh <OUT> [K=6] [GAP=25]     окружение: API (http://localhost:19090), TOKEN
set -u
OUT=${1:?OUT}; K=${2:-6}; GAP=${3:-25}; API=${API:?API}; TOKEN=${TOKEN:?TOKEN}
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один агент"
W=/var/lib/w86chainctl; rm -rf $W; mkdir -p $W
cp /bin/dash $W/nginx; cp /bin/bash $W/bash
[ -x /usr/bin/curl ] || die "нет /usr/bin/curl"
t0=$(date +%s); echo "$t0" > "$OUT/t0"
i=0
while [ "$i" -lt "$K" ]; do
    i=$((i + 1))
    # Каждый прогон — СВОЙ транзитный юнит: дерево растёт от systemd, а не от этого скрипта. Иначе все прогоны —
    # потомки одного bash драйвера и сливаются в ОДИН инцидент с корнем bash (репетиция 15.10: 1 инцидент из 6).
    # nginx живёт 8 с (родитель обязан пережить bash), bash выходит сразу, curl — фоном на 6 с; --collect снимает юнит.
    systemd-run --quiet --collect --unit="w86chain-$i-$t0" --property=Type=exec -- \
        $W/nginx -c "$W/bash -c '/usr/bin/curl -s --max-time 6 -o /dev/null http://10.255.255.1/ & exit 0'; sleep 8" \
        || die "systemd-run прогона $i не удался"
    echo "[$(date -u +%FT%TZ)] прогон $i юнит w86chain-$i-$t0"
    sleep "$GAP"
done
sleep 12
# транзитных юнитов быть не должно (память transient-unit-survives-and-blocks-next-run)
left=$(systemctl list-units --all --no-legend "w86chain-*" 2>/dev/null | wc -l)
echo "остались юниты w86chain-*: $left"
sleep 20
curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/api/v1/incidents?limit=1000" > "$OUT/ctl-incidents.json"
curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/api/v1/alerts?limit=5000" > "$OUT/ctl-alerts.json"
n=$(jq -r 'if type == "array" then . else (.incidents // []) end | map(select(.root_comm == "nginx" or ((.process_chain // []) | index("nginx") != null))) | length' "$OUT/ctl-incidents.json" 2>/dev/null)
echo "инцидентов с корнем nginx: ${n:-?} (прогонов $K)"
rm -rf $W
echo "done $(date -u +%FT%TZ) incidents=${n:-?}" > "$OUT/DONE"
