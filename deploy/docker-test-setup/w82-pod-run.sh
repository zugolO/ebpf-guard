#!/bin/bash
# w82-pod-run.sh [OUT] — волна 8.2, этап 4: один запуск чартом на k3s стенда.
#
# A4  учёт пода: memory.current контейнера 10 Гц с момента helm install (пик
#     старта) + инвентарь A1 внутри пода (текст бинаря на счету пода);
# E   лимит чарта: проверяется memory.max контейнера и GOMEMLIMIT из env;
# 8.3.6 ось юнита в поде: ebpf_guard_systemd_unit_lookups_total{result}.
#
# Хостовый ebpf-guard-test на время запуска ОСТАНОВЛЕН (два агента удваивают
# нагрузку; разрешено владельцем 10.10.2026). Скрипт его НЕ поднимает обратно —
# это делает w82-pod-down.sh после всех запусков этапа.
#
# Переменные: VALUES (файл значений), LABEL (метка запуска), IDLE (с до снимка).
# Запуск на стенде отсоединённо:
#   setsid nohup /root/w82-pod-run.sh /var/tmp/w82-pod-1 > /root/w82-pod-1.log 2>&1 < /dev/null &
set -u
OUT=${1:-/var/tmp/w82-pod}
VALUES=${VALUES:-/root/w82-pod/values-stand.yaml}
CHART=${CHART:-/root/w82-pod/deploy/helm/ebpf-guard}
NS=ebpf-guard
REL=w82
API_PORT=${API_PORT:-19091}
TOKEN=${TOKEN:-w82-stage4-pod-token}
DUR=${DUR:-90}
export PATH=$PATH:/root/bin:/usr/local/bin
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}

rm -rf "$OUT"; mkdir -p "$OUT/heap"
die() { echo "die: $*" > "$OUT/DONE"; echo "die: $*" >&2; exit 1; }

helm status "$REL" -n "$NS" >/dev/null 2>&1 && die "релиз $REL уже установлен"
if systemctl is-active --quiet ebpf-guard-test.service; then
    systemctl stop ebpf-guard-test.service || die "не остановил хостового агента"
fi
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 0 ] || die "после остановки остались агенты"
echo "host-agent stopped $(date -u +%FT%TZ)" > "$OUT/meta.txt"

# Узел в DiskPressure вытесняет под сразу после старта (10.10.2026: диск 97%).
[ "$(kubectl get node -o jsonpath='{.items[0].status.conditions[?(@.type=="DiskPressure")].status}')" = False ] \
    || die "узел в DiskPressure — освободить диск (docker image prune -f)"
kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null || die "namespace"

# Холодный page-cache: иначе текст бинаря, оставшийся в кэше от импорта образа
# (на счету не пода), занизит учёт пода.
sync; echo 1 > /proc/sys/vm/drop_caches
free -m > "$OUT/free-before.txt"

t0=$(date +%s.%N); echo "$t0" > "$OUT/t0"
helm install "$REL" "$CHART" -n "$NS" -f "$VALUES" ${HELM_EXTRA:-} > "$OUT/helm-install.txt" 2>&1 \
    || die "helm install: $(tail -3 "$OUT/helm-install.txt")"

# Сэмплер: ждём процесс контейнера, дальше 10 Гц по его cgroup.
(
    end=$(awk -v t="$t0" -v d="$DUR" 'BEGIN { printf "%.0f", t + d }')
    cg=""
    while [ "$(date +%s)" -lt "$end" ]; do
        if [ -z "$cg" ]; then
            p=$(pgrep -f '^/usr/local/bin/ebpf-guard --config' | head -1)
            [ -n "$p" ] && cg=$(awk -F: '$1=="0"{print $3}' /proc/"$p"/cgroup) && echo "pid=$p cg=$cg" > "$OUT/cg.txt"
        fi
        if [ -n "$cg" ]; then
            v=$(cat /sys/fs/cgroup"$cg"/memory.current 2>/dev/null) \
                && echo "$(awk -v t="$t0" -v n="$(date +%s.%N)" 'BEGIN { printf "%.1f", n - t }') $v"
        fi
        sleep 0.1
    done
) > "$OUT/samples.tsv" &
SAMPLER=$!

# heap + metrics раз в 5 с, как только API ответил.
(
    end=$(awk -v t="$t0" -v d="$DUR" 'BEGIN { printf "%.0f", t + d }')
    while [ "$(date +%s)" -lt "$end" ]; do
        s=$(awk -v t="$t0" -v n="$(date +%s.%N)" 'BEGIN { printf "%05.1f", n - t }')
        if curl -s -o "$OUT/heap/heap-$s.pprof" --max-time 3 -H "Authorization: Bearer $TOKEN" "localhost:$API_PORT/debug/pprof/heap" \
            && [ -s "$OUT/heap/heap-$s.pprof" ]; then
            curl -s -o "$OUT/heap/metrics-$s.txt" --max-time 3 -H "Authorization: Bearer $TOKEN" "localhost:$API_PORT/metrics"
            sleep 5
        else
            rm -f "$OUT/heap/heap-$s.pprof"; sleep 0.5
        fi
    done
) &
PROFILER=$!
wait $SAMPLER $PROFILER

kubectl -n "$NS" get pods -o wide > "$OUT/pods.txt" 2>&1
kubectl -n "$NS" describe pod > "$OUT/describe.txt" 2>&1
kubectl -n "$NS" logs ds/$REL-ebpf-guard --tail=200 > "$OUT/pod.log" 2>&1
read -r pid cg < <(sed -n 's/^pid=\([0-9]*\) cg=\(.*\)$/\1 \2/p' "$OUT/cg.txt")
[ -n "${pid:-}" ] || die "процесс контейнера не найден"
{ cat /sys/fs/cgroup"$cg"/memory.max; tr '\0' '\n' < /proc/"$pid"/environ | grep -E '^(GOMEMLIMIT|NODE_NAME)='; } > "$OUT/limits.txt"

awk 'NF == 2 && $2 > m { m = $2; t = $1 } END { printf "peak_mib=%.1f peak_s=%s\n", m / 1048576, t }' "$OUT/samples.tsv" > "$OUT/peak.txt"
awk 'NF == 2 { s = int($1); if ($2 > m[s]) m[s] = $2 } END { for (s in m) printf "%3d %.1f\n", s, m[s] / 1048576 }' "$OUT/samples.tsv" | sort -n > "$OUT/per-second-mib.txt"

# Инвентарь A1 внутри пода (60 с внутри): текст бинаря на счету пода.
PID=$pid TOK=$TOKEN API=localhost:$API_PORT /root/w82-mem-inventory.sh "$OUT/inv" > "$OUT/inv.log" 2>&1
grep -E '^ebpf_guard_systemd_unit_lookups_total' "$OUT/inv/metrics60.txt" > "$OUT/unit-lookups.txt" 2>/dev/null
# 8.3.6: триггер из юнита system.slice и контроль вне его (сессия — user.slice).
# Долгоживущий юнит: мс-юнит исчезает раньше ленивого рескана резолвера
# (cgroupUnitRescanInterval) и честно даёт unresolved — как на хосте.
unit_metrics() { curl -s --max-time 5 -H "Authorization: Bearer $TOKEN" "localhost:$API_PORT/metrics" \
    | grep -E '^ebpf_guard_systemd_unit_lookups_total'; }
unit_metrics > "$OUT/unit-before.txt"
systemd-run --quiet --unit=w82-unit-probe /bin/sh -c 'for i in 1 2 3 4 5 6; do /bin/true; sleep 6; done' > "$OUT/unit-trigger.txt" 2>&1
sleep 45
unit_metrics > "$OUT/unit-after.txt"
curl -s --max-time 5 -H "Authorization: Bearer $TOKEN" "localhost:$API_PORT/api/v1/alerts?limit=500" > "$OUT/alerts.json"
grep -o 'w82_unit_probe' "$OUT/alerts.json" | wc -l > "$OUT/unit-probe-alerts.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
