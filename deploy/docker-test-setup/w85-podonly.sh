#!/bin/bash
# w85-podonly.sh <SRC> [N=3] — волна 8.5, D1 (метка 8.5.7): N прогонов пода с F1.
# Каждый прогон, как w82-podonly: старт → 5 мин idle → пакет атак → 10 мин удержания.
# SRC — каталог сборки из коммита (w85-ship.sh): бинарь SRC/build/ebpf-guard,
# правила и чарт — оттуда же; /opt/ebpf-guard и рабочий агент не меняются (хостовый
# ebpf-guard-test остановлен на время каждого прогона и поднят после).
# Выход: $A/run-<i>/{pod-run,pod-attack,report.txt}, $A/d1-summary.txt; маркер конца — $MARK.
# Запуск отсоединённо, скрипт — файлом (не pkill -f / pgrep -f с литералом в ssh):
#   setsid nohup bash /root/w85-podonly.sh /root/w85-src-<sha> 3 > /root/w85-podonly.out 2>&1 < /dev/null &
set -u
SRC=${1:?usage: w85-podonly.sh <SRC> [N]}; N=${2:-3}
A=${A:-/var/lib/w85-podonly}; MARK=${MARK:-/root/W85-PODONLY-DONE}
S=$SRC/deploy/docker-test-setup
export PATH=$PATH:/usr/local/go/bin:/root/bin:/usr/local/bin KUBECONFIG=/etc/rancher/k3s/k3s.yaml
rm -f "$MARK"; rm -rf "$A"; mkdir -p "$A/img"
fin() { echo "$1" > "$MARK"; exit "${2:-0}"; }
[ -x "$SRC/build/ebpf-guard" ] && [ -s "$SRC/BINARY-SHA256" ] || fin "die: нет собранного бинаря из коммита в $SRC" 1
[ "$(sha256sum "$SRC/build/ebpf-guard" | cut -d' ' -f1)" = "$(cut -d' ' -f1 "$SRC/BINARY-SHA256")" ] || fin "die: бинарь не тот, что записан в BINARY-SHA256" 1
cp "$SRC/build/ebpf-guard" "$A/img/ebpf-guard"
TAG=w85d1-$(sha256sum "$A/img/ebpf-guard" | cut -c1-12)
cp "$SRC/GIT-HEAD" "$A/git-head.txt"; sha256sum "$A/img/ebpf-guard" > "$A/binary-sha.txt"
printf "FROM gcr.io/distroless/static:debug\nCOPY ebpf-guard /usr/local/bin/ebpf-guard\nENV GOMEMLIMIT=off\nENTRYPOINT [\"/usr/local/bin/ebpf-guard\"]\n" > "$A/img/Dockerfile"
docker build -q -t zugolo/ebpf-guard:$TAG "$A/img" > "$A/img.log" 2>&1
docker save zugolo/ebpf-guard:$TAG | k3s ctr -n k8s.io images import - >> "$A/img.log" 2>&1
k3s ctr -n k8s.io images ls -q | grep -q "$TAG\$" || fin "die: образ $TAG не импортирован" 1
TOK=w85-d1-pod-token
W85_REPO=$SRC W85_ARG_PREDICATES=1 python3 "$S/w82-pod-night-values.py" "$S/config-test.yaml" $TAG $TOK "$A/values.yaml" > "$A/values.log" 2>&1 || fin "die: values: $(tail -2 "$A/values.log")" 1
grep -q 'arg_predicates' "$A/values.yaml" || fin "die: в values пода нет arg_predicates" 1
mkdir -p /var/lib/ebpf-guard-pod; echo 0 > /var/lib/ebpf-guard-pod/observer-root-pid
for i in $(seq 1 "$N"); do
    R=$A/run-$i; mkdir -p "$R"
    ARG_PREDICATES=1 VALUES=$A/values.yaml CHART=$SRC/deploy/helm/ebpf-guard API_PORT=19091 TOKEN=$TOK DUR=90 UNIT_PROBE=0 \
        bash "$S/w82-pod-run.sh" "$R/pod-run" > "$R/pod-run.log" 2>&1
    if grep -q '^die' "$R/pod-run/DONE" 2>/dev/null; then
        echo "run $i: die в pod-run: $(cat "$R/pod-run/DONE")" >> "$A/d1-summary.txt"
        helm uninstall w82 -n ebpf-guard > /dev/null 2>&1; systemctl start ebpf-guard-test.service
        continue
    fi
    p=$(sed -n "s/^pid=\([0-9]*\) .*/\1/p" "$R/pod-run/cg.txt")
    # ждём 5 мин аптайма процесса пода (idle до пакета); опрос — ps, не ssh в окно
    while [ -n "$p" ] && [ "$(ps -o etimes= -p $p | tr -d ' ')" -lt 300 ]; do sleep 10; done
    ARG_PREDICATES=1 SETUP=$S TOKEN=$TOK API_PORT=19091 HOLD_S=600 bash "$S/w82-pod-attack.sh" "$R/pod-attack" > "$R/pod-attack.log" 2>&1
    helm uninstall w82 -n ebpf-guard > /dev/null 2>&1
    for k in $(seq 1 60); do [ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 0 ] && break; sleep 2; done
    systemctl start ebpf-guard-test.service; sleep 5
    RUN=$R/pod-run ATT=$R/pod-attack bash "$S/w85-close-report.sh" d1 > "$R/report.txt" 2>&1
    grep -aE '^(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ): 8\.5\.7' "$R/report.txt" | sed "s/^/run $i: /" >> "$A/d1-summary.txt"
    go clean -cache > /dev/null 2>&1
done
fin "done agents=$(ps -eo cmd | grep -c '[e]bpf-guard --config')"
