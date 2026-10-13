#!/bin/bash
# w85-e1-pod.sh <SRC> — E1 в поде DaemonSet (k3s стенда, hostPID): статический бинарь из SRC, боевой конфиг, 300 запусков
# настоящего systemd-detect-virt НА ХОСТЕ в окне пода (мс-процессы хоста видит агент пода). Читается: источник образа
# (ebpf_guard_exe_path_image_total — cached/proc/filename против unresolved), запасной readlink, подавления virt-detect-self.
# Хостовый агент на время остановлен и возвращён. Результат — $A/{m0,m1,report}.txt, маркер $MARK.
set -u
SRC=${1:?SRC}; A=${A:-/var/lib/w85-e1pod}; MARK=${MARK:-/root/W85-E1POD-DONE}; S=$SRC/deploy/docker-test-setup; N=${N:-300}
export PATH=$PATH:/usr/local/go/bin:/root/bin:/usr/local/bin KUBECONFIG=/etc/rancher/k3s/k3s.yaml
rm -f "$MARK"; rm -rf "$A"; mkdir -p "$A/img"
fin() { echo "$1" > "$MARK"; exit "${2:-0}"; }
cleanup() { helm uninstall w82 -n ebpf-guard > /dev/null 2>&1; for k in $(seq 1 60); do [ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 0 ] && break; sleep 2; done
    systemctl start ebpf-guard-test.service; sleep 5; docker rmi zugolo/ebpf-guard:${TAG:-none} > /dev/null 2>&1; k3s ctr -n k8s.io images rm docker.io/zugolo/ebpf-guard:${TAG:-none} > /dev/null 2>&1; }
( cd "$SRC" && CGO_ENABLED=0 go build -tags rego -trimpath -o "$A/img/ebpf-guard" ./cmd/ebpf-guard ) > "$A/build.log" 2>&1 || fin "die: сборка" 1
go clean -cache >/dev/null 2>&1
TAG=w85e1-$(sha256sum "$A/img/ebpf-guard" | cut -c1-12)
sha256sum "$A/img/ebpf-guard" > "$A/binary-sha.txt"
printf "FROM gcr.io/distroless/static:debug\nCOPY ebpf-guard /usr/local/bin/ebpf-guard\nENV GOMEMLIMIT=off\nENTRYPOINT [\"/usr/local/bin/ebpf-guard\"]\n" > "$A/img/Dockerfile"
docker build -q -t zugolo/ebpf-guard:$TAG "$A/img" > "$A/img.log" 2>&1
docker save zugolo/ebpf-guard:$TAG | k3s ctr -n k8s.io images import - >> "$A/img.log" 2>&1
k3s ctr -n k8s.io images ls -q | grep -q "$TAG\$" || fin "die: образ не импортирован" 1
TOK=w85-e1-pod-token
W85_REPO=$SRC python3 "$S/w82-pod-night-values.py" "$S/config-test.yaml" $TAG $TOK "$A/values.yaml" > "$A/values.log" 2>&1 || fin "die: values" 1
mkdir -p /var/lib/ebpf-guard-pod; echo 0 > /var/lib/ebpf-guard-pod/observer-root-pid
VALUES=$A/values.yaml CHART=$SRC/deploy/helm/ebpf-guard API_PORT=19091 TOKEN=$TOK DUR=60 UNIT_PROBE=0 bash "$S/w82-pod-run.sh" "$A/pod-run" > "$A/pod-run.log" 2>&1
grep -q '^done' "$A/pod-run/DONE" 2>/dev/null || { cleanup; fin "die: под не поднялся: $(cat "$A/pod-run/DONE" 2>/dev/null)" 1; }
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOK" localhost:19091/metrics; }
sleep 20
M > "$A/m0.txt"
for i in $(seq 1 "$N"); do systemd-detect-virt > /dev/null 2>&1; sleep 0.05; done
sleep 5
M > "$A/m1.txt"
kubectl -n ebpf-guard logs "$(kubectl -n ebpf-guard get pods -o name | head -1)" --tail=-1 2> /dev/null | grep -a "proc table\|host root" > "$A/pod-proc-table.log"
cleanup
{
    echo "== E1 в поде (hostPID): $N запусков systemd-detect-virt на хосте"
    grep -a "host root" "$A/pod-proc-table.log" | cut -c1-200 | sed 's/^/  журнал: /'
    d() { awk -v n="$1" 'index($0, n) == 1 { print $NF; exit }' "$A/$2.txt"; }
    for s in 'ebpf_guard_exe_path_image_total{result="cached"}' 'ebpf_guard_exe_path_image_total{result="proc"}' 'ebpf_guard_exe_path_image_total{result="filename"}' \
             'ebpf_guard_exe_path_image_total{result="stale"}' 'ebpf_guard_exe_path_image_total{result="unresolved"}' \
             'ebpf_guard_exe_path_readlink_fallback_total{result="resolved"}' 'ebpf_guard_exe_path_readlink_fallback_total{result="unresolved"}' \
             'ebpf_guard_exe_path_lookups_total{field="exe_path",result="resolved"}' 'ebpf_guard_exe_path_lookups_total{field="exe_path",result="unresolved"}' \
             'ebpf_guard_rule_exceptions_total{exception_name="virt-detect-self",rule_id="mitre_vm_detect_dmi_read"}'; do
        a=$(d "$s" m0); b=$(d "$s" m1); echo "  $s: ${a:-нет} → ${b:-нет} (Δ $(awk -v a="${a:-0}" -v b="${b:-0}" 'BEGIN { printf "%.0f", b - a }'))"
    done
} > "$A/report.txt" 2>&1
fin "done agents=$(ps -eo cmd | grep -c '[e]bpf-guard --config')"
