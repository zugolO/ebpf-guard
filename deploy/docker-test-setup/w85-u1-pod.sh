#!/bin/bash
# w85-u1-pod.sh <SRC> — U1 в поде DaemonSet (k3s стенда): статический бинарь из SRC, чарт из SRC,
# боевой конфиг; проба w85-u1-smoke.sh против API пода. Хостовый агент на время остановлен и
# возвращён. Результат — $A/u1-pod.txt, маркер $MARK.
set -u
SRC=${1:?SRC}; A=${A:-/var/lib/w85-u1pod}; MARK=${MARK:-/root/W85-U1POD-DONE}; S=$SRC/deploy/docker-test-setup
export PATH=$PATH:/usr/local/go/bin:/root/bin:/usr/local/bin KUBECONFIG=/etc/rancher/k3s/k3s.yaml
rm -f "$MARK"; rm -rf "$A"; mkdir -p "$A/img"
fin() { echo "$1" > "$MARK"; exit "${2:-0}"; }
( cd "$SRC" && CGO_ENABLED=0 go build -tags rego -trimpath -o "$A/img/ebpf-guard" ./cmd/ebpf-guard ) > "$A/build.log" 2>&1 || fin "die: сборка" 1
go clean -cache >/dev/null 2>&1
TAG=w85u1-$(sha256sum "$A/img/ebpf-guard" | cut -c1-12)
printf "FROM gcr.io/distroless/static:debug\nCOPY ebpf-guard /usr/local/bin/ebpf-guard\nENV GOMEMLIMIT=off\nENTRYPOINT [\"/usr/local/bin/ebpf-guard\"]\n" > "$A/img/Dockerfile"
docker build -q -t zugolo/ebpf-guard:$TAG "$A/img" > "$A/img.log" 2>&1
docker save zugolo/ebpf-guard:$TAG | k3s ctr -n k8s.io images import - >> "$A/img.log" 2>&1
TOK=w85-u1-pod-token
W85_REPO=$SRC python3 "$S/w82-pod-night-values.py" "$S/config-test.yaml" $TAG $TOK "$A/values.yaml" > "$A/values.log" 2>&1 || fin "die: values" 1
mkdir -p /var/lib/ebpf-guard-pod; echo 0 > /var/lib/ebpf-guard-pod/observer-root-pid
VALUES=$A/values.yaml CHART=$SRC/deploy/helm/ebpf-guard API_PORT=19091 TOKEN=$TOK DUR=60 UNIT_PROBE=0 bash "$S/w82-pod-run.sh" "$A/pod-run" > "$A/pod-run.log" 2>&1
bash "$S/w85-u1-smoke.sh" localhost:19091 $TOK pod > "$A/u1-pod.txt" 2>&1
helm uninstall w82 -n ebpf-guard > /dev/null 2>&1
for k in $(seq 1 60); do [ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 0 ] && break; sleep 2; done
systemctl start ebpf-guard-test.service; sleep 5
docker rmi zugolo/ebpf-guard:$TAG >/dev/null 2>&1; k3s ctr -n k8s.io images rm docker.io/zugolo/ebpf-guard:$TAG >/dev/null 2>&1
fin "done agents=$(ps -eo cmd | grep -c '[e]bpf-guard --config')"
