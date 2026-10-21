#!/bin/bash
# Волна 8.8: лестница нагрузки Е6 с приборами Р0 — хост и под k3s.
#   (производная от w87-e6-load.sh; отличия помечены «8.8»)
#
#   w88-load.sh <host|pod> <steps|attack> <SRC> <OUT>
#
# poll.tsv: epoch status dropped_sum events_sum cpu_pressure_level overload_divisor
# 8.8, Р0: (а) генератор без артефакта connect (backlog, SO_SNDTIMEO; ошибки считаются); (б) PROBE=1 — отдельный
#   процесс w88p постоянного темпа (PROBE_RATE connect+prctl в секунду) на каждой ступени: protected судится на нём,
#   а не на смеси; (в) CONTROLS=N — N процессов w88c1..N по CTL_RATE оп/с (файловые операции), «подано/увидено» по
#   каждому из ebpf_guard_load_probe_events_total{probe}; (г) опрос /health раз в 2 с (poll.tsv) для 8.8.1.
#   CPU_LIMIT (роль pod) — limits.cpu чарта (Р8: 500m/1/2); BULK_MIX — смесь «горячего» генератора.
#
# Роль host: рабочий ebpf-guard-test ОСТАНАВЛИВАЕТСЯ на время смока (два агента делят 4 ядра, и кривая насыщения
#   мерила бы обоих), второй агент из SRC (метки стадий Е1) — единственный на машине; по выходу рабочий поднимается
#   обратно (trap). Роль pod: тот же бинарь из SRC в образе, чарт на k3s, рабочий так же остановлен (как в ночах 8.x).
# Режим steps: прогрев WARM_S, затем ступени STEPS (ops/s генератора; 0 — фон без генератора, max — MAX_OPS, умолч. 90 000),
#   каждая STEP_S секунд: срез метрик/CPU/RSS до и после, CPU-профиль 30 с в середине ступени, затем пауза GAP_S
#   и срез «слив» (догоняет ли агент хвост). Режим attack: генератор на ATTACK_RATE всё время пакета атак
#   (run-all-attacks.sh), recall по comm — держится ли детект под нагрузкой.
# Генератор — w87-e6-loadgen (e6load), смесь как поток ноды. Таблицу печатает w87-e6-table.sh.
# Вердиктов не даёт: вход постановки задач производительности.
set -u
ROLE=${1:?host|pod}; MODE=${2:?steps|attack}; SRC=${3:?SRC}; OUT=${4:?OUT}
STEPS=${STEPS:-0 500 1500 5000 15000 40000 100000 max}
STEP_S=${STEP_S:-60}; GAP_S=${GAP_S:-20}; WARM_S=${WARM_S:-60}
WORKERS=${WORKERS:-2}; MIX=${MIX:-read=60,open=20,prctl=15,connect=4,exec=1}; EXEC_CAP=${EXEC_CAP:-300}
ATTACK_RATE=${ATTACK_RATE:-5000}
# GEN_PROCS — число процессов генератора (темп делится поровну). Воркер движка выбирается по PID & mask
# (CorrelationEngine.IngestAsyncPriority): 1 процесс = один горячий pid на одном воркере, N — поток многих pid.
GEN_PROCS=${GEN_PROCS:-1}
PROBE=${PROBE:-0}; PROBE_RATE=${PROBE_RATE:-1000}; CONTROLS=${CONTROLS:-0}; CTL_RATE=${CTL_RATE:-50}
CPU_LIMIT=${CPU_LIMIT:-}; BULK_MIX=${BULK_MIX:-$MIX}
# Волна 9, заход B: сборка замеров выбрана явно, а не случайным флагом (plan.md «Волна 9 — заход B»):
#   под — core (как в поставке: без тега rego, policy.rego.enabled=false); хост — full ($SRC/build/ebpf-guard = make build,
#   -tags rego) с policy.rego.enabled=true, как будет ночью. Оба плеча A/B одной сборкой. Рантайм-флаги rego_built/
#   rego_active сверяются с намерением ниже (die при расхождении), печатаются в driver.log и $OUT/build.txt.
POD_TAGS=${POD_TAGS-}; HOST_REGO=${HOST_REGO:-1}; export HOST_REGO POD_TAGS
HERE=$(cd "$(dirname "$0")" && pwd)
SERVICE=ebpf-guard-test.service
NS=ebpf-guard; REL=e88; POD_TOKEN=w88podtoken0123456789abcdef01234567; POD_STATE=/var/lib/ebpf-guard-pod
export PATH=$PATH:/usr/local/go/bin:/root/bin:/usr/local/bin
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
source "$HERE/w85-second-agent-lib.sh"

rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
say() { echo "[$(date -u +%FT%TZ)] $*"; }
die() { echo "die: $*" > "$OUT/DONE"; say "DIE: $*"; exit 1; }
n_agents() { ps -eo cmd | grep -cE '^(/usr/local/bin/|[^ ]*/build/)ebpf-guard --config'; }

GEN_PIDS=""; POD_UP=0; SA_UP=0
SOMAXCONN_OLD=$(sysctl -n net.core.somaxconn 2> /dev/null)
TWREUSE_OLD=$(sysctl -n net.ipv4.tcp_tw_reuse 2> /dev/null)
BPFSTATS_OLD=$(sysctl -n kernel.bpf_stats_enabled 2> /dev/null)
cleanup() {
    [ "${BPFSTATS:-0}" = 1 ] && [ -n "$BPFSTATS_OLD" ] && sysctl -qw kernel.bpf_stats_enabled="$BPFSTATS_OLD" 2> /dev/null
    [ -n "$SOMAXCONN_OLD" ] && sysctl -qw net.core.somaxconn="$SOMAXCONN_OLD" 2> /dev/null
    [ -n "$TWREUSE_OLD" ] && sysctl -qw net.ipv4.tcp_tw_reuse="$TWREUSE_OLD" 2> /dev/null
    [ -n "$GEN_PIDS" ] && kill $GEN_PIDS 2> /dev/null
    [ -n "${AUX_PIDS:-}" ] && kill $AUX_PIDS 2> /dev/null
    [ -n "${POLL_PID:-}" ] && kill "$POLL_PID" 2> /dev/null
    [ "$SA_UP" = 1 ] && sa_stop
    if [ "$POD_UP" = 1 ]; then
        # Волна 9, заход B: причина рестарта пода на max (OOMKilled? паника?) — до удаления релиза
        kubectl -n "$NS" describe pod > "$OUT/pod-describe.txt" 2>&1
        kubectl -n "$NS" logs "ds/$REL-ebpf-guard" --previous --tail=200 > "$OUT/pod-previous.log" 2>&1
        helm uninstall "$REL" -n "$NS" > /dev/null 2>&1
        local k; for k in $(seq 1 60); do [ "$(n_agents)" -eq 0 ] && break; sleep 2; done
    fi
    systemctl is-active --quiet "$SERVICE" || systemctl start "$SERVICE"
    sleep 5
    say "выход: рабочий $(systemctl is-active "$SERVICE"), агентов $(n_agents)"
}
trap cleanup EXIT

say "w88 role=$ROLE mode=$MODE head=$(cat "$SRC/GIT-HEAD" 2> /dev/null) steps='$STEPS' step=${STEP_S}s mix=$MIX workers=$WORKERS gen_procs=$GEN_PROCS"
[ "$(n_agents)" -eq 1 ] || die "до запуска ожидался ровно один (рабочий) агент, есть $(n_agents)"
[ -x "$SRC/build/ebpf-guard" ] || die "нет $SRC/build/ebpf-guard"
( cd "$SRC" && go build -o build/e6load ./deploy/docker-test-setup/w87-e6-loadgen ) || die "сборка генератора"
GEN="$SRC/build/e6load"
# 8.8: comm процесса берётся из ИМЕНИ ФАЙЛА ([[exec-a-spoof-control-keeps-file-name]]) — зонды и контрольные процессы
# запускаются копиями генератора с именами w88p, w88c1… (префикс w88 читает loadprobe).
# TIME_WAIT клиентских сокетов loopback исчерпывал эфемерные порты на ступенях 45 000+ оп/с (connect ≈ 4% операций);
# tcp_tw_reuse=1 на время смока, восстанавливается в cleanup.
sysctl -qw net.ipv4.tcp_tw_reuse=1 2> /dev/null
# Волна 9, заход B: BPFSTATS=1 — kernel.bpf_stats_enabled=1 и снимок bpftool prog show -j в каждом срезе (цена зондов в ядре по ступеням)
[ "${BPFSTATS:-0}" = 1 ] && sysctl -qw kernel.bpf_stats_enabled=1
sysctl -qw net.core.somaxconn=65535 || say "somaxconn не поднят: backlog слушателя урезан ядром"
mkdir -p /srv/e6/bin
cp "$GEN" /srv/e6/bin/w88p
for k in $(seq 1 "$CONTROLS"); do cp "$GEN" "/srv/e6/bin/w88c$k"; done
cp "$GEN" /srv/e6/bin/w88hot
sha256sum "$SRC/build/ebpf-guard" | cut -c1-12 > "$OUT/agent-sha12"

# ── агент ────────────────────────────────────────────────────────────────────────────────────────────────────
systemctl stop "$SERVICE" || die "не остановил рабочего"
for k in $(seq 1 30); do [ "$(n_agents)" -eq 0 ] && break; sleep 1; done
[ "$(n_agents)" -eq 0 ] || die "после остановки рабочего остались агенты"
say "рабочий остановлен"

if [ "$ROLE" = host ]; then
    SA_ENV="${AGENT_ENV:-}" SA_UNIT= SA_CFG_PATCH="$HERE/w87-e1-patch.py" sa_start "$SRC" /root/w88-run 19281 || die "второй агент не поднялся"
    SA_UP=1; APID=$SA_PID; API=$SA_API; TOKEN=$SA_TOKEN
else
    [ "$(kubectl get node -o jsonpath='{.items[0].status.conditions[?(@.type=="DiskPressure")].status}')" = False ] || die "узел в DiskPressure"
    helm status "$REL" -n "$NS" > /dev/null 2>&1 && die "релиз $REL уже стоит"
    kubectl get ns "$NS" > /dev/null 2>&1 || kubectl create namespace "$NS" > /dev/null || die "namespace"
    B="$OUT/pod-image"; mkdir -p "$B"
    ( cd "$SRC" && CGO_ENABLED=0 go build ${POD_TAGS:+-tags $POD_TAGS} -trimpath -o "$B/ebpf-guard" ./cmd/ebpf-guard ) > "$OUT/pod-build.log" 2>&1 || die "сборка бинаря пода"
    TAG="w88-$(sha256sum "$B/ebpf-guard" | cut -c1-12)"; echo "$TAG" > "$OUT/pod-tag"
    printf 'FROM gcr.io/distroless/static:debug\nCOPY ebpf-guard /usr/local/bin/ebpf-guard\nENV GOMEMLIMIT=off\nENTRYPOINT ["/usr/local/bin/ebpf-guard"]\n' > "$B/Dockerfile"
    docker build -q -t "zugolo/ebpf-guard:$TAG" "$B" > "$OUT/pod-image.log" 2>&1 || die "docker build"
    rm -f "$B/ebpf-guard"
    docker save "zugolo/ebpf-guard:$TAG" | k3s ctr -n k8s.io images import - >> "$OUT/pod-image.log" 2>&1
    k3s ctr -n k8s.io images ls -q | grep -q "zugolo/ebpf-guard:$TAG\$" || die "образ не импортирован"
    # конфиг пода = config-test.yaml + метки стадий; rules/rego в поде разрешаются от workingDir /opt/ebpf-guard (= SRC)
    python3 - "$SRC/deploy/docker-test-setup/config-test.yaml" "$OUT/pod-config.yaml" <<'PY' || die "конфиг пода"
import sys, yaml
c = yaml.safe_load(open(sys.argv[1]))
assert c["server"]["enable_pprof"] is True
c["server"]["pprof_stage_labels"] = True
c["server"]["pprof_rule_labels"] = False
# Волна 9 (Д15): под — core; config-test.yaml несёт policy.rego.enabled=true для хоста full, поду — выключить явно
import os
c.setdefault("policy", {}).setdefault("rego", {})["enabled"] = "rego" in os.environ.get("POD_TAGS", "")
yaml.safe_dump(c, open(sys.argv[2], "w"), allow_unicode=True, sort_keys=False)
PY
    mkdir -p "$POD_STATE"; echo 0 > "$POD_STATE/observer-root-pid"
    W85_REPO="$SRC" W85_ARG_PREDICATES=1 python3 "$HERE/w82-pod-night-values.py" "$OUT/pod-config.yaml" "$TAG" "$POD_TOKEN" "$OUT/pod-values.yaml" \
        > "$OUT/pod-values.log" 2>&1 || die "values: $(cat "$OUT/pod-values.log")"
    # values-скрипт требует rules.path под /opt/ebpf-guard — путь внутри пода; hostPath ведёт в SRC
    helm install "$REL" "$SRC/deploy/helm/ebpf-guard" -n "$NS" -f "$OUT/pod-values.yaml" ${CPU_LIMIT:+--set resources.limits.cpu=$CPU_LIMIT} > "$OUT/helm-install.txt" 2>&1 || die "helm install: $(tail -3 "$OUT/helm-install.txt")"
    POD_UP=1; API=http://127.0.0.1:19091; TOKEN=$POD_TOKEN
    APID=""
    for k in $(seq 1 120); do
        APID=$(pgrep -f '^/usr/local/bin/ebpf-guard --config' | head -1)
        [ -n "$APID" ] && curl -sf --max-time 3 -H "Authorization: Bearer $TOKEN" "$API/metrics" > /dev/null && break
        sleep 2
    done
    [ -n "$APID" ] || die "процесс пода не появился"
    curl -sf --max-time 5 -H "Authorization: Bearer $TOKEN" "$API/metrics" > /dev/null || die "API пода не ответил"
    kubectl -n "$NS" get pods -o wide > "$OUT/pods.txt" 2>&1
    # фактический limits.cpu пода (при пустом CPU_LIMIT — умолчание чарта, не override); печатается в журнал прогона
    kubectl -n "$NS" get pods -o jsonpath='{.items[0].spec.containers[0].resources.limits.cpu}' > "$OUT/pod-limits-cpu.txt" 2>&1
    say "limits.cpu пода: $(cat "$OUT/pod-limits-cpu.txt") (CPU_LIMIT=${CPU_LIMIT:-<умолчание чарта>})"
fi
echo "$APID" > "$OUT/agent-pid"
[ "$(n_agents)" -eq 1 ] || die "после старта ожидался ровно один агент (смоковый), есть $(n_agents)"
m() { curl -s --max-time 10 -H "Authorization: Bearer $TOKEN" "$API/metrics"; }
flag() { m | awk -v f="$1" '$0 ~ "^ebpf_guard_runtime_flag\\{flag=\"" f "\"\\}" { print $NF }'; }
if [ "$ROLE" = host ]; then want_built=1; want_active=$HOST_REGO; else want_built=$([ -n "$POD_TAGS" ] && echo 1 || echo 0); want_active=$want_built; fi
printf 'role=%s rego_built=%s rego_active=%s (ждали built=%s active=%s) pod_tags=%s\n' "$ROLE" "$(flag rego_built)" "$(flag rego_active)" "$want_built" "$want_active" "$POD_TAGS" > "$OUT/build.txt"
say "сборка: $(cat "$OUT/build.txt")"
[ "$(flag rego_built)" = "$want_built" ] && [ "$(flag rego_active)" = "$want_active" ] || die "сборка/Rego не те: $(cat "$OUT/build.txt")"
[ "$(flag pprof_stage_labels)" = 1 ] || die "pprof_stage_labels не 1 по рантайму"
[ "$(flag enable_pprof)" = 1 ] || die "enable_pprof не 1 по рантайму"
pst=$(m | awk '/^ebpf_guard_kernel_predicate_state\{/ && $NF == 1' | sed 's/.*state="\([^"]*\)".*/\1/')
echo "kernel_predicate_state=$pst" > "$OUT/f1.txt"
say "агент pid $APID ($ROLE), stage_labels=1, F1=$pst; прогрев ${WARM_S}s"
sleep "$WARM_S"

# ── срез ─────────────────────────────────────────────────────────────────────────────────────────────────────
snap() { # snap <каталог> <метка>
    local d=$1 t=$2
    date +%s.%N > "$d/$t.t"
    m > "$d/$t.prom"
    awk '{ print $14 + $15 }' "/proc/$APID/stat" > "$d/$t.ticks" 2> /dev/null
    awk '/^VmRSS/ { print $2 }' "/proc/$APID/status" > "$d/$t.rss" 2> /dev/null
    head -1 /proc/stat > "$d/$t.cpu"
    # Волна 9, заход B: сумма по потокам агента «CPU ns / ожидание в очереди запуска ns / число квантов» — run_delay
    # отделяет «поток ждёт ядро» от «поток ждёт блокировку/канал».
    [ "${BPFSTATS:-0}" = 1 ] && bpftool prog show -j > "$d/$t.bpfprogs" 2> /dev/null
    cat /proc/$APID/task/*/schedstat 2> /dev/null | awk '{ c += $1; r += $2; n += $3 } END { print c, r, n }' > "$d/$t.sched"
}
gen() { # gen <rate|max> <dur_s> <json> — GEN_PROCS процессов, итог каждого в <json>.<p>
    # Волна 9 (решение владельца 20.10): с неблокирующим connect «max» без предела давал 175–207 тыс. оп/с и
    # занимал ящик целиком (по 8.8.Н не судится, с прежними таблицами несравним) — теперь потолок MAX_OPS;
    # MAX_OPS=0 возвращает «без ограничения».
    local r=$1 p; [ "$r" = max ] && r=${MAX_OPS:-90000}
    r=$(awk -v r="$r" -v n="$GEN_PROCS" 'BEGIN { print r / n }')
    GEN_PIDS=""
    for p in $(seq 1 "$GEN_PROCS"); do
        "$GEN" -rate "$r" -dur "${2}s" -workers "$WORKERS" -mix "$BULK_MIX" -exec-cap "$(awk -v c="$EXEC_CAP" -v n="$GEN_PROCS" 'BEGIN { print c / n }')" \
            -dir "/srv/e6/p$p" > "$3.$p" 2> "$3.$p.err" &
        GEN_PIDS="$GEN_PIDS $!"
    done
}

# ── 8.8, Р7: разбор обвала (DIAG=1) ──────────────────────────────────────────────────────────────────────────
#   block/mutex-профили включены на всё время ступеней (рантайм-переключатель), в середине ступени 20 с bpftrace
#   offcpu по tgid агента; по концу ступени снимаются block.pprof, mutex.pprof, goroutine.txt. Цены профилей
#   искажают абсолют — прогон диагностический, вердиктов по CPU не даёт.
DIAG=${DIAG:-0}
diag_on() { curl -s --max-time 10 -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"enabled\":$1}" "$API/api/v1/tuning/pprof-block-mutex" > /dev/null; }
diag_step() { # diag_step <каталог ступени> — запускается в фоне в начале ступени
    local d=$1
    sleep 20
    bpftrace "$HERE/w88-offcpu.bt" "$APID" > "$d/offcpu.txt" 2> "$d/offcpu.err" &
    local bp=$!
    sleep 20; kill -INT "$bp" 2> /dev/null; wait "$bp" 2> /dev/null
}
diag_collect() {
    local d=$1
    curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/debug/pprof/block" > "$d/block.pprof"
    curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/debug/pprof/mutex" > "$d/mutex.pprof"
    curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/debug/pprof/goroutine?debug=1" > "$d/goroutine.txt"
}

# ── Волна 9, заход B: GOSNAP=1 — моментальные снимки стеков горутин (goroutine?debug=2) раз в 0,5 с в середине ступени.
#   Время внутри handle() воркера (busy_seconds) в 2–3 раза превышало CPU агента: по снимкам видно, где воркер ждёт.
gosnap_step() { # gosnap_step <каталог ступени> — в фоне, начало ступени
    local d=$1 k
    sleep 20
    for k in $(seq 1 40); do
        curl -s --max-time 5 -H "Authorization: Bearer $TOKEN" "$API/debug/pprof/goroutine?debug=2" > "$d/gor-$k.txt"
        sleep 0.5
    done
}

# ── 8.8: приборы Р0 ───────────────────────────────────────────────────────────────────────────────────────────
AUX_PIDS=""; POLL_PID=""
poll_start() { # poll_start <файл> — «epoch status vis drops events» раз в 2 с
    ( while :; do
        h=$(curl -s --max-time 3 -H "Authorization: Bearer $TOKEN" "$API/health" | tr -d '\n ')
        st=$(echo "$h" | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p')
        mm=$(m)
        dr=$(echo "$mm" | awk '/^ebpf_guard_events_dropped_total\{/ && !/reason="path_denylist"/ { s += $NF } /^ebpf_guard_file_hot_shed_total\{outcome="shed"\}/ { s += $NF } END { printf "%d", s }')
        ev=$(echo "$mm" | awk '/^ebpf_guard_events_total\{/ { s += $NF } END { printf "%d", s }')
        lv=$(echo "$mm" | awk '/^ebpf_guard_cpu_pressure_level / { print $NF }')
        dv=$(echo "$mm" | awk '/^ebpf_guard_overload_shed_divisor / { print $NF }')
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s.%N)" "${st:-none}" "$dr" "$ev" "${lv:-na}" "${dv:-na}"
        sleep 2
      done ) > "$1" 2> /dev/null &
    POLL_PID=$!
}
aux_start() { # aux_start <dur_s> <каталог ступени> — зонд и контрольные процессы на длительность ступени
    local dur=$1 d=$2 k
    AUX_PIDS=""
    # AUX_SKIP_STEP0=1: на ступени 0 (фон ноды) приборных процессов нет — их события сами были «нагрузкой» (п.3 владельца)
    [ "${AUX_SKIP_STEP0:-0}" = 1 ] && [ "${CUR_STEP:-}" = 0 ] && return 0
    if [ "$PROBE" = 1 ]; then
        /srv/e6/bin/w88p -rate "$PROBE_RATE" -dur "${dur}s" -workers 1 -mix connect=50,prctl=50 -exec-cap 0 -dir /srv/e6/probe > "$d/probe.json" 2> "$d/probe.err" &
        AUX_PIDS="$AUX_PIDS $!"
    fi
    for k in $(seq 1 "$CONTROLS"); do
        "/srv/e6/bin/w88c$k" -rate "$CTL_RATE" -dur "${dur}s" -workers 1 -mix read=50,open=50 -exec-cap 0 -dir "/srv/e6/ctl$k" > "$d/ctl.$k.json" 2> "$d/ctl.$k.err" &
        AUX_PIDS="$AUX_PIDS $!"
    done
}
poll_start "$OUT/poll.tsv"
[ "$DIAG" = 1 ] && diag_on true

if [ "$MODE" = steps ]; then
    i=0
    for s in $STEPS; do
        i=$((i + 1)); D=$(printf '%s/step-%02d-%s' "$OUT" "$i" "$s"); mkdir -p "$D"
        kill -0 "$APID" 2> /dev/null || die "агент умер перед ступенью $s"
        snap "$D" a
        cp "$D/a.t" "$D/step-start.t"
        CUR_STEP=$s
        aux_start "$STEP_S" "$D"
        if [ "$DIAG" = 1 ]; then diag_step "$D" & DIAG_PID=$!; fi
        if [ "${GOSNAP:-0}" = 1 ]; then gosnap_step "$D" & GOSNAP_PID=$!; fi
        [ "$s" != 0 ] && gen "$s" "$STEP_S" "$D/gen.json"
        # 8.8: CPU-профиль 30 с жёг CPU агента внутри ступени и сам взводил сторож CPU пода (уровень 2 на ступени 0), поэтому
        # по умолчанию выключен; PROFILE=1 возвращает его для разрезов по стадиям.
        PROF=""
        if [ "${PROFILE:-0}" = 1 ]; then
            ( sleep 15; curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/debug/pprof/profile?seconds=30" > "$D/cpu.pprof" ) &
            PROF=$!
        fi
        if [ -n "$GEN_PIDS" ]; then wait $GEN_PIDS; GEN_PIDS=""; else sleep "$STEP_S"; fi
        [ -n "$AUX_PIDS" ] && wait $AUX_PIDS; AUX_PIDS=""
        date +%s.%N > "$D/step-end.t"
        if [ "$DIAG" = 1 ]; then wait "${DIAG_PID:-}" 2> /dev/null; diag_collect "$D"; fi
        [ "${GOSNAP:-0}" = 1 ] && wait "${GOSNAP_PID:-}" 2> /dev/null
        snap "$D" b
        [ -n "$PROF" ] && wait "$PROF"
        sleep "$GAP_S"
        snap "$D" c
        say "ступень $s: gen $(cat "$D"/gen.json.[0-9]* 2> /dev/null | cut -c1-120 | head -2) профиль $(wc -c < "$D/cpu.pprof" 2> /dev/null || echo 0) Б"
    done
else
    D="$OUT/attack"; mkdir -p "$D"
    A="$SRC/deploy/docker-test-setup/attacks"
    ls "$A/attack-results" 2> /dev/null | sort > "$D/results-before.lst"
    snap "$D" a
    gen "$ATTACK_RATE" 3600 "$D/gen.json"
    # п.1б: «горячий атакующий» — сам разгоняет темп выше порога сброса и читает /etc/shadow, пока идёт пакет
    HOT_PID=""
    if [ "${HOT_ATTACKER:-1}" = 1 ]; then
        /srv/e6/bin/w88hot -rate "${HOT_RATE:-6000}" -dur 3600s -workers 2 -mix read=100 -exec-cap 0 -shadow-every 2s -dir /srv/e6/hot > "$D/hot.json" 2> "$D/hot.err" &
        HOT_PID=$!
    fi
    sleep 15
    snap "$D" g
    ( cd "$A" && EBPF_GUARD_API="$API" EBPF_GUARD_TOKEN="$TOKEN" SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$D/attacks.log" 2>&1; echo "rc=$?" > "$D/attacks.rc" )
    snap "$D" b
    [ -n "$HOT_PID" ] && { kill -INT "$HOT_PID" 2> /dev/null; wait "$HOT_PID" 2> /dev/null; }
    kill -INT $GEN_PIDS 2> /dev/null; wait $GEN_PIDS 2> /dev/null; GEN_PIDS=""
    sleep 20
    snap "$D" c
    cp "$A/attack-manifest.json" "$D/" 2> /dev/null
    ls "$A/attack-results" 2> /dev/null | sort | comm -13 "$D/results-before.lst" - > "$D/results-new.lst"
    for f in $(grep -E '^(baseline|final)-alerts-.*\.json$' "$D/results-new.lst"); do cp "$A/attack-results/$f" "$D/"; done
    echo "recall по comm: $(ATT=$D bash "$HERE/w85-close-report.sh" recall)" | tee "$D/recall.txt"
fi
[ "$ROLE" = host ] && cp /root/w88-run/agent.log "$OUT/agent.log"
[ "$ROLE" = pod ] && kubectl -n "$NS" logs "ds/$REL-ebpf-guard" --tail=300 > "$OUT/pod.log" 2>&1
[ "$DIAG" = 1 ] && diag_on false
[ -n "$POLL_PID" ] && kill "$POLL_PID" 2> /dev/null; POLL_PID=""
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
