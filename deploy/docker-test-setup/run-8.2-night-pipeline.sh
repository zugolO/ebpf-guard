#!/bin/bash
# run-8.2-night-pipeline.sh — НОЧЬ ЗАКРЫТИЯ волны 8.2 (этап 5). Две части:
#
#   ХОСТ (ebpf-guard-test, тот же режим, что ночи H2–H4 — сравнимость 3.*):
#     idle IDLE_SECS → night-report (3.ATTACK — сторож, 3.MEM, 3.P1-19, 8.1.*;
#     8.3.4/8.3.7 читаются по содержимому архива) → пакет атак + гейт (recall по
#     манифесту — половина (в) 8.2.5).
#   ПОД (k3s, образ из HEAD, БОЕВОЙ конфиг config-test.yaml и каталог rules/
#     через hostPath — пробел Г1 доводки: до этой ночи под мерился только на
#     пробных правилах): старт 10 Гц (8.2.1) → idle до аптайма ≥ 30 мин → инвентарь
#     A1 (8.2.2, 8.2.4, учёт пода) → пакет атак без наведённого дропа + 600 с
#     удержания (8.2.1, 8.2.5 (а)(б)(в); выселение ancestry тиком Cleanup, T1) →
#     хостовый агент возвращается.
#   8.2.3 — A2 (go test без -race/-short) в префлайте, на коде HEAD.
#   Вердикты 8.2.x печатает w82-close-report.sh (фикстуры w82-close-report-fixtures.sh).
#
# Исполняется НА СТЕНДЕ одним отцепленным процессом; ждать маркер локально,
# заходить по ssh ОДИН раз после маркера ([[waiting-loop-must-not-ssh-into-window]]).
# Всё, что может сделать ночь неизмеримой (образ, чарт, генератор values, A2,
# DiskPressure), проверяется в ПРЕФЛАЙТЕ, до восьми часов.
#
# die — ТОЛЬКО для неизмеримого прогона ([[die-only-for-unmeasurable-run]]).
# После die в сегменте пода хостовый агент возвращается (trap), иначе стенд
# остаётся без агента до ручного захода.
#
# Вход: EXPECT_NR (обязателен), IDLE_SECS (умолч. 28800), EXPECT_GOMEMLIMIT
#       (умолч. 192 МиБ — режим хоста ночей H2–H4; под получает свой из чарта),
#       NIGHT_TAG (умолч. 8.2-night), NIGHT_ART (умолч. /var/lib/night-<tag>),
#       NIGHT_PREV (idle прошлой ночи для 3.P1-19), POD_IDLE_SECS (умолч. 1830),
#       POD_HOLD_SECS (умолч. 600), SKIP_HOST_ATTACKS=1 (только для смока).
set -u
SETUP="${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}"
REPO="$(cd "$SETUP/../.." && pwd)"
SERVICE="${SERVICE:-ebpf-guard-test.service}"
API="${NIGHT_API:-http://localhost:19090}"
DB="${NIGHT_DB:-/var/lib/ebpf-guard/test-events.db}"
IDLE_SECS="${IDLE_SECS:-28800}"
EXPECT_NR="${EXPECT_NR:?EXPECT_NR не задан — аллоулист прогона объявляется, а не угадывается}"
EXPECT_GOMEMLIMIT="${EXPECT_GOMEMLIMIT:-201326592}"
NIGHT_TAG="${NIGHT_TAG:-8.2-night}"
ART="${NIGHT_ART:-/var/lib/night-$NIGHT_TAG}"
POD_IDLE_SECS="${POD_IDLE_SECS:-1830}"
POD_HOLD_SECS="${POD_HOLD_SECS:-600}"
POD_TOKEN="${POD_TOKEN:-w82-night-pod-token}"
POD_STATE=/var/lib/ebpf-guard-pod
NS=ebpf-guard; REL=w82
LOG="/root/run-$NIGHT_TAG-pipeline.log"
MARK="/root/PIPELINE-$(printf '%s' "$NIGHT_TAG" | tr 'a-z.-' 'A-Z__')-DONE"
START_FILE="/root/agent-start-$NIGHT_TAG.txt"
ARCHIVE="/root/collect-$NIGHT_TAG.tgz"
export PATH=$PATH:/usr/local/go/bin:/root/bin:/usr/local/bin
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}

rm -f "$MARK"
exec >>"$LOG" 2>&1
say() { echo "[$(date -u +%FT%TZ)] $*"; }
die() { say "СТОП (прогон неизмерим): $*"; echo "die: $*" > "$MARK"; exit 1; }
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)
_curl() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$@"; }
_m() {
    awk -v m="$2" -v lab="${3:-}" '
        /^#/ { next }
        { name = $1; sub(/\{.*/, "", name) }
        name == m && (lab == "" || index($1, lab) > 0) { s += $NF; seen = 1 }
        END { if (seen) printf "%.0f\n", s }' "$1" < /dev/null
}
n_agents() { ps -eo cmd | grep -c "[e]bpf-guard --config"; }

say "=== НОЧЬ ЗАКРЫТИЯ 8.2, tag=$NIGHT_TAG, idle=${IDLE_SECS} с, под: idle ${POD_IDLE_SECS} с, удержание ${POD_HOLD_SECS} с; git $(git -C "$REPO" rev-parse --short HEAD) ==="
rm -rf "$ART"; mkdir -p "$ART" || die "не создать $ART"
GIT_HEAD=$(git -C "$REPO" rev-parse HEAD)

# ── [1] префлайт хоста ─────────────────────────────────────────────────────
[ "$(n_agents)" -eq 1 ] || die "агентов $(n_agents), а не 1"
bin="$REPO/build/ebpf-guard"
"$bin" version > "$ART/binary-version.txt" 2>&1
grep -q 'rego=true' "$ART/binary-version.txt" || die "бинарь без тега rego"
[ -n "$TOKEN" ] || die "нет admin-токена"
free_kb=$(df -Pk /var/lib | awk 'NR == 2 { print $4 }')
[ "${free_kb:-0}" -gt 4194304 ] || die "свободно ${free_kb} КиБ на /var/lib — нужен запас под ночной стор и образ пода (≥ 4 ГиБ)"
# kubelet чистит НЕИСПОЛЬЗУЕМЫЕ образы при диске ≥ 85% (imageGCHighThresholdPercent)
# до 80%: на смоке 10.10.2026 образ пода, импортированный в префлайте, был удалён
# за 25 минут до helm install (ErrImageNeverPull). Ночь живёт ≥ 8 ч — порог 80.
used_pct=$(df -P / | awk 'NR == 2 { sub(/%/, "", $5); print $5 }')
[ "${used_pct:-100}" -le 80 ] || die "диск / занят на ${used_pct}% > 80 — kubelet удалит образ пода до утра (go clean -cache, старые образы docker)"
say "префлайт: агент один, бинарь rego, свободно $((free_kb / 1024)) МиБ, диск / ${used_pct}%"

# ── [1a] префлайт пода — ДО восьми часов ──────────────────────────────────
for c in helm kubectl docker k3s jq python3 go; do command -v "$c" >/dev/null || die "нет $c в PATH"; done
python3 -c 'import yaml' 2>/dev/null || die "python3 без модуля yaml — values пода не построить"
helm status "$REL" -n "$NS" >/dev/null 2>&1 && die "релиз $REL уже установлен — под остался от прошлого захода"
[ "$(kubectl get node -o jsonpath='{.items[0].status.conditions[?(@.type=="DiskPressure")].status}')" = False ] \
    || die "узел в DiskPressure — под будет вытеснен (docker image prune -f)"
grep -q 'configRaw' "$REPO/deploy/helm/ebpf-guard/templates/configmap.yaml" || die "чарт без configRaw — боевой конфиг в под не попадёт"

# Образ пода — из HEAD, в префлайте: тождество кода пода и хоста предъявляется
# sha, а не тегом ([[archive-must-carry-binary-identity]]).
B="$ART/pod-image"; mkdir -p "$B"
( cd "$REPO" && CGO_ENABLED=0 go build -tags rego -trimpath -o "$B/ebpf-guard" ./cmd/ebpf-guard ) > "$ART/pod-build.log" 2>&1 \
    || die "сборка статического бинаря пода: $(tail -3 "$ART/pod-build.log")"
POD_SHA=$(sha256sum "$B/ebpf-guard" | cut -c1-12)
POD_TAG="w82-night-$POD_SHA"
cat > "$B/Dockerfile" <<'EOF'
FROM gcr.io/distroless/static:debug
COPY ebpf-guard /usr/local/bin/ebpf-guard
ENV GOMEMLIMIT=off
ENTRYPOINT ["/usr/local/bin/ebpf-guard"]
EOF
docker build -q -t "zugolo/ebpf-guard:$POD_TAG" "$B" > "$ART/pod-image.log" 2>&1 || die "docker build образа пода: $(tail -3 "$ART/pod-image.log")"
rm -f "$B/ebpf-guard"
# Импорт в k3s — НЕ здесь, а перед helm install (pod_image_import): до утра
# неиспользуемый образ может удалить GC kubelet.
pod_image_import() {
    docker save "zugolo/ebpf-guard:$POD_TAG" | k3s ctr -n k8s.io images import - >> "$ART/pod-image.log" 2>&1
    k3s ctr -n k8s.io images ls -q | grep -q "zugolo/ebpf-guard:$POD_TAG\$"
}
pod_image_import || die "импорт образа в k3s: образа нет в списке после импорта (без него ErrImageNeverPull)"
{ echo "pod_bin_sha12=$POD_SHA"; echo "pod_tag=$POD_TAG"; echo "git=$GIT_HEAD"; } > "$ART/pod-identity.txt"
mkdir -p "$POD_STATE"
python3 "$SETUP/w82-pod-night-values.py" "$SETUP/config-test.yaml" "$POD_TAG" "$POD_TOKEN" "$ART/pod-values.yaml" \
    > "$ART/pod-values.log" 2>&1 || die "values пода: $(cat "$ART/pod-values.log")"
helm template "$REL" "$REPO/deploy/helm/ebpf-guard" -n "$NS" -f "$ART/pod-values.yaml" > "$ART/pod-rendered.yaml" 2> "$ART/pod-template.err" \
    || die "helm template: $(tail -3 "$ART/pod-template.err")"
grep -q '/opt/ebpf-guard/rules/' "$ART/pod-rendered.yaml" || die "в отрисованном конфиге пода нет каталога правил /opt/ebpf-guard/rules/"
grep -q 'workingDir: "/opt/ebpf-guard"' "$ART/pod-rendered.yaml" || die "в отрисованном поде нет workingDir — rules/rego не разрешится"
say "префлайт пода: образ $POD_TAG собран и импортируется, values и отрисовка чарта в порядке"

# ── [1b] 8.2.3 — A2 на коде HEAD (без -race/-short, как шаг CI) ───────────
( cd "$REPO" && go test -count=1 -v -run '^TestW82_AllocPerEvent' ./internal/correlator/ ) > "$ART/a2.txt" 2>&1
grep -aqE '(ДОСТИГНУТО|ПРОВАЛЕН): 8\.2\.3 ' "$ART/a2.txt" || die "A2 не напечатал вердикт 8.2.3: $(tail -3 "$ART/a2.txt")"
say "A2: $(grep -aoE '(ДОСТИГНУТО|ПРОВАЛЕН): 8\.2\.3 [^(]*' "$ART/a2.txt" | head -1)"
# Сборка образа и A2 наращивают кэш Go на ГБ — вернуть диск ниже порога GC kubelet.
go clean -cache
say "кэш сборки очищен, диск / $(df -P / | awk 'NR == 2 { print $5 }')"

# ── [2] стор с нуля и рестарт хоста ───────────────────────────────────────
systemctl stop "$SERVICE"
ts=$(date -u +%Y%m%dT%H%M%SZ)
for f in "$DB" "$DB-wal" "$DB-shm"; do [ -e "$f" ] && mv "$f" "$f.pre-$NIGHT_TAG-$ts"; done
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
{ echo "sha256=$sha_file"; echo "sha256_proc=$sha_proc"; echo "pid=$pid"; echo "git=$GIT_HEAD"; } > "$ART/binary-identity.txt"
[ "$sha_file" = "$sha_proc" ] || die "sha процесса ${sha_proc:0:16} ≠ sha файла ${sha_file:0:16}"
[ "$(n_agents)" -eq 1 ] || die "после рестарта агентов $(n_agents)"
sleep 10
got_nr=$(journalctl -u "$SERVICE" --since "$(date -d "$(cat "$START_FILE")" '+%F %T')" --no-pager -o cat \
    | grep -a '"collector":"syscall"' | grep -o '"monitored_syscalls":[0-9]*' | tail -1 | cut -d: -f2)
[ "$got_nr" = "$EXPECT_NR" ] || die "monitored_syscalls в журнале = ${got_nr:-НЕ НАПЕЧАТАН}, объявлено $EXPECT_NR"
say "агент поднят: pid $pid, sha ${sha_file:0:16}, monitored_syscalls=$got_nr (объявлено $EXPECT_NR)"

# ── [2a] входной сторож хоста (рантайм, не конфиг) ────────────────────────
M0="$ART/metrics-preflight.txt"
_curl "$API/metrics" > "$M0"
[ -s "$M0" ] || die "/metrics пуст в префлайте — прибор не отвечает"
gml=$(_m "$M0" go_gc_gomemlimit_bytes)
[ "$gml" = "$EXPECT_GOMEMLIMIT" ] || die "GOMEMLIMIT в процессе = ${gml:-нет серии}, объявлено $EXPECT_GOMEMLIMIT"
np=$(_m "$M0" ebpf_guard_ringbuf_wait_mode 'mode="netpoll"')
[ -z "$np" ] || [ "$np" = 0 ] || die "ветка кольца netpoll включена на $np коллекторах — ночь обязана быть базой"
for q in event_high event_low rego enforce; do
    [ -n "$(_m "$M0" ebpf_guard_queue_depth_hwm "queue=\"$q\"")" ] || die "серии queue_depth_hwm{queue=\"$q\"} нет — 8.1.2 неизмерима"
done
[ -n "$(_m "$M0" ebpf_guard_events_dropped_by_queue_total 'queue="protected"')" ] || die "серии потерь protected нет — 8.2.5 (а) неизмерима"
[ -n "$(_m "$M0" ebpf_guard_file_events_by_op_total 'op="truncate"')" ] || die "серии file_events_by_op_total нет — 8.1.4 неизмерима"
prof_bytes=$(_curl --max-time 20 -o "$ART/cpu-preflight.pprof" -w '%{size_download}' "$API/debug/pprof/profile?seconds=3")
[ "${prof_bytes:-0}" -gt 1000 ] || die "CPU-профиль в префлайте ${prof_bytes:-0} Б — прибор мёртв"
cgline=$(awk -F: '$1 == "0" { print $3 }' "/proc/$pid/cgroup" 2>/dev/null | head -1)
[ -n "$cgline" ] && [ -r "/sys/fs/cgroup$cgline/memory.current" ] || die "cgroup агента не читается"
read -r cg_now < "/sys/fs/cgroup$cgline/memory.current"
HOST_RULES=$(_m "$M0" ebpf_guard_active_rules_total)
[ -n "$HOST_RULES" ] && [ "$HOST_RULES" -gt 0 ] || die "active_rules_total хоста = ${HOST_RULES:-нет серии} — сверять набор пода не с чем"
{ echo "cgroup=$cgline"; echo "memory.current.start=$cg_now"; echo "gomemlimit=$gml"; echo "rules_active=$HOST_RULES"; } > "$ART/run-intent.txt"
say "сторожа хоста: GOMEMLIMIT $gml, кольцо блокирующее, очереди и потери материализованы, cgroup $((cg_now / 1048576)) МиБ"

# ── [3] ночь хоста ─────────────────────────────────────────────────────────
say "idle: ${IDLE_SECS} с, срез 300 с, heap и CPU-профиль каждый час"
( cd "$SETUP" && OUT_DIR="$ART/idle" DURATION="$IDLE_SECS" INTERVAL=300 NO_RESTART=1 \
    HEAP_EVERY=12 CPU_PROFILE_EVERY=12 CGROUP_MEM=1 STORE_DB="$DB" SERVICE="$SERVICE" bash ./idle-run.sh ) > "$ART/idle-run.out" 2>&1
say "idle закончен (rc=$?)"
pid_now=$(systemctl show -p MainPID --value "$SERVICE")
[ "$pid_now" = "$pid" ] || say "ВНИМАНИЕ: MainPID сменился за ночь ($pid → $pid_now)"
journalctl _PID=1 -o json --since "$(date -d "$(cat "$START_FILE")" '+%F %T')" --no-pager \
    > "$ART/idle/node-units-journal.json" 2>/dev/null
if [ -s "$ART/idle/node-units-journal.json" ] \
    && python3 "$SETUP/node-units-extract.py" < "$ART/idle/node-units-journal.json" > "$ART/idle/node-units.tsv.part"; then
    mv "$ART/idle/node-units.tsv.part" "$ART/idle/node-units.tsv"
else
    rm -f "$ART/idle/node-units.tsv.part"; say "ВНИМАНИЕ: журнал юнитов ноды не снят — 3.P1-19 будет НЕИЗМЕРИМ"
fi
NIGHT_PREV="${NIGHT_PREV:-}" bash "$SETUP/night-report.sh" "$ART/idle" 300 > "$ART/night-report.txt" 2>&1
cat "$ART/night-report.txt"

# ── [4] атаки и гейт хоста ─────────────────────────────────────────────────
if [ "${SKIP_HOST_ATTACKS:-0}" = 1 ]; then
    say "SKIP_HOST_ATTACKS=1 (смок): атак и гейта на хосте нет — 8.2.5 (в) будет НЕИЗМЕРИМ"
else
    export IDLE_METRICS_START="$ART/idle/metrics-start.txt" IDLE_METRICS_END="$ART/idle/metrics-end.txt"
    export IDLE_STATE_END="$ART/idle/state-end.json"
    export IDLE_ALERTS_START="$ART/idle/alerts-start.json" IDLE_ALERTS_END="$ART/idle/alerts-end.json"
    export IDLE_INCIDENTS_START="$ART/idle/incidents-start.json" IDLE_INCIDENTS_END="$ART/idle/incidents-end.json"
    export EBPF_GUARD_TOKEN="$TOKEN"
    say "атаки хоста: run-all-attacks.sh"
    ( cd "$SETUP/attacks" && bash ./run-all-attacks.sh ) > "$ART/attacks.txt" 2>&1
    say "атаки хоста закончены (rc=$?)"
    ( cd "$SETUP/attacks" && bash ./run-gate.sh ) > "$ART/gate.txt" 2>&1
    say "гейт закончен (rc=$?); $(sed 's/\x1b\[[0-9;]*m//g' "$ART/gate.txt" | grep -a 'recall по манифесту' | tail -1)"
    [ -d "$SETUP/attacks/attack-results" ] && cp -r "$SETUP/attacks/attack-results" "$ART/attacks-results" 2>/dev/null
    cp "$SETUP/attacks/attack-manifest.json" "$ART/attack-manifest-host.json" 2>/dev/null
fi
_curl "$API/metrics" > "$ART/metrics-final.txt"
# 3.ATTACK: серии attack на idle нет, пока нет ни одного такого инцидента —
# ноль предъявляет снимок того же процесса после атак (night-report.sh).
NIGHT_PREV="${NIGHT_PREV:-}" NIGHT_LATER_METRICS="$ART/metrics-final.txt" \
    bash "$SETUP/night-report.sh" "$ART/idle" 300 > "$ART/night-report.txt" 2>&1
_curl "$API/debug/pprof/heap" > "$ART/heap-final.pprof"
read -r cg_end < "/sys/fs/cgroup$cgline/memory.current" 2>/dev/null || cg_end="?"
echo "memory.current.end=$cg_end" >> "$ART/run-intent.txt"
journalctl -u "$SERVICE" --since "$(date -d "$(cat "$START_FILE")" '+%F %T')" --no-pager -o cat > "$ART/journal-agent-$NIGHT_TAG.log"

# archive — собирается при ЛЮБОМ исходе сегмента пода: die там не должен
# стоить восьми часов хоста.
archive() {
    cp "$SETUP/config-test.yaml" "$START_FILE" "$ART/" 2>/dev/null
    cp "$0" "$ART/" 2>/dev/null
    cp "$SETUP/night-report.sh" "$SETUP/night-report-fixtures.sh" "$SETUP/node-units-extract.py" "$SETUP/idle-run.sh" \
       "$SETUP/w82-close-report.sh" "$SETUP/w82-close-report-fixtures.sh" "$SETUP/w82-mem-report.sh" \
       "$SETUP/w82-mem-report-fixtures.sh" "$SETUP/w82-ws-peak.sh" "$SETUP/w82-pod-night-values.py" "$ART/" 2>/dev/null
    tar czf "$ARCHIVE" -C "$(dirname "$ART")" "$(basename "$ART")"
    say "архив $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
}

# ── [5] сегмент пода ───────────────────────────────────────────────────────
# Хостовый агент останавливает w82-pod-run.sh; вернуть его обязан пайплайн при
# ЛЮБОМ исходе — trap на выходе.
pod_down() {
    helm uninstall "$REL" -n "$NS" >/dev/null 2>&1
    for i in $(seq 1 60); do [ "$(n_agents)" -eq 0 ] && break; sleep 2; done
    systemctl is-active --quiet "$SERVICE" || systemctl start "$SERVICE"
    sleep 5
    say "под снят, хостовый агент: $(systemctl is-active "$SERVICE"), агентов $(n_agents)"
}
trap 'pod_down; archive' EXIT
echo 0 > "$POD_STATE/observer-root-pid"   # не взведён: дерево пайплайна — это и атаки ([[observer-pid-file-with-zero-is-disarmed]])
pod_image_import || die "повторный импорт образа пода перед helm install не удался"
say "под: старт (helm install, 10 Гц × 90 с), образ $POD_TAG (в k3s, диск / $(df -P / | awk 'NR == 2 { print $5 }'))"
VALUES="$ART/pod-values.yaml" CHART="$REPO/deploy/helm/ebpf-guard" API_PORT=19091 TOKEN="$POD_TOKEN" DUR=90 UNIT_PROBE=0 \
    bash "$SETUP/w82-pod-run.sh" "$ART/pod-run" > "$ART/pod-run.log" 2>&1
grep -q '^done' "$ART/pod-run/DONE" 2>/dev/null || die "старт пода: $(cat "$ART/pod-run/DONE" 2>/dev/null || tail -3 "$ART/pod-run.log")"
ppid_pod=$(sed -n 's/^pid=\([0-9]*\) .*/\1/p' "$ART/pod-run/cg.txt")
say "под поднят: pid $ppid_pod, $(cat "$ART/pod-run/peak.txt" | head -1)"
kubectl -n "$NS" logs ds/$REL-ebpf-guard > "$ART/pod-agent-start.log" 2>&1
curl -s --max-time 30 -H "Authorization: Bearer $POD_TOKEN" localhost:19091/metrics > "$ART/pod-metrics-start.txt"
# Сторож Г1: под обязан работать на ТОМ ЖЕ наборе, что хост. Пробный набор или
# пустой каталог — 8.2.1 судил бы не продукт.
POD_RULES=$(_m "$ART/pod-metrics-start.txt" ebpf_guard_active_rules_total)
[ "${POD_RULES:-}" = "$HOST_RULES" ] || die "active_rules_total пода = ${POD_RULES:-нет серии}, хоста $HOST_RULES — под не на боевом наборе"
echo "pod_rules_active=$POD_RULES" >> "$ART/pod-identity.txt"
say "под: правил $POD_RULES (= хост), «released cilium/ebpf kernel BTF cache» $(grep -ac 'released cilium/ebpf kernel BTF cache' "$ART/pod-agent-start.log") раз"

# idle пода до аптайма POD_IDLE_SECS; без заходов в API (окно idle).
while :; do
    et=$(ps -o etimes= -p "$ppid_pod" 2>/dev/null | tr -d ' ')
    [ -n "$et" ] || die "процесс пода $ppid_pod пропал за idle (рестарт/OOM) — $(kubectl -n "$NS" get pods -o wide 2>&1 | tail -1)"
    [ "$et" -ge "$POD_IDLE_SECS" ] && break
    sleep 20
done
PID=$ppid_pod TOK=$POD_TOKEN API=localhost:19091 bash "$SETUP/w82-mem-inventory.sh" "$ART/pod-inv" > "$ART/pod-inv.log" 2>&1
say "под: инвентарь на аптайме $(sed -n 's/.*etimes= *\([0-9]*\).*/\1/p' "$ART/pod-inv/meta.txt") с"
grep -E '^ebpf_guard_collector_up' "$ART/pod-inv/metrics60.txt" > "$ART/pod-collector-up.txt" 2>/dev/null

say "под: пакет атак (без наведённого дропа) + удержание ${POD_HOLD_SECS} с"
TOKEN="$POD_TOKEN" API_PORT=19091 HOLD_S="$POD_HOLD_SECS" bash "$SETUP/w82-pod-attack.sh" "$ART/pod-attack" > "$ART/pod-attack.log" 2>&1
grep -q '^done' "$ART/pod-attack/DONE" 2>/dev/null || say "ВНИМАНИЕ: пакет пода: $(cat "$ART/pod-attack/DONE" 2>/dev/null || tail -3 "$ART/pod-attack.log")"
for f in "$ART"/pod-attack/heap-mid-*.pprof "$ART"/pod-attack/heap-pre.pprof "$ART"/pod-attack/heap-post.pprof; do
    [ -s "$f" ] && go tool pprof -top -cum -sample_index=inuse_space "$f" > "${f%.pprof}.top" 2>/dev/null
done
kubectl -n "$NS" logs ds/$REL-ebpf-guard > "$ART/pod-agent.log" 2>&1
trap - EXIT
pod_down
[ "$(n_agents)" -eq 1 ] || say "ВНИМАНИЕ: после возврата хоста агентов $(n_agents)"

# ── [6] отчёт 8.2 ──────────────────────────────────────────────────────────
RUN="$ART/pod-run" ATT="$ART/pod-attack" INV="$ART/pod-inv" GATE="$ART/gate.txt" A2="$ART/a2.txt" \
    bash "$SETUP/w82-close-report.sh" > "$ART/close-report.txt" 2>&1
cat "$ART/close-report.txt"

# ── [6a] сторож полноты меток ──────────────────────────────────────────────
# Читает ОТЧЁТЫ (night-report + close-report), не plan.md. Фикстура —
# run-8.2-night-guard-fixtures.sh, вырезает блок между маркерами.
# GUARD-BEGIN
REQUIRED_LABELS=(3.P1-19 3.MEM 3.ATTACK 3.STORE 8.1.1 8.1.2 8.1.3 8.1.4 8.2.1 8.2.2 8.2.3 8.2.4 8.2.5)
# Пайплайн новый: прогонов раньше доставки его меток нет, освобождений не нужно.
LABELS_SINCE=()
_label_since() { local e; for e in "${LABELS_SINCE[@]+"${LABELS_SINCE[@]}"}"; do [ "${e%% *}" = "$1" ] && { printf '%s' "${e#* }"; return; }; done; }
# label_completeness <отчёт> [старт ISO] — метки без вердиктной строки.
label_completeness() {
    local report="$1" start="${2:-}" lbl since missing=""
    for lbl in "${REQUIRED_LABELS[@]}"; do
        since=$(_label_since "$lbl")
        if [ -n "$since" ] && [ -n "$start" ] && [[ "$start" < "$since" ]]; then continue; fi
        grep -aE "(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО): *${lbl//./\\.}( |$)" "$report" >/dev/null 2>&1 \
            || grep -aE "${lbl//./\\.} (ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" "$report" >/dev/null 2>&1 \
            || missing="$missing $lbl"
    done
    printf '%s' "$missing"
}
# GUARD-END
cat "$ART/night-report.txt" "$ART/close-report.txt" > "$ART/all-reports.txt"
missing=$(label_completeness "$ART/all-reports.txt" "$(cat "$START_FILE")")
if [ -n "$missing" ]; then
    say "СТОРОЖ ПОЛНОТЫ: меток без вердиктной строки:$missing"
    echo "die: метки без вердикта:$missing" > "$MARK"
fi
say "сторож полноты: $(( ${#REQUIRED_LABELS[@]} - $(printf '%s' "$missing" | wc -w) ))/${#REQUIRED_LABELS[@]} меток вынесли вердикт"

# ── [7] архив ──────────────────────────────────────────────────────────────
archive
say "=== НОЧЬ ЗАКРЫТИЯ 8.2 закончена ==="
[ -s "$MARK" ] || echo "done $(date -u +%FT%TZ)" > "$MARK"
