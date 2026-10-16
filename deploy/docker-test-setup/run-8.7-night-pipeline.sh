#!/bin/bash
# run-8.7-night-pipeline.sh — НОЧЬ ЗАКРЫТИЯ волны 8.7 (заход C). Собрана из пайплайна ночи 8.6 (те же хост и под, те же сторожа);
# восемь изменений (plan.md, «Ночь закрытия 8.7 — что прогоняем»):
#   1. CPU-профиль под пакетом атак: хост (окно пакета, $ART/attack-cpu/cpu-NNN.pprof) и каждый прогон пода
#      (pod-attack/cpu-NNN.pprof), куски по 30 с, метки event_type ставит агент (enable_pprof); разложение — эмиттер 8.7.1;
#   2. block/mutex-профиль — отдельное окно 10 мин ПОСЛЕ idle и ДО пакета, под рантайм-флагом (w87-profiles.sh block-mutex);
#      на окно 8.7.2 (idle) оно не попадает; флаг обязан вернуться в 0;
#   3. срез idle пода на 30-й минуте у КАЖДОГО из ≥ 5 прогонов (все прогоны idle 1830 с), вход 8.2.2 по медиане (mem-slice);
#   4. 8.5.5 без инцидентов с root_pid == 1 в обеих долях (chain, Д12′), прежняя доля печатается справочно;
#   5. база 8.6.6 — медиана пиков пяти прогонов ночи 8.6 (143,5), читается из архива W87_BASE86 тем же кодом;
#   6. 8.1.1: справочно прыжки next_gc > 1 МиБ за срез и event_type алертов на краях окна (ref-811), класс не меняют;
#   7. cpu-preflight — 30 с (прибор жив ≥ 1000 сэмплов), а не 3 с;
#   8. архив без полной истории attacks-results — только файлы этой ночи.
# Флаги ночи по РАНТАЙМУ (сверх 8.6): pprof_block_mutex = 0 на idle (включается только окном block/mutex), ring_drain_window называется.
#
# REQUIRED_LABELS (30): 8.7.1 8.7.2 8.7.3 8.7.4 8.7.5 8.7.6 8.7.Д 8.6.1 8.6.3а 8.6.3б 8.6.6 8.1.1 8.2.2 8.5.5 + 3.P1-19 3.MEM 3.ATTACK
#   3.STORE 8.1.2 8.1.3 8.1.4 8.2.1 8.2.3 8.2.4 8.2.5 8.4.x 8.5.1 8.5.2 8.5.8 8.1.1r. Убраны 8.6.2 (→ 8.7.1), 8.6.4 (→ 8.7.4),
#   8.6.5 (→ 8.7.5), 8.6.Д (→ 8.7.Д). Сторож: вычёркивание каждой из 30 меток краснит (run-8.7-night-replay.sh).
#
# Исполняется НА СТЕНДЕ одним отцепленным процессом; ждать маркер локально, заходить по ssh ОДИН раз после маркера
# ([[waiting-loop-must-not-ssh-into-window]]). die — ТОЛЬКО для неизмеримого прогона ([[die-only-for-unmeasurable-run]]).
#
# Вход (сверх 8.6): W87_BASE86 (архив ночи 8.6: pod-run/pod-attack/pod-runs/pod-inv/idle — базы 8.7.2 и Д6′), IDENT_TESTS.
# Вход: EXPECT_NR (обязателен), IDLE_SECS (43200), EXPECT_GOMEMLIMIT, NIGHT_TAG (8.6-night), NIGHT_ART, NIGHT_PREV (idle ночи 8.5
#       для 3.P1-19), BASE_IDLE_82 (idle ночи 8.2 — база 8.5.1), W86_BASE (/root/w86-base — архив ночи 8.5: idle-8.5, pod-run-8.5,
#       pod-attack-8.5, pod-inv-8.5, host-final-alerts-8.5.json, host-manifest-8.5.json), BASE_INC (final-incidents ночи 8.2,
#       база доли с process_chain), POD_RUNS_N (5), POD_IDLE_SECS (1830, длинный прогон 1), POD_SHORT_IDLE_SECS (300, прогоны 2…N),
#       POD_HOLD_SECS (600), SKIP_HOST_ATTACKS=1 (только смок), DUMP (дамп w86-b), BENCH_DUMP_OK (1 — не пересчитывать бенч).
set -u
SETUP="${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}"
REPO="$(cd "$SETUP/../.." && pwd)"
SERVICE="${SERVICE:-ebpf-guard-test.service}"
API="${NIGHT_API:-http://localhost:19090}"
DB="${NIGHT_DB:-/var/lib/ebpf-guard/test-events.db}"
IDLE_SECS="${IDLE_SECS:-43200}"
EXPECT_NR="${EXPECT_NR:?EXPECT_NR не задан — аллоулист прогона объявляется, а не угадывается}"
W86_BASE="${W86_BASE:-/root/w86-base}"
BASE_IDLE_82="${BASE_IDLE_82:?BASE_IDLE_82 не задан — база 8.5.1 (idle ночи 8.2) называется, а не угадывается}"
STATE_FILE="${STATE_FILE:-/var/lib/ebpf-guard/profiler-state.json}"
EXPECT_GOMEMLIMIT="${EXPECT_GOMEMLIMIT:-201326592}"
NIGHT_TAG="${NIGHT_TAG:-8.7-night}"
ART="${NIGHT_ART:-/var/lib/night-$NIGHT_TAG}"
POD_RUNS_N="${POD_RUNS_N:-5}"
POD_IDLE_SECS="${POD_IDLE_SECS:-1830}"
POD_SHORT_IDLE_SECS="${POD_SHORT_IDLE_SECS:-1830}"   # Д3′: срез на 30-й минуте у КАЖДОГО прогона
POD_HOLD_SECS="${POD_HOLD_SECS:-600}"
POD_TOKEN="${POD_TOKEN:-w87-night-pod-token}"
W87_BASE86="${W87_BASE86:-/root/w87-data86}"
IDENT_TESTS="${IDENT_TESTS:-TestDispatch_ShippedRulesetSameAlerts TestP3_ShippedRulesetSameAlertsWithArgsGate TestP4_ShippedRulesetSameAlertsByFieldID}"
POD_STATE=/var/lib/ebpf-guard-pod
DUMP="${DUMP:-/root/w86-b-out/events.jsonl}"
CPU_PROFILE_EVERY="${CPU_PROFILE_EVERY:-12}"
NS=ebpf-guard; REL=w82
LOG="/root/run-$NIGHT_TAG-pipeline.log"
[ -n "${REPLAY_ART:-}" ] && LOG=/dev/stdout
MARK="/root/PIPELINE-$(printf '%s' "$NIGHT_TAG" | tr 'a-z.-' 'A-Z__')-DONE"
START_FILE="/root/agent-start-$NIGHT_TAG.txt"
ARCHIVE="/root/collect-$NIGHT_TAG.tgz"
export PATH=$PATH:/usr/local/go/bin:/root/bin:/usr/local/bin
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}

[ -n "${REPLAY_ART:-}" ] && MARK="${REPLAY_ART}/PIPELINE-REPLAY-MARK"
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
_mf() {   # то же, без округления (интервал счётчиков — дробное)
    awk -v m="$2" -v lab="${3:-}" '
        /^#/ { next }
        { name = $1; sub(/\{.*/, "", name) }
        name == m && (lab == "" || index($1, lab) > 0) { s += $NF; seen = 1 }
        END { if (seen) printf "%g\n", s }' "$1" < /dev/null
}
n_agents() { ps -eo cmd | grep -c "[e]bpf-guard --config"; }

# runtime_flags <файл метрик> — перечень расхождений флагов ночи с объявленным (пусто — всё как объявлено).
# Читает РАНТАЙМ процесса (серии ebpf_guard_runtime_*), а не конфиг; «нет серии» ≠ «выключено» — это названный класс.
runtime_flags() {
    local f=$1 v bad="" st
    check01() { v=$(_m "$f" ebpf_guard_runtime_flag "flag=\"$1\""); [ -n "$v" ] || { bad="$bad; нет серии флага $1 (бинарь не из 8.7)"; return; }; [ "$v" = "$2" ] || bad="$bad; $1=$v (объявлено $2)"; }
    check01 event_dump 0
    check01 pprof_rule_labels 0
    check01 enable_pprof 1
    check01 pprof_block_mutex 0
    v=$(_mf "$f" ebpf_guard_runtime_counters_interval_seconds)
    [ -n "$v" ] || bad="$bad; нет серии counters_interval"
    [ -z "$v" ] || [ "$v" = 15 ] || bad="$bad; counters_interval=${v} с (объявлено 15)"
    v=$(_m "$f" ebpf_guard_runtime_block_backend 'backend="log"')
    [ "$v" = 1 ] || bad="$bad; block_backend не log (серия backend=\"log\" = ${v:-нет})"
    st=$(awk '/^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "$f")
    [ "$st" = active ] || bad="$bad; kernel_predicate_state=${st:-нет серии} (объявлено active — arg_predicates)"
    printf '%s' "${bad#; }"
}

if [ -z "${REPLAY_ART:-}" ]; then   # ── живые этапы [1]–[5]; в режиме реплея (REPLAY_ART) пропускаются ──
say "=== НОЧЬ ЗАКРЫТИЯ 8.7, tag=$NIGHT_TAG, idle=${IDLE_SECS} с, под: ${POD_RUNS_N} прогонов (первый idle ${POD_IDLE_SECS} с, остальные ${POD_SHORT_IDLE_SECS} с, удержание ${POD_HOLD_SECS} с); git $(git -C "$REPO" rev-parse --short HEAD) ==="
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
# kubelet чистит НЕИСПОЛЬЗУЕМЫЕ образы при диске ≥ 85% до 80%: ночь живёт долго — порог 80.
used_pct=$(df -P / | awk 'NR == 2 { sub(/%/, "", $5); print $5 }')
[ "${used_pct:-100}" -le 80 ] || die "диск / занят на ${used_pct}% > 80 — kubelet удалит образ пода до утра (go clean -cache, старые образы docker)"
# чужие циклы и транзитные юниты (память transient-unit-survives-and-blocks-next-run, harness-pkill-f)
foreign=$(ps -eo pid,cmd | grep -E '[w]8[0-9]-[a-z0-9-]*\.sh|[r]un-[0-9.]+-night|[i]dle-run\.sh|[r]un-all-attacks|[w]82-pod-(run|attack)|[w]86-c0-stand|[w]86-d1' | grep -vE "run-8\.6-night-pipeline|w86-rehearsal\.sh|w86-night-set\.sh" | head -3)
[ -z "$foreign" ] || die "чужие циклы стенда: $(echo "$foreign" | tr '\n' ';' | cut -c1-200)"
tr_units=$(ls /run/systemd/transient/ 2>/dev/null | grep -vE '^(cri-containerd|docker-|kubepods|session-|snap\.lxd)' | grep -E '\.(service|scope)$' | head -3)
[ -z "$tr_units" ] || die "транзитные юниты: $(echo "$tr_units" | tr '\n' ' ')"
# LSM-программы второго агента из смоков должны быть отвязаны. bpftool 5.15 владельцев (pids) не печатает — считаются
# ПРОГРАММЫ типа lsm: у одинокого рабочего агента их EXPECT_LSM_PROGS (5; смок Д14а: «программ 10 → 5 как до агента»).
lsm_n=$(bpftool -j prog show 2>/dev/null | jq -r '[.[] | select(.type == "lsm")] | length' 2>/dev/null)
[ -n "$lsm_n" ] || die "bpftool не показал программы — LSM-хвост второго агента не проверить"
[ "$lsm_n" = "${EXPECT_LSM_PROGS:-5}" ] || die "программ типа lsm $lsm_n, у одинокого рабочего агента ${EXPECT_LSM_PROGS:-5} — второй агент из смоков не отвязан (bpftool link show)"
lsm_owners="$lsm_n программ lsm (ожидалось ${EXPECT_LSM_PROGS:-5})"
say "префлайт: агент один, бинарь rego, свободно $((free_kb / 1024)) МиБ, диск / ${used_pct}%, чужих циклов и транзитных юнитов нет, ${lsm_owners}"

# ── [1a] префлайт пода — ДО двенадцати часов ──────────────────────────────
for c in helm kubectl docker k3s jq python3 go bpftool; do command -v "$c" >/dev/null || die "нет $c в PATH"; done
python3 -c 'import yaml' 2>/dev/null || die "python3 без модуля yaml — values пода не построить"
helm status "$REL" -n "$NS" >/dev/null 2>&1 && die "релиз $REL уже установлен — под остался от прошлого захода"
[ "$(kubectl get node -o jsonpath='{.items[0].status.conditions[?(@.type=="DiskPressure")].status}')" = False ] \
    || die "узел в DiskPressure — под будет вытеснен (docker image prune -f)"
grep -q 'configRaw' "$REPO/deploy/helm/ebpf-guard/templates/configmap.yaml" || die "чарт без configRaw — боевой конфиг в под не попадёт"
for f in "$W86_BASE/idle-8.5/snapshots" "$W86_BASE/pod-attack-8.5" "$W86_BASE/pod-run-8.5" "$W86_BASE/pod-inv-8.5" "$W86_BASE/host-final-alerts-8.5.json" "$W86_BASE/host-manifest-8.5.json" "$BASE_IDLE_82" \
         "$W87_BASE86/idle/snapshots" "$W87_BASE86/pod-attack" "$W87_BASE86/pod-run" "$W87_BASE86/pod-inv" "$W87_BASE86/host-final-alerts-8.6.json" "$W87_BASE86/host-manifest-8.6.json"; do
    [ -e "$f" ] || die "нет базы $f (архив ночи 8.5 / 8.6 / ночи 8.2)"
done
[ -s "$DUMP" ] || die "нет дампа событий $DUMP — бенч 8.6.3б неизмерим"

# Образ пода — из HEAD, в префлайте: тождество кода пода и хоста предъявляется sha ([[archive-must-carry-binary-identity]]).
B="$ART/pod-image"; mkdir -p "$B"
( cd "$REPO" && CGO_ENABLED=0 go build -tags rego -trimpath -o "$B/ebpf-guard" ./cmd/ebpf-guard ) > "$ART/pod-build.log" 2>&1 \
    || die "сборка статического бинаря пода: $(tail -3 "$ART/pod-build.log")"
POD_SHA=$(sha256sum "$B/ebpf-guard" | cut -c1-12)
POD_TAG="w87-night-$POD_SHA"
cat > "$B/Dockerfile" <<'EOF'
FROM gcr.io/distroless/static:debug
COPY ebpf-guard /usr/local/bin/ebpf-guard
ENV GOMEMLIMIT=off
ENTRYPOINT ["/usr/local/bin/ebpf-guard"]
EOF
docker build -q -t "zugolo/ebpf-guard:$POD_TAG" "$B" > "$ART/pod-image.log" 2>&1 || die "docker build образа пода: $(tail -3 "$ART/pod-image.log")"
rm -f "$B/ebpf-guard"
pod_image_import() {
    docker save "zugolo/ebpf-guard:$POD_TAG" | k3s ctr -n k8s.io images import - >> "$ART/pod-image.log" 2>&1
    k3s ctr -n k8s.io images ls -q | grep -q "zugolo/ebpf-guard:$POD_TAG\$"
}
pod_image_import || die "импорт образа в k3s: образа нет в списке после импорта (без него ErrImageNeverPull)"
{ echo "pod_bin_sha12=$POD_SHA"; echo "pod_tag=$POD_TAG"; echo "git=$GIT_HEAD"; } > "$ART/pod-identity.txt"
mkdir -p "$POD_STATE"
W85_ARG_PREDICATES=1 python3 "$SETUP/w82-pod-night-values.py" "$SETUP/config-test.yaml" "$POD_TAG" "$POD_TOKEN" "$ART/pod-values.yaml" \
    > "$ART/pod-values.log" 2>&1 || die "values пода: $(cat "$ART/pod-values.log")"
helm template "$REL" "$REPO/deploy/helm/ebpf-guard" -n "$NS" -f "$ART/pod-values.yaml" > "$ART/pod-rendered.yaml" 2> "$ART/pod-template.err" \
    || die "helm template: $(tail -3 "$ART/pod-template.err")"
grep -q '/opt/ebpf-guard/rules/' "$ART/pod-rendered.yaml" || die "в отрисованном конфиге пода нет каталога правил /opt/ebpf-guard/rules/"
grep -q 'arg_predicates' "$ART/pod-rendered.yaml" || die "в отрисованном конфиге пода нет arg_predicates — под не про F1"
grep -q 'workingDir: "/opt/ebpf-guard"' "$ART/pod-rendered.yaml" || die "в отрисованном поде нет workingDir — rules/rego не разрешится"
say "префлайт пода: образ $POD_TAG собран и импортируется, values и отрисовка чарта в порядке"

# ── [1b] A2/A1 (go test) и бенч 8.6.3б + тождество G3 на дампе — на коде HEAD, ДО двенадцати часов ──
( cd "$REPO" && go test -count=1 -v -run '^(TestW82_AllocPerEvent|TestW85_A1_AllocPerEventPostF1Mix)' ./internal/correlator/ ) > "$ART/a2.txt" 2>&1
grep -aqE '(ДОСТИГНУТО|ПРОВАЛЕН): 8\.2\.3 ' "$ART/a2.txt" || die "A2 не напечатал вердикт 8.2.3: $(tail -3 "$ART/a2.txt")"
grep -aqE '(ДОСТИГНУТО|ПРОВАЛЕН): 8\.5\.8 ' "$ART/a2.txt" || die "A1 не напечатал вердикт 8.5.8: $(tail -3 "$ART/a2.txt")"
say "A2: $(grep -aoE '(ДОСТИГНУТО|ПРОВАЛЕН): 8\.2\.3 [^(]*' "$ART/a2.txt" | head -1); A1: $(grep -aoE '(ДОСТИГНУТО|ПРОВАЛЕН): 8\.5\.8 [^(]*' "$ART/a2.txt" | head -1)"
IDENT_TESTS="$IDENT_TESTS" bash "$SETUP/w86-bench-night.sh" "$REPO" "$ART/bench" "$DUMP" > "$ART/bench.log" 2>&1
grep -q '^done' "$ART/bench/DONE" 2>/dev/null || say "ВНИМАНИЕ: бенч 8.6.3б: $(cat "$ART/bench/DONE" 2>/dev/null || tail -3 "$ART/bench.log") — 8.6.3б/8.7.4 будут НЕИЗМЕРИМЫ"
say "бенч G0 на дампе: $(grep -a '^ns_stand=' "$ART/bench/bench-result.txt" 2>/dev/null) ns/событие; тождество G3: $(grep -a -- '--- \(PASS\|FAIL\): TestDispatch_ShippedRulesetSameAlerts' "$ART/bench/c0-identity.txt" 2>/dev/null | head -1)"
# Сборка образа, A2 и бенч наращивают кэш Go на ГБ — вернуть диск ниже порога GC kubelet.
go clean -cache
say "кэш сборки очищен, диск / $(df -P / | awk 'NR == 2 { print $5 }')"

# ── [2] стор с нуля и рестарт хоста ───────────────────────────────────────
if [ -s "$STATE_FILE" ]; then cp "$STATE_FILE" "$ART/profiler-state-before-night.json"; fi
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
prof_bytes=$(_curl --max-time 60 -o "$ART/cpu-preflight.pprof" -w '%{size_download}' "$API/debug/pprof/profile?seconds=30")
[ "${prof_bytes:-0}" -gt 1000 ] || die "CPU-профиль в префлайте ${prof_bytes:-0} Б — прибор мёртв (enable_pprof выключен?)"
pf_samples=$(go tool pprof -sample_index=samples -top "$ART/cpu-preflight.pprof" 2> /dev/null | sed -n 's/^Duration: .*Total samples = \([0-9]*\).*/\1/p' | head -1)
[ "${pf_samples:-0}" -ge 30 ] || say "ВНИМАНИЕ: cpu-preflight 30 с дал ${pf_samples:-0} сэмплов — прибор профиля слаб"
cgline=$(awk -F: '$1 == "0" { print $3 }' "/proc/$pid/cgroup" 2>/dev/null | head -1)
[ -n "$cgline" ] && [ -r "/sys/fs/cgroup$cgline/memory.stat" ] || die "cgroup агента не читается"
read -r cg_now < "/sys/fs/cgroup$cgline/memory.current"
HOST_RULES=$(_m "$M0" ebpf_guard_active_rules_total)
[ -n "$HOST_RULES" ] && [ "$HOST_RULES" -gt 0 ] || die "active_rules_total хоста = ${HOST_RULES:-нет серии} — сверять набор пода не с чем"
{ echo "cgroup=$cgline"; echo "memory.current.start=$cg_now"; echo "gomemlimit=$gml"; echo "rules_active=$HOST_RULES"; } > "$ART/run-intent.txt"

# ── [2b] F1 включается переключателем, если не активен (в конфиге он выключен до зелёной ночи) ──
st0=$(awk '/^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "$M0")
[ -n "$st0" ] || die "серии kernel_predicate_state нет — бинарь без F1"
if [ "$st0" != active ]; then
    _curl -X POST -H 'Content-Type: application/json' -d '{"enabled":true}' "$API/api/v1/tuning/kernel-predicates" > "$ART/f1-switch.json"
fi
for i in $(seq 1 30); do
    _curl "$API/metrics" > "$ART/metrics-f1.txt"
    st1=$(awk '/^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "$ART/metrics-f1.txt")
    [ "$st1" = active ] && break; sleep 1
done
[ "$st1" = active ] || die "после включения F1 состояние = ${st1:-нет серии} (было $st0), не active — ночь не про F1: $(cat "$ART/f1-switch.json" 2>/dev/null)"
echo "f1_state_start=$st0; f1_state_after_switch=$st1" >> "$ART/run-intent.txt"
# флаги РАНТАЙМА после включения F1 (kernel_predicate_state — часть сверки)
badf=$(runtime_flags "$ART/metrics-f1.txt")
[ -z "$badf" ] || die "флаги ночи в рантайме не как объявлено: $badf"
grep -a 'ebpf_guard_runtime_' "$ART/metrics-f1.txt" > "$ART/runtime-flags.txt"
say "флаги рантайма хоста: event_dump=0 pprof_rule_labels=0 enable_pprof=1 counters_interval=15 с block_backend=log F1 active (профиль CPU ${prof_bytes} Б)"

# ── [2c] исключение qemu-ga (Д16) работает живьём: за ≤ 200 с ни одного алерта от qemu-ga ──
qg0=$(_m "$ART/metrics-f1.txt" ebpf_guard_rule_exceptions_total 'exception_name="qemu-ga-os-release"')
for i in $(seq 1 20); do sleep 10; done
_curl "$API/metrics" > "$ART/metrics-qemu.txt"
qg1=$(_m "$ART/metrics-qemu.txt" ebpf_guard_rule_exceptions_total 'exception_name="qemu-ga-os-release"')
qg_alerts=$(_curl "$API/api/v1/alerts?limit=2000" | jq -r '[(if type == "array" then . else .alerts end)[] | select((.comm // .Comm) == "qemu-ga")] | length' 2>/dev/null)
echo "qemu_ga_exception_applied=$(( ${qg1:-0} - ${qg0:-0} )) qemu_ga_alerts=${qg_alerts:-?}" >> "$ART/run-intent.txt"
[ "${qg_alerts:-1}" = 0 ] || die "от qemu-ga ${qg_alerts:-?} алертов за первые 200 с — исключение Д16 не работает живьём"
say "qemu-ga (Д16): исключение применено $(( ${qg1:-0} - ${qg0:-0} )) раз за 200 с, алертов от qemu-ga 0"

# ── [3] ночь хоста ─────────────────────────────────────────────────────────
say "idle: ${IDLE_SECS} с, срез 300 с (cgroup-mem anon/file и go_memstats на каждом), heap и CPU-профиль каждые ${CPU_PROFILE_EVERY} срезов"
( cd "$SETUP" && OUT_DIR="$ART/idle" DURATION="$IDLE_SECS" INTERVAL=300 NO_RESTART=1 \
    HEAP_EVERY=12 CPU_PROFILE_EVERY="$CPU_PROFILE_EVERY" CGROUP_MEM=1 STORE_DB="$DB" SERVICE="$SERVICE" bash ./idle-run.sh ) > "$ART/idle-run.out" 2>&1
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

# ── [3a] block/mutex-профиль: отдельное окно 10 мин ПОСЛЕ idle и ДО пакета (П0(б)), не в окне 8.7.2 ──────────
say "block/mutex-профиль: окно ${BLOCK_WINDOW_SECS:-600} с под рантайм-флагом (после idle, до пакета)"
API_HP=${API#http://}
bash "$SETUP/w87-profiles.sh" block-mutex "$API_HP" "$TOKEN" "$ART/blockmutex" "${BLOCK_WINDOW_SECS:-600}" > "$ART/blockmutex.log" 2>&1
grep -q '^done' "$ART/blockmutex/DONE" 2>/dev/null || say "ВНИМАНИЕ: block/mutex-окно: $(cat "$ART/blockmutex/DONE" 2>/dev/null || tail -3 "$ART/blockmutex.log") — 8.7.6 будет ПРОВАЛЕН"

# ── [3b] положительные контроли трёх номеров при включённом F1 (8.5.2) ──────
_curl "$API/metrics" > "$ART/metrics-controls.txt"
python3 "$SETUP/w85-ctl.py" 5 3000 > "$ART/ctl1.out" 2>&1
mkdir -p /tmp/w85 && cp /usr/bin/python3 /tmp/w85/xmrig && /tmp/w85/xmrig -c 'pass' > "$ART/xmrig.out" 2>&1
sleep 20
_curl "$API/api/v1/alerts?limit=2000" > "$ART/controls-alerts.json"

# ── [3c] контроли 8.4.2 (dpkg -r и спуфы) ──────────────────────────────────
say "контроли 8.4.2: dpkg -r + спуфы (w84-controls.sh)"
API="$API" TOKEN="$TOKEN" bash "$SETUP/w84-controls.sh" "$ART/w84" > "$ART/w84.log" 2>&1
grep -q '^done' "$ART/w84/DONE" 2>/dev/null || say "ВНИМАНИЕ: контроли 8.4.2: $(cat "$ART/w84/DONE" 2>/dev/null || tail -3 "$ART/w84.log") — 8.4.x будет НЕИЗМЕРИМ"

# ── [4] атаки и гейт хоста, затем контроли в окне атак ─────────────────────
if [ "${SKIP_HOST_ATTACKS:-0}" = 1 ]; then
    say "SKIP_HOST_ATTACKS=1 (смок): атак и гейта на хосте нет — 8.2.5 (в) и 8.7.4 будут НЕИЗМЕРИМЫ"
else
    export IDLE_METRICS_START="$ART/idle/metrics-start.txt" IDLE_METRICS_END="$ART/idle/metrics-end.txt"
    export IDLE_STATE_END="$ART/idle/state-end.json"
    export IDLE_ALERTS_START="$ART/idle/alerts-start.json" IDLE_ALERTS_END="$ART/idle/alerts-end.json"
    export IDLE_INCIDENTS_START="$ART/idle/incidents-start.json" IDLE_INCIDENTS_END="$ART/idle/incidents-end.json"
    export EBPF_GUARD_TOKEN="$TOKEN"
    ls "$SETUP/attacks/attack-results" 2>/dev/null | sort > "$ART/results-before.lst"
    mkdir -p "$ART/attack-cpu"; rm -f "$ART/attack-cpu/STOP-CPU"
    bash "$SETUP/w87-profiles.sh" pack-cpu "$API_HP" "$TOKEN" "$ART/attack-cpu" 30 > "$ART/attack-cpu.log" 2>&1 &
    CPU_LOOP=$!
    say "атаки хоста: run-all-attacks.sh (CPU-профиль окна пакета: $ART/attack-cpu, куски по 30 с)"
    ( cd "$SETUP/attacks" && bash ./run-all-attacks.sh ) > "$ART/attacks.txt" 2>&1
    say "атаки хоста закончены (rc=$?)"
    ( cd "$SETUP/attacks" && bash ./run-gate.sh ) > "$ART/gate.txt" 2>&1
    say "гейт закончен (rc=$?); $(sed 's/\x1b\[[0-9;]*m//g' "$ART/gate.txt" | grep -a 'recall по манифесту' | tail -1)"
    touch "$ART/attack-cpu/STOP-CPU"; wait "$CPU_LOOP" 2>/dev/null
    say "профиль CPU под пакетом хоста: $(wc -l < "$ART/attack-cpu/cpu-index.txt" 2>/dev/null | tr -d ' ') кусков"
    # архив без истории: только файлы этой ночи (решение 8: изменение 8)
    if [ -d "$SETUP/attacks/attack-results" ]; then
        mkdir -p "$ART/attacks-results"
        ls "$SETUP/attacks/attack-results" | sort | comm -13 "$ART/results-before.lst" - | while read -r f; do cp -r "$SETUP/attacks/attack-results/$f" "$ART/attacks-results/" 2>/dev/null; done
    fi
    cp "$SETUP/attacks/attack-manifest.json" "$ART/attack-manifest-host.json" 2>/dev/null
fi
# контроли в окне атак: пауза на сброс лимитера (10 алертов/правило/60 с), затем три правила и цепочка
sleep 90
say "контроли трёх поправленных правил (положительные — настоящие процессы с настоящим comm) и контроль цепочки nginx→bash→curl"
API="$API" TOKEN="$TOKEN" bash "$SETUP/w86-night-rule-controls.sh" "$ART/rule-ctl" > "$ART/rule-ctl.log" 2>&1
grep -q '^done' "$ART/rule-ctl/DONE" 2>/dev/null || say "ВНИМАНИЕ: контроли правил: $(cat "$ART/rule-ctl/DONE" 2>/dev/null || tail -3 "$ART/rule-ctl.log") — 8.7.4 будет НЕИЗМЕРИМ"
cp "$ART/rule-ctl/driver.log" "$ART/rule-ctl-output.txt" 2>/dev/null
sleep 60
API="$API" TOKEN="$TOKEN" bash "$SETUP/w86-chain-controls.sh" "$ART/chain-ctl" 6 25 > "$ART/chain-ctl.log" 2>&1
grep -q '^done' "$ART/chain-ctl/DONE" 2>/dev/null || say "ВНИМАНИЕ: контроль цепочки: $(cat "$ART/chain-ctl/DONE" 2>/dev/null || tail -3 "$ART/chain-ctl.log") — 8.5.5 будет НЕИЗМЕРИМ"
say "контроль цепочки: $(cat "$ART/chain-ctl/DONE" 2>/dev/null | cut -c1-120)"
_curl "$API/metrics" > "$ART/metrics-final.txt"
NIGHT_PREV="${NIGHT_PREV:-}" NIGHT_LATER_METRICS="$ART/metrics-final.txt" \
    bash "$SETUP/night-report.sh" "$ART/idle" 300 > "$ART/night-report.txt" 2>&1
_curl "$API/debug/pprof/heap" > "$ART/heap-final.pprof"
read -r cg_end < "/sys/fs/cgroup$cgline/memory.current" 2>/dev/null || cg_end="?"
echo "memory.current.end=$cg_end" >> "$ART/run-intent.txt"
journalctl -u "$SERVICE" --since "$(date -d "$(cat "$START_FILE")" '+%F %T')" --no-pager -o cat > "$ART/journal-agent-$NIGHT_TAG.log"

archive() {
    cp "$SETUP/config-test.yaml" "$START_FILE" "$ART/" 2>/dev/null
    cp "$0" "$ART/" 2>/dev/null
    cp "$SETUP/night-report.sh" "$SETUP/night-report-fixtures.sh" "$SETUP/node-units-extract.py" "$SETUP/idle-run.sh" \
       "$SETUP/w82-close-report.sh" "$SETUP/w82-close-report-fixtures.sh" "$SETUP/w82-mem-report.sh" \
       "$SETUP/w82-mem-report-fixtures.sh" "$SETUP/w82-ws-peak.sh" "$SETUP/w82-pod-night-values.py" \
       "$SETUP/w85-close-report.sh" "$SETUP/w85-close-report-fixtures.sh" "$SETUP/w85-ctl.py" \
       "$SETUP/w86-close-report.sh" "$SETUP/w86-close-report-fixtures.sh" "$SETUP/w86-pprof-fixture.py" \
       "$SETUP/w87-close-report.sh" "$SETUP/w87-close-report-fixtures.sh" "$SETUP/w87-pprof-fixture.py" "$SETUP/w87-profiles.sh" \
       "$SETUP/w86-night-rule-controls.sh" "$SETUP/w86-chain-controls.sh" "$SETUP/w86-bench-night.sh" \
       "$SETUP/attacks/new-rules.txt" "$REPO/plan.md" \
       "$SETUP/w84-controls.sh" "$SETUP/w84-close-report.sh" "$SETUP/w84-chain-witness.bt" "$SETUP/w84-pidreuse.py" "$ART/" 2>/dev/null
    tar czf "$ARCHIVE" -C "$(dirname "$ART")" "$(basename "$ART")"
    say "архив $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
}

# ── [5] сегмент пода: ≥ 5 прогонов ЭТОЙ ночи, один бинарь ────────────────────
pod_down() {
    helm uninstall "$REL" -n "$NS" >/dev/null 2>&1
    local k; for k in $(seq 1 60); do [ "$(n_agents)" -eq 0 ] && break; sleep 2; done
    systemctl is-active --quiet "$SERVICE" || systemctl start "$SERVICE"
    sleep 5
    say "под снят, хостовый агент: $(systemctl is-active "$SERVICE"), агентов $(n_agents)"
}
trap 'pod_down; archive' EXIT
echo 0 > "$POD_STATE/observer-root-pid"   # не взведён: дерево пайплайна — это и атаки ([[observer-pid-file-with-zero-is-disarmed]])
: > "$ART/pod-runs.list"; : > "$ART/pod-invs.list"
# pod_run_one <i> <idle_с> — старт чартом → idle → пакет атак + удержание → метрики/инциденты. Каталоги: i=1 — $ART/pod-run,
# $ART/pod-attack (+ инвентарь на аптайме); i>1 — $ART/pod-runs/run-i/{pod-run,pod-attack}.
pod_run_one() {
    local i=$1 idle=$2 R A pr pa ppid_pod et
    if [ "$i" = 1 ]; then R="$ART/pod-run"; A="$ART/pod-attack"; else R="$ART/pod-runs/run-$i/pod-run"; A="$ART/pod-runs/run-$i/pod-attack"; mkdir -p "$ART/pod-runs/run-$i"; fi
    pod_image_import || die "повторный импорт образа пода перед helm install не удался (прогон $i)"
    say "под $i: старт (helm install, 10 Гц × 90 с), образ $POD_TAG (в k3s, диск / $(df -P / | awk 'NR == 2 { print $5 }'))"
    ARG_PREDICATES=1 VALUES="$ART/pod-values.yaml" CHART="$REPO/deploy/helm/ebpf-guard" API_PORT=19091 TOKEN="$POD_TOKEN" DUR=90 UNIT_PROBE=0 \
        bash "$SETUP/w82-pod-run.sh" "$R" > "$R.log" 2>&1
    if ! grep -q '^done' "$R/DONE" 2>/dev/null; then
        [ "$i" = 1 ] && die "старт пода 1: $(cat "$R/DONE" 2>/dev/null || tail -3 "$R.log")"
        say "ВНИМАНИЕ: старт пода $i не удался: $(cat "$R/DONE" 2>/dev/null || tail -3 "$R.log") — прогон не засчитывается"
        pod_down; return 1
    fi
    ppid_pod=$(sed -n 's/^pid=\([0-9]*\) .*/\1/p' "$R/cg.txt")
    say "под $i поднят: pid $ppid_pod, $(head -1 "$R/peak.txt")"
    curl -s --max-time 30 -H "Authorization: Bearer $POD_TOKEN" localhost:19091/metrics > "$R/pod-metrics-start.txt"
    if [ "$i" = 1 ]; then
        kubectl -n "$NS" logs ds/$REL-ebpf-guard > "$ART/pod-agent-start.log" 2>&1
        cp "$R/pod-metrics-start.txt" "$ART/pod-metrics-start.txt"
        POD_RULES=$(_m "$R/pod-metrics-start.txt" ebpf_guard_active_rules_total)
        [ "${POD_RULES:-}" = "$HOST_RULES" ] || die "active_rules_total пода = ${POD_RULES:-нет серии}, хоста $HOST_RULES — под не на боевом наборе"
        echo "pod_rules_active=$POD_RULES" >> "$ART/pod-identity.txt"
        say "под: правил $POD_RULES (= хост), «released cilium/ebpf kernel BTF cache» $(grep -ac 'released cilium/ebpf kernel BTF cache' "$ART/pod-agent-start.log") раз"
    fi
    # флаги РАНТАЙМА пода: расхождение — прогон 1 die (под не про те флаги), прогоны > 1 не засчитываются
    local pbad; pbad=$(runtime_flags "$R/pod-metrics-start.txt")
    if [ -n "$pbad" ]; then
        [ "$i" = 1 ] && die "флаги пода в рантайме не как объявлено: $pbad"
        say "ВНИМАНИЕ: флаги пода $i: $pbad — прогон не засчитывается"; echo "$pbad" > "$R/pod-flags-violation.txt"
        pod_down; return 1
    fi
    while :; do
        et=$(ps -o etimes= -p "$ppid_pod" 2>/dev/null | tr -d ' ')
        [ -n "$et" ] || { [ "$i" = 1 ] && die "процесс пода $ppid_pod пропал за idle (рестарт/OOM) — $(kubectl -n "$NS" get pods -o wide 2>&1 | tail -1)"; say "ВНИМАНИЕ: процесс пода $i пропал — прогон не засчитывается"; pod_down; return 1; }
        [ "$et" -ge "$idle" ] && break
        sleep 20
    done
    # Д3′: срез на 30-й минуте у КАЖДОГО прогона (i=1 — $ART/pod-inv, i>1 — $ART/pod-runs/run-i/pod-inv)
    local INVD; if [ "$i" = 1 ]; then INVD="$ART/pod-inv"; else INVD="$ART/pod-runs/run-$i/pod-inv"; fi
    PID=$ppid_pod TOK=$POD_TOKEN API=localhost:19091 bash "$SETUP/w82-mem-inventory.sh" "$INVD" > "$INVD.log" 2>&1
    say "под $i: инвентарь на аптайме $(sed -n 's/.*etimes= *\([0-9]*\).*/\1/p' "$INVD/meta.txt") с"
    echo "$INVD" >> "$ART/pod-invs.list"
    if [ "$i" = 1 ]; then grep -E '^ebpf_guard_collector_up' "$INVD/metrics60.txt" > "$ART/pod-collector-up.txt" 2>/dev/null; fi
    say "под $i: пакет атак (без наведённого дропа) + удержание ${POD_HOLD_SECS} с"
    CPU_PROFILE=1 ARG_PREDICATES=1 SETUP="$SETUP" TOKEN="$POD_TOKEN" API_PORT=19091 HOLD_S="$POD_HOLD_SECS" bash "$SETUP/w82-pod-attack.sh" "$A" > "$A.log" 2>&1
    grep -q '^done' "$A/DONE" 2>/dev/null || say "ВНИМАНИЕ: пакет пода $i: $(cat "$A/DONE" 2>/dev/null || tail -3 "$A.log")"
    for f in "$A"/heap-mid-*.pprof "$A"/heap-pre.pprof "$A"/heap-post.pprof; do
        [ -s "$f" ] && go tool pprof -top -cum -sample_index=inuse_space "$f" > "${f%.pprof}.top" 2>/dev/null
    done
    if [ "$i" = 1 ]; then kubectl -n "$NS" logs ds/$REL-ebpf-guard > "$ART/pod-agent.log" 2>&1; fi
    echo "$POD_SHA" > "$R/pod-sha.txt"
    echo "$R:$A" >> "$ART/pod-runs.list"
    return 0
}
# засчитанных прогонов должно быть POD_RUNS_N; сорвавшийся прогон повторяется (запас — две попытки сверх)
ridx=0; tries=0
while [ "$(wc -l < "$ART/pod-runs.list" | tr -d ' ')" -lt "$POD_RUNS_N" ] && [ "$tries" -lt $((POD_RUNS_N + 2)) ]; do
    ridx=$((ridx + 1)); tries=$((tries + 1))
    if [ "$ridx" = 1 ]; then pod_run_one 1 "$POD_IDLE_SECS"; else pod_run_one "$ridx" "$POD_SHORT_IDLE_SECS"; fi
    pod_down
    [ "$(n_agents)" -eq 1 ] || say "ВНИМАНИЕ: после снятия пода $ridx агентов $(n_agents)"
done
say "прогонов пода засчитано: $(wc -l < "$ART/pod-runs.list" | tr -d ' ') из $POD_RUNS_N (попыток $tries)"
trap - EXIT
[ "$(n_agents)" -eq 1 ] || say "ВНИМАНИЕ: после возврата хоста агентов $(n_agents)"

else
    # РЕПЛЕЙ (мак): только отчётная часть [6]–[6a] на КОПИИ архива (REPLAY_ART). Те же команды эмиттеров, тот же сторож
    # полноты; метки, чьих входов в архиве нет, дают НЕИЗМЕРИМ с названным классом, а не пропадают.
    ART="$REPLAY_ART"; [ -d "$ART" ] || { echo "REPLAY_ART=$ART не каталог"; exit 2; }
    START_FILE="$ART/${REPLAY_START_FILE:-agent-start-8.5-night.txt}"
    say "=== РЕПЛЕЙ отчётов 8.7 на $ART (живые этапы пропущены) ==="
fi

# ── [6] отчёты ─────────────────────────────────────────────────────────────
RUN="$ART/pod-run" ATT="$ART/pod-attack" INV="$ART/pod-inv" GATE="$ART/gate.txt" A2="$ART/a2.txt" \
    bash "$SETUP/w82-close-report.sh" > "$ART/close-report.txt" 2>&1
# 8.2.2 судит w87 mem-slice по срезам КАЖДОГО прогона (Д3′); строка 8.2.2 первого среза в отчёт не идёт
grep -av ': 8\.2\.2 ' "$ART/close-report.txt" > "$ART/close-report.txt.x" && mv "$ART/close-report.txt.x" "$ART/close-report.txt"
cat "$ART/close-report.txt"
POD_RUNS_LIST=$(tr '\n' ' ' < "$ART/pod-runs.list" 2>/dev/null)
POD_INVS_LIST=$(tr '\n' ' ' < "$ART/pod-invs.list" 2>/dev/null)
NIGHT_DATE=$(date -u -d "$(cat "$START_FILE" 2>/dev/null)" +%Y%m%d 2>/dev/null || date -u +%Y%m%d)
# пакет этой ночи — последний ПО ИМЕНИ (final-*-YYYYMMDD_HHMMSS.json): в архиве теперь только файлы этой ночи
HOST_FINAL=$(ls "$ART"/attacks-results/final-alerts-*.json 2>/dev/null | sort | tail -1)
HOST_INC=$(ls "$ART"/attacks-results/final-incidents-*.json 2>/dev/null | sort | tail -1)
BASE_HOST_FINAL="$W87_BASE86/host-final-alerts-8.6.json"
BASE_DATE=${BASE_DATE:-20261015}   # дата ночи 8.6 (старт 20261015): реестр new-rules.txt — по ДАТЕ, база < дата ≤ ночь
# база пятёрки прогонов ночи 8.6 (Д6′)
BASE_PODS="$W87_BASE86/pod-run:$W87_BASE86/pod-attack"; for bi in 2 3 4 5; do BASE_PODS="$BASE_PODS $W87_BASE86/pod-runs/run-$bi/pod-run:$W87_BASE86/pod-runs/run-$bi/pod-attack"; done
{
    # 8.5.1 — поток syscall в userspace против idle ночи 8.2 (регресс-сторож F1) и 8.5.2 — контроли трёх номеров
    IDLE="$ART/idle" BASE_IDLE="$BASE_IDLE_82" bash "$SETUP/w85-close-report.sh" flow
    CTL_ALERTS="$ART/controls-alerts.json" CTL_STATE="$ART/metrics-controls.txt" GATE="$ART/gate.txt" bash "$SETUP/w85-close-report.sh" controls
    bash "$SETUP/w84-close-report.sh" "$ART/w84"
    grep -aoE '(ДОСТИГНУТО|ПРОВАЛЕН): 8\.5\.8 .*' "$ART/a2.txt" | head -1
} > "$ART/close-report-85.txt" 2>&1
cat "$ART/close-report-85.txt"
{
    # 8.6.1 — сторож «не хуже ночи 8.6»: idle ≤ 0,6 × ночь 8.5 (прежняя формула, база ночи 8.5)
    IDLE="$ART/idle" BASE_IDLE="$W86_BASE/idle-8.5" bash "$SETUP/w87-close-report.sh" cpu-idle86
    # 8.7.2 — idle ≤ 0,8 × ночь 8.6
    IDLE="$ART/idle" BASE_IDLE="$W87_BASE86/idle" bash "$SETUP/w87-close-report.sh" cpu-idle
    IDLE="$ART/idle" bash "$SETUP/w87-close-report.sh" sched
    # 8.7.1 — порог 82,3 мкс без смягчения (решение 6)
    POD_RUNS="$POD_RUNS_LIST" BASE_ATT="$W86_BASE/pod-attack-8.5" bash "$SETUP/w87-close-report.sh" cpu-event
    IDLE="$ART/idle" bash "$SETUP/w87-close-report.sh" rule-eval
    BENCH_FILE="$ART/bench/bench-result.txt" IDENT="$ART/binary-identity.txt" bash "$SETUP/w87-close-report.sh" bench
    DET_NEW="$HOST_FINAL" DET_OLD="$BASE_HOST_FINAL" DET_MAN="$ART/attack-manifest-host.json" NEW_RULES="$SETUP/attacks/new-rules.txt" \
        NIGHT_DATE="$NIGHT_DATE" BASE_DATE="$BASE_DATE" RULE_CTL="$ART/rule-ctl-output.txt" C0_IDENT="$ART/bench/c0-identity.txt" IDENT_TESTS="$IDENT_TESTS" \
        bash "$SETUP/w87-close-report.sh" detect
    POD_RUNS="$POD_RUNS_LIST" POD_SHA="$(sed -n 's/^pod_bin_sha12=//p' "$ART/pod-identity.txt" 2>/dev/null)" bash "$SETUP/w87-close-report.sh" pod-median
    POD_RUNS="$POD_RUNS_LIST" INV="$ART/pod-inv" BASE_PODS="$BASE_PODS" BASE_INV="$W87_BASE86/pod-inv" bash "$SETUP/w87-close-report.sh" pod-peak
    POD_INVS="$POD_INVS_LIST" bash "$SETUP/w87-close-report.sh" mem-slice
    INC="$HOST_INC" BASE_INC="${BASE_INC:-}" CH_M0="$ART/idle/metrics-start.txt" CH_M1="$ART/metrics-final.txt" CTL_INC="$ART/chain-ctl/ctl-incidents.json" \
        bash "$SETUP/w87-close-report.sh" chain
    POD_RUNS="$POD_RUNS_LIST" HOST_CPU_DIR="$ART/attack-cpu" BLOCK_DIR="$ART/blockmutex" bash "$SETUP/w87-close-report.sh" prof
    IDLE="$ART/idle" bash "$SETUP/w87-close-report.sh" memsplit
    IDLE="$ART/idle" EDGE_ALERTS="$ART/idle/alerts-end.json" bash "$SETUP/w87-close-report.sh" ref-811
} > "$ART/close-report-87.txt" 2>&1
cat "$ART/close-report-87.txt"
# 8.7.Д — последним: статус «ночь:<метка>» читает вердикты всех отчётов выше
cat "$ART/night-report.txt" "$ART/close-report.txt" "$ART/close-report-85.txt" "$ART/close-report-87.txt" > "$ART/reports-before-d.txt"
PLAN="${PLAN:-$ART/plan.md}"; [ -s "$PLAN" ] || PLAN="$REPO/plan.md"
PLAN="$PLAN" REPORTS="$ART/reports-before-d.txt" bash "$SETUP/w87-close-report.sh" dlist > "$ART/close-report-87d.txt" 2>&1
cat "$ART/close-report-87d.txt"

# ── [6a] сторож полноты меток ──────────────────────────────────────────────
# Читает ОТЧЁТЫ, не plan.md. Фикстура — run-8.6-night-guard-fixtures.sh, вырезает блок между маркерами.
# GUARD-BEGIN
REQUIRED_LABELS=(3.P1-19 3.MEM 3.ATTACK 3.STORE 8.1.1 8.1.1r 8.1.2 8.1.3 8.1.4 8.2.1 8.2.2 8.2.3 8.2.4 8.2.5 8.4.x 8.5.1 8.5.2 8.5.5 8.5.8 8.6.1 8.6.3а 8.6.3б 8.6.6 8.7.1 8.7.2 8.7.3 8.7.4 8.7.5 8.7.6 8.7.Д)
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
cat "$ART/night-report.txt" "$ART/close-report.txt" "$ART/close-report-85.txt" "$ART/close-report-87.txt" "$ART/close-report-87d.txt" > "$ART/all-reports.txt"
missing=$(label_completeness "$ART/all-reports.txt" "$(cat "$START_FILE")")
if [ -n "$missing" ]; then
    say "СТОРОЖ ПОЛНОТЫ: меток без вердиктной строки:$missing"
    echo "die: метки без вердикта:$missing" > "$MARK"
fi
say "сторож полноты: $(( ${#REQUIRED_LABELS[@]} - $(printf '%s' "$missing" | wc -w) ))/${#REQUIRED_LABELS[@]} меток вынесли вердикт"

# ── [7] архив ──────────────────────────────────────────────────────────────
if [ -n "${REPLAY_ART:-}" ]; then
    say "=== РЕПЛЕЙ закончен: ${missing:+меток без вердикта:$missing}${missing:-все метки вынесли вердикт} ==="
    [ -z "$missing" ]; exit $?
fi
archive
say "=== НОЧЬ ЗАКРЫТИЯ 8.7 закончена ==="
[ -s "$MARK" ] || echo "done $(date -u +%FT%TZ)" > "$MARK"
