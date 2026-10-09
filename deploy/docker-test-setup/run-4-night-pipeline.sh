#!/bin/bash
# run-4-night-pipeline.sh — ЗАМЕР №4 = ЭТАП D волны 8.1: 8 часов idle под
# заданным GOMEMLIMIT, почасовые heap и CPU-профили, cgroup-память каждый срез,
# высшие отметки очередей. Атак нет: лимит памяти под атаками — этап F, отдельный
# заход ([[run-intent-must-be-declared]]).
#
# Исполняется НА СТЕНДЕ одним отцепленным процессом; ожидать финиша локально,
# заходить по ssh ОДИН раз после маркера ([[waiting-loop-must-not-ssh-into-window]]).
#
# ЧТО МЕРИТ И ЧЕМ:
#   8.1.1    траектория cgroup-памяти → «прогрев или накопление» по anon плюс пик
#            memory.current против лимита чарта (прибор: snapshots/cgroup-mem.tsv,
#            CGROUP_MEM=1 в idle-run.sh). ВХОД item 5, не его вердикт;
#   8.1.2    потери очереди protected на idle — пункт 4 критерия выхода волны;
#            ноль берётся ТОЛЬКО с предъявленным прибором очередей (item 9);
#   3.MEM    наклон RSS/heap по часам (как в ночи №3, для сравнимости);
#   3.P1-19  нарастание по фоновым часам (без стартов юнитов ноды, журнал PID 1)
#            и цена каждого события ноды против прошлой ночи (NIGHT_PREV), №549;
#   3.ATTACK инциденты verdict="attack" на idle;
#   item 8   CPU-профиль раз в час: ⅔ CPU вне коррелятора в ночи №3 не разложены.
#
# ЧЕМ ОТЛИЧАЕТСЯ ОТ НОЧИ №3, И ПОЧЕМУ ЭТО ОБЪЯВЛЕНО ЗДЕСЬ:
#   1. GOMEMLIMIT задан (drop-in w8-gomemlimit.conf). Ночь №3 намеренно шла в
#      режиме GC стенда, и её RSS с лимитом пода несравним вовсе. Поэтому лимит
#      проверяется ВНУТРИ процесса (go_gc_gomemlimit_bytes), а не в unit-файле:
#      конфиг и исходник уже один раз стоили часа стенда на выключенном приборе
#      ([[entry-guard-must-read-runtime-not-config]]).
#   2. Ожидание кольца обязано быть БЛОКИРУЮЩИМ. Ночь — база, а не A/B item 6;
#      если бы прогон втихую пошёл по netpoll-ветке, вся его память и CPU
#      относились бы к непросуженной правке ([[ab-toggle-measures-the-restart]]).
#      Проверяется серией ebpf_guard_ringbuf_wait_mode, а не отсутствием
#      переменной в окружении.
#   3. Приборы яруса A (qhwm, CPU-профиль, cgroup) проверяются В ПРЕФЛАЙТЕ, до
#      того как сгорят 8 часов: прогон без них измеряет не то, зачем заводился
#      ([[wave-criteria-need-an-emitter]], [[empty-metric-snapshot-is-silently-zero]]).
#   4. После отчёта — сторож полноты меток: каждая объявленная метка обязана
#      напечатать вердиктное слово, иначе архив не собирается.
#
# die — ТОЛЬКО для неизмеримого прогона ([[die-only-for-unmeasurable-run]]): два
# агента, не тот бинарь, выключенный прибор, не тот режим GC, не та ветка кольца.
#
# Вход: EXPECT_NR (обязателен), IDLE_SECS (умолчание 28800 = 8 ч),
#       EXPECT_GOMEMLIMIT (умолчание 201326592 = 192 МиБ),
#       NIGHT_RUN_ATTACKS=1 (по умолчанию атак НЕТ), NIGHT_ART (умолчание /var/lib/night-4),
#       NIGHT_PREV (каталог idle прошлой ночи — сравнение цен событий ноды).
set -u
SETUP="${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}"
REPO="$(cd "$SETUP/../.." && pwd)"
SERVICE="${SERVICE:-ebpf-guard-test.service}"
API="${NIGHT_API:-http://localhost:19090}"
DB="${NIGHT_DB:-/var/lib/ebpf-guard/test-events.db}"
ART="${NIGHT_ART:-/var/lib/night-4}"
IDLE_SECS="${IDLE_SECS:-28800}"
EXPECT_NR="${EXPECT_NR:?EXPECT_NR не задан — аллоулист прогона объявляется, а не угадывается}"
EXPECT_GOMEMLIMIT="${EXPECT_GOMEMLIMIT:-201326592}"
# NIGHT_TAG разводит имена артефактов, чтобы смок приборов (короткий прогон на
# 15 минут, этап B) не затирал лог, маркер и архив боевой ночи: ровно эта
# коллизия стоила бы повторения восьми часов.
NIGHT_TAG="${NIGHT_TAG:-4-night}"
LOG="/root/run-$NIGHT_TAG-pipeline.log"
MARK="/root/PIPELINE-$(printf '%s' "$NIGHT_TAG" | tr 'a-z-' 'A-Z_')-DONE"
START_FILE="/root/agent-start-$NIGHT_TAG.txt"
ARCHIVE="/root/collect-$NIGHT_TAG.tgz"
export PATH=$PATH:/usr/local/go/bin

rm -f "$MARK"
exec >>"$LOG" 2>&1
say() { echo "[$(date -u +%FT%TZ)] $*"; }
die() { say "СТОП (прогон неизмерим): $*"; echo "die: $*" > "$MARK"; exit 1; }
TOKEN=$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)
_curl() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$@"; }
# _m <файл> <метрика> [фильтр] — сумма серий; ПУСТО, если серии нет (пустота ≠ 0).
_m() {
    awk -v m="$2" -v lab="${3:-}" '
        /^#/ { next }
        { name = $1; sub(/\{.*/, "", name) }
        name == m && (lab == "" || index($1, lab) > 0) { s += $NF; seen = 1 }
        END { if (seen) printf "%.0f\n", s }' "$1" < /dev/null
}

say "=== ЗАМЕР №4 (этап D волны 8.1), tag=$NIGHT_TAG, idle=${IDLE_SECS} с; git $(git -C "$REPO" rev-parse --short HEAD) ==="
rm -rf "$ART"; mkdir -p "$ART" || die "не создать $ART"

# ── [1] преflight: что меряем ──────────────────────────────────────────────
n_agents=$(ps -eo cmd | grep -c "[e]bpf-guard --config")
[ "$n_agents" -eq 1 ] || die "агентов $n_agents, а не 1"
bin="$REPO/build/ebpf-guard"
"$bin" version > "$ART/binary-version.txt" 2>&1
grep -q 'rego=true' "$ART/binary-version.txt" || die "бинарь без тега rego"
[ -n "$TOKEN" ] || die "нет admin-токена"
free_kb=$(df -Pk /var/lib | awk 'NR == 2 { print $4 }')
[ "${free_kb:-0}" -gt 2097152 ] || die "свободно ${free_kb} КиБ на /var/lib — ночной стор и профили не поместятся"
say "преflight: агент один, бинарь rego, свободно $((free_kb / 1024)) МиБ"

# ── [2] стор с нуля и рестарт ──────────────────────────────────────────────
systemctl stop "$SERVICE"
ts=$(date -u +%Y%m%dT%H%M%SZ)
for f in "$DB" "$DB-wal" "$DB-shm"; do [ -e "$f" ] && mv "$f" "$f.pre-4-night-$ts"; done
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
{ echo "sha256=$sha_file"; echo "sha256_proc=$sha_proc"; echo "pid=$pid"; echo "git=$(git -C "$REPO" rev-parse HEAD)"; } > "$ART/binary-identity.txt"
[ "$sha_file" = "$sha_proc" ] || die "sha процесса ${sha_proc:0:16} ≠ sha файла ${sha_file:0:16}"
n_agents=$(ps -eo cmd | grep -c "[e]bpf-guard --config")
[ "$n_agents" -eq 1 ] || die "после рестарта агентов $n_agents"
sleep 10
got_nr=$(journalctl -u "$SERVICE" --since "$(date -d "$(cat "$START_FILE")" '+%F %T')" --no-pager -o cat \
    | grep -a '"collector":"syscall"' | grep -o '"monitored_syscalls":[0-9]*' | tail -1 | cut -d: -f2)
[ "$got_nr" = "$EXPECT_NR" ] || die "monitored_syscalls в журнале = ${got_nr:-НЕ НАПЕЧАТАН}, объявлено $EXPECT_NR"
say "агент поднят: pid $pid, sha ${sha_file:0:16}, monitored_syscalls=$got_nr (объявлено $EXPECT_NR)"

# ── [2a] входной сторож прогона: режим GC, ветка кольца, живость приборов ──
# Всё читается из РАНТАЙМА поднятого агента, ни одна проверка не смотрит в
# конфиг или в unit-файл.
M0="$ART/metrics-preflight.txt"
_curl "$API/metrics" > "$M0"
[ -s "$M0" ] || die "/metrics пуст в преflight — прибор не отвечает"

gml=$(_m "$M0" go_gc_gomemlimit_bytes)
[ -n "$gml" ] || die "серии go_gc_gomemlimit_bytes нет — режим GC прогона неизвестен"
[ "$gml" = "$EXPECT_GOMEMLIMIT" ] || die "GOMEMLIMIT в процессе = $gml, объявлено $EXPECT_GOMEMLIMIT (drop-in w8-gomemlimit.conf не применился — ночь мерила бы другой режим GC, несравнимый с лимитом пода)"
say "сторож: GOMEMLIMIT в процессе $gml (объявлено $EXPECT_GOMEMLIMIT)"

np=$(_m "$M0" ebpf_guard_ringbuf_wait_mode 'mode="netpoll"')
bl=$(_m "$M0" ebpf_guard_ringbuf_wait_mode 'mode="blocking"')
if [ -z "$np" ] || [ -z "$bl" ]; then
    say "ВНИМАНИЕ: серий ebpf_guard_ringbuf_wait_mode нет — бинарь предшествует item 6; ночь идёт по блокирующей ветке по построению"
else
    [ "$np" = "0" ] || die "ветка кольца netpoll включена на $np коллекторах — ночь обязана быть базой, а не окном A/B item 6"
    say "сторож: ветка кольца блокирующая (blocking=$bl, netpoll=$np)"
fi

for q in event_high event_low rego enforce; do
    v=$(_m "$M0" ebpf_guard_queue_depth_hwm "queue=\"$q\"")
    [ -n "$v" ] || die "серии ebpf_guard_queue_depth_hwm{queue=\"$q\"} нет — прибор очередей (item 9) мёртв, метка 8.1.2 была бы неизмерима все 8 часов"
done
say "сторож: высшие отметки очередей печатаются (4 очереди)"

# Серия потерь очереди обязана БЫТЬ при нулевых потерях: смок 03.10.2026 показал,
# что на здоровом прогоне её нет вовсе, и метка 8.1.2 тогда печатает НЕИЗМЕРИМ
# всегда — пункт 4 критерия выхода волны недостижим по построению
# ([[verdict-line-that-can-only-say-unmeasurable]]). Проверяется здесь, а не
# после восьми часов.
dq=$(_m "$M0" ebpf_guard_events_dropped_by_queue_total 'queue="protected"')
[ -n "$dq" ] || die "серии events_dropped_by_queue_total{queue=\"protected\"} нет при нулевых потерях — метка 8.1.2 была бы НЕИЗМЕРИМА все 8 часов"
say "сторож: серия потерь очереди protected материализована (сумма $dq)"

# Волна 8.1, этап H: прибор оси file.op (item 7) обязан быть в экспозиции ДО
# восьми часов — иначе метка 8.1.4 печатала бы НЕИЗМЕРИМ всю ночь.
fo=$(_m "$M0" ebpf_guard_file_events_by_op_total 'op="truncate"')
[ -n "$fo" ] || die "серии ebpf_guard_file_events_by_op_total нет — бинарь без item 7, метка 8.1.4 была бы НЕИЗМЕРИМА все 8 часов"
say "сторож: прибор оси file.op материализован (truncate сейчас $fo)"

prof_bytes=$(_curl --max-time 20 -o "$ART/cpu-preflight.pprof" -w '%{size_download}' "$API/debug/pprof/profile?seconds=3")
[ "${prof_bytes:-0}" -gt 1000 ] || die "CPU-профиль в преflight вернул ${prof_bytes:-0} Б — прибор item 8(б) мёртв, почасовые профили ночи были бы пустыми"
say "сторож: CPU-профиль отвечает ($prof_bytes Б за 3 с)"

cgline=$(awk -F: '$1 == "0" { print $3 }' "/proc/$pid/cgroup" 2>/dev/null | head -1)
[ -n "$cgline" ] && [ -r "/sys/fs/cgroup$cgline/memory.current" ] \
    || die "cgroup агента не читается (путь «${cgline:-нет}») — вопрос «прогрев или накопление» неизмерим, а он и есть предмет этапа D"
read -r cg_now < "/sys/fs/cgroup$cgline/memory.current"
say "сторож: cgroup агента /sys/fs/cgroup$cgline, memory.current на старте $((cg_now / 1048576)) МиБ"
{ echo "cgroup=$cgline"; echo "memory.current.start=$cg_now"; echo "gomemlimit=$gml"; } > "$ART/run-intent.txt"

# ── [3] ночь ───────────────────────────────────────────────────────────────
say "idle: ${IDLE_SECS} с, срез 300 с, heap и CPU-профиль каждый час, cgroup каждый срез"
( cd "$SETUP" && OUT_DIR="$ART/idle" DURATION="$IDLE_SECS" INTERVAL=300 NO_RESTART=1 \
    HEAP_EVERY=12 CPU_PROFILE_EVERY=12 CGROUP_MEM=1 STORE_DB="$DB" SERVICE="$SERVICE" bash ./idle-run.sh ) > "$ART/idle-run.out" 2>&1
say "idle закончен (rc=$?)"
pid_now=$(systemctl show -p MainPID --value "$SERVICE")
[ "$pid_now" = "$pid" ] || say "ВНИМАНИЕ: MainPID сменился за ночь ($pid → $pid_now) — метки 8.1.1/8.1.2/3.* это назовут классом «рестарт»"

# ── [3a] старты юнитов ноды за ночь — вход 3.P1-19 (№549) ─────────────────
# Метка судит нарастание по часам БЕЗ стартов юнитов; журнал PID 1 снимается
# после окна (идёт после конца измерительного цикла, в объём часов не попадает).
# Не снялся — файла нет, и метка печатает НЕИЗМЕРИМ с классом, а не «все часы
# фоновые» ([[empty-metric-snapshot-is-silently-zero]]).
journalctl _PID=1 -o json --since "$(date -d "$(cat "$START_FILE")" '+%F %T')" --no-pager \
    > "$ART/idle/node-units-journal.json" 2>/dev/null
if [ -s "$ART/idle/node-units-journal.json" ] \
    && python3 "$SETUP/node-units-extract.py" < "$ART/idle/node-units-journal.json" > "$ART/idle/node-units.tsv.part"; then
    mv "$ART/idle/node-units.tsv.part" "$ART/idle/node-units.tsv"
    say "юниты ноды: стартов за ночь $(wc -l < "$ART/idle/node-units.tsv")"
else
    rm -f "$ART/idle/node-units.tsv.part"
    say "ВНИМАНИЕ: журнал юнитов ноды не снят — 3.P1-19 будет НЕИЗМЕРИМ"
fi

# ── [4] отчёт ночи ─────────────────────────────────────────────────────────
# NIGHT_PREV — каталог idle прошлой ночи на стенде: цена каждого таймера
# печатается рядом с ценой того же юнита прошлой ночи (решение владельца по №549).
NIGHT_PREV="${NIGHT_PREV:-}" bash "$SETUP/night-report.sh" "$ART/idle" 300 > "$ART/night-report.txt" 2>&1
cat "$ART/night-report.txt"

# ── [4a] сторож полноты меток ──────────────────────────────────────────────
# Метка без вердиктной строки = критерий недостижим ([[wave-criteria-need-an-emitter]]).
# Сторож читает ОТЧЁТ, а не plan.md: совпадение таблицы с постановкой — ручная
# синхронизация, как у стражей волн 6.2.x–6.4. Сам сторож прогоняется офлайн
# фикстурой run-4-night-guard-fixtures.sh, которая ВЫРЕЗАЕТ таблицу и цикл из
# этого файла: страж, чья регулярка молча не совпадает, печатает «0 расхождений»
# и пропускает всё ([[helper-called-before-definition-is-silent-pass]]).
#
# Расхождение НЕ отказ собрать архив: восемь часов данных дороже, и правило
# «die только для неизмеримого прогона» ([[die-only-for-unmeasurable-run]]) здесь
# в силе — но маркер прогона скажет die, чтобы неполнота не прочиталась как
# успех при разборе.
# GUARD-BEGIN
REQUIRED_LABELS=(3.P1-19 3.MEM 3.ATTACK 3.STORE 8.1.1 8.1.2 8.1.3 8.1.4)
# Момент ДОСТАВКИ эмиттера метки на стенд ([[label-since-means-delivery-not-mtime]]):
# метка требуется от прогона, стартовавшего не раньше. 8.1.3/8.1.4 доставлены
# между ночью №4 (старт 2026-10-03T19:18:59Z, отчёт их не печатал и печатать не
# мог) и ночью H (2026-10-06T23:01:41Z, печатала). 3.P1-19 переопределена
# 09.10.2026 под тем же именем — освобождения ей не нужно: старый эмиттер её
# печатал, новый на архиве без журнала юнитов печатает НЕИЗМЕРИМ.
LABELS_SINCE=("8.1.3 2026-10-06T12:00:00Z" "8.1.4 2026-10-06T12:00:00Z")
# _label_since <метка> — момент из LABELS_SINCE или пусто.
_label_since() { local e; for e in "${LABELS_SINCE[@]}"; do [ "${e%% *}" = "$1" ] && { printf '%s' "${e#* }"; return; }; done; }
# label_completeness <отчёт> [старт прогона ISO] — метки без вердиктной строки.
# Без старта метка требуется всегда (закрытый отказ): освобождение даёт только
# предъявленный момент прогона раньше момента доставки.
label_completeness() {
    local report="$1" start="${2:-}" lbl since missing=""
    for lbl in "${REQUIRED_LABELS[@]}"; do
        since=$(_label_since "$lbl")
        if [ -n "$since" ] && [ -n "$start" ] && [[ "$start" < "$since" ]]; then continue; fi
        grep -aE "(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО): *${lbl}( |$)" "$report" >/dev/null 2>&1 \
            || grep -aE "${lbl} (ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" "$report" >/dev/null 2>&1 \
            || missing="$missing $lbl"
    done
    printf '%s' "$missing"
}
# label_exempt <старт прогона ISO> — освобождённые метки, печатаются вслух.
label_exempt() {
    local start="${1:-}" lbl since out=""
    for lbl in "${REQUIRED_LABELS[@]}"; do
        since=$(_label_since "$lbl")
        [ -n "$since" ] && [ -n "$start" ] && [[ "$start" < "$since" ]] && out="$out $lbl(с $since)"
    done
    printf '%s' "$out"
}
# GUARD-END
missing=$(label_completeness "$ART/night-report.txt" "$(cat "$START_FILE")")
ex=$(label_exempt "$(cat "$START_FILE")"); [ -n "$ex" ] && say "сторож полноты: освобождены по моменту доставки:$ex"
if [ -n "$missing" ]; then
    say "СТОРОЖ ПОЛНОТЫ: меток без вердиктной строки:$missing"
    echo "die: метки без вердикта:$missing" > "$MARK"
fi
say "сторож полноты: $(( ${#REQUIRED_LABELS[@]} - $(printf '%s' "$missing" | wc -w) ))/${#REQUIRED_LABELS[@]} меток вынесли вердикт"

# ── [5] атаки — только если прогон их объявил ──────────────────────────────
if [ "${NIGHT_RUN_ATTACKS:-0}" = 1 ]; then
    export IDLE_METRICS_START="$ART/idle/metrics-start.txt" IDLE_METRICS_END="$ART/idle/metrics-end.txt"
    export IDLE_STATE_END="$ART/idle/state-end.json"
    export IDLE_ALERTS_START="$ART/idle/alerts-start.json" IDLE_ALERTS_END="$ART/idle/alerts-end.json"
    export IDLE_INCIDENTS_START="$ART/idle/incidents-start.json" IDLE_INCIDENTS_END="$ART/idle/incidents-end.json"
    export EBPF_GUARD_TOKEN="$TOKEN"
    say "атаки: run-all-attacks.sh"
    ( cd "$SETUP/attacks" && bash ./run-all-attacks.sh ) > "$ART/attacks.txt" 2>&1
    say "атаки закончены (rc=$?)"
    say "гейт: run-gate.sh"
    ( cd "$SETUP/attacks" && bash ./run-gate.sh ) > "$ART/gate.txt" 2>&1
    say "гейт закончен (rc=$?)"
    [ -d "$SETUP/attacks/attack-results" ] && cp -r "$SETUP/attacks/attack-results" "$ART/attacks-results" 2>/dev/null
else
    say "атак нет (NIGHT_RUN_ATTACKS≠1): лимит памяти под атаками — этап F, отдельный заход"
fi

# ── [6] снимки ПОСЛЕ всего ─────────────────────────────────────────────────
_curl "$API/metrics" > "$ART/metrics-final.txt"
_curl "$API/debug/pprof/heap" > "$ART/heap-final.pprof"
read -r cg_end < "/sys/fs/cgroup$cgline/memory.current" 2>/dev/null || cg_end="?"
echo "memory.current.end=$cg_end" >> "$ART/run-intent.txt"
journalctl -u "$SERVICE" --since "$(date -d "$(cat "$START_FILE")" '+%F %T')" --no-pager -o cat > "$ART/journal-agent-$NIGHT_TAG.log"
cp "$SETUP/config-test.yaml" "$ART/config-test.yaml"
cp "$START_FILE" "$ART/"
cp "$0" "$ART/" 2>/dev/null
# Архив несёт СВОИ копии эмиттера и его фикстур: реплей обязан гоняться той
# версией, что считала этот прогон ([[archive-carries-its-own-guard-copy]]).
cp "$SETUP/night-report.sh" "$SETUP/night-report-fixtures.sh" "$SETUP/node-units-extract.py" \
   "$SETUP/idle-run.sh" "$SETUP/idle-run-cgroup-fixtures.sh" "$ART/" 2>/dev/null
tar czf "$ARCHIVE" -C "$(dirname "$ART")" "$(basename "$ART")"
say "=== ЗАМЕР №4 закончен; архив $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1)) ==="
[ -s "$MARK" ] || echo "done $(date -u +%FT%TZ)" > "$MARK"
