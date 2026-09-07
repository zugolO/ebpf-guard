#!/bin/bash
# run-6.2.4-pipeline.sh — прогон волны 6.2.4 (долг прогона 6.2.3, находки
# №253…№260). Форк run-6.2.3-pipeline.sh, не переписывание: механика
# прогона 6.2.3 доказана живьём (архив реплеится, сторожи результата
# работают), здесь меняются только items 6/7/8 постановки волны 6.2.4
# (plan.md, «Что делает волна 6.2.4»).
#
# ЧТО ЭТОТ ПРОГОН МЕРЯЕТ. Прогон 6.2.3 дал архив collect-6.2.3 (3 провала
# из 22) и восемь находок №253…№260 при офлайн-разборе. Items 1…5
# постановки (развилка №253 exceptions verified-daemon-image, №254 ось
# образа на промоушене инцидента, №255 реестр нодовых акторов из факта,
# №256 кап базы дрейфа величиной) сделаны в коде офлайн 07.09.2026, но НЕ
# вжиты в этот пайплайн — критерии 6.2.4.5/6.2.4.6/6.2.4.7/6.2.4.12 этим
# прогоном НЕ ИЗМЕРЯЮТСЯ. Этот форк решает ТОЛЬКО items 6/7/8:
#   №257  сторож потерь распространяется на пролог: снимок метрик сразу
#         после старта агента (Шаг 2, ДО 1800-секундного ожидания) пишется
#         в /root/metrics-prologue-start-6.2.4.txt и передаётся контролям —
#         дельта [старт агента, t0] печатается рядом с 6.2.4.A;
#   №260  страж на observer_exclude: критерий 6.2.4.13 (в wave6.2.4-controls.sh)
#         печатает наличие /var/lib/ebpf-guard/observer-root-pid и
#         ebpf_guard_events_excluded_total{reason="observer_tree"} на обеих
#         границах окна;
#   №258  ожидание тихого окна волны переведено на встроенное средство
#         оболочки (wave6.2.4-controls.sh, не здесь) — execve `sleep` внутри
#         окна больше не происходит;
#   №259  порядок останова агента (закрытие коллекторов ДО слива
#         ingest-пула) починен в коде движка (cmd/ebpf-guard/main.go,
#         gracefulShutdown) — пайплайн лишь подтверждает отсутствие
#         `kernel_counter: failed to read counter` в journal-agent-6.2.4.log.
# Пункты 3…6 постановки 6.2.3-долга — механизм немоты op=write №249,
# сужение верхушки шума №248, исключение c2_periodic_beacon_pattern №247 —
# унаследованы от 6.2.3 БЕЗ изменений (их критерии 6.2.3.5/6.2.3.6/6.2.3.13
# остаются под старыми метками, см. wave6.2.4-controls.sh).
#
# Гигиена (память ebpf-guard-measurement-hygiene): чистый стор, рестарт
# больше чем за 1200 с до окна, никаких заходов на сервер внутри окна,
# никаких фоновых циклов на стенде.
#
# СМОК: SMOKE=1 гоняет ВСЕ ветки на коротких временах (пролог 60, окно 60,
# профиль 5). Ни один блок не пропускается — память
# smoke-only-does-not-cover-attack-window: смок, не покрывающий окно,
# стоил целого замера.
set -u
export PATH=$PATH:/usr/local/bin:/usr/local/go/bin
SETUP="${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}"
SVC="${SVC:-ebpf-guard-test.service}"
SMOKE="${SMOKE:-0}"
if [ "$SMOKE" = "1" ]; then
    PROLOGUE="${PROLOGUE:-60}"
    WINDOW="${WINDOW:-60}"
    ART="${ART:-/var/lib/w624-smoke-artifacts}"
    OUT="${OUT:-/root/run-6.2.4-smoke.log}"
    COLLECT="${COLLECT:-/root/collect-6.2.4-smoke}"
    DONE_MARK="${DONE_MARK:-/root/PIPELINE-6.2.4-SMOKE-DONE}"
    PROFILE_SECS="${PROFILE_SECS:-5}"
else
    PROLOGUE="${PROLOGUE:-1800}"
    WINDOW="${WINDOW:-600}"
    ART="${ART:-/var/lib/w624-artifacts}"
    OUT="${OUT:-/root/run-6.2.4.log}"
    COLLECT="${COLLECT:-/root/collect-6.2.4}"
    DONE_MARK="${DONE_MARK:-/root/PIPELINE-6.2.4-DONE}"
    PROFILE_SECS="${PROFILE_SECS:-30}"
fi
NS="${NS:-w624}"
GATE_FORMULA="${GATE_FORMULA:-all}"
VERDICTS="${VERDICTS:-/root/wave6.2.4-controls-verdicts.txt}"

echo "=== ПРОГОН 6.2.4$([ "$SMOKE" = "1" ] && echo ' (СМОК)'), старт $(date -u +%FT%TZ) ==="
echo "пролог ${PROLOGUE}s, окно ${WINDOW}s, профиль ${PROFILE_SECS}s, формула гейта $GATE_FORMULA"

# ── Шаг 0. Реестры ДО прогона (пункт Д «Переноса в 6.1…6.4»). ──────────────
# Волна 6.2.4 меняет САМИ УСЛОВИЯ шести правил (исход №253: exceptions
# verified-daemon-image на четырёх info-двойниках cron/sshd + node-host-daemon
# на sigma_cpu_info_access/mitre_vm_detect_dmi_read, п. 2в постановки).
# Правило с изменённым условием на архивах СТАРШЕ правки читается реплеем
# как потеря — механика new-rules.txt рассчитана ровно на это (память
# new-rule-breaks-replays); renamed-rules.txt дал бы ПРЕФЛАЙТ FAIL №170 (id
# не менялся), silent-rules.txt утверждал бы, что стенд не воспроизводит
# сценарий, — а он его воспроизводит (это сужение оси, а не выключение).
echo "--- реестры до прогона ---"
for f in idle-actors.txt new-rules.txt renamed-rules.txt silent-rules.txt; do
    _r624_found=0
    for d in "$SETUP/attacks" "$SETUP/scripts" "$SETUP" /opt/ebpf-guard/scripts; do
        if [ -f "$d/$f" ]; then
            echo "  $d/$f: $(wc -l < "$d/$f") строк"
            _r624_found=1
            break
        fi
    done
    [ "$_r624_found" -eq 1 ] || echo "  СТОП-КАНДИДАТ: $f не найден"
done
# Шесть правил с ИЗМЕНЁННЫМ УСЛОВИЕМ этой волны (item 2/2в постановки
# 6.2.4, №253). Правки волн 6.2.1…6.2.3 в реестр не вносятся вновь — они уже
# покрыты своими записями датой ≤ 06.09.2026, и архив collect-6.2.3 снят УЖЕ
# с ними.
W624_NARROWED_COND="sigma_passwd_shadow_read_daemon sensitive_file_read_daemon sigma_log_deletion_daemon sigma_utmp_wtmp_modified_daemon sigma_cpu_info_access mitre_vm_detect_dmi_read"
# Дата архива, который записи обязаны покрывать: collect-6.2.3 снят
# 06.09.2026. Запись с датой <= этой архив НЕ покрывает (run-gate.sh:1459,
# сравнение СТРОГОЕ).
W624_ARCHIVE_DATE=20260906
W624_NODE_ACTORS_REQ="k3s-server coredns containerd containerd-shim iptables local-path-prov runc"
_r624_reg="$SETUP/attacks/new-rules.txt"
_r624_idle="$SETUP/attacks/idle-actors.txt"
_r624_gap=""
for _r in $W624_NARROWED_COND; do
    awk -v r="$_r" -v a="$W624_ARCHIVE_DATE" \
        '!/^[[:space:]]*(#|$)/ && $1 == r && $2 ~ /^[0-9]{8}$/ && $2+0 > a+0 {found=1} END{exit !found}' \
        "$_r624_reg" 2>/dev/null || _r624_gap="$_r624_gap new-rules.txt:$_r"
done
for _a in $W624_NODE_ACTORS_REQ; do
    grep -qE "^${_a}[[:space:]]" "$_r624_idle" 2>/dev/null || _r624_gap="$_r624_gap idle-actors.txt:$_a"
done
if [ -n "$_r624_gap" ]; then
    echo "СТОП ДО ПРОГОНА: реестры не заполнены:$_r624_gap"
    echo "  Реплей архива этой волны встанет ЖЁСТКИМ СТОПОМ №1 без единого регресса продукта"
    echo "  (пункт Д «Переноса в 6.1…6.4»). Прогон не начат — агент не тронут, стор не очищен."
    exit 1
fi
echo "  реестры сверены: правок условий $(echo $W624_NARROWED_COND | wc -w) в new-rules.txt (дата > $W624_ARCHIVE_DATE), акторов ноды $(echo $W624_NODE_ACTORS_REQ | wc -w) в idle-actors.txt"

# Сторож гигиены (память ebpf-guard-measurement-hygiene, п.5): осиротевший
# цикл ожидания от прошлой сессии даёт весь фон замера себе. На прогоне 6.0.F
# два таких поллера дали 1195 совпадений/ч против 7/ч — 170×.
_r624_orph=$(ps -eo pid,ppid,etimes,args 2>/dev/null | awk '$2==1 && $3>300' | grep -cE 'until |while |pgrep ')
echo "  осиротевших фоновых циклов на стенде: $_r624_orph"
if [ "${_r624_orph:-0}" -gt 0 ]; then
    echo "СТОП ДО ПРОГОНА: на стенде $_r624_orph осиротевших циклов ожидания (ppid=1, >300с, until/while/pgrep)."
    ps -eo pid,ppid,etimes,args 2>/dev/null | awk '$2==1 && $3>300' | grep -E 'until |while |pgrep ' | sed 's/^/    /'
    echo "  Весь фон окна будет ИХ фоном, а не фоном ноды. Снять и перезапустить."
    exit 1
fi

# ── Шаг 1. Чистый стор и рестарт. ─────────────────────────────────────────
echo "--- стор ---"
kubectl -n "$NS" delete pod --all --ignore-not-found --wait=true >/dev/null 2>&1
rm -rf "$ART" 2>/dev/null
systemctl stop "$SVC"
rm -f /var/lib/ebpf-guard/test-events.db /var/lib/ebpf-guard/test-events.db-wal /var/lib/ebpf-guard/test-events.db-shm
systemctl start "$SVC"
# №240: момент старта пишется ДВАЖДЫ — читаемой строкой и ЭПОХОЙ. journalctl
# кормится эпохой: systemd.time(7) не разбирает ISO-8601 с суффиксом «T…Z»
# как единый токен, и прошлый прогон получил из-за этого пустой журнал.
date -u +%FT%TZ > /root/agent-start-6.2.4.txt
date -u +%s    > /root/agent-start-6.2.4.epoch
echo "агент поднят $(cat /root/agent-start-6.2.4.txt) (эпоха $(cat /root/agent-start-6.2.4.epoch)), стор пуст"

# ── Шаг 2. Приборность до пролога: ждать пролог ради неизмеримого прогона
#    незачем (память die-only-for-unmeasurable-run).
sleep 30
if ! journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.2.4.epoch)" --no-pager | grep -q 'k8s enricher active'; then
    echo "СТОП: k8s-энричер не поднялся после рестарта — прогон неизмерим"
    date -u +%FT%TZ > "$DONE_MARK"
    exit 1
fi
echo "k8s-энричер поднят"

# Немота по среде фиксируется здесь же, пока журнал стартовых строк свеж
# (находка №225). Файловая ось (№234/открытый вопрос 7) — рядом с syscall'ной.
journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.2.4.epoch)" --no-pager \
    | grep -E 'no reachable nr in the kernel allowlist|cgroup escape collector unavailable|file rules whose op condition names no operation any hook produces' \
    > /root/env-muteness-6.2.4.txt 2>/dev/null
echo "немота по среде записана: /root/env-muteness-6.2.4.txt ($(wc -l < /root/env-muteness-6.2.4.txt) строк)"

# ── Шаг 2б (№257, item 6 постановки 6.2.4). Снимок метрик СРАЗУ после
#    старта агента — ДО 1800-секундного пролога, а не на границе t0
#    контролей. Без этого снимка сторож потерь 6.2.3.0/6.2.4.0 видит только
#    отрезок [t0,t1] и молчит о том, что накопилось за сам пролог: архив
#    collect-6.2.3 потерял 1336 файловых событий именно там, и никакой
#    вердикт этого не отразил (находка №257). Пишется ВНЕ $ART — контроли
#    очищают и пересоздают $ART при старте (находка №228) и стёрли бы файл,
#    попади он туда раньше их запуска.
_r624_api="${VPS_IP:+http://${VPS_IP}:19090}"; _r624_api="${_r624_api:-http://localhost:19090}"
_r624_token="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
if curl -s --max-time 30 -H "Authorization: Bearer $_r624_token" "$_r624_api/metrics" > /root/metrics-prologue-start-6.2.4.txt 2>/dev/null \
    && [ -s /root/metrics-prologue-start-6.2.4.txt ]; then
    echo "снимок метрик пролога записан: /root/metrics-prologue-start-6.2.4.txt ($(wc -l < /root/metrics-prologue-start-6.2.4.txt) строк)"
else
    echo "СНИМОК ПРОЛОГА НЕ ВЗЯТ: /root/metrics-prologue-start-6.2.4.txt пуст или недоступен — 6.2.4.A напечатает дельту пролога как НЕИЗМЕРИМУЮ, не как ноль"
    rm -f /root/metrics-prologue-start-6.2.4.txt
fi

# ── Шаг 3. Пролог. Ключ дрейфа обязан закрыть обучение ДО окна (пункт А). ──
echo "--- пролог ${PROLOGUE}s (обучение дрейфа закрывается: 600 × 2 = 1200 с) ---"
sleep "$PROLOGUE"

# ── Шаг 4. Контроли. ──────────────────────────────────────────────────────
echo "--- контроли волны 6.2.4 ---"
W624_WINDOW="$WINDOW" W624_NS="$NS" W624_ART="$ART" W624_SVC="$SVC" \
W624_CHURN=3 W624_GATE=100 W624_GATE_FORMULA="$GATE_FORMULA" \
W624_PROFILE_SECS="$PROFILE_SECS" W624_SMOKE="$SMOKE" \
W624_VERDICTS="$VERDICTS" \
W624_PROLOGUE_METRICS="/root/metrics-prologue-start-6.2.4.txt" \
    bash "$SETUP/wave6.2.4-controls.sh"

# ── Шаг 5. Сборка архива. Кладётся ТОЛЬКО то, что написал этот прогон
#    (находка №228). Ничего не копируется из каталогов прошлых волн.
echo "--- сборка архива ---"
rm -rf "$COLLECT"; mkdir -p "$COLLECT/controls" "$COLLECT/node"
cp -r "$ART" "$COLLECT/controls/artifacts" 2>/dev/null
cp "$VERDICTS" "$COLLECT/controls/" 2>/dev/null
cp /root/agent-start-6.2.4.txt /root/agent-start-6.2.4.epoch /root/env-muteness-6.2.4.txt "$COLLECT/" 2>/dev/null
cp /root/metrics-prologue-start-6.2.4.txt "$COLLECT/" 2>/dev/null
cp "$SETUP/config-test.yaml" "$SETUP/wave6.2.4-controls.sh" "$SETUP/wave6.2.4-metrics-lib.sh" "$SETUP/run-6.2.4-pipeline.sh" "$COLLECT/" 2>/dev/null

# №240: журнал агента — ЭПОХОЙ, и с проверкой кода возврата, а не тихим `>`.
_j623="$COLLECT/journal-agent-6.2.4.log"
journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.2.4.epoch)" --no-pager > "$_j623" 2>"$COLLECT/journal-agent-6.2.4.err"
_j623_rc=$?
_j623_lines=$(wc -l < "$_j623" 2>/dev/null)
echo "  журнал агента: $_j623_lines строк (код возврата journalctl $_j623_rc)"
[ -s "$COLLECT/journal-agent-6.2.4.err" ] && sed 's/^/    journalctl stderr: /' "$COLLECT/journal-agent-6.2.4.err"

# Критерий 6.2.4.4: непустота И покрытие окна. Сторож живёт В ПАЙПЛАЙНЕ, а не
# в глазах читателя архива через сутки: пустой журнал = прогон объявляет себя
# нереплеиваемым.
W624_REPLAYABLE=1
if [ "${_j623_lines:-0}" -lt 1 ]; then
    echo "  6.2.4.4 ПРОВАЛЕН: journal-agent-6.2.4.log ПУСТ — архив этого прогона НЕРЕПЛЕИВАЕМ (находка №240)"
    W624_REPLAYABLE=0
elif [ -s "$ART/window-epoch.txt" ]; then
    # Файл-мост от контролей: у них эпохи окна есть, у пайплайна их нет
    # (открытый вопрос 14).
    _t0=$(grep '^t0=' "$ART/window-epoch.txt" | cut -d= -f2)
    _t1=$(grep '^t1=' "$ART/window-epoch.txt" | cut -d= -f2)
    _jfirst=$(head -1 "$_j623" | grep -oE '^[A-Za-z]{3} [0-9]{2} [0-9:]{8}' )
    _jfirst_e=$(date -d "$_jfirst" +%s 2>/dev/null)
    _jlast=$(tail -1 "$_j623" | grep -oE '^[A-Za-z]{3} [0-9]{2} [0-9:]{8}' )
    _jlast_e=$(date -d "$_jlast" +%s 2>/dev/null)
    echo "  окно [$_t0, $_t1]; журнал [${_jfirst_e:-?}, ${_jlast_e:-?}]"
    if [ -z "${_jfirst_e:-}" ] || [ -z "${_jlast_e:-}" ]; then
        echo "  6.2.4.4 НЕИЗМЕРИМ: метки времени журнала не разобраны — покрытие окна не проверено"
        W624_REPLAYABLE=0
    elif [ "$_jfirst_e" -le "${_t0:-0}" ] && [ "$_jlast_e" -ge "${_t1:-0}" ]; then
        echo "  6.2.4.4 ДОСТИГНУТО: журнал непуст ($_j623_lines строк) и ПОКРЫВАЕТ окно (первая строка ≤ t0, последняя ≥ t1)"
    else
        echo "  6.2.4.4 ПРОВАЛЕН: журнал непуст, но НЕ покрывает окно [$_t0,$_t1] — производные от него контроли неподтверждаемы"
        W624_REPLAYABLE=0
    fi
else
    echo "  6.2.4.4 НЕИЗМЕРИМ: контроли не оставили $ART/window-epoch.txt — границы окна пайплайну неизвестны"
    W624_REPLAYABLE=0
fi
{
    echo "критерий=6.2.4.4"
    echo "время_UTC=$(date -u +%FT%TZ)"
    echo "журнал_строк=$_j623_lines реплеиваем=$W624_REPLAYABLE"
    echo "---"
} >> "$VERDICTS" 2>/dev/null

kubectl get nodes -o wide > "$COLLECT/node/nodes.txt" 2>/dev/null
kubectl get pods -A -o wide > "$COLLECT/node/pods.txt" 2>/dev/null
kubectl version -o json > "$COLLECT/node/version.json" 2>/dev/null
git -C /opt/ebpf-guard log --oneline -6 > "$COLLECT/git-head.txt" 2>/dev/null
echo "архив: $COLLECT ($(du -sh "$COLLECT" 2>/dev/null | cut -f1))"
echo "  забрать: rsync -az root@<стенд>:$COLLECT/ server-logs/$(basename "$COLLECT")/"
echo "  (размер выше посчитан ДО того, как в архив ляжет сам лог пайплайна — правка №241)"

echo "=== ПРОГОН 6.2.4$([ "$SMOKE" = "1" ] && echo ' (СМОК)') ЗАВЕРШЁН $(date -u +%FT%TZ) ==="
date -u +%FT%TZ > "$DONE_MARK"
# №241: копия лога — БУКВАЛЬНО последним действием, после маркера. Иначе
# архивная копия обрывается на «--- сборка архива ---» и по ней нельзя
# отличить упавший прогон от прошедшего целиком.
[ -f "$OUT" ] && cp "$OUT" "$COLLECT/run-6.2.4.log"
