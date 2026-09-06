#!/bin/bash
# run-6.2.2-pipeline.sh — прогон волны 6.2.2 (долг прогона 6.2.1).
#
# ЧТО ЭТОТ ПРОГОН МЕРЯЕТ. Прогон 6.2.1 (05.09.2026, архив
# server-logs/collect-6.2.1) провалил гейт волны 6 (1932/ч при 100/ч) и дал
# пятнадцать находок №230…№244. ШЕСТЬ из них — дефекты самого измерителя, и
# они починены ДО этого прогона: без них прогон печатает ложный PASS, а не
# величину.
#
# ЧЕМ ОТЛИЧАЕТСЯ ОТ run-6.2.1-pipeline.sh:
#   №240  момент старта агента пишется ТАКЖЕ эпохой, и journalctl зовётся
#         через `--since "@<эпоха>"`. Прошлый прогон кормил journalctl
#         строкой `2026-09-05T02:10:09Z`; systemd.time(7) суффикс «T…Z» не
#         разбирает, ошибка ушла в `2>/dev/null`, и journal-agent-6.2.1.log
#         приехал в архив НУЛЕВОГО РАЗМЕРА — вместе с ним стали
#         неподтверждаемыми контроли заморозки и потерь событий;
#   №240  сторож непустоты И ПОКРЫТИЯ журнала: пустой или не покрывающий
#         окно журнал = прогон ОБЪЯВЛЯЕТ СЕБЯ нереплеиваемым, а не приезжает
#         тихо (критерий 6.2.2.4). Границы окна берутся из файла-моста
#         $ART/window-epoch.txt, который пишут контроли (открытый вопрос 14
#         решён файлом, а не переносом сторожа внутрь контролей: сборка
#         архива — работа пайплайна);
#   №241  копия лога пайплайна в архив — БУКВАЛЬНО ПОСЛЕДНЕЕ действие, после
#         всех echo и после записи маркера. В архиве 6.2.1 копия снималась
#         ДО строк «архив: …» и «ПРОГОН ЗАВЕРШЁН», поэтому по архиву нельзя
#         было отличить упавшую сборку от прошедшей целиком;
#   №232  формула гейта фиксируется ЗДЕСЬ, до прогона, и в прогоне не
#         меняется (W622_GATE_FORMULA). Обе величины печатаются всегда.
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
    ART="${ART:-/root/wave6.2.2-smoke-artifacts}"
    OUT="${OUT:-/root/run-6.2.2-smoke.log}"
    COLLECT="${COLLECT:-/root/collect-6.2.2-smoke}"
    DONE_MARK="${DONE_MARK:-/root/PIPELINE-6.2.2-SMOKE-DONE}"
    PROFILE_SECS="${PROFILE_SECS:-5}"
else
    PROLOGUE="${PROLOGUE:-1800}"
    WINDOW="${WINDOW:-600}"
    ART="${ART:-/root/wave6.2.2-artifacts}"
    OUT="${OUT:-/root/run-6.2.2.log}"
    COLLECT="${COLLECT:-/root/collect-6.2.2}"
    DONE_MARK="${DONE_MARK:-/root/PIPELINE-6.2.2-DONE}"
    PROFILE_SECS="${PROFILE_SECS:-30}"
fi
NS="${NS:-w622}"
GATE_FORMULA="${GATE_FORMULA:-all}"
VERDICTS="${VERDICTS:-/root/wave6.2.2-controls-verdicts.txt}"

echo "=== ПРОГОН 6.2.2$([ "$SMOKE" = "1" ] && echo ' (СМОК)'), старт $(date -u +%FT%TZ) ==="
echo "пролог ${PROLOGUE}s, окно ${WINDOW}s, профиль ${PROFILE_SECS}s, формула гейта $GATE_FORMULA"

# ── Шаг 0. Реестры ДО прогона (пункт Д «Переноса в 6.1…6.4»). ──────────────
# Волна 6.2.2 меняет САМИ УСЛОВИЯ четырёх правил. Правило с изменённым
# условием на архивах СТАРШЕ правки читается реплеем как потеря — механика
# new-rules.txt рассчитана ровно на это (память new-rule-breaks-replays);
# renamed-rules.txt дал бы ПРЕФЛАЙТ FAIL №170 (id не менялся), silent-rules.txt
# утверждал бы, что стенд не воспроизводит сценарий, — а он его
# воспроизводит инъекциями контроля 6.2.2.6 этого же прогона.
echo "--- реестры до прогона ---"
for f in idle-actors.txt new-rules.txt renamed-rules.txt silent-rules.txt; do
    _r622_found=0
    for d in "$SETUP/attacks" "$SETUP/scripts" "$SETUP" /opt/ebpf-guard/scripts; do
        if [ -f "$d/$f" ]; then
            echo "  $d/$f: $(wc -l < "$d/$f") строк"
            _r622_found=1
            break
        fi
    done
    [ "$_r622_found" -eq 1 ] || echo "  СТОП-КАНДИДАТ: $f не найден"
done
# Четыре правила с ИЗМЕНЁННЫМ УСЛОВИЕМ этой волны. Сужения ПО COMM в реестр
# не вносятся вовсе (на старых архивах этих comm нет, запись маскировала бы
# настоящий регресс), правки 6.2.1 — тоже: они уже покрыты своими записями
# датой 20260905 и архив collect-6.2.1 снят УЖЕ с ними.
W622_NARROWED_COND="c2_periodic_beacon_pattern beacon_fixed_interval sigma_log_deletion sigma_iptables_flush"
# Дата архива, который записи обязаны покрывать: collect-6.2.1 снят
# 05.09.2026. Запись с датой <= этой архив НЕ покрывает (run-gate.sh:1459,
# сравнение СТРОГОЕ).
W622_ARCHIVE_DATE=20260905
W622_NODE_ACTORS_REQ="k3s-server coredns containerd containerd-shim iptables local-path-prov runc"
_r622_reg="$SETUP/attacks/new-rules.txt"
_r622_idle="$SETUP/attacks/idle-actors.txt"
_r622_gap=""
for _r in $W622_NARROWED_COND; do
    awk -v r="$_r" -v a="$W622_ARCHIVE_DATE" \
        '!/^[[:space:]]*(#|$)/ && $1 == r && $2 ~ /^[0-9]{8}$/ && $2+0 > a+0 {found=1} END{exit !found}' \
        "$_r622_reg" 2>/dev/null || _r622_gap="$_r622_gap new-rules.txt:$_r"
done
for _a in $W622_NODE_ACTORS_REQ; do
    grep -qE "^${_a}[[:space:]]" "$_r622_idle" 2>/dev/null || _r622_gap="$_r622_gap idle-actors.txt:$_a"
done
if [ -n "$_r622_gap" ]; then
    echo "СТОП ДО ПРОГОНА: реестры не заполнены:$_r622_gap"
    echo "  Реплей архива этой волны встанет ЖЁСТКИМ СТОПОМ №1 без единого регресса продукта"
    echo "  (пункт Д «Переноса в 6.1…6.4»). Прогон не начат — агент не тронут, стор не очищен."
    exit 1
fi
echo "  реестры сверены: правок условий $(echo $W622_NARROWED_COND | wc -w) в new-rules.txt (дата > $W622_ARCHIVE_DATE), акторов ноды $(echo $W622_NODE_ACTORS_REQ | wc -w) в idle-actors.txt"

# Сторож гигиены (память ebpf-guard-measurement-hygiene, п.5): осиротевший
# цикл ожидания от прошлой сессии даёт весь фон замера себе. На прогоне 6.0.F
# два таких поллера дали 1195 совпадений/ч против 7/ч — 170×.
_r622_orph=$(ps -eo pid,ppid,etimes,args 2>/dev/null | awk '$2==1 && $3>300' | grep -cE 'until |while |pgrep ')
echo "  осиротевших фоновых циклов на стенде: $_r622_orph"
if [ "${_r622_orph:-0}" -gt 0 ]; then
    echo "СТОП ДО ПРОГОНА: на стенде $_r622_orph осиротевших циклов ожидания (ppid=1, >300с, until/while/pgrep)."
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
date -u +%FT%TZ > /root/agent-start-6.2.2.txt
date -u +%s    > /root/agent-start-6.2.2.epoch
echo "агент поднят $(cat /root/agent-start-6.2.2.txt) (эпоха $(cat /root/agent-start-6.2.2.epoch)), стор пуст"

# ── Шаг 2. Приборность до пролога: ждать пролог ради неизмеримого прогона
#    незачем (память die-only-for-unmeasurable-run).
sleep 30
if ! journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.2.2.epoch)" --no-pager | grep -q 'k8s enricher active'; then
    echo "СТОП: k8s-энричер не поднялся после рестарта — прогон неизмерим"
    date -u +%FT%TZ > "$DONE_MARK"
    exit 1
fi
echo "k8s-энричер поднят"

# Немота по среде фиксируется здесь же, пока журнал стартовых строк свеж
# (находка №225). Файловая ось (№234/открытый вопрос 7) — рядом с syscall'ной.
journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.2.2.epoch)" --no-pager \
    | grep -E 'no reachable nr in the kernel allowlist|cgroup escape collector unavailable|file rules with an op no hook produces' \
    > /root/env-muteness-6.2.2.txt 2>/dev/null
echo "немота по среде записана: /root/env-muteness-6.2.2.txt ($(wc -l < /root/env-muteness-6.2.2.txt) строк)"

# ── Шаг 3. Пролог. Ключ дрейфа обязан закрыть обучение ДО окна (пункт А). ──
echo "--- пролог ${PROLOGUE}s (обучение дрейфа закрывается: 600 × 2 = 1200 с) ---"
sleep "$PROLOGUE"

# ── Шаг 4. Контроли. ──────────────────────────────────────────────────────
echo "--- контроли волны 6.2.2 ---"
W622_WINDOW="$WINDOW" W622_NS="$NS" W622_ART="$ART" W622_SVC="$SVC" \
W622_CHURN=3 W622_GATE=100 W622_GATE_FORMULA="$GATE_FORMULA" \
W622_PROFILE_SECS="$PROFILE_SECS" W622_SMOKE="$SMOKE" \
W622_VERDICTS="$VERDICTS" \
    bash "$SETUP/wave6.2.2-controls.sh"

# ── Шаг 5. Сборка архива. Кладётся ТОЛЬКО то, что написал этот прогон
#    (находка №228). Ничего не копируется из каталогов прошлых волн.
echo "--- сборка архива ---"
rm -rf "$COLLECT"; mkdir -p "$COLLECT/controls" "$COLLECT/node"
cp -r "$ART" "$COLLECT/controls/artifacts" 2>/dev/null
cp "$VERDICTS" "$COLLECT/controls/" 2>/dev/null
cp /root/agent-start-6.2.2.txt /root/agent-start-6.2.2.epoch /root/env-muteness-6.2.2.txt "$COLLECT/" 2>/dev/null
cp "$SETUP/config-test.yaml" "$SETUP/wave6.2.2-controls.sh" "$SETUP/wave6.2.2-metrics-lib.sh" "$SETUP/run-6.2.2-pipeline.sh" "$COLLECT/" 2>/dev/null

# №240: журнал агента — ЭПОХОЙ, и с проверкой кода возврата, а не тихим `>`.
_j622="$COLLECT/journal-agent-6.2.2.log"
journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.2.2.epoch)" --no-pager > "$_j622" 2>"$COLLECT/journal-agent-6.2.2.err"
_j622_rc=$?
_j622_lines=$(wc -l < "$_j622" 2>/dev/null)
echo "  журнал агента: $_j622_lines строк (код возврата journalctl $_j622_rc)"
[ -s "$COLLECT/journal-agent-6.2.2.err" ] && sed 's/^/    journalctl stderr: /' "$COLLECT/journal-agent-6.2.2.err"

# Критерий 6.2.2.4: непустота И покрытие окна. Сторож живёт В ПАЙПЛАЙНЕ, а не
# в глазах читателя архива через сутки: пустой журнал = прогон объявляет себя
# нереплеиваемым.
W622_REPLAYABLE=1
if [ "${_j622_lines:-0}" -lt 1 ]; then
    echo "  6.2.2.4 ПРОВАЛЕН: journal-agent-6.2.2.log ПУСТ — архив этого прогона НЕРЕПЛЕИВАЕМ (находка №240)"
    W622_REPLAYABLE=0
elif [ -s "$ART/window-epoch.txt" ]; then
    # Файл-мост от контролей: у них эпохи окна есть, у пайплайна их нет
    # (открытый вопрос 14).
    _t0=$(grep '^t0=' "$ART/window-epoch.txt" | cut -d= -f2)
    _t1=$(grep '^t1=' "$ART/window-epoch.txt" | cut -d= -f2)
    _jfirst=$(head -1 "$_j622" | grep -oE '^[A-Za-z]{3} [0-9]{2} [0-9:]{8}' )
    _jfirst_e=$(date -d "$_jfirst" +%s 2>/dev/null)
    _jlast=$(tail -1 "$_j622" | grep -oE '^[A-Za-z]{3} [0-9]{2} [0-9:]{8}' )
    _jlast_e=$(date -d "$_jlast" +%s 2>/dev/null)
    echo "  окно [$_t0, $_t1]; журнал [${_jfirst_e:-?}, ${_jlast_e:-?}]"
    if [ -z "${_jfirst_e:-}" ] || [ -z "${_jlast_e:-}" ]; then
        echo "  6.2.2.4 НЕИЗМЕРИМ: метки времени журнала не разобраны — покрытие окна не проверено"
        W622_REPLAYABLE=0
    elif [ "$_jfirst_e" -le "${_t0:-0}" ] && [ "$_jlast_e" -ge "${_t1:-0}" ]; then
        echo "  6.2.2.4 ДОСТИГНУТО: журнал непуст ($_j622_lines строк) и ПОКРЫВАЕТ окно (первая строка ≤ t0, последняя ≥ t1)"
    else
        echo "  6.2.2.4 ПРОВАЛЕН: журнал непуст, но НЕ покрывает окно [$_t0,$_t1] — производные от него контроли неподтверждаемы"
        W622_REPLAYABLE=0
    fi
else
    echo "  6.2.2.4 НЕИЗМЕРИМ: контроли не оставили $ART/window-epoch.txt — границы окна пайплайну неизвестны"
    W622_REPLAYABLE=0
fi
{
    echo "критерий=6.2.2.4"
    echo "время_UTC=$(date -u +%FT%TZ)"
    echo "журнал_строк=$_j622_lines реплеиваем=$W622_REPLAYABLE"
    echo "---"
} >> "$VERDICTS" 2>/dev/null

kubectl get nodes -o wide > "$COLLECT/node/nodes.txt" 2>/dev/null
kubectl get pods -A -o wide > "$COLLECT/node/pods.txt" 2>/dev/null
kubectl version -o json > "$COLLECT/node/version.json" 2>/dev/null
git -C /opt/ebpf-guard log --oneline -6 > "$COLLECT/git-head.txt" 2>/dev/null
echo "архив: $COLLECT ($(du -sh "$COLLECT" 2>/dev/null | cut -f1))"
echo "  забрать: rsync -az root@<стенд>:$COLLECT/ server-logs/$(basename "$COLLECT")/"
echo "  (размер выше посчитан ДО того, как в архив ляжет сам лог пайплайна — правка №241)"

echo "=== ПРОГОН 6.2.2$([ "$SMOKE" = "1" ] && echo ' (СМОК)') ЗАВЕРШЁН $(date -u +%FT%TZ) ==="
date -u +%FT%TZ > "$DONE_MARK"
# №241: копия лога — БУКВАЛЬНО последним действием, после маркера. Иначе
# архивная копия обрывается на «--- сборка архива ---» и по ней нельзя
# отличить упавший прогон от прошедшего целиком.
[ -f "$OUT" ] && cp "$OUT" "$COLLECT/run-6.2.2.log"
