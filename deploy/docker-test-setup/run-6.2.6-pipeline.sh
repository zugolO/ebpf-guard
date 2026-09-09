#!/bin/bash
# run-6.2.6-pipeline.sh — прогон волны 6.2.6 (долг прогона 6.2.4, находки
# №261…№270). Механический форк run-6.2.4-pipeline.sh. Решает ТОЛЬКО items
# 5 и 6 постановки волны (plan.md, §6.2.6, «Что делает волна 6.2.6»):
#
#   ITEM 5 (№267/№268) — измеритель: живёт в wave6.2.6-controls.sh и
#     wave6.2.6-metrics-lib.sh (три подпункта 6.2.6.1, comm-фильтр 6.2.6.11,
#     новый критерий 6.2.6.15). Этот файл их не трогает, только зовёт форк
#     контролей вместо 6.2.4-версии.
#
#   ITEM 6 (№269/№270) — СТРАЖ ПОЛНОТЫ ПАЙПЛАЙНА, ГЛАВНЫЙ ITEM ВОЛНЫ.
#     wave6.2.6-completeness-guard.sh вызывается ПОСЛЕ контролей и ДО сборки
#     архива (Шаг 4.5 ниже): сверяет таблицу меток постановки со списком
#     меток, реально вынесших вердикт в захваченном логе прогона ($OUT).
#     Расхождение = архив НЕ СОБИРАЕТСЯ (`exit 1` до Шага 5) — три волны
#     подряд (6.2.2→6.2.3→6.2.4) форкались механически, наследовали РАБОЧУЮ
#     механику предыдущей волны и ни разу не проверяли ПОКРЫТИЕ постановки;
#     6.2.4 дала 31 `OK` при четырёх нереализованных критериях и одном,
#     напечатанном под чужим номером (6.2.3.7 вместо 6.2.4.6) — этот страж
#     ловит ровно такую мутацию (см. --self-test самого стража).
#
# ВТОРОЙ ПРОХОД (08.09.2026): items 1…4 доведены до КРИТЕРИЕВ. 6.2.4.5/.6/.7/
# .12, 6.2.6.16, 6.2.6.17 и сводная 6.2.6.14 вжаты в wave6.2.6-controls.sh,
# окно стартов подов (item 3) объявлено третьим именованным окном и пишется
# в window-epoch.txt. Страж 6.2.6.18 теперь проверяет полноту ДВАЖДЫ:
# статически ДО прогона (Шаг 0б — форк без новых критериев падает за секунды,
# а не через час стенда) и по логу ПЕРЕД сборкой архива (Шаг 4.5).
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
    ART="${ART:-/var/lib/w626-smoke-artifacts}"
    OUT="${OUT:-/root/run-6.2.6-smoke.log}"
    COLLECT="${COLLECT:-/root/collect-6.2.6-smoke}"
    DONE_MARK="${DONE_MARK:-/root/PIPELINE-6.2.6-SMOKE-DONE}"
    PROFILE_SECS="${PROFILE_SECS:-5}"
else
    PROLOGUE="${PROLOGUE:-1800}"
    WINDOW="${WINDOW:-600}"
    ART="${ART:-/var/lib/w626-artifacts}"
    OUT="${OUT:-/root/run-6.2.6.log}"
    COLLECT="${COLLECT:-/root/collect-6.2.6}"
    DONE_MARK="${DONE_MARK:-/root/PIPELINE-6.2.6-DONE}"
    PROFILE_SECS="${PROFILE_SECS:-30}"
fi
NS="${NS:-w626}"
GATE_FORMULA="${GATE_FORMULA:-all}"
VERDICTS="${VERDICTS:-/root/wave6.2.6-controls-verdicts.txt}"

echo "=== ПРОГОН 6.2.6$([ "$SMOKE" = "1" ] && echo ' (СМОК)'), старт $(date -u +%FT%TZ) ==="
echo "пролог ${PROLOGUE}s, окно ${WINDOW}s, профиль ${PROFILE_SECS}s, формула гейта $GATE_FORMULA"

# ── Шаг 0. Реестры ДО прогона (пункт Д «Переноса в 6.1…6.4»). ──────────────
# Волна 6.2.6 меняет САМИ УСЛОВИЯ шести правил (исход №253: exceptions
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
# 6.2.6, №253). Правки волн 6.2.1…6.2.3 в реестр не вносятся вновь — они уже
# покрыты своими записями датой ≤ 06.09.2026, и архив collect-6.2.3 снят УЖЕ
# с ними.
W626_NARROWED_COND="sigma_passwd_shadow_read_daemon sensitive_file_read_daemon sigma_log_deletion_daemon sigma_utmp_wtmp_modified_daemon sigma_cpu_info_access mitre_vm_detect_dmi_read"
# Дата архива, который записи обязаны покрывать: collect-6.2.3 снят
# 06.09.2026. Запись с датой <= этой архив НЕ покрывает (run-gate.sh:1459,
# сравнение СТРОГОЕ).
W626_ARCHIVE_DATE=20260906
W626_NODE_ACTORS_REQ="k3s-server coredns containerd containerd-shim iptables local-path-prov runc"
_r624_reg="$SETUP/attacks/new-rules.txt"
_r624_idle="$SETUP/attacks/idle-actors.txt"
_r624_gap=""
for _r in $W626_NARROWED_COND; do
    awk -v r="$_r" -v a="$W626_ARCHIVE_DATE" \
        '!/^[[:space:]]*(#|$)/ && $1 == r && $2 ~ /^[0-9]{8}$/ && $2+0 > a+0 {found=1} END{exit !found}' \
        "$_r624_reg" 2>/dev/null || _r624_gap="$_r624_gap new-rules.txt:$_r"
done
for _a in $W626_NODE_ACTORS_REQ; do
    grep -qE "^${_a}[[:space:]]" "$_r624_idle" 2>/dev/null || _r624_gap="$_r624_gap idle-actors.txt:$_a"
done
if [ -n "$_r624_gap" ]; then
    echo "СТОП ДО ПРОГОНА: реестры не заполнены:$_r624_gap"
    echo "  Реплей архива этой волны встанет ЖЁСТКИМ СТОПОМ №1 без единого регресса продукта"
    echo "  (пункт Д «Переноса в 6.1…6.4»). Прогон не начат — агент не тронут, стор не очищен."
    exit 1
fi
echo "  реестры сверены: правок условий $(echo $W626_NARROWED_COND | wc -w) в new-rules.txt (дата > $W626_ARCHIVE_DATE), акторов ноды $(echo $W626_NODE_ACTORS_REQ | wc -w) в idle-actors.txt"

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

# ── Шаг 0б (ITEM 6, №270). СТАТИЧЕСКАЯ СВЕРКА ПОЛНОТЫ — ДО РЕСТАРТА АГЕНТА.
#    Тот же страж, тот же список меток, но вопрос задаётся ДО прогона: есть
#    ли в тексте пайплайна строка, СПОСОБНАЯ вынести вердикт по каждой метке
#    постановки. Форк, унаследовавший механику предыдущей волны без её новых
#    критериев (ровно №270), падает здесь — а не через час стенда, на сборке
#    архива. Проверка по логу (Шаг 4.5) при этом остаётся: строка в скрипте
#    может и не исполниться, и только лог говорит, что вердикт РЕАЛЬНО вынесен.
echo "--- 6.2.6.18 (статическая сверка полноты, до прогона) ---"
if ! bash "$SETUP/wave6.2.6-completeness-guard.sh" --scan \
        "$SETUP/wave6.2.6-controls.sh" "$SETUP/run-6.2.6-pipeline.sh" "$SETUP/wave6.2.6-metrics-lib.sh"; then
    echo "СТОП ДО ПРОГОНА: пайплайн не покрывает таблицу меток постановки волны 6.2.6 (№269/№270)."
    echo "  Агент не тронут, стор не очищен — прогон не начат."
    exit 1
fi

# ── Шаг 0в. ВХОД ИЗМЕРЕНИЯ СУЩЕСТВУЕТ. Три вещи, каждая из которых, будучи
#    забытой, даёт НЕ провал, а тихую неизмеримость главной части волны — то
#    есть час стенда ради лога, из которого ничего не следует:
#      • exporter.volume_by_source — ось comm у объёма (item 1). Без неё
#        6.2.6.2 не ранжирует по comm, а 6.2.6.22(в) не считает утечку
#        МЕТРИКОЙ (сторовый счёт там запрещён по букве критерия);
#      • rules/anomaly.yaml — синтетическое правило item 4. Без него
#        EvaluateNamedExceptions не находит ruleID, отказ открытый (аномалии
#        не глушатся), но переезд объёма 6.2.6.20 доказывать нечем;
#      • profiler.lineage.enabled — источник родословной для оси предка
#        (item 5). Выключенный, он делает ось молча равной parent_exe_path
#        (открытый вопрос 10(б)): item 5 не делает НИЧЕГО, а в YAML-правилах
#        всё выглядит задеплоенным.
#    Проверка — до рестарта агента: чинить конфиг дешевле, чем прогон.
echo "--- вход измерения (item 1 / item 4 / item 5) ---"
_r626_cfg="${W626_CONFIG:-$SETUP/config-test.yaml}"
# Каталог правил берётся ИЗ КОНФИГА (rules.path), а не из догадки о корне
# репозитория: на стенде агент читает именно его, и проверять наличие
# anomaly.yaml где-то ещё значило бы проверять не тот файл.
_r626_rules=$(awk '/^rules:/{r=1;next} r && /path:/{gsub(/[" ]/,"",$2); print $2; exit} r && /^[a-zA-Z]/{exit}' "$_r626_cfg" 2>/dev/null)
_r626_rules="${_r626_rules:-/opt/ebpf-guard/rules/}"
_r626_in_fail=0
if grep -qE '^[[:space:]]*volume_by_source:[[:space:]]*true' "$_r626_cfg" 2>/dev/null; then
    echo "  OK: exporter.volume_by_source: true — ось {rule_id, comm} будет снята"
else
    echo "  СТОП: exporter.volume_by_source не включён в $_r626_cfg — ось comm (item 1) не появится в /metrics"; _r626_in_fail=1
fi
if [ -s "${_r626_rules%/}/anomaly.yaml" ]; then
    echo "  OK: ${_r626_rules%/}/anomaly.yaml на месте — слой исключений item 4 достижим"
else
    echo "  СТОП: ${_r626_rules%/}/anomaly.yaml отсутствует в каталоге правил из конфига — переезд объёма anomaly_detection (6.2.6.20) доказывать нечем"; _r626_in_fail=1
fi
if awk '/^profiler:/{p=1} p && /lineage:/{l=1} l && /enabled:[[:space:]]*false/{print "off"; exit} l && /^[a-zA-Z]/{exit}' "$_r626_cfg" 2>/dev/null | grep -q off; then
    echo "  СТОП: profiler.lineage.enabled: false — ось предка (item 5) деградирует до parent_exe_path МОЛЧА, и 6.2.6.22(а) даст ноль не потому, что правка не работает"; _r626_in_fail=1
else
    echo "  OK: profiler.lineage не выключен явно — источник родословной для оси предка есть"
fi
if [ "$_r626_in_fail" -ne 0 ]; then
    echo "СТОП ДО ПРОГОНА: вход измерения неполон (см. строки выше). Агент не тронут, стор не очищен."
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
date -u +%FT%TZ > /root/agent-start-6.2.6.txt
date -u +%s    > /root/agent-start-6.2.6.epoch
echo "агент поднят $(cat /root/agent-start-6.2.6.txt) (эпоха $(cat /root/agent-start-6.2.6.epoch)), стор пуст"

# ── Шаг 2. Приборность до пролога: ждать пролог ради неизмеримого прогона
#    незачем (память die-only-for-unmeasurable-run).
sleep 30
if ! journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.2.6.epoch)" --no-pager | grep -q 'k8s enricher active'; then
    echo "СТОП: k8s-энричер не поднялся после рестарта — прогон неизмерим"
    date -u +%FT%TZ > "$DONE_MARK"
    exit 1
fi
echo "k8s-энричер поднят"

# Немота по среде фиксируется здесь же, пока журнал стартовых строк свеж
# (находка №225). Файловая ось (№234/открытый вопрос 7) — рядом с syscall'ной.
journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.2.6.epoch)" --no-pager \
    | grep -E 'no reachable nr in the kernel allowlist|cgroup escape collector unavailable|file rules whose op condition names no operation any hook produces' \
    > /root/env-muteness-6.2.6.txt 2>/dev/null
echo "немота по среде записана: /root/env-muteness-6.2.6.txt ($(wc -l < /root/env-muteness-6.2.6.txt) строк)"

# ── Шаг 2б (№257, item 6 постановки 6.2.6). Снимок метрик СРАЗУ после
#    старта агента — ДО 1800-секундного пролога, а не на границе t0
#    контролей. Без этого снимка сторож потерь 6.2.3.0/6.2.6.0 видит только
#    отрезок [t0,t1] и молчит о том, что накопилось за сам пролог: архив
#    collect-6.2.3 потерял 1336 файловых событий именно там, и никакой
#    вердикт этого не отразил (находка №257). Пишется ВНЕ $ART — контроли
#    очищают и пересоздают $ART при старте (находка №228) и стёрли бы файл,
#    попади он туда раньше их запуска.
_r624_api="${VPS_IP:+http://${VPS_IP}:19090}"; _r624_api="${_r624_api:-http://localhost:19090}"
_r624_token="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
if curl -s --max-time 30 -H "Authorization: Bearer $_r624_token" "$_r624_api/metrics" > /root/metrics-prologue-start-6.2.6.txt 2>/dev/null \
    && [ -s /root/metrics-prologue-start-6.2.6.txt ]; then
    echo "снимок метрик пролога записан: /root/metrics-prologue-start-6.2.6.txt ($(wc -l < /root/metrics-prologue-start-6.2.6.txt) строк)"
else
    echo "СНИМОК ПРОЛОГА НЕ ВЗЯТ: /root/metrics-prologue-start-6.2.6.txt пуст или недоступен — 6.2.6.A напечатает дельту пролога как НЕИЗМЕРИМУЮ, не как ноль"
    rm -f /root/metrics-prologue-start-6.2.6.txt
fi

# ── Шаг 3. Пролог. Ключ дрейфа обязан закрыть обучение ДО окна (пункт А). ──
echo "--- пролог ${PROLOGUE}s (обучение дрейфа закрывается: 600 × 2 = 1200 с) ---"
sleep "$PROLOGUE"

# ── Шаг 4. Контроли. ──────────────────────────────────────────────────────
echo "--- контроли волны 6.2.6 ---"
W626_WINDOW="$WINDOW" W626_NS="$NS" W626_ART="$ART" W626_SVC="$SVC" \
W626_CHURN=3 W626_GATE=100 W626_GATE_FORMULA="$GATE_FORMULA" \
W626_PROFILE_SECS="$PROFILE_SECS" W626_SMOKE="$SMOKE" \
W626_VERDICTS="$VERDICTS" \
W626_PROLOGUE_METRICS="/root/metrics-prologue-start-6.2.6.txt" \
    bash "$SETUP/wave6.2.6-controls.sh"

# ── Шаг 4.4 (правка 08.09.2026, дефект порядка). ЖУРНАЛ И ВЕРДИКТ 6.2.6.4 —
#    ДО СТРАЖА ПОЛНОТЫ, а не внутри сборки архива.
#
#    Форк унаследовал из 6.2.4 порядок «страж → сборка архива», а вердикт
#    6.2.6.4 (реплеиваемость) печатался ВНУТРИ сборки, то есть ПОСЛЕ стража.
#    Страж читает лог прогона и ищет в нём вердиктную строку каждой метки —
#    значит на ЛЮБОМ живом прогоне 6.2.6.4 не нашлась бы и архив не собрался
#    бы никогда (а внутри сборки вердикт всё равно бы не напечатался, потому
#    что до неё дело не дошло). Синтетические фикстуры --self-test стража
#    этого не показывали: в них строка 6.2.6.4 присутствует заранее. Журнал
#    снимается сюда, в /root, и копируется в архив на Шаге 5 уже готовым.
# №240: журнал агента — ЭПОХОЙ, и с проверкой кода возврата, а не тихим `>`.
_j623="/root/journal-agent-6.2.6.log"
journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.2.6.epoch)" --no-pager > "$_j623" 2>/root/journal-agent-6.2.6.err
_j623_rc=$?
_j623_lines=$(wc -l < "$_j623" 2>/dev/null)
echo "  журнал агента: $_j623_lines строк (код возврата journalctl $_j623_rc)"
[ -s /root/journal-agent-6.2.6.err ] && sed 's/^/    journalctl stderr: /' /root/journal-agent-6.2.6.err

# Критерий 6.2.6.4: непустота И покрытие окна. Сторож живёт В ПАЙПЛАЙНЕ, а не
# в глазах читателя архива через сутки: пустой журнал = прогон объявляет себя
# нереплеиваемым.
W626_REPLAYABLE=1
if [ "${_j623_lines:-0}" -lt 1 ]; then
    echo "  6.2.6.4 ПРОВАЛЕН: journal-agent-6.2.6.log ПУСТ — архив этого прогона НЕРЕПЛЕИВАЕМ (находка №240)"
    W626_REPLAYABLE=0
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
        echo "  6.2.6.4 НЕИЗМЕРИМ: метки времени журнала не разобраны — покрытие окна не проверено"
        W626_REPLAYABLE=0
    elif [ "$_jfirst_e" -le "${_t0:-0}" ] && [ "$_jlast_e" -ge "${_t1:-0}" ]; then
        echo "  6.2.6.4 ДОСТИГНУТО: журнал непуст ($_j623_lines строк) и ПОКРЫВАЕТ окно (первая строка ≤ t0, последняя ≥ t1)"
    else
        echo "  6.2.6.4 ПРОВАЛЕН: журнал непуст, но НЕ покрывает окно [$_t0,$_t1] — производные от него контроли неподтверждаемы"
        W626_REPLAYABLE=0
    fi
else
    echo "  6.2.6.4 НЕИЗМЕРИМ: контроли не оставили $ART/window-epoch.txt — границы окна пайплайну неизвестны"
    W626_REPLAYABLE=0
fi
{
    echo "критерий=6.2.6.4"
    echo "время_UTC=$(date -u +%FT%TZ)"
    echo "журнал_строк=$_j623_lines реплеиваем=$W626_REPLAYABLE"
    echo "---"
} >> "$VERDICTS" 2>/dev/null


# ── Шаг 4.5 (ITEM 6, №269/№270). СТРАЖ ПОЛНОТЫ ПАЙПЛАЙНА — ПЕРЕД СБОРКОЙ
#    АРХИВА, а не после и не как предупреждение. Три волны подряд
#    (6.2.2→6.2.3→6.2.4) форкались механически, наследовали работающую
#    механику предыдущей волны и НИКОГДА не проверяли, что новые критерии
#    постановки реально вжиты — 6.2.4 дала 31 `OK`, хотя четыре критерия не
#    были реализованы вовсе, а один печатался под чужим номером. Сторож
#    читает захваченный лог прогона ($OUT — этот же файл, вызывающая сторона
#    обязана перенаправить в него stdout всего пайплайна) и сверяет его со
#    своей константной таблицей меток постановки волны 6.2.6. Расхождение
#    прерывает пайплайн ДО Шага 5: архив, который не измеряет то, ради чего
#    запущен, не должен выглядеть как собранный архив.
echo "--- 6.2.6.18: страж полноты пайплайна (item 6) ---"
if ! bash "$SETUP/wave6.2.6-completeness-guard.sh" --check "$OUT"; then
    echo "=== ПРОГОН 6.2.6 ОСТАНОВЛЕН: 6.2.6.18 ОТКАЗАЛСЯ СОБРАТЬ АРХИВ (расхождение таблицы меток постановки со списком вынесенных вердиктов, №269/№270) ==="
    {
        echo "критерий=6.2.6.18"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: расхождение таблицы меток постановки со списком вынесенных вердиктов — см. вывод стража выше в $OUT"
        echo "---"
    } >> "$VERDICTS" 2>/dev/null
    exit 1
fi

# ── Шаг 5. Сборка архива. Кладётся ТОЛЬКО то, что написал этот прогон
#    (находка №228). Ничего не копируется из каталогов прошлых волн.
echo "--- сборка архива ---"
rm -rf "$COLLECT"; mkdir -p "$COLLECT/controls" "$COLLECT/node"
cp -r "$ART" "$COLLECT/controls/artifacts" 2>/dev/null
cp "$VERDICTS" "$COLLECT/controls/" 2>/dev/null
cp /root/agent-start-6.2.6.txt /root/agent-start-6.2.6.epoch /root/env-muteness-6.2.6.txt "$COLLECT/" 2>/dev/null
cp /root/metrics-prologue-start-6.2.6.txt "$COLLECT/" 2>/dev/null
cp "$SETUP/config-test.yaml" "$SETUP/wave6.2.6-controls.sh" "$SETUP/wave6.2.6-metrics-lib.sh" "$SETUP/wave6.2.6-completeness-guard.sh" "$SETUP/run-6.2.6-pipeline.sh" "$COLLECT/" 2>/dev/null

cp /root/journal-agent-6.2.6.log "$COLLECT/journal-agent-6.2.6.log" 2>/dev/null
[ -s /root/journal-agent-6.2.6.err ] && cp /root/journal-agent-6.2.6.err "$COLLECT/journal-agent-6.2.6.err" 2>/dev/null

kubectl get nodes -o wide > "$COLLECT/node/nodes.txt" 2>/dev/null
kubectl get pods -A -o wide > "$COLLECT/node/pods.txt" 2>/dev/null
kubectl version -o json > "$COLLECT/node/version.json" 2>/dev/null
git -C /opt/ebpf-guard log --oneline -6 > "$COLLECT/git-head.txt" 2>/dev/null
echo "архив: $COLLECT ($(du -sh "$COLLECT" 2>/dev/null | cut -f1))"
echo "  забрать: rsync -az root@<стенд>:$COLLECT/ server-logs/$(basename "$COLLECT")/"
echo "  (размер выше посчитан ДО того, как в архив ляжет сам лог пайплайна — правка №241)"

echo "=== ПРОГОН 6.2.6$([ "$SMOKE" = "1" ] && echo ' (СМОК)') ЗАВЕРШЁН $(date -u +%FT%TZ) ==="
date -u +%FT%TZ > "$DONE_MARK"
# №241: копия лога — БУКВАЛЬНО последним действием, после маркера. Иначе
# архивная копия обрывается на «--- сборка архива ---» и по ней нельзя
# отличить упавший прогон от прошедшего целиком.
[ -f "$OUT" ] && cp "$OUT" "$COLLECT/run-6.2.6.log"
