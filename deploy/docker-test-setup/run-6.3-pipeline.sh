#!/bin/bash
# run-6.3-pipeline.sh — прогон волны 6.3 (DNS-коллектор, находки №326…№329).
# Форк run-6.2.6-pipeline.sh. Заводится ФАЗОЙ 1: фаза 0 (items 1…8) закрыта
# офлайн 15.09.2026, и её единственный живой заход (item 7) гонял
# wave6.3-controls.sh НАПРЯМУЮ, без обёртки — отчего две вещи были
# недостижимы по построению:
#
#   • 6.2.6.A (пролог > learning_period × enforce_deadline_periods И ноль
#     потерь за пролог) — обе половины требуют пролога и снимка метрик ДО
#     него, то есть именно того, что делает пайплайн, а не контроли;
#   • страж полноты (6.3.8) — реестр вынесенных меток писался, но никто его
#     не сверял с таблицей постановки.
#
# ЧТО ДОБАВЛЕНО ОТНОСИТЕЛЬНО 6.2.6-ВЕРСИИ (не механический форк):
#
#   Шаг 0    — реестр сужений волны 6.3: ОДИННАДЦАТЬ правил, чьи УСЛОВИЯ
#              изменила находка №329 (item 8), обязаны стоять в new-rules.txt
#              датой моложе архива, иначе реплей объявит их потерями.
#   Шаг 0в   — вход измерения переписан под 6.3: включённый DNS-коллектор,
#              манифест rule_id без дрейфа и — главное — СВЕРКА БИНАРЯ С
#              ПРАВИЛАМИ (см. ниже).
#   Шаг 2    — приборность DNS: коллектор поднялся, бэкфилл сокетов (item 5)
#              отработал и напечатал свою метрику.
#
# ПОЧЕМУ СВЕРКА БИНАРЯ С ПРАВИЛАМИ — ОТДЕЛЬНЫЙ ШАГ. Правки item 8 завели ДВА
# НОВЫХ ПОЛЯ УСЛОВИЙ (qname_max_label_entropy, qname_max_label_len), которых
# нет в старом бинаре, а загрузка правил в ebpf-guard — ВСЁ ИЛИ НИЧЕГО:
# неизвестное поле в одном правиле роняет валидацию ВСЕГО набора
# (rule_loader.go: LoadRulesFromFile → ошибка → LoadRulesFromDir прерывается).
# Выкат `rules/` без пересборки бинаря даёт агента С НУЛЁМ ПРАВИЛ, и прогон
# напечатает не «шум упал», а приборный ноль по каждой метке разом — час
# стенда за лог, из которого ничего не следует. Проверяется ТЕМ ЖЕ бинарём,
# который будет запущен (`ebpf-guard rules --config …` использует ровно тот
# же загрузчик), и ДО остановки работающего агента.
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
    ART="${ART:-/var/lib/w63-smoke-artifacts}"
    OUT="${OUT:-/root/run-6.3-smoke.log}"
    COLLECT="${COLLECT:-/root/collect-6.3-smoke}"
    DONE_MARK="${DONE_MARK:-/root/PIPELINE-6.3-SMOKE-DONE}"
    PROFILE_SECS="${PROFILE_SECS:-5}"
else
    PROLOGUE="${PROLOGUE:-1800}"
    WINDOW="${WINDOW:-600}"
    ART="${ART:-/var/lib/w63-artifacts}"
    OUT="${OUT:-/root/run-6.3.log}"
    COLLECT="${COLLECT:-/root/collect-6.3}"
    DONE_MARK="${DONE_MARK:-/root/PIPELINE-6.3-DONE}"
    PROFILE_SECS="${PROFILE_SECS:-30}"
fi
NS="${NS:-w63}"
GATE_FORMULA="${GATE_FORMULA:-all}"
VERDICTS="${VERDICTS:-/root/wave6.3-controls-verdicts.txt}"

# ── ЛОГ ПРОГОНА ЗАХВАТЫВАЕТ САМ ПАЙПЛАЙН (правка 09.09.2026, найдена смоком).
#
# Шаг 4.5 кормит страж полноты файлом $OUT — «полным stdout controls.sh +
# пайплайна». Но НИКТО этот файл не создавал: он появлялся, только если
# оператор вручную завернул запуск в `| tee $OUT`. Запуск обычным способом
# (`nohup … >/dev/null &`) давал пустой $OUT, страж — «НЕИЗМЕРИМ: лог прогона
# пуст», и АРХИВ ОТКАЗЫВАЛСЯ СОБИРАТЬСЯ после целого прогона — при том что все
# 24 метки вердикт вынесли. То есть требование к запуску жило в голове
# оператора, а цена ошибки была в час стенда. Теперь пайплайн перезапускает
# сам себя под `tee`: $OUT существует всегда и содержит ровно то, что страж и
# должен читать. Флаг-страж от бесконечной рекурсии — W63_LOG_CAPTURED.
if [ -z "${W63_LOG_CAPTURED:-}" ]; then
    export W63_LOG_CAPTURED=1
    mkdir -p "$(dirname "$OUT")" 2>/dev/null
    # `tee` в конце конвейера, поэтому $? принадлежит ему, а не пайплайну —
    # настоящий код возврата проносится через файл. Имя файла своё на запуск:
    # фиксированное имя столкнуло бы два одновременных прогона (боевой и смок
    # на одном стенде — обычная пара) и вернуло бы чужой код.
    _w63_rcf=$(mktemp /tmp/.w626-rc.XXXXXX)
    { bash "$0" "$@" 2>&1; echo "$?" > "$_w63_rcf"; } | tee "$OUT"
    _w63_rc=$(cat "$_w63_rcf" 2>/dev/null || echo 1)
    rm -f "$_w63_rcf"
    exit "${_w63_rc:-1}"
fi

echo "=== ПРОГОН 6.3$([ "$SMOKE" = "1" ] && echo ' (СМОК)'), старт $(date -u +%FT%TZ) ==="
echo "пролог ${PROLOGUE}s, окно ${WINDOW}s, профиль ${PROFILE_SECS}s, формула гейта $GATE_FORMULA"

# ── Шаг 0. Реестры ДО прогона (пункт Д «Переноса в 6.1…6.4»). ──────────────
# Волна 6.3 меняет САМИ УСЛОВИЯ ОДИННАДЦАТИ правил (находка №329, item 8):
# семь энтропийных переведены с qname_entropy (Шеннон по СКЛЕЙКЕ всех меток
# кроме TLD) на конъюнкцию qname_max_label_entropy И qname_dga_score, четыре
# «длинных» — с длины всего имени на длину самой длинной МЕТКИ.
# Правило с изменённым условием на архивах СТАРШЕ правки читается реплеем
# как потеря — механика new-rules.txt рассчитана ровно на это (память
# new-rule-breaks-replays); renamed-rules.txt дал бы ПРЕФЛАЙТ FAIL №170 (id
# не менялся ни у одного), silent-rules.txt утверждал бы, что стенд не
# воспроизводит сценарий, — а он его воспроизводит (положительный контроль
# 6.3.1 обязан поднимать эти правила и после правки).
echo "--- реестры до прогона ---"
for f in idle-actors.txt new-rules.txt renamed-rules.txt silent-rules.txt; do
    _r63_found=0
    for d in "$SETUP/attacks" "$SETUP/scripts" "$SETUP" /opt/ebpf-guard/scripts; do
        if [ -f "$d/$f" ]; then
            echo "  $d/$f: $(wc -l < "$d/$f") строк"
            _r63_found=1
            break
        fi
    done
    [ "$_r63_found" -eq 1 ] || echo "  СТОП-КАНДИДАТ: $f не найден"
done
# Одиннадцать правил с ИЗМЕНЁННЫМ УСЛОВИЕМ этой волны (item 8, №329).
# Правки прошлых волн в реестр не вносятся вновь — они покрыты своими
# записями датой ≤ 14.09.2026.
W63_NARROWED_COND="dns_dga_high_entropy netintr_dns_high_entropy_query webshell_dns_high_entropy supply_chain_pkg_dga_dns exfil_dns_high_query_rate exfil_dns_high_entropy_txt exfil_dns_deep_subdomain dns_tunneling_long_domain exfil_dns_txt_long_label webshell_dns_exfil_long_subdomain netintr_dns_long_label"
# Дата архива, который записи обязаны покрывать. Записи №329 стоят датой
# 20260915, сравнение в run-gate.sh СТРОГОЕ (`d < $2`), поэтому покрыты
# архивы по 14.09.2026 включительно — сюда и поставлено.
#
# ГРАНИЧНЫЙ СЛУЧАЙ, названный явно: collect-6.2.9.F.3 снят 15.09.2026, то
# есть В ТОТ ЖЕ ДЕНЬ, и записями НЕ покрывается. Это безопасно не по
# счастливой случайности, а по измеренному факту находки №326: доля DNS в
# объёме всех четырнадцати окон куста 6.2.x — НОЛЬ алертов (и в
# alerts_filtered_total, и в срезе лимитера). Терять на этом архиве нечего:
# правила там не срабатывали и до сужения. Три правила «длинной» семьи,
# которые РЕАЛЬНО срабатывали, жили в архивах 2.9.2…2.9.7 (август) — те
# покрыты записями с запасом в месяц.
W63_ARCHIVE_DATE=20260914
W63_NODE_ACTORS_REQ="k3s-server coredns containerd containerd-shim iptables local-path-prov runc"
_r63_reg="$SETUP/attacks/new-rules.txt"
_r63_idle="$SETUP/attacks/idle-actors.txt"
_r63_gap=""
for _r in $W63_NARROWED_COND; do
    awk -v r="$_r" -v a="$W63_ARCHIVE_DATE" \
        '!/^[[:space:]]*(#|$)/ && $1 == r && $2 ~ /^[0-9]{8}$/ && $2+0 > a+0 {found=1} END{exit !found}' \
        "$_r63_reg" 2>/dev/null || _r63_gap="$_r63_gap new-rules.txt:$_r"
done
for _a in $W63_NODE_ACTORS_REQ; do
    grep -qE "^${_a}[[:space:]]" "$_r63_idle" 2>/dev/null || _r63_gap="$_r63_gap idle-actors.txt:$_a"
done
if [ -n "$_r63_gap" ]; then
    echo "СТОП ДО ПРОГОНА: реестры не заполнены:$_r63_gap"
    echo "  Реплей архива этой волны встанет ЖЁСТКИМ СТОПОМ №1 без единого регресса продукта"
    echo "  (пункт Д «Переноса в 6.1…6.4»). Прогон не начат — агент не тронут, стор не очищен."
    exit 1
fi
echo "  реестры сверены: правок условий $(echo $W63_NARROWED_COND | wc -w) в new-rules.txt (дата > $W63_ARCHIVE_DATE), акторов ноды $(echo $W63_NODE_ACTORS_REQ | wc -w) в idle-actors.txt"

# Сторож гигиены (память ebpf-guard-measurement-hygiene, п.5): осиротевший
# цикл ожидания от прошлой сессии даёт весь фон замера себе. На прогоне 6.0.F
# два таких поллера дали 1195 совпадений/ч против 7/ч — 170×.
_r63_orph=$(ps -eo pid,ppid,etimes,args 2>/dev/null | awk '$2==1 && $3>300' | grep -cE 'until |while |pgrep ')
echo "  осиротевших фоновых циклов на стенде: $_r63_orph"
if [ "${_r63_orph:-0}" -gt 0 ]; then
    echo "СТОП ДО ПРОГОНА: на стенде $_r63_orph осиротевших циклов ожидания (ppid=1, >300с, until/while/pgrep)."
    ps -eo pid,ppid,etimes,args 2>/dev/null | awk '$2==1 && $3>300' | grep -E 'until |while |pgrep ' | sed 's/^/    /'
    echo "  Весь фон окна будет ИХ фоном, а не фоном ноды. Снять и перезапустить."
    exit 1
fi

# ── Шаг 0а (решение владельца 15.09.2026, item 8(б)). A/B ВОЗВРАЩАЕТ ПРОЛОГ.
#    6.2.6.A принят НЕПРИМЕНИМЫМ к волне 6.3 условно: пока A/B выключен, волна
#    нового дрейф-пути не вводит. Но DNS-события доходят до профилировщика
#    (engine.go, ad.ProcessEvent на общем пути ingest; eventTypeSamplingKey
#    знает "dns"), то есть тумблер dns.enabled в 6.3.4/6.3.5 двигает ТУ ЖЕ
#    базу дрейфа — и окно B, снятое без пролога, померяет ОБУЧЕНИЕ, а не
#    базовую линию (пункт А «Переноса в 6.1…6.4», пришедший с другой стороны).
#    Условие проверяется здесь, а не в контролях: контроли видят пролог уже
#    состоявшимся и не могут его потребовать.
if [ "${AB_ENABLED:-0}" = "1" ] && [ "$SMOKE" != "1" ] && [ "${PROLOGUE:-0}" -lt 1200 ]; then
    echo "СТОП ДО ПРОГОНА: AB_ENABLED=1 при прологе ${PROLOGUE}s < 1200s."
    echo "  Включение A/B (6.3.4/6.3.5) перезапускает агента с другим составом коллекторов и"
    echo "  тем самым возвращает требование 6.2.6.A: пролог обязан быть длиннее"
    echo "  learning_period × enforce_deadline_periods, иначе окно B меряет обучение базы дрейфа."
    echo "  Решение владельца 15.09.2026 (item 8(б)). Агент не тронут, стор не очищен."
    exit 1
fi

# ── Шаг 0б (ITEM 6, №270). СТАТИЧЕСКАЯ СВЕРКА ПОЛНОТЫ — ДО РЕСТАРТА АГЕНТА.
#    Тот же страж, тот же список меток, но вопрос задаётся ДО прогона: есть
#    ли в тексте пайплайна строка, СПОСОБНАЯ вынести вердикт по каждой метке
#    постановки. Форк, унаследовавший механику предыдущей волны без её новых
#    критериев (ровно №270), падает здесь — а не через час стенда, на сборке
#    архива. Проверка по логу (Шаг 4.5) при этом остаётся: строка в скрипте
#    может и не исполниться, и только лог говорит, что вердикт РЕАЛЬНО вынесен.
echo "--- 6.3.8 (статическая сверка полноты, до прогона) ---"
if ! bash "$SETUP/wave6.3-completeness-guard.sh" --scan \
        "$SETUP/wave6.3-controls.sh" "$SETUP/run-6.3-pipeline.sh" "$SETUP/wave6.3-metrics-lib.sh"; then
    echo "СТОП ДО ПРОГОНА: пайплайн не покрывает таблицу меток постановки волны 6.3 (№269/№270)."
    echo "  Агент не тронут, стор не очищен — прогон не начат."
    exit 1
fi

# ── Шаг 0в. ВХОД ИЗМЕРЕНИЯ СУЩЕСТВУЕТ. Четыре вещи, каждая из которых,
#    будучи забытой, даёт НЕ провал, а тихую неизмеримость главной части
#    волны — то есть час стенда ради лога, из которого ничего не следует.
#    Проверка — ДО остановки работающего агента: чинить конфиг и пересобирать
#    бинарь дешевле, чем прогон.
echo "--- вход измерения волны 6.3 ---"
_r63_cfg="${W63_CONFIG:-$SETUP/config-test.yaml}"
# Каталог правил берётся ИЗ КОНФИГА (rules.path), а не из догадки о корне
# репозитория: на стенде агент читает именно его, и проверять что-то в другом
# каталоге значило бы проверять не тот файл.
_r63_rules=$(awk '/^rules:/{r=1;next} r && /path:/{gsub(/[" ]/,"",$2); print $2; exit} r && /^[a-zA-Z]/{exit}' "$_r63_cfg" 2>/dev/null)
_r63_rules="${_r63_rules:-/opt/ebpf-guard/rules/}"
_r63_in_fail=0

# (1) DNS-коллектор включён. Без него ВСЯ волна — приборный ноль: 6.3.0
#     (видимость), 6.3.1/6.3.2 (контроли детекта), 6.3.3 (объём) читают один
#     и тот же поток событий.
# ВНИМАНИЕ к форме awk (поймано офлайн-прогоном преflight'а 15.09.2026).
# Унаследованная форма `c && /dns:/{d=1} d && /enabled: false/` НЕ СБРАСЫВАЕТ
# d при выходе из блока dns, поэтому на живом config-test.yaml она читала
# `enabled: false` СОСЕДНЕГО блока tls и давала ЛОЖНЫЙ СТОП при включённом
# DNS. Здесь флаг переставляется на КАЖДОМ ключе второго уровня, то есть
# принадлежность строки блоку проверяется, а не предполагается.
if awk '
    /^collectors:/{c=1; next}
    c && /^[A-Za-z#]/{exit}
    c && /^[[:space:]]{2}[a-z_]+:[[:space:]]*$/ { d = ($1 == "dns:") ? 1 : 0; next }
    c && d && /enabled:[[:space:]]*false/ { print "off"; exit }' "$_r63_cfg" 2>/dev/null | grep -q off; then
    echo "  СТОП: collectors.dns.enabled: false в $_r63_cfg — вся волна 6.3 измеряет пустоту"; _r63_in_fail=1
else
    echo "  OK: collectors.dns не выключен явно — поток DNS-событий будет"
fi

# (2) Манифест rule_id (item 1) на месте и без дрейфа. 6.3.3 фильтрует им
#     объём окна; разошедшийся с rules/ манифест даёт величину не про DNS.
if [ -s "$SETUP/attacks/dns-rule-ids.txt" ] && [ -x "$SETUP/generate-dns-rule-manifest.sh" ]; then
    if (cd "$SETUP" && ./generate-dns-rule-manifest.sh --check >/dev/null 2>&1); then
        echo "  OK: манифест DNS ($(grep -cvE '^[[:space:]]*(#|$)' "$SETUP/attacks/dns-rule-ids.txt") rule_id) совпал с rules/*.yaml"
    else
        echo "  СТОП: манифест dns-rule-ids.txt разошёлся с rules/*.yaml — 6.3.3 отфильтрует объём не по тем правилам"; _r63_in_fail=1
    fi
else
    echo "  СТОП: манифест dns-rule-ids.txt или generate-dns-rule-manifest.sh отсутствуют (item 1) — фильтровать объём нечем"; _r63_in_fail=1
fi

# (3) БИНАРЬ И ПРАВИЛА ОДНОГО ПОКОЛЕНИЯ — главный преflight фазы 1.
#     Находка №329 (item 8) завела два НОВЫХ поля условий
#     (qname_max_label_entropy, qname_max_label_len). Загрузка правил —
#     ВСЁ ИЛИ НИЧЕГО: неизвестное поле в ОДНОМ правиле роняет валидацию ВСЕГО
#     набора, и агент поднимается с НУЛЁМ правил. Такой прогон не провалится
#     — он напечатает ноль по каждой метке, и ноль будет приборным.
#     Проверяется ТЕМ ЖЕ загрузчиком, который поднимет агента: подкоманда
#     `rules` зовёт loadRulesWithTuning на rules.path из конфига.
_r63_bin="${W63_BIN:-/opt/ebpf-guard/build/ebpf-guard}"
if [ ! -x "$_r63_bin" ]; then
    echo "  СТОП: бинарь $_r63_bin не найден или не исполняем — сверить его с правилами нечем"; _r63_in_fail=1
else
    _r63_rules_out=$("$_r63_bin" rules --config "$_r63_cfg" 2>&1)
    _r63_rules_n=$(printf '%s' "$_r63_rules_out" | grep -oE '^loaded [0-9]+ rules' | grep -oE '[0-9]+' | head -1)
    if [ -z "${_r63_rules_n:-}" ] || [ "${_r63_rules_n:-0}" -lt 1 ]; then
        echo "  СТОП: $_r63_bin НЕ ЗАГРУЖАЕТ правила из $_r63_rules:"
        printf '%s\n' "$_r63_rules_out" | tail -5 | sed 's/^/      /'
        # Причина НЕ утверждается, пока не предъявлена: сообщение про «старый
        # бинарь» печатается только если ошибка и вправду про валидацию поля.
        # Иначе (нечитаемый конфиг, пустой каталог, права) диагноз был бы
        # утверждением того, чего сторож не установил, — ровно тот класс, что
        # эта волна ловит у критериев.
        if printf '%s' "$_r63_rules_out" | grep -qE 'invalid field name|rule set validation failed'; then
            echo "      ПРИЧИНА ПРЕДЪЯВЛЕНА: загрузчик отверг ПОЛЕ условия. Почти наверняка правила выкачены"
            echo "      БЕЗ пересборки бинаря — поля qname_max_label_entropy/qname_max_label_len появились"
            echo "      правкой №329 (item 8). Пересобрать (make build) и повторить."
        else
            echo "      ПРИЧИНА НЕ ПРЕДЪЯВЛЕНА: ошибка не про валидацию поля (см. вывод выше) — разбирать по ней,"
            echo "      а не по гипотезе о старом бинаре."
        fi
        _r63_in_fail=1
    else
        # Ноль правил — не единственная форма расхождения: старый бинарь мог
        # бы (в другой волне) принять набор и молча не знать поля. Поэтому
        # рядом с количеством проверяется, что ИМЕННО новые поля живы: правило
        # манифеста с новым полем обязано быть в списке загруженных.
        if grep -q 'qname_max_label_entropy\|qname_max_label_len' "${_r63_rules%/}"/*.yaml 2>/dev/null; then
            if printf '%s' "$_r63_rules_out" | grep -q 'dns_dga_high_entropy'; then
                echo "  OK: бинарь и правила одного поколения — загружено $_r63_rules_n правил, dns_dga_high_entropy среди них (новые поля №329 приняты загрузчиком)"
            else
                echo "  СТОП: загружено $_r63_rules_n правил, но dns_dga_high_entropy среди них НЕТ — набор не тот, что правил item 8"; _r63_in_fail=1
            fi
        else
            echo "  СТОП: в каталоге правил $_r63_rules НЕТ полей №329 — на стенде лежат правила ДО правки item 8, а измерять волна собирается её"; _r63_in_fail=1
        fi
    fi
fi

# (4) Родословная не выключена: ось предка кормит атрибуцию по дереву
#     (6.2.9.F.3), без неё величина окна не делится на ноду и измеритель.
# Та же поправка, что у блока dns выше: флаг принадлежности сбрасывается на
# каждом ключе второго уровня, иначе `enabled: false` любого последующего
# подблока profiler читается как выключенная родословная.
if awk '
    /^profiler:/{p=1; next}
    p && /^[A-Za-z#]/{exit}
    p && /^[[:space:]]{2}[a-z_]+:[[:space:]]*$/ { l = ($1 == "lineage:") ? 1 : 0; next }
    p && l && /enabled:[[:space:]]*false/ { print "off"; exit }' "$_r63_cfg" 2>/dev/null | grep -q off; then
    echo "  СТОП: profiler.lineage.enabled: false — атрибуция по дереву (6.2.9.F.3) недостижима, доля измерителя не считается"; _r63_in_fail=1
else
    echo "  OK: profiler.lineage не выключен явно — источник родословной есть"
fi

if [ "$_r63_in_fail" -ne 0 ]; then
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
date -u +%FT%TZ > /root/agent-start-6.3.txt
date -u +%s    > /root/agent-start-6.3.epoch
echo "агент поднят $(cat /root/agent-start-6.3.txt) (эпоха $(cat /root/agent-start-6.3.epoch)), стор пуст"

# ── Шаг 2. Приборность до пролога: ждать пролог ради неизмеримого прогона
#    незачем (память die-only-for-unmeasurable-run).
sleep 30
if ! journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.3.epoch)" --no-pager | grep -q 'k8s enricher active'; then
    echo "СТОП: k8s-энричер не поднялся после рестарта — прогон неизмерим"
    date -u +%FT%TZ > "$DONE_MARK"
    exit 1
fi
echo "k8s-энричер поднят"

# Приборность DNS (item 5). Коллектор мог подняться и остаться слепым:
# dns_socket_map наполняется из trace_connect, а coredns держит upstream-
# сокеты, connect()-нутые ДО старта агента. Бэкфилл из /proc/net/udp чинит
# именно это, и его метрика — свидетельство того, что механизм РАБОТАЛ
# (ноль законен, если на старте не было ни одного уже-подключённого сокета;
# отличие от «механизм не запускался» — память
# positive-control-needs-result-sentinel).
if journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.3.epoch)" --no-pager | grep -q 'dns: starting collector'; then
    echo "DNS-коллектор поднят"
else
    echo "СТОП: DNS-коллектор не стартовал после рестарта — вся волна 6.3 измеряла бы пустоту"
    date -u +%FT%TZ > "$DONE_MARK"
    exit 1
fi
_r63_bf=$(curl -s --max-time 30 -H "Authorization: Bearer ${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}" \
    "${VPS_IP:+http://${VPS_IP}:19090}${VPS_IP:-http://localhost:19090}/metrics" 2>/dev/null \
    | awk '$1=="ebpf_guard_dns_socket_map_backfilled_total"{print $2+0; exit}')
if [ -z "${_r63_bf:-}" ]; then
    echo "  бэкфилл сокетов (item 5): МЕТРИКА НЕ НАЙДЕНА — на стенде бинарь без правки item 5 либо экспортёр её не публикует; слепота coredns этим прогоном не снята"
else
    echo "  бэкфилл сокетов (item 5): $_r63_bf сокетов внесено в dns_socket_map (ноль законен — значит на старте не было уже-подключённых сокетов)"
fi

# Немота по среде фиксируется здесь же, пока журнал стартовых строк свеж
# (находка №225). Файловая ось (№234/открытый вопрос 7) — рядом с syscall'ной.
journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.3.epoch)" --no-pager \
    | grep -E 'no reachable nr in the kernel allowlist|cgroup escape collector unavailable|file rules whose op condition names no operation any hook produces' \
    > /root/env-muteness-6.3.txt 2>/dev/null
echo "немота по среде записана: /root/env-muteness-6.3.txt ($(wc -l < /root/env-muteness-6.3.txt) строк)"

# ── Шаг 2б (№257, item 6 постановки 6.2.6). Снимок метрик СРАЗУ после
#    старта агента — ДО 1800-секундного пролога, а не на границе t0
#    контролей. Без этого снимка сторож потерь 6.2.3.0/6.2.6.0 видит только
#    отрезок [t0,t1] и молчит о том, что накопилось за сам пролог: архив
#    collect-6.2.3 потерял 1336 файловых событий именно там, и никакой
#    вердикт этого не отразил (находка №257). Пишется ВНЕ $ART — контроли
#    очищают и пересоздают $ART при старте (находка №228) и стёрли бы файл,
#    попади он туда раньше их запуска.
_r63_api="${VPS_IP:+http://${VPS_IP}:19090}"; _r63_api="${_r63_api:-http://localhost:19090}"
_r63_token="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
if curl -s --max-time 30 -H "Authorization: Bearer $_r63_token" "$_r63_api/metrics" > /root/metrics-prologue-start-6.3.txt 2>/dev/null \
    && [ -s /root/metrics-prologue-start-6.3.txt ]; then
    echo "снимок метрик пролога записан: /root/metrics-prologue-start-6.3.txt ($(wc -l < /root/metrics-prologue-start-6.3.txt) строк)"
else
    echo "СНИМОК ПРОЛОГА НЕ ВЗЯТ: /root/metrics-prologue-start-6.3.txt пуст или недоступен — 6.2.6.A напечатает дельту пролога как НЕИЗМЕРИМУЮ, не как ноль"
    rm -f /root/metrics-prologue-start-6.3.txt
fi

# ── Шаг 3. Пролог. Ключ дрейфа обязан закрыть обучение ДО окна (пункт А). ──
echo "--- пролог ${PROLOGUE}s (обучение дрейфа закрывается: 600 × 2 = 1200 с) ---"
sleep "$PROLOGUE"

# ── Шаг 4. Контроли. ──────────────────────────────────────────────────────
echo "--- контроли волны 6.3 ---"
W63_WINDOW="$WINDOW" W63_NS="$NS" W63_ART="$ART" W63_SVC="$SVC" \
W63_CHURN=3 W63_GATE=100 W63_GATE_FORMULA="$GATE_FORMULA" \
W63_PROFILE_SECS="$PROFILE_SECS" W63_SMOKE="$SMOKE" \
W63_VERDICTS="$VERDICTS" \
W63_FORCE_NODE_EVENT="${FORCE_NODE_EVENT:-1}" \
W63_AB_ENABLED="${AB_ENABLED:-0}" \
W63_PROLOGUE_METRICS="/root/metrics-prologue-start-6.3.txt" \
    bash "$SETUP/wave6.3-controls.sh"

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
_j63="/root/journal-agent-6.3.log"
journalctl -u "$SVC" --since "@$(cat /root/agent-start-6.3.epoch)" --no-pager > "$_j63" 2>/root/journal-agent-6.3.err
_j63_rc=$?
_j63_lines=$(wc -l < "$_j63" 2>/dev/null)
echo "  журнал агента: $_j63_lines строк (код возврата journalctl $_j63_rc)"
[ -s /root/journal-agent-6.3.err ] && sed 's/^/    journalctl stderr: /' /root/journal-agent-6.3.err

# Критерий 6.2.6.4: непустота И покрытие окна. Сторож живёт В ПАЙПЛАЙНЕ, а не
# в глазах читателя архива через сутки: пустой журнал = прогон объявляет себя
# нереплеиваемым.
W63_REPLAYABLE=1
if [ "${_j63_lines:-0}" -lt 1 ]; then
    echo "  6.2.6.4 ПРОВАЛЕН: journal-agent-6.3.log ПУСТ — архив этого прогона НЕРЕПЛЕИВАЕМ (находка №240)"
    W63_REPLAYABLE=0
elif [ -s "$ART/window-epoch.txt" ]; then
    # Файл-мост от контролей: у них эпохи окна есть, у пайплайна их нет
    # (открытый вопрос 14).
    _t0=$(grep '^t0=' "$ART/window-epoch.txt" | cut -d= -f2)
    _t1=$(grep '^t1=' "$ART/window-epoch.txt" | cut -d= -f2)
    _jfirst=$(head -1 "$_j63" | grep -oE '^[A-Za-z]{3} [0-9]{2} [0-9:]{8}' )
    _jfirst_e=$(date -d "$_jfirst" +%s 2>/dev/null)
    _jlast=$(tail -1 "$_j63" | grep -oE '^[A-Za-z]{3} [0-9]{2} [0-9:]{8}' )
    _jlast_e=$(date -d "$_jlast" +%s 2>/dev/null)
    echo "  окно [$_t0, $_t1]; журнал [${_jfirst_e:-?}, ${_jlast_e:-?}]"
    if [ -z "${_jfirst_e:-}" ] || [ -z "${_jlast_e:-}" ]; then
        echo "  6.2.6.4 НЕИЗМЕРИМ: метки времени журнала не разобраны — покрытие окна не проверено"
        W63_REPLAYABLE=0
    elif [ "$_jfirst_e" -le "${_t0:-0}" ] && [ "$_jlast_e" -ge "${_t1:-0}" ]; then
        echo "  6.2.6.4 ДОСТИГНУТО: журнал непуст ($_j63_lines строк) и ПОКРЫВАЕТ окно (первая строка ≤ t0, последняя ≥ t1)"
    else
        echo "  6.2.6.4 ПРОВАЛЕН: журнал непуст, но НЕ покрывает окно [$_t0,$_t1] — производные от него контроли неподтверждаемы"
        W63_REPLAYABLE=0
    fi
else
    echo "  6.2.6.4 НЕИЗМЕРИМ: контроли не оставили $ART/window-epoch.txt — границы окна пайплайну неизвестны"
    W63_REPLAYABLE=0
fi
{
    echo "критерий=6.2.6.4"
    echo "время_UTC=$(date -u +%FT%TZ)"
    echo "журнал_строк=$_j63_lines реплеиваем=$W63_REPLAYABLE"
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
#    своей константной таблицей меток постановки волны 6.3. Расхождение
#    прерывает пайплайн ДО Шага 5: архив, который не измеряет то, ради чего
#    запущен, не должен выглядеть как собранный архив.
echo "--- 6.3.8: страж полноты пайплайна (item 6) ---"
if ! bash "$SETUP/wave6.3-completeness-guard.sh" --check "$OUT"; then
    echo "=== ПРОГОН 6.3 ОСТАНОВЛЕН: 6.3.8 ОТКАЗАЛСЯ СОБРАТЬ АРХИВ (расхождение таблицы меток постановки со списком вынесенных вердиктов, №269/№270) ==="
    {
        echo "критерий=6.3.8"
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
cp /root/agent-start-6.3.txt /root/agent-start-6.3.epoch /root/env-muteness-6.3.txt "$COLLECT/" 2>/dev/null
cp /root/metrics-prologue-start-6.3.txt "$COLLECT/" 2>/dev/null
cp "$SETUP/config-test.yaml" "$SETUP/wave6.3-controls.sh" "$SETUP/wave6.3-metrics-lib.sh" "$SETUP/wave6.3-completeness-guard.sh" "$SETUP/run-6.3-pipeline.sh" "$COLLECT/" 2>/dev/null
# Манифест DNS и его генератор (item 1) — часть провенанса величины 6.3.3:
# без манифеста через сутки нельзя сказать, ПО КАКИМ правилам был отфильтрован
# объём окна. Реестр сужений (item 8) — по той же причине: он объясняет, почему
# одиннадцать правил на архивах старше 15.09.2026 читаются иначе.
cp "$SETUP/attacks/dns-rule-ids.txt" "$SETUP/generate-dns-rule-manifest.sh" "$COLLECT/" 2>/dev/null
cp "$SETUP/attacks/new-rules.txt" "$COLLECT/" 2>/dev/null

cp /root/journal-agent-6.3.log "$COLLECT/journal-agent-6.3.log" 2>/dev/null
[ -s /root/journal-agent-6.3.err ] && cp /root/journal-agent-6.3.err "$COLLECT/journal-agent-6.3.err" 2>/dev/null

kubectl get nodes -o wide > "$COLLECT/node/nodes.txt" 2>/dev/null
kubectl get pods -A -o wide > "$COLLECT/node/pods.txt" 2>/dev/null
kubectl version -o json > "$COLLECT/node/version.json" 2>/dev/null
git -C /opt/ebpf-guard log --oneline -6 > "$COLLECT/git-head.txt" 2>/dev/null
echo "архив: $COLLECT ($(du -sh "$COLLECT" 2>/dev/null | cut -f1))"
echo "  забрать: rsync -az root@<стенд>:$COLLECT/ server-logs/$(basename "$COLLECT")/"
echo "  (размер выше посчитан ДО того, как в архив ляжет сам лог пайплайна — правка №241)"

# №309 (волна 6.2.9.F.2, item 5): сторож валидности UTF-8 собранного лога —
# `cut -c`/`grep` без `-a` слепнут на невалидном UTF-8 молча (BSD grep на mac
# объявляет такой файл двоичным и не печатает НИЧЕГО, не возвращая ошибки),
# и весь метод волн — офлайн-реплей архива (память gate-offline-replay-on-mac)
# — стоит на чтении именно этого файла. Печатается СЛОВОМ, а не тихо, и
# ДО финальной копии — чтобы строка попала в саму копию, а не только в живой
# stdout под tee.
if [ -s "$OUT" ]; then
    if command -v iconv >/dev/null 2>&1 && iconv -f UTF-8 -t UTF-8 "$OUT" >/dev/null 2>&1; then
        echo "СТОРОЖ №309: run-6.3.log ВАЛИДЕН В UTF-8 — офлайн-разбор (grep/sed без -a) безопасен"
    else
        echo "СТОРОЖ №309: run-6.3.log НЕВАЛИДЕН В UTF-8 (либо iconv недоступен) — офлайн-разбор ОБЯЗАН использовать grep -a, иначе BSD grep молча ничего не найдёт"
    fi
fi

echo "=== ПРОГОН 6.3$([ "$SMOKE" = "1" ] && echo ' (СМОК)') ЗАВЕРШЁН $(date -u +%FT%TZ) ==="
date -u +%FT%TZ > "$DONE_MARK"
# №241: копия лога — БУКВАЛЬНО последним действием, после маркера. Иначе
# архивная копия обрывается на «--- сборка архива ---» и по ней нельзя
# отличить упавший прогон от прошедшего целиком.
[ -f "$OUT" ] && cp "$OUT" "$COLLECT/run-6.3.log"
