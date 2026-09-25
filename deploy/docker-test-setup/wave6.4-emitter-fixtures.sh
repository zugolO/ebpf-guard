#!/usr/bin/env bash
# wave6.4-emitter-fixtures.sh — фикстурный сторож меток 6.4.0…6.4.8 (item 8
# постановки волны 6.4). Копия wave6.3-emitter-fixtures.sh с переставленными
# маркерами (W648-EMITTERS вместо W639-EMITTERS) и СВОЕЙ таблицей ожиданий —
# по образцу, которым сам 6.3-файл форкался бы от более раннего аналога, если
# бы тот существовал; здесь форк прямой, от единственного прообраза.
#
# ЗАЧЕМ. `--scan` и `--check` стража (wave6.4-completeness-guard.sh) отвечают
# ДА для строки, которая не способна напечатать ничего, кроме НЕИЗМЕРИМ:
# метка заговорила, реестр полон, критерий выхода недостижим — ровно форма
# №373 (волна 6.3.9.F, 6.3.9.4/6.3.9.5 были безусловными echo). Этот файл
# исполняет САМИ ВЕТКИ на синтетических входах и спрашивает, умеет ли КАЖДАЯ
# метка (кроме законно-постоянной 6.4.5, см. ниже) вынести ГОДНУЮ величину
# хоть на одном входе ([[verdict-line-that-can-only-say-unmeasurable]]).
#
# КАК. Блок эмиттеров вынимается из run-6.4-pipeline.sh между маркерами
# W648-EMITTERS-BEGIN/END (не по номерам строк — те разъезжаются с первой же
# правкой выше) и исполняется с подставленными переменными на синтетических
# снимках /metrics и файлах-сторожах контролей items 5/6. Проверяется не только
# КЛАСС каждой метки (той же функцией классификации, что у стража, чтобы
# инструменты не расходились в трактовке одного и того же слова), но и
# НАПЕЧАТАННЫЙ ТЕКСТ: item 2 волны 6.5 показал, что №455/№457/№458 трижды
# давали верный класс под лживым доказательством. Текстовые сверки сторожит
# реестр №461, а образец «величина посчитана дважды» (корень №458) — сторож
# №460; оба обязаны краснеть на лжи и были прогнаны на ней.
#
# ВХОДНЫЕ ПЕРЕМЕННЫЕ ГАРНЕССА (зеркалят реальные переменные блока
# W648-EMITTERS в run-6.4-pipeline.sh — см. комментарий над самим блоком):
#   ART             — каталог артефактов (снимки /metrics на границах окна,
#                      сторожевые файлы контролей items 5/6);
#   _w63l_metrics   — свежий снимок /metrics (строка целиком, как curl её бы
#                      вернул) для меток 6.4.0/6.4.2;
#   _w648_role      — "A" | "B", свойство КОНФИГА (collectors.tls.enabled);
#   W63_BASELINE_CONTROLS / W63_BASELINE_ART — переиспользуемый прибор
#                      wave6.3.9f-item3-baseline-controls.sh для 6.4.7.
#
# ИНВАРИАНТЫ НА КАЖДОЙ ФИКСТУРЕ (не только ожидаемые классы):
#   И1 — ровно 9 меток 6.4.0…6.4.8 получили вердиктную строку, ни одна дважды;
#   И2 — каждая напечатанная вердиктная строка несёт вердиктное слово
#        ВПЛОТНУЮ за меткой (та же регулярка, что у стража) — иначе страж
#        полноты её не увидит, а фикстура бы этого не заметила;
#   И3 — ни одна метка не печатает ДВЕ вердиктные строки за прогон.
set -u

# WARNING 5 (ярус A, item 1/2): ниже `_assign_map` объявляет `local -A K S` —
# ассоциативные массивы требуют bash>=4. На bash 3.2 разбор падал бы на
# объявлении и/или зеленел неполным разбором; репозиторная конвенция — явный
# страж версии с внятным отказом, а не ложная зелень (см.
# run-2.9.9-pipeline.sh: `[ "${BASH_VERSINFO[0]}" -ge 4 ] || die`).
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: нужен bash>=4 (ассоциативные массивы в _assign_map) — текущий ${BASH_VERSION:-неизвестен}"
    exit 2
fi

SETUP="${SETUP:-$(cd "$(dirname "$0")" && pwd)}"
PIPE="${PIPE:-$SETUP/run-6.4-pipeline.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/w648-emit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
_efail() { echo "    ПРОВАЛ: $*"; FAILS=$((FAILS + 1)); }

# _text_ok <строка> <обязательные подстроки…> — 0, если ВСЕ на месте. Один
# механизм сверки на позитивные фикстуры (№455/№457/№461) и на их негативный
# реплей: реплей не вправе проверяться ДРУГИМ кодом, чем сама фикстура.
_text_ok() {
    local line="$1"; shift
    local sub
    for sub in "$@"; do
        printf '%s' "$line" | grep -qF -- "$sub" || return 1
    done
    return 0
}

# Реестр негативного реплея ТЕКСТА (WARNING 2 item 2). Каждая УСПЕШНАЯ
# текстовая сверка кладёт сюда настоящую вердиктную строку и ТОЧНЫЙ набор её
# обязательных подстрок; реплей берёт их отсюда, а не из захардкоженной пары
# литералов, поэтому порча настоящих ожиданий реплей ПРОКРАСНЕЕТ.
_REPLAY_FILE="$WORK/text-replay.tsv"
: > "$_REPLAY_FILE"
_replay_note() { # <имя> <строка> <обязательные подстроки…>
    local name="$1" line="$2"; shift 2
    printf '%s\t%s' "$name" "$line" >> "$_REPLAY_FILE"
    local sub
    for sub in "$@"; do printf '\t%s' "$sub" >> "$_REPLAY_FILE"; done
    printf '\n' >> "$_REPLAY_FILE"
}

# ── Блок эмиттеров ───────────────────────────────────────────────────────────
if ! grep -q 'W648-EMITTERS-BEGIN' "$PIPE" || ! grep -q 'W648-EMITTERS-END' "$PIPE"; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: в $PIPE нет маркеров W648-EMITTERS-BEGIN/END — вынимать нечего"
    exit 2
fi
sed -n '/W648-EMITTERS-BEGIN/,/W648-EMITTERS-END/p' "$PIPE" > "$WORK/block.sh"
_block_lines=$(wc -l < "$WORK/block.sh")
if [ "${_block_lines:-0}" -lt 40 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: между маркерами всего ${_block_lines} строк — блок вынут не тот"
    exit 2
fi
bash -n "$WORK/block.sh" || { echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: вынутый блок не разбирается bash -n"; exit 2; }

# ── Классификация — ТА ЖЕ, что у стража полноты (item 9). Переиспользуется
#    без изменений: инструменты не должны разойтись в трактовке слова.
_cls() {
    if printf '%s' "$1" | grep -q 'ЗАПРОШЕН'; then echo NOTREQ
    elif printf '%s' "$1" | grep -qE 'ПРОВАЛЕН|НЕИЗМЕРИМ'; then echo FAIL
    elif printf '%s' "$1" | grep -qE 'ДОСТИГНУТО|ИЗМЕРЕНО'; then echo OK
    else echo '?'; fi
}

# _mk_metrics <файл> <tracked_pids|"" > <строки attach_failures{reason=...} N ...> <events_total{type=tls} N> <alert_volume{event_type=tls} N> <alert_volume суммарно N>
# Строит текстовый снимок /metrics ровно с теми сериями, которые читает блок
# W648-EMITTERS (см. комментарии над ним в run-6.4-pipeline.sh): tracked_pids
# — гейдж без меток; attach_failures — счётчик с меткой reason; events_total
# — счётчик с меткой type; alert_volume_by_event_type_total — счётчик с
# меткой event_type. Отсутствующий аргумент = серии в снимке НЕТ ВООБЩЕ.
# СЕДЬМОЙ аргумент (необязательный) — ebpf_guard_tls_attach_success_total,
# МОНОТОННАЯ величина привязки (№449). Необязательный ровно затем, чтобы
# двенадцать уже написанных фикстур продолжали описывать бинарь БЕЗ №449 и
# проверяли ветку отката на мгновенный tracked_pids.
_mk_metrics() {
    local f="$1" tracked="$2" fails="$3" ev="$4" avol_tls="$5" avol_any="$6" att="${7:-}"
    : > "$f"
    [ -n "$tracked" ] && echo "ebpf_guard_tls_tracked_pids_total $tracked" >> "$f"
    [ -n "$att" ] && echo "ebpf_guard_tls_attach_success_total $att" >> "$f"
    if [ -n "${fails:-}" ]; then
        local reason count
        for pair in $fails; do
            reason="${pair%%=*}"; count="${pair##*=}"
            echo "ebpf_guard_tls_attach_failures_total{reason=\"$reason\"} $count" >> "$f"
        done
    fi
    [ -n "$ev" ] && echo "ebpf_guard_events_total{type=\"tls\"} $ev" >> "$f"
    [ -n "$avol_tls" ] && echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"tls\"} $avol_tls" >> "$f"
    [ -n "$avol_any" ] && echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"dns\"} $((avol_any - avol_tls))" >> "$f"
}

# _run <ART> <role A|B> [W63_BASELINE_CONTROLS on|off]
_run() {
    local art="$1" role="$2" blc="${3:-off}"
    cat > "$WORK/harness.sh" <<EOF
set -u
ART="$art"
_w648_role="$role"
W63_BASELINE_CONTROLS="$blc"
W63_BASELINE_ART="$art/baseline"
_w63l_metrics="\$(cat "$art/metrics-live.txt" 2>/dev/null)"
EOF
    cat "$WORK/block.sh" >> "$WORK/harness.sh"
    bash "$WORK/harness.sh" 2>&1
}

# _check <имя фикстуры> <вывод> <ожидания вида "метка=КЛАСС" ...>
_check() {
    local name="$1" out="$2"; shift 2
    echo "--- фикстура: $name"
    local lbl exp got line n
    # И1/И3: по одной вердиктной строке на метку, девять меток.
    n=0
    for lbl in 6.4.0 6.4.1 6.4.2 6.4.3 6.4.4 6.4.5 6.4.6 6.4.7 6.4.8; do
        line=$(printf '%s\n' "$out" | grep -cE "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)")
        [ "${line:-0}" -eq 1 ] || _efail "$name: метка $lbl напечатала ${line:-0} вердиктных строк вместо одной (И2/И3)"
        n=$((n + line))
    done
    [ "$n" -eq 9 ] || _efail "$name: вердиктных строк всего $n вместо девяти (И1)"
    # Ожидаемые классы.
    for exp in "$@"; do
        lbl="${exp%%=*}"; exp="${exp##*=}"
        line=$(printf '%s\n' "$out" | grep -E "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" | tail -1)
        got=$(_cls "$line")
        if [ "$got" = "$exp" ]; then
            echo "    OK  $lbl = $got"
        else
            _efail "$name: $lbl дал класс $got, ожидался $exp — строка: $(printf '%s' "$line" | cut -c1-160)"
        fi
    done
}

echo "=== ФИКСТУРНЫЙ ПРОГОН ВЕРДИКТНЫХ ВЕТОК 6.4.0…6.4.8 (блок из $PIPE, ${_block_lines} строк) ==="

# ── 1. ПРОГОН A ЗДОРОВОЙ ПАРЫ: collectors.tls.enabled: false, метрики окна
#    сняты, опорный набор НЕ просился на этом заходе (off).
A="$WORK/artA"; mkdir -p "$A"
_mk_metrics "$A/metrics-live.txt" "" "" "" "" ""
_mk_metrics "$A/metrics-window-start.txt" "" "" 0 0 0
_mk_metrics "$A/metrics-window-end.txt"   "" "" 0 0 0
_check "прогон A здоровой пары (tls выключен конфигом)" "$(_run "$A" A off)" \
    6.4.0=OK 6.4.1=OK 6.4.2=NOTREQ 6.4.3=NOTREQ 6.4.4=NOTREQ 6.4.5=NOTREQ 6.4.6=OK 6.4.7=NOTREQ 6.4.8=OK

# ── 2. ПРОГОН B ЗДОРОВОЙ ПАРЫ: привязка удалась, события идут, оба контроля
#    items 5/6 сняты и положительны, опорный набор снят и цел.
B="$WORK/artB"; mkdir -p "$B/baseline"
_mk_metrics "$B/metrics-live.txt" 3 "no_symbols=1" "" "" ""
_mk_metrics "$B/metrics-window-start.txt" "" "" 100 40 90
_mk_metrics "$B/metrics-window-end.txt"   "" "" 260 55 210
{
    echo "events_delta=160"
    echo "manifest_alerts=6"
} > "$B/tls-control-plaintext.txt"
{
    echo "bound=yes"
    echo "identity_match=yes"
    echo "event=yes"
} > "$B/tls-control-container.txt"
printf '6.0.13 OK\n5.9.5c OK\n6.3.1 OK\n' > "$B/baseline/baseline-labels-baseline.txt"
printf '6.0.13 OK\n5.9.5c OK\n6.3.1 OK\n' > "$B/baseline/baseline-labels-check.txt"
_check "прогон B здоровой пары (tls включён, оба контроля сняты, набор цел)" "$(_run "$B" B on)" \
    6.4.0=OK 6.4.1=OK 6.4.2=OK 6.4.3=OK 6.4.4=OK 6.4.5=NOTREQ 6.4.6=OK 6.4.7=OK 6.4.8=OK

# ── 3. «ПРИБОР НЕ ЗНАЕТ, ЧТО С НИМ» (6.4.0 ПРОВАЛЕН): обе серии присутствуют
#    (коллектор жив и отдаёт метрики), но tracked_pids=0 И сумма отказов=0 —
#    ни привязки, ни причины отказа. Постановка 6.4, метка 6.4.0.
C="$WORK/artC"; mkdir -p "$C/baseline"
_mk_metrics "$C/metrics-live.txt" 0 "no_symbols=0" "" "" ""
_mk_metrics "$C/metrics-window-start.txt" "" "" 0 0 0
_mk_metrics "$C/metrics-window-end.txt"   "" "" 0 0 0
_check "прибор не знает своё состояние (tracked=0 И отказов=0, обе серии живы)" "$(_run "$C" B off)" \
    6.4.0=FAIL 6.4.1=OK 6.4.2=FAIL 6.4.5=NOTREQ 6.4.8=OK

# ── 4. ПРИВЯЗКА ПОЛНОСТЬЮ ПРОВАЛЕНА: коллектор жив, отказы предъявлены по
#    причине (№379 закрыт — молчания нет), но tracked_pids=0 — ни одного
#    процесса. Контроли items 5/6 не исполнены в этом заходе.
D="$WORK/artD"; mkdir -p "$D"
_mk_metrics "$D/metrics-live.txt" 0 "no_elf=2 no_symbol_found=1" "" "" ""
_mk_metrics "$D/metrics-window-start.txt" "" "" 0 0 0
_mk_metrics "$D/metrics-window-end.txt"   "" "" 0 0 0
_check "привязка полностью провалена (tracked=0, отказы предъявлены по причинам)" "$(_run "$D" B off)" \
    6.4.0=OK 6.4.1=OK 6.4.2=FAIL 6.4.3=FAIL 6.4.4=FAIL 6.4.5=NOTREQ 6.4.7=NOTREQ 6.4.8=OK

# ── 5. МЕТРИКИ ВООБЩЕ НЕ СНЯТЫ (бинарь без починки item 2, или снимок не
#    взят) — 6.4.0/6.4.2 обязаны говорить НЕИЗМЕРИМ с названным классом, а
#    не молчать и не читать отсутствие как ноль.
E="$WORK/artE"; mkdir -p "$E"
_mk_metrics "$E/metrics-live.txt" "" "" "" "" ""
: > "$E/metrics-window-start.txt"; : > "$E/metrics-window-end.txt"
_check "метрики не отданы вовсе (снимков нет)" "$(_run "$E" B off)" \
    6.4.0=FAIL 6.4.1=FAIL 6.4.2=FAIL 6.4.6=FAIL 6.4.8=OK

# ── 6. ОКНО ПУСТО ПРИ ЖИВОЙ ПРИВЯЗКЕ: tracked_pids>=1, но события/окно за
#    границами снимков не выросли — легальный ноль, класс ПРОДУКТОВЫЙ (не
#    приборный: привязка есть).
F="$WORK/artF"; mkdir -p "$F"
_mk_metrics "$F/metrics-live.txt" 2 "" "" "" ""
_mk_metrics "$F/metrics-window-start.txt" "" "" 50 10 30
_mk_metrics "$F/metrics-window-end.txt"   "" "" 50 10 30
_check "окно пусто при живой привязке (ноль продуктовый)" "$(_run "$F" B off)" \
    6.4.0=OK 6.4.1=OK 6.4.2=OK 6.4.6=OK 6.4.8=OK

# ── 7. ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ (item 5) ЕЩЁ НЕ ИСПОЛНЕН — файл-сторож
#    отсутствует: 6.4.3 обязан назвать класс, а не притвориться нулём.
G="$WORK/artG"; mkdir -p "$G"
_mk_metrics "$G/metrics-live.txt" 4 "" "" "" ""
_mk_metrics "$G/metrics-window-start.txt" "" "" 10 2 5
_mk_metrics "$G/metrics-window-end.txt"   "" "" 30 3 8
_check "контроль item 5 не исполнен (файла tls-control-plaintext.txt нет)" "$(_run "$G" B off)" \
    6.4.0=OK 6.4.2=OK 6.4.3=FAIL 6.4.8=OK

# ── 8. ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ИСПОЛНЕН, НО ОДНА ИЗ ДВУХ ВЕЛИЧИН НУЛЕВАЯ:
#    рост событий есть, алертов манифеста нет — 6.4.3 обязан ПРОВАЛИТЬСЯ
#    (обе величины обязаны быть положительными, а не «хотя бы одна»).
H="$WORK/artH"; mkdir -p "$H"
_mk_metrics "$H/metrics-live.txt" 4 "" "" "" ""
_mk_metrics "$H/metrics-window-start.txt" "" "" 10 2 5
_mk_metrics "$H/metrics-window-end.txt"   "" "" 30 3 8
{ echo "events_delta=40"; echo "manifest_alerts=0"; } > "$H/tls-control-plaintext.txt"
_check "контроль item 5 частичный (события есть, алертов манифеста 0)" "$(_run "$H" B off)" \
    6.4.3=FAIL 6.4.8=OK

# ── 9. КОНТЕЙНЕРНЫЙ КОНТРОЛЬ (item 6) НАЗЫВАЕТ СВОЙ СОБСТВЕННЫЙ КЛАСС
#    (например, под без libssl в образе) — 6.4.4 обязан ПЕРЕДАТЬ этот класс,
#    а не подставлять свой общий текст поверх.
I="$WORK/artI"; mkdir -p "$I"
_mk_metrics "$I/metrics-live.txt" 4 "" "" "" ""
_mk_metrics "$I/metrics-window-start.txt" "" "" 10 2 5
_mk_metrics "$I/metrics-window-end.txt"   "" "" 30 3 8
echo "class=под без libssl в образе — тождество библиотеки не проверено" > "$I/tls-control-container.txt"
_check "контейнерный контроль называет собственный класс НЕИЗМЕРИМ" "$(_run "$I" B off)" \
    6.4.4=FAIL 6.4.8=OK

# ── 10. ОПОРНЫЙ НАБОР (6.4.7) ЗАПРОШЕН, НО ПОТЕРЯЛ КОНТРОЛЬ — ПРОВАЛЕН
#    отменяет включение TLS (критерий выхода постановки 6.4, п. 5).
J="$WORK/artJ"; mkdir -p "$J/baseline"
_mk_metrics "$J/metrics-live.txt" 3 "" "" "" ""
_mk_metrics "$J/metrics-window-start.txt" "" "" 10 2 5
_mk_metrics "$J/metrics-window-end.txt"   "" "" 30 3 8
printf '6.0.13 OK\n5.9.5c OK\n6.3.1 OK\n' > "$J/baseline/baseline-labels-baseline.txt"
printf '6.0.13 OK\n5.9.5c FAIL\n'          > "$J/baseline/baseline-labels-check.txt"
_check "опорный набор потерял положительный контроль детекта" "$(_run "$J" B on)" \
    6.4.7=FAIL 6.4.8=OK

# ── 11. ОПОРНЫЙ НАБОР ПУСТ ПО OK — «ничего не потеряно» есть тождество, не
#    величина (тот же приём, что 6.3.9.5).
K="$WORK/artK"; mkdir -p "$K/baseline"
_mk_metrics "$K/metrics-live.txt" 3 "" "" "" ""
_mk_metrics "$K/metrics-window-start.txt" "" "" 10 2 5
_mk_metrics "$K/metrics-window-end.txt"   "" "" 30 3 8
printf '6.0.13 FAIL\n' > "$K/baseline/baseline-labels-baseline.txt"
printf '6.0.13 OK\n'   > "$K/baseline/baseline-labels-check.txt"
_check "опорный набор без единого взятого контроля" "$(_run "$K" B on)" \
    6.4.7=FAIL 6.4.8=OK

# ── 12. СЧЁТЧИК УБЫЛ ВНУТРИ ОКНА (рестарт агента) — 6.4.1/6.4.6 обязаны
#    назвать этот класс, а не напечатать отрицательную дельту как величину.
L="$WORK/artL"; mkdir -p "$L"
_mk_metrics "$L/metrics-live.txt" 3 "" "" "" ""
_mk_metrics "$L/metrics-window-start.txt" "" "" 500 80 200
_mk_metrics "$L/metrics-window-end.txt"   "" "" 20  5  30
_check "счётчик events_total убыл внутри окна (рестарт)" "$(_run "$L" B off)" \
    6.4.1=FAIL 6.4.8=OK

# ── 13. №449: СНИМОК ВЗЯТ ПОСЛЕ КОНТРОЛЕЙ items 5/6, которые убили своего
#    держателя. Мгновенный tracked_pids=0, монотонная привязка = 3. Это
#    ПРОДУКТОВО УСПЕШНЫЙ прогон: 6.4.2 обязана быть ДОСТИГНУТО, а 6.4.1 —
#    назвать свой ноль ПРОДУКТОВЫМ, а не приборным. До №449 ровно этот вход
#    читался как «не привязались ни разу» и ронял критерий выхода (2).
M="$WORK/artM"; mkdir -p "$M"
_mk_metrics "$M/metrics-live.txt" 0 "" "" "" "" 3
_mk_metrics "$M/metrics-window-start.txt" "" "" 10 2 5
_mk_metrics "$M/metrics-window-end.txt"   "" "" 10 2 5
_w648_m_out="$(_run "$M" B off)"
_check "снимок после контролей: tracked_pids=0 при attach_success_total=3 (№449)" "$_w648_m_out" \
    6.4.0=OK 6.4.1=OK 6.4.2=OK 6.4.8=OK
if printf '%s\n' "$_w648_m_out" | grep -qE '6\.4\.1[[:space:]]+ИЗМЕРЕНО.*ПРОДУКТОВЫЙ'; then
    echo "    OK  6.4.1 назвала ноль ПРОДУКТОВЫМ (привязка была), а не приборным"
else
    _efail "№449: 6.4.1 при attach_success_total=3 обязана назвать ноль ПРОДУКТОВЫМ — строка: $(printf '%s\n' "$_w648_m_out" | grep -E '6\.4\.1[[:space:]]+ИЗМЕРЕНО' | cut -c1-200)"
fi

# ── 14. НИ ОДНОЙ ПРИВЯЗКИ ЗА ЖИЗНЬ ПРОЦЕССА при живой серии — это по-прежнему
#    ПРОВАЛЕН, и монотонный счётчик не смягчает вердикт, а делает его
#    непробиваемым: ноль здесь уже не спишешь на убитого держателя.
N="$WORK/artN"; mkdir -p "$N"
_mk_metrics "$N/metrics-live.txt" 0 "no_elf=2" "" "" "" 0
_mk_metrics "$N/metrics-window-start.txt" "" "" 0 0 0
_mk_metrics "$N/metrics-window-end.txt"   "" "" 0 0 0
_check "привязок за жизнь процесса ноль при предъявленных отказах" "$(_run "$N" B off)" \
    6.4.0=OK 6.4.1=OK 6.4.2=FAIL 6.4.8=OK

# ── 15…17. №455: ТРИ РАЗНЫХ МИРА ЗА ОДНИМ «event=no» у 6.4.4. До №455 все
#    три печатали один ПРОВАЛЕН, и вердикт волны не мог отличить «обмена в
#    поде не было» от «событие дошло, детекта нет» и от «алерт подавлен
#    дедупом». Класс проверяется ПО ТЕКСТУ, потому что все три — класс FAIL:
#    различие несёт именно формулировка, и непроверенная формулировка есть
#    непроверенная ветка (№451).
_w648_cc_case() { # <имя> <строки сторожевого файла> <обязательная подстрока>
    local name="$1" body="$2" want="$3"
    local art="$WORK/art-$(echo "$name" | tr -cd '[:alnum:]')"
    mkdir -p "$art"
    _mk_metrics "$art/metrics-live.txt" 0 "" "" "" "" 3
    _mk_metrics "$art/metrics-window-start.txt" "" "" 10 2 5
    _mk_metrics "$art/metrics-window-end.txt"   "" "" 30 3 8
    printf '%s\n' "$body" > "$art/tls-control-container.txt"
    local out line
    out="$(_run "$art" B off)"
    line=$(printf '%s\n' "$out" | grep -E "(^|[^0-9.])6\.4\.4[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" | tail -1)
    echo "--- фикстура: $name"
    if _text_ok "$line" "$want"; then
        echo "    OK  6.4.4 назвала класс «${want}»"
        _replay_note "№455 ${name}" "$line" "$want"
    else
        _efail "№455/${name}: 6.4.4 обязана назвать класс «${want}» — строка: $(printf '%s' "$line" | cut -c1-190)"
    fi
}

echo
echo "=== №455: три мира за «event=no» у метки 6.4.4 ==="
_w648_cc_case "алерт пода схлопнут дедупом" \
    "bound=yes
identity_match=yes
event=no
pod_events=3
events_delta=6
alert_delta=0
dedup_delta=2" \
    "СХЛОПНУТ ДЕДУПОМ"
_w648_cc_case "событие дошло, детекта нет — класс продуктовый" \
    "bound=yes
identity_match=yes
event=no
pod_events=3
events_delta=6
alert_delta=0
dedup_delta=0" \
    "класс ПРОДУКТОВЫЙ"
_w648_cc_case "обмен в поде не дошёл до коллектора вовсе" \
    "bound=yes
identity_match=yes
event=no
pod_events=0
events_delta=0
alert_delta=0
dedup_delta=0" \
    "события TLS С ЛЕЙБЛОМ ПОДА = 0"
_w648_cc_case "все три условия выполнены — величины напечатаны" \
    "bound=yes
identity_match=yes
event=yes
pod_events=4
events_delta=6
alert_delta=1
dedup_delta=0" \
    "ДОСТИГНУТО"

echo
echo "--- сторож №373: способна ли каждая метка (кроме законно-постоянной 6.4.5) вынести годную величину хоть на одном входе"
_all_out="$(_run "$A" A off)
$(_run "$B" B on)
$(_run "$C" B off)
$(_run "$D" B off)
$(_run "$F" B off)
$(_run "$G" B off)
$(_run "$J" B on)"
for lbl in 6.4.0 6.4.1 6.4.2 6.4.3 6.4.4 6.4.6 6.4.7 6.4.8; do
    if printf '%s\n' "$_all_out" | grep -qE "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ИЗМЕРЕНО)"; then
        echo "    OK  $lbl способна вынести годную величину"
    else
        _efail "№373: $lbl НИ НА ОДНОМ из семи входов не смогла напечатать ДОСТИГНУТО/ИЗМЕРЕНО — строка неспособна сказать ничего, кроме отказа"
    fi
done
# 6.4.5 исключена намеренно: развилка item 4 постановки 6.4 ЗАКРЫТА
# 23.09.2026 исходом (б) (находка №433) — у метки нет предмета, который мог
# бы дать годную величину НИ НА ОДНОМ прогоне A или B, и это решение
# владельца, а не пробел эмиттера (тот же приём, что 6.3.9.6 в волне 6.3.9.F,
# исключённая из этого же сторожа по решению владельца, находка №372).
echo "    (6.4.5 исключена намеренно: развилка item 4 закрыта исходом (б), №433 — предмета нет ни на одном прогоне)"

# ═════════════════════════════════════════════════════════════════════════════
# БЛОК W64B — метки волны 6.4.B (6.4B.0…6.4B.5, долг прогона collect-6.4-B).
#
# ЗАЧЕМ ВТОРОЙ БЛОК, А НЕ ФИКСТУРЫ В ПЕРВОМ. У блока W648 инвариант И1 —
# «ровно девять вердиктных строк»; дописывание меток 6.4.B в него сломало бы и
# его, и счётчик метки 6.4.8. Блоки разделены в пайплайне, разделены и здесь.
#
# ЧЕМ ОТЛИЧАЕТСЯ ВХОД. Блок W64B читает не только /metrics, но и БИНАРЬ
# (`"$_r63_bin" version`, признак №441/№442) — поэтому гарнесс подкладывает
# исполняемый файл-двойник, печатающий нужную строку. Это ровно то, что
# [[entry-guard-must-read-runtime-not-config]] требует от самого пайплайна:
# судится рантайм, и фикстура обязана уметь подделать именно рантайм.
# ═════════════════════════════════════════════════════════════════════════════
if ! grep -q 'W64B-EMITTERS-BEGIN' "$PIPE" || ! grep -q 'W64B-EMITTERS-END' "$PIPE"; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: в $PIPE нет маркеров W64B-EMITTERS-BEGIN/END — метки волны 6.4.B вынимать нечем"
    exit 2
fi
sed -n '/W64B-EMITTERS-BEGIN/,/W64B-EMITTERS-END/p' "$PIPE" > "$WORK/blockb.sh"
_blockb_lines=$(wc -l < "$WORK/blockb.sh")
if [ "${_blockb_lines:-0}" -lt 40 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: между маркерами W64B всего ${_blockb_lines} строк — блок вынут не тот"
    exit 2
fi
bash -n "$WORK/blockb.sh" || { echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: блок W64B не разбирается bash -n"; exit 2; }

# _mk_metrics_b <файл> <scans|""> <candidates|""> <"reason=N ..."|""> <"collector=V ..."|"">
# Отсутствующий аргумент = серии в снимке НЕТ ВООБЩЕ (а не ноль — ровно та
# развилка, ради которой заведены №439/№446).
_mk_metrics_b() {
    local f="$1" scans="$2" cand="$3" reasons="$4" ups="$5"
    : > "$f"
    [ -n "$scans" ] && echo "ebpf_guard_tls_scans_total $scans" >> "$f"
    [ -n "$cand" ] && echo "ebpf_guard_tls_scan_candidates $cand" >> "$f"
    local pair
    for pair in ${reasons:-}; do
        echo "ebpf_guard_tls_attach_failures_total{reason=\"${pair%%=*}\"} ${pair##*=}" >> "$f"
    done
    for pair in ${ups:-}; do
        echo "ebpf_guard_collector_up{collector=\"${pair%%=*}\"} ${pair##*=}" >> "$f"
    done
}

_ALL6="objects_not_loaded=0 no_elf=0 no_symbols=0 no_symbol_found=0 libssl_mismatch=0 attach_failed=0"

# _mk_bin <путь> <строка build-features или "">
_mk_bin() {
    local f="$1" feat="$2"
    { echo '#!/usr/bin/env bash'
      echo 'echo "ebpf-guard version test"'
      [ -n "$feat" ] && echo "echo \"build-features: $feat\""
      echo 'exit 0'
    } > "$f"
    chmod +x "$f"
}

# _runb <снимок /metrics> <role> <entry_class> <бинарь> <http_enabled yes|no>
_runb() {
    local met="$1" role="$2" ec="$3" bin="$4" httpen="$5" stubany="${6:-no}" stubnames="${7:-}"
    cat > "$WORK/harnessb.sh" <<EOF
set -u
_w648_role="$role"
_w64b_entry_class="$ec"
_w64b_entry_msg="синтетический вход фикстуры"
_w64b_http_enabled="$httpen"
_w64b_stub_any="${stubany:-no}"
_w64b_stub_names="${stubnames:-}"
_r63_bin="$bin"
_w648_tracked=0
_w648_att=2
_w63l_metrics="\$(cat "$met" 2>/dev/null)"
EOF
    cat "$WORK/blockb.sh" >> "$WORK/harnessb.sh"
    bash "$WORK/harnessb.sh" 2>&1
}

# _checkb — те же инварианты И1/И2/И3, своя таблица меток (шесть).
_checkb() {
    local name="$1" out="$2"; shift 2
    echo "--- фикстура 6.4.B: $name"
    local lbl exp got line n
    n=0
    for lbl in 6.4B.0 6.4B.1 6.4B.2 6.4B.3 6.4B.4 6.4B.5; do
        line=$(printf '%s\n' "$out" | grep -cE "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)")
        [ "${line:-0}" -eq 1 ] || _efail "$name: метка $lbl напечатала ${line:-0} вердиктных строк вместо одной (И2/И3)"
        n=$((n + line))
    done
    [ "$n" -eq 6 ] || _efail "$name: вердиктных строк всего $n вместо шести (И1)"
    for exp in "$@"; do
        lbl="${exp%%=*}"; exp="${exp##*=}"
        line=$(printf '%s\n' "$out" | grep -E "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" | tail -1)
        got=$(_cls "$line")
        if [ "$got" = "$exp" ]; then
            echo "    OK  $lbl = $got"
        else
            _efail "$name: $lbl дал класс $got, ожидался $exp — строка: $(printf '%s' "$line" | cut -c1-160)"
        fi
    done
}

echo
echo "=== ФИКСТУРНЫЙ ПРОГОН ВЕРДИКТНЫХ ВЕТОК 6.4B.0…6.4B.5 (блок из $PIPE, ${_blockb_lines} строк) ==="

BIN_OK="$WORK/bin-ok";    _mk_bin "$BIN_OK"    "tls_attach_failures=true http_plaintext_loader=true"
BIN_NOGEN="$WORK/bin-ng"; _mk_bin "$BIN_NOGEN" "tls_attach_failures=false http_plaintext_loader=false"
BIN_OLD="$WORK/bin-old";  _mk_bin "$BIN_OLD"   ""

# ── B1. ЗДОРОВЫЙ ПРОГОН B: сканы идут, ось collector_up предъявлена обеими
#    сторонами, все шесть reason материализованы, бинарь несёт оба признака.
MB1="$WORK/mb1.txt"; _mk_metrics_b "$MB1" 7 2 "$_ALL6" "tls=1 http_plaintext=1 iouring=0"
_checkb "здоровый прогон B (сканы идут, ось предъявлена обеими сторонами)" \
    "$(_runb "$MB1" B OK "$BIN_OK" yes)" \
    6.4B.0=OK 6.4B.1=OK 6.4B.2=OK 6.4B.3=OK 6.4B.4=OK 6.4B.5=OK

# ── B2. ПРОГОН A: приборность TLS не судится (сторож и discoveryLoop не
#    запускаются по построению), но метки о БИНАРЕ и о честности метрики
#    обязаны выносить вердикт и здесь — они не про TLS-поток.
MB2="$WORK/mb2.txt"; _mk_metrics_b "$MB2" "" "" "$_ALL6" "dns=1 syscall=1 iouring=0"
_checkb "прогон A (TLS выключен конфигом)" \
    "$(_runb "$MB2" A NOTREQ "$BIN_OK" no)" \
    6.4B.0=NOTREQ 6.4B.1=NOTREQ 6.4B.2=OK 6.4B.3=OK 6.4B.4=OK 6.4B.5=OK

# ── B3. ПОДПИСЬ №436: серия сканов есть и равна нулю — discoveryLoop не
#    сделал ни одного прохода за жизнь процесса. Это ПРОВАЛЕН, а не
#    НЕИЗМЕРИМ: прибор ответил, и ответ отрицательный.
MB3="$WORK/mb3.txt"; _mk_metrics_b "$MB3" 0 0 "$_ALL6" "tls=0 dns=1"
_checkb "подпись №436 (сканов ноль при живой серии)" \
    "$(_runb "$MB3" B OK "$BIN_OK" no)" \
    6.4B.1=FAIL 6.4B.2=OK 6.4B.5=OK

# ── B4. БИНАРЬ БЕЗ №445: серии сканов нет вовсе — «скан шёл» неотличимо от
#    «Start ушёл в stub mode выше цикла». Отсутствие серии обязано читаться
#    как НЕИЗМЕРИМ с названным классом, а не как ноль сканов.
MB4="$WORK/mb4.txt"; _mk_metrics_b "$MB4" "" "" "$_ALL6" "tls=1 iouring=0"
_checkb "бинарь без №445 (серии сканов нет)" \
    "$(_runb "$MB4" B OK "$BIN_OK" no)" \
    6.4B.1=FAIL 6.4B.5=OK

# ── B5. ОТРИЦАТЕЛЬНЫЙ СЛУЧАЙ НОДОЙ НЕ ПРЕДЪЯВЛЕН: все collector_up равны
#    единице. Это НЕ «метрика честна» — до №438 так выглядел и сломанный
#    прибор ([[collector-up-is-not-a-health-signal]]), поэтому класс —
#    НЕИЗМЕРИМ, а не ДОСТИГНУТО.
MB5="$WORK/mb5.txt"; _mk_metrics_b "$MB5" 3 1 "$_ALL6" "tls=1 dns=1 syscall=1"
_checkb "все collector_up равны единице (отрицательный случай не предъявлен)" \
    "$(_runb "$MB5" B OK "$BIN_OK" no)" \
    6.4B.1=OK 6.4B.2=FAIL 6.4B.5=OK

# ── B6. СЕРИИ collector_up НЕТ ВОВСЕ — отсутствие серии не есть её ноль
#    ([[metric-anchor-must-carry-full-series-name]]).
MB6="$WORK/mb6.txt"; _mk_metrics_b "$MB6" 3 1 "$_ALL6" ""
_checkb "серии collector_up нет в снимке" \
    "$(_runb "$MB6" B OK "$BIN_OK" no)" \
    6.4B.2=FAIL 6.4B.5=OK

# ── B7. REASON МАТЕРИАЛИЗОВАНЫ ЧАСТИЧНО (три из шести) — недостающие
#    по-прежнему читаются отсутствием серии как ноль отказов (№439).
MB7="$WORK/mb7.txt"; _mk_metrics_b "$MB7" 3 1 "no_elf=0 no_symbols=0 attach_failed=1" "tls=1 iouring=0"
_checkb "материализованы три reason из шести" \
    "$(_runb "$MB7" B OK "$BIN_OK" no)" \
    6.4B.3=FAIL 6.4B.5=OK

# ── B8. СЕРИЙ attach_failures НЕТ ВОВСЕ — бинарь без №439.
MB8="$WORK/mb8.txt"; _mk_metrics_b "$MB8" 3 1 "" "tls=1 iouring=0"
_checkb "серий attach_failures нет вовсе (бинарь без №439)" \
    "$(_runb "$MB8" B OK "$BIN_OK" no)" \
    6.4B.3=FAIL 6.4B.5=OK

# ── B9. БИНАРЬ БЕЗ ПРИЗНАКА http_plaintext_loader — решение по №442 этим
#    прогоном не предъявлено (судится БИНАРЬ, не исходник, №441).
MB9="$WORK/mb9.txt"; _mk_metrics_b "$MB9" 3 1 "$_ALL6" "tls=1 iouring=0"
_checkb "бинарь без признака http_plaintext_loader" \
    "$(_runb "$MB9" B OK "$BIN_OLD" no)" \
    6.4B.4=FAIL 6.4B.5=OK

# ── B10. БИНАРЬ СОБРАН БЕЗ make generate: признак есть и равен false —
#    загрузчик заявлен, но объектов в сборке нет.
_checkb "бинарь без make generate (http_plaintext_loader=false)" \
    "$(_runb "$MB9" B OK "$BIN_NOGEN" yes)" \
    6.4B.4=FAIL 6.4B.5=OK

# ── B11. ВХОДНОЙ СТОРОЖ НЕ ОСТАВИЛ КЛАССА (ветка item 4 не исполнялась) —
#    6.4B.0 обязана назвать этот класс, а не молчать и не притвориться OK.
_checkb "входной сторож не оставил класса" \
    "$(_runb "$MB1" B "" "$BIN_OK" yes)" \
    6.4B.0=FAIL 6.4B.5=OK

# ── B12. №457: СЕРИЯ ЛЖЁТ ЕДИНИЦЕЙ. Все collector_up равны единице, а журнал
#    говорит, что коллектор ушёл в stub mode. Это НЕ «нода не предъявила
#    отрицательного случая» — случай ПРЕДЪЯВЛЕН, и метрика его не показала.
#    Ветка НЕИЗМЕРИМ здесь была бы ложным PASS для №438.
_checkb "серия лжёт единицей при stub mode в журнале (№457)" \
    "$(_runb "$MB5" B OK "$BIN_OK" no yes "lsm ")" \
    6.4B.2=FAIL 6.4B.5=OK
_w64b_line=$(printf '%s\n' "$(_runb "$MB5" B OK "$BIN_OK" no yes "lsm ")" | grep -E "6\.4B\.2[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" | tail -1)
if _text_ok "$_w64b_line" "серия ЛЖЁТ единицей"; then
    echo "    OK  6.4B.2 назвала класс «серия ЛЖЁТ единицей», а не «случай не предъявлен»"
    _replay_note "№457 stub mode" "$_w64b_line" "серия ЛЖЁТ единицей"
else
    _efail "№457: 6.4B.2 при stub mode в журнале и всех единицах обязана назвать класс «серия ЛЖЁТ единицей» — строка: $(printf '%s' "$_w64b_line" | cut -c1-190)"
fi

# ── B13. №458: СЧЁТ ВЕРЕН, ИМЕНОВАННЫЙ СОСТАВ ЛЖИВ. Закрывающий прогон волны
#    24.09.2026 напечатал «единиц 6, нулей 1 (нули у: dns fileaccess kmod lsm
#    network syscall tls)»: разбор серии вёлся с awk -F'"', где $NF это хвост
#    «} 1», а не величина, — значит $NF+0 == 0 истинно ДЛЯ ЛЮБОЙ серии.
#    Вердикт брался верно, а доказательство под ним называло не тех, и прогон
#    с нулём у tls выглядел бы ровно так же. Методика волны судит по
#    НАЗВАННОМУ составу, поэтому фикстура проверяет имена, а не только класс.
MB13="$WORK/mb13.txt"; _mk_metrics_b "$MB13" 3 1 "$_ALL6" "dns=1 lsm=0 tls=1"
_checkb "ось предъявлена обеими сторонами (№458: состав называется поимённо)" \
    "$(_runb "$MB13" B OK "$BIN_OK" no)" \
    6.4B.2=OK 6.4B.5=OK
_w64b_n458=$(printf '%s\n' "$(_runb "$MB13" B OK "$BIN_OK" no)" | grep -E "6\.4B\.2[[:space:]]+ДОСТИГНУТО" | tail -1)
_w64b_zpart=$(printf '%s' "$_w64b_n458" | sed -n 's/.*нулей [0-9]* (\([^)]*\)).*/\1/p')
_w64b_opart=$(printf '%s' "$_w64b_n458" | sed -n 's/.*единиц [0-9]* (\([^)]*\)).*/\1/p')
if [ "$(printf '%s' "$_w64b_zpart" | tr -s ' ' | sed 's/ *$//')" = "lsm" ]; then
    echo "    OK  6.4B.2 назвала нулём РОВНО lsm, а не весь состав серии"
else
    _efail "№458: при единственном нуле (lsm) метка обязана назвать ровно его — названо: «${_w64b_zpart:-ПУСТО}» (строка: $(printf '%s' "$_w64b_n458" | cut -c1-190))"
fi
case " $_w64b_opart " in
    *" tls "*) echo "    OK  6.4B.2 назвала единицы поимённо и tls среди них" ;;
    *) _efail "№458: состав единиц обязан называться поимённо и содержать tls — названо: «${_w64b_opart:-ПУСТО}»" ;;
esac
case " $_w64b_zpart " in
    *" tls "*|"tls "*|*" tls") _efail "№458: tls равен единице, но попал в состав нулей — разбор серии снова берёт не то поле" ;;
    *) : ;;
esac

echo
echo "--- сторож №373 для меток 6.4.B: каждая обязана вынести годную величину хоть на одном входе"
_allb_out="$(_runb "$MB1" B OK "$BIN_OK" yes)
$(_runb "$MB2" A NOTREQ "$BIN_OK" no)
$(_runb "$MB3" B OK "$BIN_OK" no)
$(_runb "$MB5" B OK "$BIN_OK" no)
$(_runb "$MB9" B OK "$BIN_OLD" no)"
for lbl in 6.4B.0 6.4B.1 6.4B.2 6.4B.3 6.4B.4 6.4B.5; do
    if printf '%s\n' "$_allb_out" | grep -qE "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ИЗМЕРЕНО)"; then
        echo "    OK  $lbl способна вынести годную величину"
    else
        _efail "№373: $lbl НИ НА ОДНОМ входе не смогла напечатать ДОСТИГНУТО/ИЗМЕРЕНО — строка неспособна сказать ничего, кроме отказа"
    fi
done
# Исключений в этой таблице НЕТ: в отличие от 6.4.5, у каждой метки волны
# 6.4.B есть предмет, способный дать годную величину на прогоне B.

# ═════════════════════════════════════════════════════════════════════════════
# БЛОК W64-REACHABILITY — сторож ДОСТИЖИМОСТИ критерия выхода (№451).
#
# ЗАЧЕМ ОТДЕЛЬНО. У блока один исход, стоящий денег: `die` до пролога, когда
# заход объявлен закрывающим (W64_INTENT=close), а тумблеры закрыть волну не
# позволяют. Ветка `die`, проверенная только глазами, — ровно та форма, из-за
# которой волна 6.4 уже потеряла прогон: офлайн-зелёное там означало «я прочёл
# код», а не «ветка исполнялась» ([[self-test-fixtures-miss-live-log-shape]],
# [[invariants-find-what-fixtures-cannot]]).
#
# Проверяется КОД ВЫХОДА, а не текст: die обязан быть 1, разведочный заход — 0.
if ! grep -q 'W64-REACHABILITY-BEGIN' "$PIPE" || ! grep -q 'W64-REACHABILITY-END' "$PIPE"; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: в $PIPE нет маркеров W64-REACHABILITY-BEGIN/END"
    exit 2
fi
sed -n '/W64-REACHABILITY-BEGIN/,/W64-REACHABILITY-END/p' "$PIPE" > "$WORK/reach.sh"
bash -n "$WORK/reach.sh" || { echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: блок W64-REACHABILITY не разбирается bash -n"; exit 2; }

# _reach <role> <W64_TLS_CONTROLS> <W63_BASELINE_CONTROLS> <W64_INTENT>
# Печатает «<код выхода>|<первая строка вывода>».
_reach() {
    local out rc
    out=$( set +e; env -i bash -c '
        set -u
        _w648_role="'"$1"'"
        W64_TLS_CONTROLS="'"$2"'"
        W63_BASELINE_CONTROLS="'"$3"'"
        W64_INTENT="'"$4"'"
        _r63_cfg="/tmp/w64-fixture-config.yaml"
        . "'"$WORK"'/reach.sh"
    ' 2>&1 )
    rc=$?
    printf '%s|%s' "$rc" "$(printf '%s\n' "$out" | head -1)"
}

_checkreach() { # <имя> <ожидаемый код> <ожидаемый маркер в строке> <role> <ctl> <blc> <intent>
    local name="$1" exp_rc="$2" exp_txt="$3"; shift 3
    local res rc line
    res=$(_reach "$@")
    rc="${res%%|*}"; line="${res#*|}"
    if [ "$rc" != "$exp_rc" ]; then
        _efail "достижимость/$name: код выхода $rc вместо $exp_rc — строка: $(printf '%s' "$line" | cut -c1-140)"
    elif ! printf '%s' "$line" | grep -q "$exp_txt"; then
        _efail "достижимость/$name: код $rc верный, но строка не несёт «$exp_txt» — $(printf '%s' "$line" | cut -c1-140)"
    else
        echo "    OK  $name → код $rc, класс назван"
    fi
}

echo
echo "=== СТОРОЖ ДОСТИЖИМОСТИ КРИТЕРИЯ ВЫХОДА (блок W64-REACHABILITY) ==="
_checkreach "закрывающий заход со всеми тумблерами → идёт дальше" \
    0 "ДОСТИЖИМОСТЬ КРИТЕРИЯ ВЫХОДА" B both on close
_checkreach "закрывающий заход БЕЗ контролей items 5/6 → die" \
    1 "СТОП ДО ПРОЛОГА" B off on close
_checkreach "закрывающий заход БЕЗ опорного набора → die" \
    1 "СТОП ДО ПРОЛОГА" B both off close
_checkreach "закрывающий заход на роли A → die (TLS выключен конфигом)" \
    1 "СТОП ДО ПРОЛОГА" A both on close
_checkreach "разведочный заход с теми же тумблерами → предупреждение, НЕ die" \
    0 "ВНИМАНИЕ" B off off probe
_checkreach "мусорное намерение → отказ с кодом 2, а не молчаливый probe" \
    2 "W64_INTENT" B both on nonsense

# ═════════════════════════════════════════════════════════════════════════════
# ITEM 1 и ITEM 2 волны 6.5 — ярус A, долги ПРИБОРА ОТЧЁТА.
#
# ITEM 1 (№460). №458 — не единичный дефект, а ОБРАЗЕЦ: величина, которой взят
# класс, и величина, напечатанная как доказательство, считались ДВУМЯ
# независимыми проходами. Класс был верен, доказательство под ним лгало.
# Точечная правка №458 сам образец не запрещала. Сторож №460 краснеет, когда
# величина, напечатанная в вердиктной строке, вычисляется в блоке эмиттеров
# больше одного раза — либо как одна переменная с двумя вычислениями, либо как
# одна и та же серия, разобранная двумя РАЗНЫМИ переменными (ровно №458: счёт
# единиц/нулей одной строкой, а их имена — другой).
#
# ITEM 2 (№461). Классовые фикстуры (№373) проверяли, что метка СПОСОБНА
# напечатать годную величину, — но не то, что напечатанная величина ВЕРНА.
# №455/№457/№458 трижды давали верный класс под лживым текстом, и фикстуры
# молчали. Здесь у КАЖДОЙ метки есть сверка ТЕКСТА (имена и числа), а реестр
# сверенных меток (№461) сторожит полноту: пропуск = красный с перечислением.
# ═════════════════════════════════════════════════════════════════════════════

# _emitter_printed_vars <файл блока> — базовые имена переменных, которые
# печатает ХОТЬ ОДНА вердиктная строка блока. Вердиктной считается только
# строка `echo`, несущая метку и вердиктное слово: те же слова в прозе
# (комментариях) строками доказательства не являются и не считаются.
_emitter_printed_vars() {
    grep -E '^[[:space:]]*echo "' "$1" \
        | grep -E 'ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО' \
        | grep -oE '\$\{?[A-Za-z_][A-Za-z0-9_]*' \
        | sed -E 's/^\$\{?//' | sort -u
}

# _paren_delta <текст> — баланс «(» минус «)», УЧАСТНЫЙ К КАВЫЧКАМ. На вход идёт
# тело v=$( ... ) ЦЕЛИКОМ (многострочно), поэтому состояние кавычек переносится
# через строки: живой awk-программой тело открывает ОДНУ кавычку на первой строке
# и закрывает её на последней.
#
# Автомат NORMAL / IN_SINGLE / IN_DOUBLE; «(»/«)» учитываются ТОЛЬКО в NORMAL, и
# тело считается закрытым, когда баланс NORMAL-скобок доходит до нуля:
#   NORMAL:    `'` → IN_SINGLE; `"` → IN_DOUBLE; `(`/`)` — в баланс; `\` экранирует;
#              token-leading `#` — комментарий до конца строки (скобки в нём НЕ
#              считаются).
#   IN_SINGLE: всё буквально (в т.ч. `"` и `(`/`)`), выход — только по `'`. Именно
#              поэтому `split($1, a, /collector="/)` и `"\""` внутри awk-тела не
#              переключают режим и не ломают выемку ЖИВЫХ тел.
#   IN_DOUBLE: `\` экранирует следующий символ; `"` → NORMAL; `'` буквальна;
#              скобки внутри двойных кавычек НЕ считаются.
#
# `#`-КОММЕНТАРИИ (заход 6.5, item 1). В NORMAL `#` считается началом
# комментария ТОЛЬКО когда он token-leading: в начале строки либо сразу после
# пробела/таба или одного из метасимволов-границ слова `;|&()><`. Тогда до
# конца строки ни `(`, ни `)` в баланс не идут (по правилам sh в команде
# `x=$(cmd # note )` скобка ВНУТРИ комментария тело НЕ закрывает, а `(` в
# комментарии его НЕ открывает; `)# (`, `># (` — тоже комментарий после
# границы слова). `#` внутри слова (`${x#y}`, `a#b`) и `#` в кавычках — НЕ
# комментарий: поэтому `${x#…}`/`"…#…"` баланс не сдвигают. Полноценным
# sh-парсером `#`-комментарии по-прежнему НЕ покрыты: список границ — ровно
# метасимволы sh `;|&()><` плюс пробел/таб/начало строки, и этого хватает
# живым блокам, но произвольный shell-код автомат не разбирает.
# Наивный счёт «(» минус «)» (прошлая версия) закрывал тело рано на `)` внутри
# строки (напр. `awk 'BEGIN { print ")" }'`): хвост тела тихо отбрасывался, а
# переменная выпадала из подписи. Полноценный sh-парсер по-прежнему не заводится
# (это не нужно): покрыт ровно тот класс, что даёт живые блоки.
_paren_delta() { # <текст тела v=$( … )> → «(»−«)» вне кавычек и вне `#`-комментариев
    printf '%s\n' "$1" | awk -v sq="'" -v dq='"' '
        BEGIN { st = "N"; p = "" }
        {
            n = length($0)
            for (i = 1; i <= n; i++) {
                c = substr($0, i, 1)
                if (esc) { esc = 0; p = c; continue }
                if (st == "N") {
                    if (c == "#" && (p == "" || p == " " || p == "\t" || p == ";" || p == "|" || p == "&" || p == "(" || p == ")" || p == ">" || p == "<")) break
                    if (c == "\\") esc = 1
                    else if (c == sq) st = "S"
                    else if (c == dq) st = "D"
                    else if (c == "(") bal++
                    else if (c == ")") bal--
                } else if (st == "S") {
                    if (c == sq) st = "N"
                } else {
                    if (c == "\\") esc = 1
                    else if (c == dq) st = "N"
                }
                p = c
            }
            p = ""
        }
        END { print bal + 0 }'
}

# _norm_pred <предикат> — канон предиката среза (WARNING 1). Убирает пробелы,
# `+0` и `int(...)`, затем сводит к одному ключу семантически ОДИН срез: для
# неотрицательной счётчиковой величины `==0`/`<=0`/`<1` — это ноль, а
# `!=0`/`>0`/`>=1` — ненулевое. Так `$NF+0 == 0` и `$NF == 0` (дубль №460 на
# живом read-стиле) дают один ключ. РЕАЛЬНО разные срезы остаются разными:
# `==1`, `>0`, `<3` не схлопываются (`>0` — не то же, что `$NF==1`).
# WARNING 1 волны 6.5: каждый предикат завершается `\n` — иначе конвейер
# `while … _norm_pred … done | sort -u` склеивал бы ВСЕ предикаты тела в одну
# строку, и ключ среза становился бы УПОРЯДОЧЕННОЙ последовательностью, а не
# МНОЖЕСТВОМ. Тогда два тела с теми же срезами, перечисленными в другом
# порядке (`$NF==1$NF==0` против `$NF==0$NF==1`), давали бы разные ключи, и
# №460 молчал бы на настоящем дубле (ровно образец №458 с переставленными
# ветками awk счётчиков).
_norm_pred() {
    local p="$1" rest op num
    p="${p//[[:blank:]]/}"
    p="${p//+0/}"
    p="${p//int(/}"
    p="${p//)/}"
    rest="${p#\$NF}"
    op="${rest%%[0-9]*}"
    num="${rest#"$op"}"
    case "${op}${num}" in
        '==0'|'<=0'|'<1') printf '$NF==0\n' ;;
        '!=0'|'>0'|'>=1') printf '$NF>0\n' ;;
        *) printf '$NF%s%s\n' "$op" "$num" ;;
    esac
}

# _assign_sig <тело-присваивания> — срезы ВЫЧИСЛЕНИЯ, по строке на срез:
# «серия ~ предикат среза ~ label-селектор ~ источник». Тело передаётся ЦЕЛИКОМ
# (многострочно): для v=$( ... ) это весь блок до парной скобки, поэтому имя
# серии и предикат видны, даже если они лежат на нижних строках awk. Предикат —
# $NF(+0) сравнение с числом: ==, !=, >=, <=, >, <, канонизируется _norm_pred
# (item 1г/WARNING 1: семантически один срез не схлопывается/не расходится
# произвольно). Пустой предикат — срез «*» (вся серия). WARNING 2: в ключ входит
# и label-селектор (`collector="..."`, `reason="..."` и т.п.) — иначе
# агрегат и именованная выборка одной серии считались бы одним срезом и №460
# давал бы ЛОЖНЫЙ красный. Источник входит в срез: два СНИМКА одной серии на
# границах окна (6.4.1) дублем не считаются. Пустой набор срезов = тело не про
# серию.
_assign_sig() {
    local body="$1" series sels labs src s sel
    series=$(printf '%s\n' "$body" | grep -oE 'ebpf_guard_[a-z_]+' | sort -u)
    [ -n "$series" ] || return 0
    sels=$(printf '%s\n' "$body" \
        | grep -oE '(\$NF|int[[:space:]]*\([[:space:]]*\$NF[[:space:]]*\))(\+0)?[[:space:]]*(==|!=|>=|<=|>|<)[[:space:]]*[0-9]+' \
        | while IFS= read -r p; do _norm_pred "$p"; done | sort -u)
    [ -n "$sels" ] || sels='*'
    # Значение лейбла ограничено «словарным» классом: иначе выражение-код awk
    # вида `split($1, a, /collector="/)` давало бы доистаточный (мусорный)
    # селектор и разводило бы по ключу тела, отличающиеся только способом
    # разбора лейбла (регресс на негативах №460.1/№460.4).
    labs=$(printf '%s\n' "$body" \
        | grep -oE '(collector|reason|event_type|type|method|family|mode)="[A-Za-z0-9_.:-]*"' \
        | sed 's/[[:blank:]]//g' | sort -u)
    [ -n "$labs" ] || labs='-'
    labs=$(printf '%s' "$labs" | tr '\n' ',')
    src=$(printf '%s\n' "$body" | grep -oE '\$ART/[A-Za-z0-9._/-]+|_w63l_metrics' | sort -u)
    [ -n "$src" ] || src='?'
    src=$(printf '%s' "$src" | tr '\n' ',')
    while IFS= read -r s; do
        [ -n "$s" ] || continue
        while IFS= read -r sel; do
            [ -n "$sel" ] || continue
            printf '%s~%s~%s~%s\n' "$s" "$sel" "$labs" "$src"
        done <<< "$sels"
    done <<< "$series"
}

# _assign_record — дописать срезы тела в массивы K/S. Массивы объявлены local
# в _assign_map и видны здесь по динамической области видимости bash.
_assign_record() { # <имя> <тело> <участок>
    local name="$1" body="$2" site="$3" k
    while IFS= read -r k; do
        [ -n "$k" ] || continue
        K[$name]="${K[$name]:-}${k}"$'\n'
        S[$name]="${S[$name]:-}${site} "
    done < <(_assign_sig "$body")
}

# _assign_map <файл блока> — по одному срезу на строку: «ИМЯ<TAB>СРЕЗ<TAB>УЧАСТОК».
# Тело v=$( ... ) берётся ЦЕЛИКОМ до парной скобки (многострочно). Для
# IFS=... read -r v1 v2 <<<"$src" срезы наследуются от присваивания, породившего
# $src (учёт <<<) — иначе «живой» стиль разбора через read не попадал в разбор
# вовсе, и сторож №460 был почти тождественно-зелёным. Участок — номер
# присваивания-вычислителя: один срез, разобранный ДВУМЯ участками, и есть
# образец №458.
_assign_map() {
    local file="$1"
    local line name rest body bal site=0 collecting=0 curname="" cursite=0
    local -A K S
    while IFS= read -r line || [ -n "$line" ]; do
        if [ "$collecting" -eq 1 ]; then
            body="${body}"$'\n'"${line}"
            # Баланс пересчитывается по ВСЕМУ телу: состояние кавычек держится
            # между строками, поэтому одной текущей строки для _paren_delta мало.
            bal=$(_paren_delta "$body")
            if [ "$bal" -le 0 ]; then
                collecting=0
                _assign_record "$curname" "$body" "$cursite"
            fi
            continue
        fi
        if [[ "$line" == *'<<<'* ]] && [[ "$line" =~ read[[:space:]]+-r[[:space:]] ]]; then
            local src="${line#*<<<}"
            # №460 (обход №458 одним пробелом): у формы `<<< "$_row"` ведущие
            # пробелы/табы после `<<<` давали пустой src, и `${K[$src]:-}`
            # ронял разбор на `K: bad array subscript` — наследование срезов не
            # происходило вовсе, и сторож оставался зелёным на гибридном
            # образце «счёт через read + имена вторым awk». Срезаем ведущие
            # пробелы/табы и пустой источник пропускаем явно.
            src="${src#"${src%%[![:space:]]*}"}"
            src="${src//[\"\$\{\}]/}"
            src="${src%%[[:space:]]*}"
            local left="${line%%<<<*}"
            left="${left##*read}"
            local w
            [ -n "$src" ] || continue
            for w in $left; do
                [[ "$w" == -* ]] && continue
                [[ "$w" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
                if [ -n "${K[$src]:-}" ]; then
                    K[$w]="${K[$src]}"
                    S[$w]="${S[$src]}"
                fi
            done
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)= ]]; then
            name="${BASH_REMATCH[1]}"
            rest="${line#*=}"
            if [[ "$rest" == '$('* ]]; then
                site=$((site + 1))
                body="$rest"
                bal=$(_paren_delta "$rest")
                if [ "$bal" -le 0 ]; then
                    _assign_record "$name" "$body" "$site"
                else
                    collecting=1; curname="$name"; cursite="$site"
                fi
            fi
        fi
    done < "$file"
    local nm k st
    for nm in "${!K[@]}"; do
        st=$(printf '%s' "${S[$nm]}" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ',')
        while IFS= read -r k; do
            [ -n "$k" ] || continue
            printf '%s\t%s\t%s\n' "$nm" "$k" "${st%,}"
        done <<< "${K[$nm]}"
    done
    if [ "$collecting" -eq 1 ]; then
        echo "    ПРОВАЛ №460-разбор: многострочное тело ${curname:-?} (участок ${cursite:-0}) не закрылось к концу файла — незакрытая кавычка/скобка в теле" >&2
        return 1
    fi
}

# _guard_single_expr <файл блока> <имя> — сторож №460. Печатает найденные
# нарушения, код возврата 1 при находке. Краснеет, когда напечатанная величина
# рождена ДВУМЯ участками: либо одна переменная с двумя вычислениями, либо один
# срез (серия+предикат+label-селектор+источник), разобранный двумя РАЗНЫМИ
# переменными (образец №458). И печатные переменные, и срезы берутся из
# _assign_map, то есть живой read-стиль входит в разбор, а не выпадает из него.
_guard_single_expr() {
    local file="$1" name="$2" bad=0
    local sigfile="$WORK/sig460-${name}.txt"
    local printf_file="$WORK/printed460-${name}.txt"
    local v sites dup d
    _assign_map "$file" | sort > "$sigfile"
    : > "$printf_file"
    while IFS= read -r v; do
        [ -n "$v" ] || continue
        awk -F'\t' -v v="$v" '$1 == v { n = split($3, a, ","); for (i = 1; i <= n; i++) print $2 "\t" v "\t" a[i] }' "$sigfile" >> "$printf_file"
    done < <(_emitter_printed_vars "$file")
    # 1) ОДНА напечатанная переменная, вычисленная больше чем одним участком.
    while IFS= read -r v; do
        [ -n "$v" ] || continue
        sites=$(awk -F'\t' -v v="$v" '$2 == v { n = split($3, a, ","); for (i = 1; i <= n; i++) print a[i] }' "$printf_file" | sort -u | grep -c . || true)
        if [ "${sites:-0}" -gt 1 ]; then
            echo "    ПРОВАЛ №460/${name}: ${v} напечатана в вердиктной строке, но вычисляется ${sites} раз(а) — величина обязана вычисляться ОДИН раз"
            bad=1
        fi
    done < <(cut -f2 "$printf_file" 2>/dev/null | sort -u)
    # 2) ОДИН срез, разобранный двумя разными участками и кормящий разные
    #    напечатанные переменные (ровно №458).
    dup=$(awk -F'\t' '
        { key = $1; var = $2; site = $3
          if (!(key in first)) { first[key] = var; firstsite[key] = site; next }
          if (firstsite[key] != site && first[key] != var) {
              pair = first[key] "~" var
              if (!(pair in pairseen)) { print pair; pairseen[pair] = 1 } } }' "$printf_file")
    if [ -n "$dup" ]; then
        while IFS= read -r d; do
            [ -n "$d" ] || continue
            echo "    ПРОВАЛ №460/${name}: один срез (серия, предикат и label-селектор) разбирают ДВЕ независимые переменные: ${d//\~/ и } — класс и доказательство обязаны читать одну и ту же переменную (образец №458)"
        done <<< "$dup"
        bad=1
    fi
    return "$bad"
}

# _assign_region <файл блока> <имя> — текст прямого присваивания `имя=` до
# начала следующего присваивания/read, без строк комментариев. Приём для
# WARNING 2 волны 6.5: область строится ТЕКСТУАЛЬНО и НАМЕРЕННО не режется
# счётчиком скобок (_paren_delta) — это НЕЗАВИСИМЫЙ от _assign_map источник:
# если разбор тела почему-либо неполон (напр. тело не закрылось), печатная
# величина всё равно видна здесь и уличена _check460_coverage.
# ОГРАНИЧЕНИЕ: область может захватить echo-строку с именем серии до
# следующего присваивания и дать ложную «серийность»; на живых блоках такой
# ложной серийности нет, а негативы задают области явно.
_assign_region() { # <файл блока> <имя>
    local file="$1" var="$2"
    awk -v v="$var" '
        $0 ~ "^[[:space:]]*" v "=" { on=1; print; next }
        on==1 {
            if ($0 ~ /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=/ || $0 ~ /^[[:space:]]*(IFS=[^[:space:]]*[[:space:]]+)?read[[:space:]]/) { exit }
            if ($0 ~ /^[[:space:]]*#/) next
            print
        }' "$file"
}

# _read_sources <файл блока> <имя> — источники `<<<` у read-строк, в чьём
# списке целей стоит <имя>. Так `IFS=… read -r a b <<<"$row"` связывает a/b с
# телом, породившим $row.
_read_sources() { # <файл блока> <имя>
    local file="$1" var="$2" line src left w
    while IFS= read -r line; do
        [[ "$line" == *'<<<'* && "$line" == *read* ]] || continue
        left="${line%%<<<*}"
        for w in $left; do
            [[ "$w" == -* ]] && continue
            [[ "$w" == "$var" ]] || continue
            src="${line#*<<<}"
            src="${src#"${src%%[![:space:]]*}"}"
            src="${src//[\"\$\{\}]/}"
            src="${src%%[[:space:]]*}"
            [ -n "$src" ] && printf '%s\n' "$src"
            break
        done
    done < "$file"
}

# _var_is_serial <файл блока> <имя> — присваивание переменной читает серию
# `ebpf_guard_` либо прямо, либо через `read … <<<` из такого присваивания.
_var_is_serial() { # <файл блока> <имя>
    local file="$1" var="$2" src
    _assign_region "$file" "$var" | grep -q 'ebpf_guard_' && return 0
    while IFS= read -r src; do
        [ -n "$src" ] || continue
        [ "$src" = "$var" ] && continue
        _var_is_serial "$file" "$src" && return 0
    done < <(_read_sources "$file" "$var")
    return 1
}

# _printed_serial_vars <файл блока> — печатные вердиктные величины, рождённые
# серией ebpf_guard_ (текстуально, НЕЗАВИСИМО от _assign_map). Именно этот
# список обязан целиком войти в подпись: неполный разбор тела (тело не закрылось)
# уносит переменную из разбора, но не из этого списка (WARNING 2 волны 6.5).
_printed_serial_vars() { # <файл блока>
    local file="$1" v
    while IFS= read -r v; do
        [ -n "$v" ] || continue
        _var_is_serial "$file" "$v" && printf '%s\n' "$v"
    done < <(_emitter_printed_vars "$file")
}

# _check460_coverage <файл БЛОКА> <имя> — (в) item 1 + WARNING 2 волны 6.5.
# Живой блок обязан быть не просто зелёным, а РАЗОБРАННЫМ: КАЖДАЯ печатная
# серийная величина обязана войти в подпись. Список не зашит (было восемь
# имён) — он выводится из самого блока, поэтому неполный разбор, из-за которого
# переменная молча выпала из подписи (_assign_map вернул неполную карту), есть
# КРАСНОЕ. Пустой список — тоже КРАСНОЕ (проверка пустого набора есть
# тождество, а не проверка).
_check460_coverage() { # <файл блока> <имя>
    local file="$1" name="$2"
    local sig v miss="" seen=""
    sig=$(_assign_map "$file" 2>/dev/null | cut -f1 | sort -u)
    while IFS= read -r v; do
        [ -n "$v" ] || continue
        seen="${seen}${v} "
        printf '%s\n' "$sig" | grep -qxF -- "$v" || miss="${miss}${v} "
    done < <(_printed_serial_vars "$file")
    if [ -n "$miss" ]; then
        _efail "№460/${name}: печатные серийные величины выпали из разбора: ${miss}— сторож пропускает ровно тот стиль, ради которого заведён"
    elif [ -z "$seen" ]; then
        _efail "№460/${name}: в блоке нет ни одной печатной серийной величины — проверять нечего (тождество, а не проверка)"
    else
        echo "    OK  №460/${name}: все печатные серийные величины входят в разбор (${seen% })"
    fi
}

_run_guard460() { # <файл блока> <имя>
    local file="$1" name="$2" out rc
    out=$(_guard_single_expr "$file" "$name"); rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "    OK  №460/${name}: ни одна напечатанная величина не вычисляется дважды"
    else
        printf '%s\n' "$out"
        _efail "№460/${name}: величина, напечатанная в вердиктной строке, вычисляется дважды — см. строки выше (образец №458)"
    fi
}

# _check460_complete <файл блока> <имя> — (пункт 3 яруса A, item 1/2).
# Гарантия ровно такая: КАЖДОЕ многострочное тело v=$( ... ) живого блока должно
# закрыться до конца файла, иначе _assign_map возвращает 1 с названным телом.
# Код возврата: 0 — тело закрыто, 1 — НЕ закрыто (красная ветка; негатив ниже
# опирается на него, а не только на подстроку вывода).
# _paren_delta считает скобки участно к кавычкам И к `#`-комментариям
# (автомат NORMAL/IN_SINGLE/IN_DOUBLE + token-leading `#` до конца строки),
# поэтому `)` внутри однокавычечного awk-тела и внутри комментария выемку не
# рвёт; незакрытым тело остаётся только при реально несбалансированной
# кавычке/скобке (комментарий `#` над _paren_delta — с парным негативом ниже).
# Полноценный sh-парсер не заводится (см. комментарий над _paren_delta), так что
# гарантия ограничена разбором `$( ... )`, а не произвольного sh-кода.
_check460_complete() { # <файл> <имя>
    local file="$1" name="$2"
    if _assign_map "$file" > /dev/null; then
        echo "    OK  №460/${name}: живой блок разобран целиком (все многострочные тела закрыты)"
    else
        _efail "№460/${name}: живой блок разобран НЕ целиком — многострочное тело не закрылось к концу файла (несбалансированная кавычка/скобка; учёт кавычек и #-комментариев в _paren_delta уже есть)"
        return 1
    fi
}

# _line_label <строка> — метка из САМОЙ строки вердикта. Реестр наполняется из
# напечатанного, а не из имени фикстуры: сверка не может зарегистрировать метку,
# которой в строке нет.
# Метка берётся из строки: 6.4.N, 6.4B.N и метки волны 6.5 (6.5.N). Список
# префиксов расширяется ВМЕСТЕ с таблицей меток — иначе новая метка проходит
# сверку текста «мимо» и №461 читает это как «сверена».
_line_label() { printf '%s' "$1" | grep -oE '6\.(4B?|5)\.[0-9]+' | head -1; }

# _TEXT_SEEN — реестр меток, чей НАПЕЧАТАННЫЙ ТЕКСТ сверён (№461).
_TEXT_SEEN=""

# _need_text <имя> <строка> <обязательные подстроки…> — сверка ТЕКСТА: берёт
# вердиктную строку метки и требует присутствия имён и чисел. Хотя бы одно
# НЕПУСТОЕ ожидание обязательно (пустой набор — тождество, а не проверка).
# Метка берётся из строки и регистрируется ТОЛЬКО после успешной сверки ВСЕХ
# ожиданий (№461): неудачная сверка не смеет засчитать метку сверенной.
_need_text() {
    local name="$1" line="$2"; shift 2
    local lbl sub miss="" nonempty=0
    lbl=$(_line_label "$line")
    for sub in "$@"; do [ -n "$sub" ] && nonempty=1; done
    if [ "$#" -lt 1 ] || [ "$nonempty" -eq 0 ]; then
        _efail "текст/${name}: не задано ни одного непустого ожидания — сверка пустого набора есть тождество, а не проверка (№461); метка не зарегистрирована"
        return 0
    fi
    if [ -z "${lbl:-}" ]; then
        _efail "текст/${name}: в строке не найдена метка 6.4.N/6.4B.N/6.5.N — строка: $(printf '%s' "$line" | cut -c1-190)"
        return 0
    fi
    for sub in "$@"; do
        _text_ok "$line" "$sub" || miss="${miss}«${sub}» "
    done
    if [ -n "$miss" ]; then
        _efail "текст/${name} (${lbl}): в напечатанной строке нет ${miss}— строка: $(printf '%s' "$line" | cut -c1-220)"
        return 0
    fi
    _TEXT_SEEN="${_TEXT_SEEN}${lbl} "
    _replay_note "$name" "$line" "$@"
    echo "    OK  текст ${lbl}: имена и числа на месте (${name})"
}

# _line_of <вывод блока> <метка> — самая вердиктная строка этой метки.
_line_of() {
    printf '%s\n' "$1" | grep -E "(^|[^0-9.])${2//./\\.}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" | tail -1
}

# ── ITEM 1. Сторож №460 гоняется по ОБОИМ вырезанным блокам. Он обязан быть
#    красным на искусственном образце (негативная проверка ниже) и зелёным на
#    живых блоках — иначе правка item 1.1 ничего не доказала.
echo
echo "=== ITEM 1: одна величина — одно вычисление (сторож №460, образец №458) ==="
_run_guard460 "$WORK/block.sh" "6.4.x"
_run_guard460 "$WORK/blockb.sh" "6.4.B"
# (в): живой блок обязан быть не только зелёным, но и РАЗОБРАННЫМ — печатные
# величины живого read-стиля обязаны попасть в подпись.
_check460_coverage "$WORK/block.sh" "6.4.x"
_check460_coverage "$WORK/blockb.sh" "6.4.B"
# (пункт 3): живой блок обязан разбираться ЦЕЛИКОМ — иначе зелёный №460
# ничего не значит. _paren_delta считает скобки участно к кавычкам, поэтому тело
# с `)` внутри однокавычечного awk-тела доходит до конца.
_check460_complete "$WORK/block.sh" "6.4.x"
_check460_complete "$WORK/blockb.sh" "6.4.B"

# Негативная проверка №460.1: ровно запрещённый образец №458 — счёт нулей и их
# именованный состав собраны ДВУМЯ однострочными проходами awk по одной серии.
_bad460="$WORK/bad460.sh"
cat > "$_bad460" <<'BAD460'
_up_zero=$(printf '%s\n' "${_w63l_metrics:-}" | awk '$1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 {n++} END{print n+0}')
_up_zn=$(printf '%s\n' "${_w63l_metrics:-}" | awk '$1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { if (split($1, a, /collector="/) > 1) { split(a[2], b, "\""); printf "%s ", b[1] } }')
if [ "${_up_zero:-0}" -ge 1 ]; then
    echo "OK: 6.4B.2 ДОСТИГНУТО: нулей ${_up_zero} (${_up_zn:-?})"
fi
BAD460
# _check460_negative <имя> <файл> <обязательная подстрока в диагнозе>
_check460_negative() {
    local name="$1" file="$2" want="$3" out rc
    out=$(_guard_single_expr "$file" "$name"); rc=$?
    if [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q "$want"; then
        printf '%s\n' "$out"
        echo "    OK  №460 покраснел на «${name}»"
    else
        _efail "№460 НЕ покраснел на «${name}» (код $rc, ждали «${want}») — проверка бесполезна"
    fi
}

# _check460_coverage_negative <имя> <файл блока> <обязательная подстрока> —
# WARNING 2 волны 6.5: _check460_coverage обязана КРАСНЕТЬ на блоке, где
# печатная серийная величина выпала из разбора. Гоняется в подоболочке:
# настоящий FAILS портить нельзя.
_check460_coverage_negative() {
    local name="$1" file="$2" want="$3" out
    out=$( ( _check460_coverage "$file" "$name" ) 2>&1 )
    if printf '%s\n' "$out" | grep -q 'ПРОВАЛ' && printf '%s\n' "$out" | grep -q "$want"; then
        printf '%s\n' "$out"
        echo "    OK  №460-полнота покраснела на «${name}»"
    else
        _efail "№460-полнота НЕ покраснела на «${name}» (ждали «${want}») — вывод: $(printf '%s' "$out" | cut -c1-200)"
    fi
}

# _check460_complete_negative <имя> <файл блока> <обязательная подстрока> —
# заход 6.5, item 1: красная ветка _check460_complete до этого негатива НЕ
# исполнялась (оба вызова позитивные), а незакрытое тело шло через
# _check460_coverage. Здесь _check460_complete зовётся на НЕЗАКРЫТОМ теле и
# обязана КРАСНЕТЬ; дефект «гарантия разбора не проверена» больше не может
# остаться незамеченным. Гоняется в подоболочке: настоящий FAILS портить
# нельзя.
#
# BLOCKER захода 6.5, item 1: одной подстроки «не закрылось к концу файла»
# НЕДОСТАТОЧНО. Безусловный диагностический echo внутри _assign_map печатает ту
# же фразу в stderr (и попадает сюда через 2>&1) даже когда красная ветка не
# исполняется. Поэтому негатив требует ВСЕ три условия: (1) ненулевой код
# возврата _check460_complete, (2) характерный текст КРАСНОЙ ветки «разобран
# НЕ целиком», (3) ОТСУТСТВИЕ зелёной формулировки «разобран целиком». Мутация
# `_assign_map` с удалённым `return 1` даёт rc=0 и зелёный вывод — негатив
# обязан это назвать.
_check460_complete_negative() {
    local name="$1" file="$2" want="$3" out rc
    out=$( ( _check460_complete "$file" "$name" ) 2>&1 ); rc=$?
    if [ "$rc" -ne 0 ] \
        && printf '%s\n' "$out" | grep -q "$want" \
        && printf '%s\n' "$out" | grep -q 'разобран НЕ целиком' \
        && ! printf '%s\n' "$out" | grep -q 'разобран целиком'; then
        printf '%s\n' "$out"
        echo "    OK  №460-разбор покраснел на «${name}» (rc=$rc)"
    else
        _efail "№460-разбор НЕ покраснел на «${name}» (rc=$rc, ждали ненулевой код и «${want}» с красной формулировкой, без зелёной ветки) — вывод: $(printf '%s' "$out" | cut -c1-200)"
    fi
}

# Негативная проверка №460.2: ОДНА И ТА ЖЕ напечатанная переменная,
# вычисленная дважды (второй проход затирает первый).
_bad460b="$WORK/bad460b.sh"
cat > "$_bad460b" <<'BAD460B'
_one=$(printf '%s\n' "${_w63l_metrics:-}" | awk '/^ebpf_guard_events_total/{print $NF}')
_one=$(printf '%s\n' "${_w63l_metrics:-}" | awk '/^ebpf_guard_events_total/{print $NF+0}')
echo "OK: 6.4.1 ИЗМЕРЕНО: вход = ${_one}"
BAD460B

# Негативная проверка №460.3: ГИБРИДНЫЙ образец — счёт одним проходом через
# read, а имена — ВТОРЫМ независимым однострочным awk. До правки (а) второе
# вычисление выпадало из разбора, и сторож оставался зелёным ровно на этом
# стиле; теперь оба участка видны и срез совпадает.
_bad460h="$WORK/bad460-hybrid.sh"
cat > "$_bad460h" <<'BAD460H'
_w64b_up_row=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ {
        n++
        cname = ""
        if (split($1, a, /collector="/) > 1) { split(a[2], b, "\""); cname = b[1] }
        if ($NF+0 == 0) { z++; if (cname != "") zn = zn cname " " }
    }
    END { printf "%d\t%s", z+0, zn }')
IFS=$'\t' read -r _up_zero _up_zn <<<"$_w64b_up_row"
_up_zn2=$(printf '%s\n' "${_w63l_metrics:-}" | awk '$1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { if (split($1, a, /collector="/) > 1) { split(a[2], b, "\""); printf "%s ", b[1] } }')
echo "OK: 6.4B.2 ДОСТИГНУТО: нулей ${_up_zero} (${_up_zn2:-?})"
BAD460H

# Негативная проверка №460.4: ПОЛНОСТЬЮ МНОГОСТРОЧНЫЙ дубль — обе переменные
# рождаются своими многострочными awk по одному срезу одной серии.
_bad460m="$WORK/bad460-multiline.sh"
cat > "$_bad460m" <<'BAD460M'
_up_zero=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 {
        n++
    }
    END { print n+0 }')
_up_zn=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 {
        if (split($1, a, /collector="/) > 1) { split(a[2], b, "\""); printf "%s ", b[1] }
    }')
echo "OK: 6.4B.2 ДОСТИГНУТО: нулей ${_up_zero} (${_up_zn:-?})"
BAD460M

# Негативная проверка №460.5 (КРИТИЧНО, обход №458 ОДНИМ ПРОБЕЛОМ): тот же
# гибридный образец, но в форме `<<< "$_row"` — с ПРОБЕЛОМ после `<<<`. До
# правки src после срезания кавычек/пробелов становился пустым, `${K[$src]:-}`
# падал на `K: bad array subscript`, срезы через read НЕ наследовались — и
# сторож был зелёным ровно на этом обходе. Теперь src срезает ведущие
# пробелы/табы и пустой источник пропускается — образец обязан краснеть.
_bad460hs="$WORK/bad460-hybrid-space.sh"
cat > "$_bad460hs" <<'BAD460HS'
_w64b_up_row=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ {
        n++
        cname = ""
        if (split($1, a, /collector="/) > 1) { split(a[2], b, "\""); cname = b[1] }
        if ($NF+0 == 0) { z++; if (cname != "") zn = zn cname " " }
    }
    END { printf "%d\t%s", z+0, zn }')
IFS=$'\t' read -r _up_zero _up_zn <<< "$_w64b_up_row"
_up_zn2=$(printf '%s\n' "${_w63l_metrics:-}" | awk '$1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { if (split($1, a, /collector="/) > 1) { split(a[2], b, "\""); printf "%s ", b[1] } }')
echo "OK: 6.4B.2 ДОСТИГНУТО: нулей ${_up_zero} (${_up_zn2:-?})"
BAD460HS

# Негативная проверка №460.6 (WARNING 1): ОДИН И ТОТ ЖЕ срез записан разными
# написаниями предиката — `$NF+0 == 0` и `$NF == 0`. До канонизации _assign_sig
# это два разных ключа и №460 зелёный на дубле; после — один срез, красный.
_bad460p="$WORK/bad460-predicate.sh"
cat > "$_bad460p" <<'BAD460P'
_up_a=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { n++ }
    END { print n+0 }')
_up_b=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF == 0 { n++ }
    END { print n+0 }')
echo "OK: 6.4B.2 ДОСТИГНУТО: нулей ${_up_a} (${_up_b})"
BAD460P

# Негативная проверка №460.7 (WARNING 1, КОРЕНЬ: _norm_pred без `\n`): два тела
# считают РОВНО те же срезы одной серии, но перечисляют ветки awk в РАЗНОМ
# порядке (`$NF+0 == 1` раньше `$NF+0 == 0` в теле A и наоборот в теле B).
# Пока предикаты не завершались переводом строки, `sort -u` собирал из них
# УПОРЯДОЧЕННУЮ последовательность, ключи тел расходились — и №460 оставался
# ЗЕЛЁНЫМ на настоящем дубле. После — оба ключа один и тот же МНОЖЕСТВО-срез,
# обе величины напечатаны, №460 обязан краснеть.
_bad460o="$WORK/bad460-order.sh"
cat > "$_bad460o" <<'BAD460O'
_up_a=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 1 { one++ }
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { zero++ }
    END { print one+0 }')
_up_b=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { zero++ }
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 1 { one++ }
    END { print zero+0 }')
echo "OK: 6.4B.2 ДОСТИГНУТО: единиц ${_up_a}, нулей ${_up_b}"
BAD460O

# Негативная проверка №460.8 (WARNING 1, контроль): тот же дубль, но ветки awk
# перечислены в ОДИНАКОВОМ порядке. Это доказывает, что №460 ловит сам дубль, а
# не артефакт порядка (набор срезов совпадает и до, и после правки `\n`).
_bad460o2="$WORK/bad460-order-same.sh"
cat > "$_bad460o2" <<'BAD460O2'
_up_a=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 1 { one++ }
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { zero++ }
    END { print one+0 }')
_up_b=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 1 { one++ }
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { zero++ }
    END { print zero+0 }')
echo "OK: 6.4B.2 ДОСТИГНУТО: единиц ${_up_a}, нулей ${_up_b}"
BAD460O2

# Негативная проверка №460.9 (КОРЕНЬ: _check460_complete): тело серийной
# величины реально НЕ закрывается к концу файла (одиночная кавычка awk-тела не
# закрыта) — до правки _paren_delta закрывал его наивно и отбрасывал хвост, но
# незакрытым оно остаётся и с участным к кавычкам автоматом. _assign_map
# возвращает 1, _up_zero выпадает из подписи, и _check460_coverage обязана это
# назвать. Это — единственный оставшийся способ уронить печатную серийную
# величину из разбора, поэтому негатив на полноту разбора сохранён.
_bad460e="$WORK/bad460-unclosed.sh"
cat > "$_bad460e" <<'BAD460E'
_up_zero=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { n++ }
    END { print n+0 }
echo "OK: 6.4B.2 ДОСТИГНУТО: нулей ${_up_zero}"
BAD460E

# Негативная проверка №460.10 (ОСТАТОЧНЫЙ WARNING волны 6.5, CORRECT: _paren_delta):
# `)` стоит ВНУТРИ однокавычечного awk-тела в ПЕРВОЙ строке тела, а печатная
# серийная величина — в хвосте. Наивный счётчик скобок закрывал тело рано
# (`BEGIN { print ")" }` давал collecting=0 на первой же строке), хвост с
# серийным вычислением тихо отбрасывался, и _up_zero выпадала из разбора: оба
# сторожа (№460 и полнота разбора) были зелёными на НЕРАЗОБРАННОМ теле. Здесь
# _up_zero вычисляется ещё и первым (целым) телом, поэтому до правки она видна
# ОДИН раз и №460 зелёный; после правки тело доводится до конца, хвост входит
# в разбор, и _up_zero вычисляется ДВАЖДЫ — №460 обязан краснеть.
_bad460q="$WORK/bad460-quoted-paren-tail.sh"
cat > "$_bad460q" <<'BAD460Q'
_up_zero=$(printf '%s\n' "${_w63l_metrics:-}" | awk '
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { n++ }
    END { print n+0 }')
_up_zero=$(printf '%s\n' "${_w63l_metrics:-}" | awk 'BEGIN { print ")" }
    $1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { n++ }
    END { print n+0 }')
echo "OK: 6.4B.2 ДОСТИГНУТО: нулей ${_up_zero}"
BAD460Q


# ПОЗИТИВНАЯ проверка №460.11 (WARNING 2): агрегат по ВСЕЙ серии collector_up и
# ИМЕНОВАННАЯ выборка collector_up{http_plaintext} — это РАЗНЫЕ срезы, и №460
# обязан быть зелёным. До включения label-селектора в ключ (WARNING 2) они
# совпадали по серии+предикату+источнику и сторож давал ЛОЖНЫЙ красный ровно на
# естественной правке 6.4B.4. Гоняется _run_guard460 (ожидает rc=0).
_ok460lab="$WORK/ok460-label.sh"
cat > "$_ok460lab" <<'OK460LAB'
_agg=$(printf '%s\n' "${_w63l_metrics:-}" | awk '$1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 1 { print $NF }')
_http=$(printf '%s\n' "${_w63l_metrics:-}" | awk '$1 ~ /^ebpf_guard_collector_up\{/ && /collector="http_plaintext"/ && $NF+0 == 1 { print $NF }')
echo "OK: 6.4B.4 ДОСТИГНУТО: единиц в серии ${_agg}, collector_up{http_plaintext}=${_http}"
OK460LAB

# ПОЗИТИВНАЯ проверка №460.12 (заход 6.5, item 1): `#`-КОММЕНТАРИИ.
# Многострочное тело с token-leading `#`, и в комментарии стоит ОДНА
# НЕсбалансированная `(`. Без учёта `#` эта `(` ОТКРЫВАЛА бы тело, оно не
# закрывалось бы к концу файла, и _check460_complete краснела бы; с учётом `#`
# комментарий пропускается, тело закрывает НАСТОЯЩАЯ скобка в хвосте, и
# _check460_complete обязан быть зелёным. Скобка в комментарии оставлена
# НЕПАРНОЙ нарочно: парная `(`+`)` давала бы зелёный и БЕЗ `#`-ветки (скобка из
# комментария закрыла бы тело рано, хвост тихо отбрасывался). Прямой негатив на
# красную ветку идёт ниже.
_hash_ok="$WORK/ok460-hash-comment.sh"
cat > "$_hash_ok" <<'HASHOK'
_up=$(printf '%s\n' "${_w63l_metrics:-}" \
    # комментарий с НЕПАРНОЙ ( — по правилам sh в баланс скобок НЕ идёт
    | awk '$1 ~ /^ebpf_guard_collector_up\{/ && $NF+0 == 0 { n++ } END { print n+0 }')
echo "OK: 6.4B.2 ДОСТИГНУТО: нулей ${_up}"
HASHOK

# _paren_case <имя> <ожидаемый баланс> <текст тела> — прямая сверка
# _paren_delta, единица измерения — баланс вне кавычек и вне `#`-комментариев.
_paren_case() {
    local name="$1" want="$2" body="$3" got
    got=$(_paren_delta "$body")
    if [ "$got" = "$want" ]; then
        echo "    OK  _paren_delta/${name}: баланс ${want}"
    else
        _efail "_paren_delta/${name}: баланс ${got} вместо ${want} — #-комментарии учтены неверно"
    fi
}

echo
echo "--- №460 негативные проверки: сторож обязан КРАСНЕТЬ на одно- и многострочном образце №458, на живом read-стиле, на раннем закрытии тела, на незакрытом теле и на красной ветке полноты разбора"
_check460_negative "synthetic-dvuhstrochnyj" "$_bad460" 'ДВЕ независимые переменные'
_check460_negative "synthetic-povtornoe-vychislenie" "$_bad460b" 'вычисляется 2 раз'
_check460_negative "synthetic-gibrid-read-i-awk" "$_bad460h" 'ДВЕ независимые переменные'
_check460_negative "synthetic-mnogostrochnyj-dubl" "$_bad460m" 'ДВЕ независимые переменные'
_check460_negative "synthetic-gibrid-read-probel-posle-<<<" "$_bad460hs" 'ДВЕ независимые переменные'
_check460_negative "synthetic-predikat-plus0-i-bez" "$_bad460p" 'ДВЕ независимые переменные'
_check460_negative "synthetic-perestavlennye-predikaty" "$_bad460o" 'ДВЕ независимые переменные'
_check460_negative "synthetic-perestavlennye-predikaty-odin-poryadok" "$_bad460o2" 'ДВЕ независимые переменные'
_check460_negative "synthetic-rannee-zakrytie-tela-hvost" "$_bad460q" 'вычисляется 2 раз'
_check460_coverage_negative "synthetic-nezakrytoe-telo" "$_bad460e" 'печатные серийные величины выпали из разбора'
_check460_complete_negative "synthetic-nezakrytoe-telo-krasnaya-vetka" "$_bad460e" 'не закрылось к концу файла'
_run_guard460 "$_ok460lab" "synthetic-label-selektor"; echo "    (позитив: агрегат и именованная выборка — РАЗНЫЕ срезы, ложного красного нет)"

# ── ITEM 1 (заход 6.5, item 1): `#`-КОММЕНТАРИИ и полнота разбора. Раньше
#    _paren_delta не знала про `#`: скобка в комментарии закрывала тело рано
#    (хвост терялся) или открывала его (ложное «не закрылось»), а комментарии
#    над функцией обещали обратное. Прямые сверки фиксируют оба случая, а
#    позитив _check460_complete сторожит интеграцию (тело закрывается НАСТОЯЩЕЙ
#    скобкой, а не скобкой из комментария).
#    `$(… # )` в ОДНУ строку — действительно НЕ закрыто (скобку съел
#    комментарий): баланс 1. Тело закрывает НАСТОЯЩАЯ скобка следующей строки
#    (следующий случай) — и хвост при этом НЕ теряется.
#    WARNING захода 6.5, item 1: token-leading `#` наступает не только после
#    `;|&(` и пробела/таба, но и после `)`, `>`, `<` — это тоже метасимволы sh.
#    Без них `)# (` и `># (` уносили скобку из комментария в баланс. Сверки
#    ниже фиксируют все четыре границы; комментарий над _paren_delta больше НЕ
#    заявляет «слепого пятна по `#` нет» без оговорки про этот список.
echo
echo '--- #-комментарии в _paren_delta: скобка в комментарии тело НЕ закрывает и НЕ открывает; # внутри слова/кавычек — не комментарий; __#__ после `)`, `>`, `<` — тоже комментарий'
_paren_case "komment-zakryvayushchaya-skobka-ne-zakryvaet" 1 '$(echo hi # note )'
_paren_case "nastoyashchaya-skobka-zakryvaet-hvost" 0 "$(printf '%s\n' '$(echo hi # note )' ')')"
_paren_case "komment-otkryvayushchaya-skobka-ne-otkryvaet" 0 "$(printf '%s\n' '$(echo hi # note (' ')')"
_paren_case "reshetka-vnutri-slova-ne-kommentarij" 0 '$(echo ${x#y} )'
_paren_case "reshetka-v-kavychkah-ne-kommentarij" 0 '$(echo "a # b (" )'
_paren_case "reshetka-posle-zakryvayushchej-skobki" 0 '$(echo hi)# ('
_paren_case "reshetka-posle-perenapravleniya-vyvod" 0 '$(echo hi )># ('
_paren_case "reshetka-posle-perenapravleniya-vvod" 0 '$(echo hi )<# ('
_paren_case "reshetka-posle-zakryvayushchej-skobki-zakrytie" 0 '$(echo hi)# )'
_check460_complete "$_hash_ok" "synthetic-hash-comment"

# ── ФИКСТУРНЫЙ ПРОГОН БЛОКА W65 (метка 6.5.1, item 5 волны 6.5). Отдельный
#    блок и отдельный харнесс: у W648/W64B свои инварианты числа меток, и
#    дописывание в них сломало бы их счётчики.
if ! grep -q 'W65-EMITTERS-BEGIN' "$PIPE" || ! grep -q 'W65-EMITTERS-END' "$PIPE"; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: в $PIPE нет маркеров W65-EMITTERS-BEGIN/END — метку 6.5.1 вынимать нечем"
    exit 2
fi
sed -n '/W65-EMITTERS-BEGIN/,/W65-EMITTERS-END/p' "$PIPE" > "$WORK/block65.sh"
_block65_lines=$(wc -l < "$WORK/block65.sh")
if [ "${_block65_lines:-0}" -lt 20 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: между маркерами W65 всего ${_block65_lines} строк — блок вынут не тот"
    exit 2
fi
bash -n "$WORK/block65.sh" || { echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: блок W65 не разбирается bash -n"; exit 2; }

# _run65 <каталог-ART> — гоняет блок с $ART, указывающим на синтетические
# артефакты контроля. Отсутствие файла — ЗАКОННЫЙ вход (контроль не поставлен).
_run65() {
    cat > "$WORK/harness65.sh" <<EOF
set -u
ART="$1"
EOF
    cat "$WORK/block65.sh" >> "$WORK/harness65.sh"
    bash "$WORK/harness65.sh" 2>&1
}

_check65() { # <имя> <вывод> <ожидаемый класс>
    local name="$1" out="$2" exp="$3" line got n
    # Информационные строки — в stderr: подстановка $( _check65 … ) обязана
    # вернуть РОВНО вердиктную строку, иначе сверка текста читает заголовок
    # фикстуры вместо вердикта.
    echo "--- фикстура 6.5.1: $name" >&2
    n=$(printf '%s\n' "$out" | grep -cE "(^|[^0-9.])6\.5\.1[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)")
    [ "${n:-0}" -eq 1 ] || _efail "$name: метка 6.5.1 напечатала ${n:-0} вердиктных строк вместо одной (И2/И3)"
    line=$(_line_of "$out" 6.5.1)
    got=$(_cls "$line")
    if [ "$got" = "$exp" ]; then
        echo "    OK  6.5.1 = $got" >&2
    else
        _efail "$name: 6.5.1 дал класс $got, ожидался $exp — строка: $(printf '%s' "$line" | cut -c1-180)" >&2
    fi
    printf '%s' "$line"
}

echo
echo "=== ФИКСТУРНЫЙ ПРОГОН ВЕРДИКТНЫХ ВЕТОК 6.5.1 (блок из $PIPE, ${_block65_lines} строк) ==="

_A65_NONE="$WORK/art65-none"; mkdir -p "$_A65_NONE"
_check65 "контроль не поставлен (файла нет) — НЕ ЗАПРОШЕН, а не провал продукта" \
    "$(_run65 "$_A65_NONE")" NOTREQ >/dev/null

_A65_CLS="$WORK/art65-cls"; mkdir -p "$_A65_CLS"
printf 'class=привязка_НЕ_подтверждена_tracked_pids=0_за_75с\n' > "$_A65_CLS/http-control-plaintext.txt"
_t65_cls=$(_check65 "контроль назвал класс неизмеримости — НЕИЗМЕРИМ с этим классом" \
    "$(_run65 "$_A65_CLS")" FAIL)

_A65_OK="$WORK/art65-ok"; mkdir -p "$_A65_OK"
{ echo "events_delta=7"; echo "events_before=0"; echo "events_after=7"; echo "tracked_pids=1"
  echo "requests_ok=3"; echo "requests_sent=3"; echo "holder_pid=4242"; echo "holder_comm=python3"
  echo "drops_delta=0"; echo "drop_reasons=-"; } \
  > "$_A65_OK/http-control-plaintext.txt"
_t65_ok=$(_check65 "живое событие предъявлено — ДОСТИГНУТО с величиной" \
    "$(_run65 "$_A65_OK")" OK)

_A65_NOREQ="$WORK/art65-noreq"; mkdir -p "$_A65_NOREQ"
{ echo "events_delta=0"; echo "tracked_pids=1"; echo "requests_ok=0"; echo "requests_sent=3"
  echo "holder_pid=4242"; echo "holder_comm=python3"; } > "$_A65_NOREQ/http-control-plaintext.txt"
_check65 "запросы не дошли — НЕИЗМЕРИМ (ноль неотличим от «обмена не было»)" \
    "$(_run65 "$_A65_NOREQ")" FAIL >/dev/null

# Продуктовый провал ДВУХ РАЗНЫХ МИРОВ (№471/№472): «события доходят, разбор
# отбивает» (ненулевая отбраковка — ровно то, что дал живой смок 25.09) и «до
# коллектора не доходит плоскость данных» (отбраковка нулевая). Класс вердикта
# у обоих один — FAIL, ПРОДУКТОВЫЙ; различает их только НАПЕЧАТАННЫЙ ТЕКСТ,
# поэтому фикстур две, и у каждой своя сверка текста ([[verdict-zero-needs-its-class-presented]]).
_A65_PROD="$WORK/art65-prod"; mkdir -p "$_A65_PROD"
{ echo "events_delta=0"; echo "tracked_pids=1"; echo "requests_ok=3"; echo "requests_sent=3"
  echo "holder_pid=4242"; echo "holder_comm=python3"
  echo "drops_delta=39"; echo "drop_reasons=parse_error"; } > "$_A65_PROD/http-control-plaintext.txt"
_t65_prod=$(_check65 "привязка есть, запросы дошли, события отбиты РАЗБОРОМ — ПРОВАЛЕН, класс ПРОДУКТОВЫЙ (№471)" \
    "$(_run65 "$_A65_PROD")" FAIL)

_A65_PROD0="$WORK/art65-prod0"; mkdir -p "$_A65_PROD0"
{ echo "events_delta=0"; echo "tracked_pids=1"; echo "requests_ok=3"; echo "requests_sent=3"
  echo "holder_pid=4242"; echo "holder_comm=python3"
  echo "drops_delta=0"; echo "drop_reasons=-"; } > "$_A65_PROD0/http-control-plaintext.txt"
_t65_prod0=$(_check65 "привязка есть, запросы дошли, отбраковки НЕТ — ПРОВАЛЕН, плоскость данных не доходит" \
    "$(_run65 "$_A65_PROD0")" FAIL)

# Сверка НАПЕЧАТАННОГО ТЕКСТА (item 2): класс совпал, но метка обязана назвать
# ВЕЛИЧИНЫ и ПРИЧИНУ, а не только слово вердикта.
_need_text "6.5.1 живое событие http_plaintext" "$_t65_ok" \
    "events_delta=7" "tracked_pids=1" "3 из 3" "python3" "отбраковано разбором за обмен 0"
# Продуктовый провал обязан НАЗЫВАТЬ причину числом и именем, а не только
# словом «ПРОВАЛЕН»: ровно на этом различии стоит №471.
_need_text "6.5.1 продуктовый провал: события отбиты разбором" "$_t65_prod" \
    "tracked_pids=1" "events_delta=0" "39" "parse_error" "теряет РАЗБОР"
_need_text "6.5.1 продуктовый провал: плоскость данных не доходит" "$_t65_prod0" \
    "tracked_pids=1" "events_delta=0" "обмен 0" "причины: -"

# ── ITEM 2. Сверка НАПЕЧАТАННОГО ТЕКСТА. Один здоровый прогон B даёт все
#    девять строк 6.4.x; отдельный снимок 6.4.B — все шесть строк 6.4B.x. У
#    КАЖДОЙ строки требуются содержательные имена и числа, а не общий класс.
echo
echo "=== ITEM 2: сверка НАПЕЧАТАННОГО ТЕКСТА (имена и числа), 6.4.0…6.4.8 + 6.4B.0…6.4B.5 + 6.5.1 ==="
TX="$WORK/artTX"; mkdir -p "$TX/baseline"
_mk_metrics "$TX/metrics-live.txt" 3 "no_symbols=1" "" "" "" 2
_mk_metrics "$TX/metrics-window-start.txt" "" "" 100 40 90
_mk_metrics "$TX/metrics-window-end.txt"   "" "" 260 55 210
{ echo "events_delta=160"; echo "manifest_alerts=6"; } > "$TX/tls-control-plaintext.txt"
{ echo "bound=yes"; echo "identity_match=yes"; echo "event=yes"; echo "pod_events=4"; echo "events_delta=6"; echo "alert_delta=1"; echo "dedup_delta=0"; } > "$TX/tls-control-container.txt"
printf '6.0.13 OK\n5.9.5c OK\n6.3.1 OK\n' > "$TX/baseline/baseline-labels-baseline.txt"
printf '6.0.13 OK\n5.9.5c OK\n6.3.1 OK\n' > "$TX/baseline/baseline-labels-check.txt"
_tx_out="$(_run "$TX" B on)"
_need_text "6.4.0 привязка и причины" "$(_line_of "$_tx_out" 6.4.0)" \
    "привязок за жизнь процесса 2" "отказов привязки всего 1" "no_symbols=1"
_need_text "6.4.1 вход ноды за окно" "$(_line_of "$_tx_out" 6.4.1)" \
    "за окно = 160" "100→260"
_need_text "6.4.2 привязка удалась и причины" "$(_line_of "$_tx_out" 6.4.2)" \
    "attach_success_total=2" "no_symbols=1"
_need_text "6.4.3 положительный контроль item 5" "$(_line_of "$_tx_out" 6.4.3)" \
    "+160" "алертов манифеста 6"
_need_text "6.4.4 контейнерный случай" "$(_line_of "$_tx_out" 6.4.4)" \
    "С ЛЕЙБЛОМ ПОДА 4" "всего за обмен 6" "алертов правила за обмен 1"
_need_text "6.4.5 не запрошено, инертны по построению (№433)" "$(_line_of "$_tx_out" 6.4.5)" \
    "tls_ja3_*" "write(2)" "инертны по построению"
# 6.4.5 (выше) и 6.4B.0 (ниже) — две из пятнадцати сверок ЗАКОННО без числовых
# величин: 6.4B.0 несёт текст входного сторожа (чисел в нём нет по природе),
# 6.4.5 — постоянный НЕИЗМЕРИМ (мерить нечего). Проверяются имена/маркеры,
# а не числа; это оставлено намеренно, а не пробел фикстуры.
_need_text "6.4.6 цена включения" "$(_line_of "$_tx_out" 6.4.6)" \
    "за окно = 15" "суммарный объём окна по оси = 120"
_need_text "6.4.7 опорный набор" "$(_line_of "$_tx_out" 6.4.7)" \
    "все 3 критериев" "роль baseline" "роль check"
_need_text "6.4.8 полнота и состав классов" "$(_line_of "$_tx_out" 6.4.8)" \
    "все восемь меток" "6.4.5=NOTREQ" "годную величину не дали 0"

MBT="$WORK/mbt-text.txt"
_mk_metrics_b "$MBT" 7 2 "$_ALL6" "dns=1 lsm=0 tls=1 http_plaintext=1 iouring=0"
_bt_out="$(_runb "$MBT" B OK "$BIN_OK" yes)"
_need_text "6.4B.0 входной сторож рантайма" "$(_line_of "$_bt_out" 6.4B.0)" \
    "входной сторож рантайма отработал" "синтетический вход фикстуры"
_need_text "6.4B.1 сканы и кандидаты" "$(_line_of "$_bt_out" 6.4B.1)" \
    "сканов 7" "libssl в последнем скане 2"
_need_text "6.4B.2 обе стороны оси поимённо" "$(_line_of "$_bt_out" 6.4B.2)" \
    "из 5 серий" "единиц 3 (dns tls http_plaintext)" "нулей 2 (lsm iouring)"
_need_text "6.4B.3 шесть reason поимённо" "$(_line_of "$_bt_out" 6.4B.3)" \
    "все 6 reason" "objects_not_loaded" "attach_failed"
_need_text "6.4B.4 признак бинаря и collector_up" "$(_line_of "$_bt_out" 6.4B.4)" \
    "http_plaintext" "collector_up{http_plaintext}=1"
_need_text "6.4B.5 полнота и состав классов" "$(_line_of "$_bt_out" 6.4B.5)" \
    "все пять меток" "6.4B.0=OK" "годную величину не дали 0"

# ── Негативные самопроверки САМОГО механизма сверки (№461): пустой набор
#    ожиданий и пропуск обязательной подстроки обязаны краснеть, и метка в
#    _TEXT_SEEN НЕ регистрируется. Ведём в подоболочке: настоящий реестр и
#    счётчик провалов портить нельзя. Метка 6.4.9 синтетическая — её нет ни в
#    реестре, ни в таблице полноты.
echo
echo "--- №461 негативные самопроверки механизма: пустой набор ожиданий и пропуск подстроки"
_neg_line="OK: 6.4.9 ИЗМЕРЕНО: синтетическая строка для самопроверки механизма сверки"
_neg_empty=$( _need_text "№461-self-пусто" "$_neg_line" 2>&1; printf '\n[SEEN=%s]' "$_TEXT_SEEN" )
if printf '%s' "$_neg_empty" | grep -q 'ПРОВАЛ' && ! printf '%s' "$_neg_empty" | grep -qE '\[SEEN=[^]]*6\.4\.9'; then
    echo "    OK  №461-self: пустой набор ожиданий отбит, метка НЕ зарегистрирована"
else
    _efail "№461-self: пустой набор ожиданий не отбит либо метка зарегистрирована до сверки — вывод: $(printf '%s' "$_neg_empty" | cut -c1-200)"
fi
_neg_miss=$( _need_text "№461-self-пропуск" "$_neg_line" "этой подстроки в строке нет" 2>&1; printf '\n[SEEN=%s]' "$_TEXT_SEEN" )
if printf '%s' "$_neg_miss" | grep -q 'ПРОВАЛ' && ! printf '%s' "$_neg_miss" | grep -qE '\[SEEN=[^]]*6\.4\.9'; then
    echo "    OK  №461-self: пропуск обязательной подстроки отбит, метка НЕ зарегистрирована"
else
    _efail "№461-self: пропуск подстроки не отбит либо метка зарегистрирована — вывод: $(printf '%s' "$_neg_miss" | cut -c1-200)"
fi

# ── Сторож №461: реестр сверенных ТЕКСТОМ меток против полного списка.
#    _guard461 <реестр> печатает список отсутствующих меток (или ПУСТ), код 1
#    при неполноте: та же проверка гоняется на синтетически испорченных
#    реестрах (негативные самопроверки ниже).
# _W64_TEXT_LABELS — ЕДИНЫЙ источник полного состава (SUGGESTION): раньше список
# пятнадцати меток был вписан в _guard461 буквально и был вторым независимым
# источником. Теперь и проверка, и её негативы читают одну константу.
_W64_TEXT_LABELS="6.4.0 6.4.1 6.4.2 6.4.3 6.4.4 6.4.5 6.4.6 6.4.7 6.4.8 6.4B.0 6.4B.1 6.4B.2 6.4B.3 6.4B.4 6.4B.5 6.5.1"
_guard461() { # <реестр> → 0 и число сверок, либо 1 и список пропущенных
    local seen="$1" lbl missing="" n
    for lbl in $_W64_TEXT_LABELS; do
        case " ${seen} " in
            *" ${lbl} "*) ;;
            *) missing="${missing}${lbl} " ;;
        esac
    done
    n=$(printf '%s' "$seen" | tr ' ' '\n' | grep -c . || true)
    if [ "${n:-0}" -lt 1 ]; then printf 'ПУСТ'; return 1; fi
    if [ -n "$missing" ]; then printf '%s' "$missing"; return 1; fi
    printf '%s' "$n"; return 0
}

echo
echo "--- сторож №461: реестр меток, чей НАПЕЧАТАННЫЙ ТЕКСТ сверён (полнота текстовых фикстур)"
if _g461_n=$(_guard461 "$_TEXT_SEEN"); then
    echo "    OK  №461: текст сверён у ВСЕХ обязательных меток (6.4.0…6.4.8 + 6.4B.0…6.4B.5 + 6.5.1), сверок ${_g461_n}"
else
    _efail "№461: НАПЕЧАТАННЫЙ ТЕКСТ не сверён: ${_g461_n}— класса недостаточно, нужна сверка имён и чисел"
fi
# Негатив №461.1: реестр потерял ОДНУ метку — сторож обязан её назвать.
if _g461_miss=$(_guard461 "${_TEXT_SEEN//6.4.4 /}"); then
    _efail "№461-негатив: реестр без метки 6.4.4 принят зелёным — пропуск не ловится"
else
    echo "    OK  №461-негатив: реестр без метки 6.4.4 отбит (пропущено: ${_g461_miss})"
fi
# Негатив №461.2: реестр ПУСТ — сверять нечего, сторож не смеет быть зелёным.
if _g461_empty=$(_guard461 ""); then
    _efail "№461-негатив: пустой реестр принят зелёным — сверять нечего, а сторож молчит"
else
    echo "    OK  №461-негатив: пустой реестр отбит (${_g461_empty})"
fi

# ── Негативный реплей ТЕКСТА (WARNING 2 item 2). Реплей берёт записи реестра
#    _REPLAY_FILE — настоящие вердиктные строки и ИХ же обязательные подстроки,
#    — поэтому порча настоящих ожиданий реплей ПРОКРАСНЕЕТ, а не останется
#    зелёной на захардкоженной паре литералов. Записи кладут сюда сами
#    позитивные фикстуры (№455, №457, №461).
echo
echo "--- №461-реплей: настоящая строка обязана пройти, строка без обязательной подстроки — покраснеть"
if [ ! -s "$_REPLAY_FILE" ]; then
    _efail "№461-реплей: реестр реплея ПУСТ — сверять нечего"
else
    _rep_n=0
    _REPLAY_LABELS=""
    while IFS=$'\t' read -r -a _rec; do
        [ "${#_rec[@]}" -ge 3 ] || continue
        _rep_n=$((_rep_n + 1))
        _rep_name="${_rec[0]}"; _rep_line="${_rec[1]}"
        _rep_lbl=$(_line_label "$_rep_line")
        _REPLAY_LABELS="${_REPLAY_LABELS}${_rep_lbl} "
        _rep_mut="${_rep_line//"${_rec[2]}"/}"
        if ! _text_ok "$_rep_line" "${_rec[@]:2}"; then
            _efail "№461-реплей/${_rep_name}: неизменённая вердиктная строка ложно отбита тем же механизмом — реплей испорчен"
        elif _text_ok "$_rep_mut" "${_rec[@]:2}"; then
            _efail "№461-реплей/${_rep_name}: строка без обязательной подстроки «${_rec[2]}» прошла сверку — реплей бесполезен (№461)"
        else
            echo "    OK  реплей ${_rep_lbl:-?}: строка без «${_rec[2]}» отбита (${_rep_name})"
        fi
    done < "$_REPLAY_FILE"
    if [ "$_rep_n" -lt 1 ]; then
        _efail "№461-реплей: разобрано 0 записей — реплей ничего не проверил"
    elif printf '%s' "$_REPLAY_LABELS" | grep -q '6\.4\.4' && printf '%s' "$_REPLAY_LABELS" | grep -q '6\.4B\.2'; then
        echo "    OK  №461-реплей: ${_rep_n} записей, включая №455 (6.4.4) и №457 (6.4B.2) — у каждой снята обязательная подстрока и сверка покраснела"
    else
        _efail "№461-реплей: реплей не покрыл №455 (6.4.4) и/или №457 (6.4B.2) — метки: ${_REPLAY_LABELS}"
    fi
fi

# Ложь №458 против РЕАЛЬНЫХ ожиданий метки 6.4B.2 (из реестра реплея), а не
# против собственных подстрок: если реальные ожидания ослабят — ложь пройдёт,
# и это КРАСНЫЙ.
_lie458='OK: 6.4B.2 ДОСТИГНУТО: ось предъявлена ОБЕИМИ сторонами в одном прогоне — из 7 серий collector_up единиц 6 (dns fileaccess kmod network syscall tls), нулей 1 (нули у: dns fileaccess kmod lsm network syscall tls); единица больше не безусловна'
_lie_subs=()
while IFS= read -r _s; do [ -n "$_s" ] && _lie_subs+=("$_s"); done \
    < <(awk -F'\t' '$1 == "6.4B.2 обе стороны оси поимённо" { for (i = 3; i <= NF; i++) print $i }' "$_REPLAY_FILE")
if [ "${#_lie_subs[@]}" -lt 1 ]; then
    _efail "№461-негатив: в реестре реплея нет записи «6.4B.2 обе стороны оси поимённо» — связать ложь №458 с реальными ожиданиями нечем"
elif _text_ok "$_lie458" "${_lie_subs[@]}"; then
    _efail "№461-негатив: историческая ложь №458 прошла РЕАЛЬНЫЕ ожидания метки 6.4B.2 — ожидания ослаблены"
else
    echo "    OK  №461-негатив: ложь №458 отбита РЕАЛЬНЫМИ ожиданиями метки 6.4B.2 (${#_lie_subs[@]} подстрок)"
fi

# ── СТОРОЖ №469: ТОЖДЕСТВО БИНАРЯ НЕ ХРАНИТСЯ В $ART. Реестр архива поймал
#    №469 живьём (смок 24.09.2026): правка №459 вернула снимок в $ART сразу
#    после `rm -rf` шага 1, но $ART чистится ВТОРОЙ раз — шапкой
#    wave6.3-controls.sh — уже после этого, и файл снова не доживал до сборки,
#    пока лог печатал «тождество бинаря в архиве». Реестр ловит потерю ПОСЛЕ
#    прогона (час стенда); этот сторож ловит её в тексте пайплайна ДО запуска.
#    Проверяется исполняемый текст, комментарии отброшены: «$ART» в объяснении
#    того, почему так делать нельзя, не должно краснеть.
echo "--- сторож №469: снимок тождества бинаря не живёт в \$ART и копируется в архив из своего места"
_w469_code=$(sed 's/[[:space:]]*#.*$//' "$PIPE")
_w469_bad=$(printf '%s\n' "$_w469_code" | grep -nE 'cp[^#]*"\$ART/binary-identity' || true)
if [ -n "$_w469_bad" ]; then
    _efail "№469: пайплайн кладёт тождество бинаря в \$ART — его стирает шапка wave6.3-controls.sh: ${_w469_bad}"
else
    echo "    OK  №469: в \$ART снимок не кладётся ни одной строкой исполняемого текста"
fi
if printf '%s\n' "$_w469_code" | grep -qE 'cp "\$_r63_binid_keep" "\$COLLECT/controls/artifacts/binary-identity.txt"'; then
    echo "    OK  №469: в архив снимок копируется на сборке из \$_r63_binid_keep (вне \$ART)"
else
    _efail "№469: в сборке архива нет копирования тождества бинаря из места вне \$ART — реестр архива провалится ПОСЛЕ прогона"
fi
if printf '%s\n' "$_w469_code" | grep -qE '^_r63_binid_keep=.*basename "\$ART"'; then
    echo "    OK  №469: имя снимка производно от роли прогона — смок и боевой заход не затирают снимок друг друга"
else
    _efail "№469: имя файла снимка не различает смок и боевой заход — один затрёт тождество другого"
fi
_w469_neg='cp "$_r63_binid_src" "$ART/binary-identity.txt" 2>/dev/null'
if printf '%s\n' "$_w469_neg" | grep -qE 'cp[^#]*"\$ART/binary-identity'; then
    echo "    OK  №469-негатив: историческая строка правки №459 этим предикатом КРАСНЕЕТ"
else
    _efail "№469-негатив: предикат не краснеет на самой строке, которой №469 и был — сторож бесполезен"
fi
if [ -s "$SETUP/wave6.5-archive-manifest.txt" ] && grep -qx 'controls/artifacts/binary-identity.txt' "$SETUP/wave6.5-archive-manifest.txt"; then
    echo "    OK  №469: реестр архива по-прежнему требует binary-identity.txt (второй, послепрогонный слой)"
else
    _efail "№469: реестр архива не требует controls/artifacts/binary-identity.txt — послепрогонного слоя нет"
fi

echo
if [ "$FAILS" -gt 0 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ ПРОВАЛЕН: расхождений $FAILS"
    exit 1
fi
echo "СТОРОЖ ЭМИТТЕРОВ ПРОЙДЕН: 14 фикстур 6.4.x + 4 фикстуры классов 6.4.4 (№455) + 13 фикстур 6.4.B (включая именованный состав оси, №458) + ${_g461_n} сверок НАПЕЧАТАННОГО ТЕКСТА (№461, включая 6.5.1) с реестром реплея + 9 негативных образцов №460 (одно- и многострочный дубль, повторное вычисление, гибрид read+awk с пробелом и без, разное написание предиката, переставленные и одинаковые ветки awk, раннее закрытие тела в кавычке уносило хвост с печатной величиной) + 1 негатив полноты разбора №460 (незакрытое тело: печатная серийная величина выпала из подписи) + 1 негатив КРАСНОЙ ВЕТКИ полноты разбора №460 (_check460_complete на незакрытом теле: ненулевой код и красная формулировка, зелёная ветка запрещена — чувствителен к удалению return 1) + 1 позитив #-комментариев (тело с НЕПАРНОЙ ( в комментарии закрывается НАСТОЯЩЕЙ скобкой) + 9 прямых сверок #-комментариев в _paren_delta (скобка в комментарии тело не закрывает и не открывает; # внутри слова/кавычек — не комментарий; __#__ после ), >, < — тоже комментарий) + 1 позитивная сверка №460 на label-селектор (агрегат ≠ именованная выборка, ложного красного нет) + 2 самопроверки полноты разбора (пункт 3: живой блок разобран целиком) + 2 сверки полноты подписи (ВСЕ печатные серийные величины в разборе, а не зашитый список) + ${_rep_n} негативных реплеев текста по РЕАЛЬНЫМ ожиданиям (включая №455 и №457) + 2 негативные самопроверки механизма сверки (пустой набор, пропуск подстроки) + 2 негатива №461 (пропущенная метка, пустой реестр) + два сторожа №373 + 6 проверок достижимости + 5 проверок №469 (тождество бинаря вне \$ART, копия на сборке, имя от роли, негатив на исторической строке, реестр архива), расхождений 0"
