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
# снимках /metrics и файлах-сторожах контролей items 5/6. Проверяется не
# текст, а КЛАСС каждой метки — той же функцией классификации, что у стража,
# чтобы инструменты не расходились в трактовке одного и того же слова.
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

SETUP="${SETUP:-$(cd "$(dirname "$0")" && pwd)}"
PIPE="${PIPE:-$SETUP/run-6.4-pipeline.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/w648-emit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
_efail() { echo "    ПРОВАЛ: $*"; FAILS=$((FAILS + 1)); }

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
    6.4.0=OK 6.4.1=OK 6.4.2=NOTREQ 6.4.3=NOTREQ 6.4.4=NOTREQ 6.4.5=FAIL 6.4.6=OK 6.4.7=NOTREQ 6.4.8=OK

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
    6.4.0=OK 6.4.1=OK 6.4.2=OK 6.4.3=OK 6.4.4=OK 6.4.5=FAIL 6.4.6=OK 6.4.7=OK 6.4.8=OK

# ── 3. «ПРИБОР НЕ ЗНАЕТ, ЧТО С НИМ» (6.4.0 ПРОВАЛЕН): обе серии присутствуют
#    (коллектор жив и отдаёт метрики), но tracked_pids=0 И сумма отказов=0 —
#    ни привязки, ни причины отказа. Постановка 6.4, метка 6.4.0.
C="$WORK/artC"; mkdir -p "$C/baseline"
_mk_metrics "$C/metrics-live.txt" 0 "no_symbols=0" "" "" ""
_mk_metrics "$C/metrics-window-start.txt" "" "" 0 0 0
_mk_metrics "$C/metrics-window-end.txt"   "" "" 0 0 0
_check "прибор не знает своё состояние (tracked=0 И отказов=0, обе серии живы)" "$(_run "$C" B off)" \
    6.4.0=FAIL 6.4.1=OK 6.4.2=FAIL 6.4.5=FAIL 6.4.8=OK

# ── 4. ПРИВЯЗКА ПОЛНОСТЬЮ ПРОВАЛЕНА: коллектор жив, отказы предъявлены по
#    причине (№379 закрыт — молчания нет), но tracked_pids=0 — ни одного
#    процесса. Контроли items 5/6 не исполнены в этом заходе.
D="$WORK/artD"; mkdir -p "$D"
_mk_metrics "$D/metrics-live.txt" 0 "no_elf=2 no_symbol_found=1" "" "" ""
_mk_metrics "$D/metrics-window-start.txt" "" "" 0 0 0
_mk_metrics "$D/metrics-window-end.txt"   "" "" 0 0 0
_check "привязка полностью провалена (tracked=0, отказы предъявлены по причинам)" "$(_run "$D" B off)" \
    6.4.0=OK 6.4.1=OK 6.4.2=FAIL 6.4.3=FAIL 6.4.4=FAIL 6.4.5=FAIL 6.4.7=NOTREQ 6.4.8=OK

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
    if printf '%s' "$line" | grep -q "$want"; then
        echo "    OK  6.4.4 назвала класс «${want}»"
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
if printf '%s' "$_w64b_line" | grep -q "серия ЛЖЁТ единицей"; then
    echo "    OK  6.4B.2 назвала класс «серия ЛЖЁТ единицей», а не «случай не предъявлен»"
else
    _efail "№457: 6.4B.2 при stub mode в журнале и всех единицах обязана назвать класс «серия ЛЖЁТ единицей» — строка: $(printf '%s' "$_w64b_line" | cut -c1-190)"
fi

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

echo
if [ "$FAILS" -gt 0 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ ПРОВАЛЕН: расхождений $FAILS"
    exit 1
fi
echo "СТОРОЖ ЭМИТТЕРОВ ПРОЙДЕН: 14 фикстур 6.4.x + 4 фикстуры классов 6.4.4 (№455) + 12 фикстур 6.4.B + два сторожа №373 + 6 проверок достижимости, расхождений 0"
