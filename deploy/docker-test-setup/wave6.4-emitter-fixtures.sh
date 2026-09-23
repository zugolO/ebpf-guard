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
_mk_metrics() {
    local f="$1" tracked="$2" fails="$3" ev="$4" avol_tls="$5" avol_any="$6"
    : > "$f"
    [ -n "$tracked" ] && echo "ebpf_guard_tls_tracked_pids_total $tracked" >> "$f"
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

echo
if [ "$FAILS" -gt 0 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ ПРОВАЛЕН: расхождений $FAILS"
    exit 1
fi
echo "СТОРОЖ ЭМИТТЕРОВ ПРОЙДЕН: 12 фикстур + сторож №373, расхождений 0"
