#!/usr/bin/env bash
# wave6.3-emitter-fixtures.sh — ТРЕТЬЯ проверка того же рода, что --scan и
# --self-test стража полноты, и единственная, отвечающая на вопрос, который
# те двое не задают по построению.
#
# ЗАЧЕМ. `--scan` спрашивает «есть ли в тексте пайплайна строка, способная
# вынести вердикт», `--check` — «вынесена ли она в логе». Обе отвечают ДА для
# строки, которая не способна напечатать ничего, кроме НЕИЗМЕРИМ: метка
# заговорила, реестр полон, критерий выхода недостижим. Именно так волна
# 6.3.9.F потеряла бы прогон B — находка №373 (6.3.9.4 и 6.3.9.5 были
# безусловными echo). Нашёл её не сторож, а ПРОГОН САМИХ ВЕТОК на фикстурах;
# этот файл делает тот прогон постоянным инструментом, а не разовой ручной
# сборкой ([[verdict-line-that-can-only-say-unmeasurable]]).
#
# КАК. Блок эмиттеров вынимается из run-6.3-pipeline.sh между маркерами
# W639-EMITTERS-BEGIN/END (не по номерам строк — те разъезжаются с первой же
# правкой выше) и исполняется с подставленными переменными на синтетических
# снимках /debug/state и реестрах опорного набора. Проверяется не текст, а
# КЛАСС каждой метки — той же функцией классификации, что у стража, чтобы
# инструменты не разошлись в трактовке одного и того же слова.
#
# ИНВАРИАНТЫ НА КАЖДОЙ ФИКСТУРЕ (не только ожидаемые классы):
#   И1 — ровно 8 меток 6.3.9.0…6.3.9.7 получили класс, ни одна дважды;
#   И2 — каждая напечатанная вердиктная строка несёт вердиктное слово
#        ВПЛОТНУЮ за меткой (та же регулярка, что у стража) — иначе страж
#        полноты её не увидит, а фикстура бы этого не заметила;
#   И3 — ни одна метка не печатает ДВЕ вердиктные строки за прогон.
set -u

SETUP="${SETUP:-$(cd "$(dirname "$0")" && pwd)}"
PIPE="${PIPE:-$SETUP/run-6.3-pipeline.sh}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/w639-emit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
_efail() { echo "    ПРОВАЛ: $*"; FAILS=$((FAILS + 1)); }

# ── Блок эмиттеров ───────────────────────────────────────────────────────────
if ! grep -q 'W639-EMITTERS-BEGIN' "$PIPE" || ! grep -q 'W639-EMITTERS-END' "$PIPE"; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: в $PIPE нет маркеров W639-EMITTERS-BEGIN/END — вынимать нечего"
    exit 2
fi
sed -n '/W639-EMITTERS-BEGIN/,/W639-EMITTERS-END/p' "$PIPE" > "$WORK/block.sh"
_block_lines=$(wc -l < "$WORK/block.sh")
if [ "${_block_lines:-0}" -lt 40 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: между маркерами всего ${_block_lines} строк — блок вынут не тот"
    exit 2
fi
bash -n "$WORK/block.sh" || { echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: вынутый блок не разбирается bash -n"; exit 2; }

# ── Классификация — ТА ЖЕ, что у стража полноты (item 9). ────────────────────
_cls() {
    if printf '%s' "$1" | grep -q 'ЗАПРОШЕН'; then echo NOTREQ
    elif printf '%s' "$1" | grep -qE 'ПРОВАЛЕН|НЕИЗМЕРИМ'; then echo FAIL
    elif printf '%s' "$1" | grep -qE 'ДОСТИГНУТО|ИЗМЕРЕНО'; then echo OK
    else echo '?'; fi
}

_mk_state() { # $1 файл, $2 anomalies, $3 seeded ("" = ключа нет, как у бинаря без правки)
    {
        echo '{'
        echo '  "engine_stats": {'
        echo '    "anomalies_total": 999999'
        echo '  },'
        echo '  "profiler_stats": {'
        echo '    "learning_complete": true,'
        [ -n "$3" ] && echo "    \"seeded_observations_total\": $3,"
        echo "    \"anomalies_total\": $2"
        echo '  }'
        echo '}'
    } > "$1"
}

# _run <каталог ART> <want> <lines> <wtotal> <каталог опорного набора>
_run() {
    cat > "$WORK/harness.sh" <<EOF
set -u
ART="$1"; W63_BASELINE_ART="$5"
_r63_nd_want="$2"; _nd63_lines=$3; _nd63w_total=$4
_nd63w_dedup=0; _nd63w_emitted=$4; _nd63w_ratelimit=0; _nd63w_other=0; _nd63w_anomaly=0
_nd63_omitted=0
_w639_classes=""
_w639_note() { _w639_classes="\${_w639_classes}\$1=\$2 "; }
_w639_note 6.3.9.0 OK
EOF
    cat "$WORK/block.sh" >> "$WORK/harness.sh"
    bash "$WORK/harness.sh" 2>&1
}

# _check <имя фикстуры> <вывод> <ожидания вида "метка=КЛАСС" ...>
_check() {
    local name="$1" out="$2"; shift 2
    echo "--- фикстура: $name"
    local lbl exp got line n
    # И1/И3: по одной вердиктной строке на метку, восемь меток.
    n=0
    for lbl in 6.3.9.1 6.3.9.2 6.3.9.3 6.3.9.4 6.3.9.5 6.3.9.6 6.3.9.7 6.3.9.8; do
        line=$(printf '%s\n' "$out" | grep -cE "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)")
        [ "${line:-0}" -eq 1 ] || _efail "$name: метка $lbl напечатала ${line:-0} вердиктных строк вместо одной (И2/И3)"
        n=$((n + line))
    done
    [ "$n" -eq 8 ] || _efail "$name: вердиктных строк всего $n вместо восьми (И1)"
    # Ожидаемые классы.
    for exp in "$@"; do
        lbl="${exp%%=*}"; exp="${exp##*=}"
        line=$(printf '%s\n' "$out" | grep -E "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" | tail -1)
        got=$(_cls "$line")
        if [ "$got" = "$exp" ]; then
            echo "    OK  $lbl = $got"
        else
            _efail "$name: $lbl дал класс $got, ожидался $exp — строка: $(printf '%s' "$line" | cut -c1-120)"
        fi
    done
}

echo "=== ФИКСТУРНЫЙ ПРОГОН ВЕРДИКТНЫХ ВЕТОК 6.3.9.1…6.3.9.8 (блок из $PIPE, ${_block_lines} строк) ==="

# ── 1. Прогон A: бинарь БЕЗ досева, окно непусто, опорного набора нет.
A="$WORK/artA"; mkdir -p "$A"
_mk_state "$A/debug-state-window-start.json" 40 ""
_mk_state "$A/debug-state-window-end.json"   60 ""
: > "$A/window-epoch.txt"
_check "прогон A (бинарь без досева)" "$(_run "$A" on 72 101 "$WORK/none")" \
    6.3.9.1=OK 6.3.9.2=OK 6.3.9.3=FAIL 6.3.9.4=FAIL 6.3.9.5=FAIL 6.3.9.6=FAIL 6.3.9.7=OK 6.3.9.8=OK

# ── 2. Прогон B: досев есть и работает, набор снят обеими ролями.
B="$WORK/artB"; mkdir -p "$B"
_mk_state "$B/debug-state-window-start.json" 33 151
_mk_state "$B/debug-state-window-end.json"   55 196
: > "$B/window-epoch.txt"
BL="$WORK/bl_full"; mkdir -p "$BL"
printf '6.0.13 OK\n5.9.5c OK\n6.3.1 OK\n' > "$BL/baseline-labels-baseline.txt"
printf '6.0.13 OK\n5.9.5c OK\n6.3.1 OK\n' > "$BL/baseline-labels-check.txt"
_check "прогон B (досев работает, контроли целы)" "$(_run "$B" on 576 67 "$BL")" \
    6.3.9.1=FAIL 6.3.9.2=OK 6.3.9.3=OK 6.3.9.4=OK 6.3.9.5=OK 6.3.9.6=FAIL 6.3.9.7=OK 6.3.9.8=OK

# ── 3. Пустое окно при непустом прогоне — приборный ноль, а не величина.
_check "пустое окно при непустом прогоне" "$(_run "$B" on 576 0 "$BL")" \
    6.3.9.1=FAIL 6.3.9.2=FAIL 6.3.9.4=FAIL 6.3.9.7=FAIL 6.3.9.8=OK

# ── 4. Диагностика не просилась конфигом — NOTREQ, а не провал.
_check "диагностика выключена конфигом" "$(_run "$A" off 0 0 "$WORK/none")" \
    6.3.9.1=NOTREQ 6.3.9.2=NOTREQ 6.3.9.7=NOTREQ 6.3.9.8=OK

# ── 5. Досев задеплоен и НЕ сработал ни разу — двойной ноль обязан быть ПРОВАЛОМ.
D="$WORK/artD"; mkdir -p "$D"
_mk_state "$D/debug-state-window-start.json" 33 151
_mk_state "$D/debug-state-window-end.json"   55 151
: > "$D/window-epoch.txt"
_check "досев задеплоен, но нем (ноль подавлений)" "$(_run "$D" on 576 67 "$BL")" \
    6.3.9.3=FAIL 6.3.9.4=OK 6.3.9.8=OK

# ── 6. Положительный контроль потерян между опорным и проверочным набором.
BLL="$WORK/bl_lost"; mkdir -p "$BLL"
printf '6.0.13 OK\n5.9.5c OK\n6.3.1 OK\n' > "$BLL/baseline-labels-baseline.txt"
printf '6.0.13 OK\n5.9.5c FAIL\n'          > "$BLL/baseline-labels-check.txt"
_check "потерян положительный контроль детекта" "$(_run "$B" on 576 67 "$BLL")" \
    6.3.9.5=FAIL 6.3.9.3=OK 6.3.9.8=OK

# ── 7. Опорный набор пуст по OK — «ничего не потеряно» есть тождество.
BLE="$WORK/bl_empty"; mkdir -p "$BLE"
printf '6.0.13 FAIL\n' > "$BLE/baseline-labels-baseline.txt"
printf '6.0.13 OK\n'   > "$BLE/baseline-labels-check.txt"
_check "опорный набор без единого взятого контроля" "$(_run "$B" on 576 67 "$BLE")" \
    6.3.9.5=FAIL 6.3.9.8=OK

# ── 8. СТОРОЖ САМОГО СТОРОЖА: хотя бы одна метка обязана УМЕТЬ сказать не-FAIL.
#      Именно этого не умели 6.3.9.4 и 6.3.9.5 (№373), и никакая фикстура с
#      ожиданием FAIL этого бы не показала — нужен явный вопрос.
echo "--- сторож №373: способна ли каждая метка вынести годную величину хоть на одном входе"
_all_out="$(_run "$A" on 72 101 "$WORK/none")
$(_run "$B" on 576 67 "$BL")
$(_run "$A" off 0 0 "$WORK/none")"
for lbl in 6.3.9.1 6.3.9.2 6.3.9.3 6.3.9.4 6.3.9.5 6.3.9.7 6.3.9.8; do
    if printf '%s\n' "$_all_out" | grep -qE "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ИЗМЕРЕНО)"; then
        echo "    OK  $lbl способна вынести годную величину"
    else
        _efail "№373: $lbl НИ НА ОДНОМ из трёх входов не смогла напечатать ДОСТИГНУТО/ИЗМЕРЕНО — строка неспособна сказать ничего, кроме отказа"
    fi
done
# 6.3.9.6 исключена намеренно: решением владельца по №372 у неё нет предмета,
# и её НЕИЗМЕРИМ с названным классом — законный окончательный вердикт.
echo "    (6.3.9.6 исключена намеренно: предмета нет по решению владельца, №372)"

echo
if [ "$FAILS" -gt 0 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ ПРОВАЛЕН: расхождений $FAILS"
    exit 1
fi
echo "СТОРОЖ ЭМИТТЕРОВ ПРОЙДЕН: 7 фикстур + сторож №373, расхождений 0"
