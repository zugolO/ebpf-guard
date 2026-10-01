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

# ── Сверки ТЕКСТА определяются ЗДЕСЬ, а не ниже по файлу. Раньше они стояли
#    после первого использования (фикстуры 6.4.3), и bash печатал
#    «_need_text: command not found» для КАЖДОЙ из них, не останавливая прогон:
#    девять сверок текста не исполнялись НИ РАЗУ, а сторож заканчивал словами
#    «расхождений 0». Порядок закреплён сторожем «вызов раньше определения» в
#    конце файла — это тот же класс ложного PASS, что [[elif-verdict-masks-independent-halves]].
# _line_label <строка> — метка из САМОЙ строки вердикта. Реестр наполняется из
# напечатанного, а не из имени фикстуры: сверка не может зарегистрировать метку,
# которой в строке нет.
# Метка берётся из строки: 6.4.N, 6.4B.N и метки волны 6.5 (6.5.N). Список
# префиксов расширяется ВМЕСТЕ с таблицей меток — иначе новая метка проходит
# сверку текста «мимо» и №461 читает это как «сверена».
_line_label() { printf '%s' "$1" | grep -oE '6\.(4B?|5|6|7)\.[0-9]+' | head -1; }

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

# _forbid_text <имя> <строка> <запрещённые подстроки…> — негативная половина
# сверки текста. Нужна там, где ветка обязана НЕ утверждать чужой класс: строка
# «ось продюсера НЕ НАПЕЧАТАНА» не смеет в том же предложении говорить
# «нагрузка ДОШЛА до слоя правил». Метку НЕ регистрирует: реестр №461 наполняется
# положительными сверками, иначе запрет засчитывался бы как сверка содержания.
_forbid_text() {
    local name="$1" line="$2"; shift 2
    local sub hit=""
    if [ "$#" -lt 1 ]; then
        _efail "запрет/${name}: не задано ни одной запрещённой подстроки — пустой запрет есть тождество"
        return 0
    fi
    if [ -z "$line" ]; then
        _efail "запрет/${name}: вердиктной строки нет вовсе — запрещать нечего, а метка молчит"
        return 0
    fi
    for sub in "$@"; do
        [ -n "$sub" ] && _text_ok "$line" "$sub" && hit="${hit}«${sub}» "
    done
    if [ -n "$hit" ]; then
        _efail "запрет/${name}: в строке ЕСТЬ ${hit}— ветка утверждает чужой класс; строка: $(printf '%s' "$line" | cut -c1-220)"
        return 0
    fi
    echo "    OK  запрет ${name}: чужого класса в строке нет"
}

# _line_of <вывод блока> <метка> — самая вердиктная строка этой метки.
_line_of() {
    printf '%s\n' "$1" | grep -E "(^|[^0-9.])${2//./\\.}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" | tail -1
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

# ── 8. КОНТРОЛЬ ИСПОЛНЕН, АЛЕРТОВ НОЛЬ — И ЭТО ЧЕТЫРЕ РАЗНЫХ СЛУЧАЯ (№493).
#    До этой правки все четыре печатались одним ПРОДУКТОВЫМ провалом: у метки
#    6.4.3 не было оси подавления, которую её сосед 6.4.4 читает с №455
#    ([[control-643-has-no-suppression-axis]], [[dedup-is-third-suppression-layer]],
#    [[control-after-attacks-hits-filled-limiter]]). Ветки проверяются ВСЕ, и
#    каждая — своим текстом, а не только классом.
H="$WORK/artH"; mkdir -p "$H"
_mk_metrics "$H/metrics-live.txt" 4 "" "" "" ""
_mk_metrics "$H/metrics-window-start.txt" "" "" 10 2 5
_mk_metrics "$H/metrics-window-end.txt"   "" "" 30 3 8
# (а) СТАРЫЙ АРХИВ: оси подавления в контроле нет вовсе — продуктовый провал
#     объявлять не на чем, класс НЕИЗМЕРИМ с названной причиной.
{ echo "events_delta=40"; echo "manifest_alerts=0"; } > "$H/tls-control-plaintext.txt"
_h493_old="$(_run "$H" B off)"
_check "контроль item 5 без оси подавления (архив до №493) — НЕИЗМЕРИМ, а не провал" "$_h493_old" \
    6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 архив без оси подавления" "$(_line_of "$_h493_old" 6.4.3)" \
    "ОСИ ПОДАВЛЕНИЯ в контроле нет вовсе" "НЕ НАПЕЧАТАН" "неотличимо" "объявлять НЕ на чем"
# (б) ДЕДУП: алерт был и схлопнут слоем ПЕРЕД лимитером.
{ echo "events_delta=40"; echo "manifest_alerts=0"; echo "manifest_alerts_since=0"
  echo "manifest_alerts_delta=0"; echo "dedup_delta=3"; echo "ratelimit_delta=0"; } > "$H/tls-control-plaintext.txt"
_h493_dd="$(_run "$H" B off)"
_check "алерт схлопнут дедупом — НЕИЗМЕРИМ (не потеря детекта)" "$_h493_dd" 6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 срез дедупа" "$(_line_of "$_h493_dd" 6.4.3)" \
    "СХЛОПНУТ ДЕДУПОМ" "срез 3" "ПЕРЕД лимитером" "№455"
# (в) ЛИМИТЕР: контроль ставится ПОСЛЕ окна атак, то есть в наполненный потолок.
{ echo "events_delta=40"; echo "manifest_alerts=0"; echo "manifest_alerts_since=0"
  echo "manifest_alerts_delta=0"; echo "dedup_delta=0"; echo "ratelimit_delta=4"; } > "$H/tls-control-plaintext.txt"
_h493_rl="$(_run "$H" B off)"
_check "алерт срезан лимитером — НЕИЗМЕРИМ (ноль есть срез)" "$_h493_rl" 6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 срез лимитера" "$(_line_of "$_h493_rl" 6.4.3)" \
    "СРЕЗАН ЛИМИТЕРОМ" "срез 4" "10/правило/60" "наполненный лимитер"
# (г) ОБА СЛОЯ НУЛЕВЫЕ И НАГРУЗКА ДОШЛА: алерт не подавлялся, его не было, и
#     матчить БЫЛО ЧЕМ — вот здесь провал ПРОДУКТОВЫЙ слоя правил, и только
#     здесь (№496: без оси продюсера этот случай неотличим от пустых событий).
{ echo "events_delta=40"; echo "manifest_alerts=0"; echo "manifest_alerts_since=0"
  echo "manifest_alerts_delta=0"; echo "dedup_delta=0"; echo "ratelimit_delta=0"
  echo "payload_axis=есть"; echo "payload_captured_delta=40"; echo "payload_empty_delta=0"
  echo "payload_detail=write_captured=20,write_empty=0,read_captured=20,read_empty=0"; } > "$H/tls-control-plaintext.txt"
_h493_pr="$(_run "$H" B off)"
_check "события есть, оба слоя нулевые, нагрузка дошла — ПРОВАЛЕН (продуктовый)" "$_h493_pr" 6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 продуктовый провал" "$(_line_of "$_h493_pr" 6.4.3)" \
    "класс ПРОДУКТОВЫЙ" "оба слоя подавления НУЛЕВЫЕ" "детекта нет" \
    "нагрузку донесли 40" "провал ИМЕННО детекта"
# (е) №496: ОСИ ПРОДЮСЕРА НЕТ (архив до №496) — вердикт ПРОВАЛЕН объявлять не
#     на чем: захват нагрузки мог не удаться, и слою правил матчить было
#     нечего. Это ровно тот вход, на котором №493 объявил продуктовый провал
#     детекта на архиве collect-6.6-japrobe.
{ echo "events_delta=6"; echo "manifest_alerts=0"; echo "manifest_alerts_since=0"
  echo "manifest_alerts_delta=0"; echo "dedup_delta=0"; echo "ratelimit_delta=0"; } > "$H/tls-control-plaintext.txt"
_h496_noaxis="$(_run "$H" B off)"
_check "оси продюсера нет (архив до №496) — НЕИЗМЕРИМ, а не провал детекта" "$_h496_noaxis" 6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 нет оси продюсера" "$(_line_of "$_h496_noaxis" 6.4.3)" \
    "ОСИ ПРОДЮСЕРА в контроле нет" "архив до №496" "ПУСТЫМ" "объявлять НЕ на чем"
# (ж) №496: СОБЫТИЯ ПРИШЛИ ПУСТЫМИ — провал ПРОДЮСЕРА, а не слоя правил.
{ echo "events_delta=6"; echo "manifest_alerts=0"; echo "manifest_alerts_since=0"
  echo "manifest_alerts_delta=0"; echo "dedup_delta=0"; echo "ratelimit_delta=0"
  echo "payload_axis=есть"; echo "payload_captured_delta=0"; echo "payload_empty_delta=6"
  echo "payload_detail=write_captured=0,write_empty=6,read_captured=0,read_empty=0"; } > "$H/tls-control-plaintext.txt"
_h496_empty="$(_run "$H" B off)"
_check "события пришли с пустой нагрузкой — ПРОВАЛЕН (дефект продюсера)" "$_h496_empty" 6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 провал продюсера" "$(_line_of "$_h496_empty" 6.4.3)" \
    "дефект ПРОДЮСЕРА" "НИ ОДНО не донесло нагрузку" "пустыми пришли 6" "чинить продюсера, а не правило"
# (з) №496, ВТОРАЯ ФОРМА ОТСУТСТВИЯ ОСИ: ключ в контроле ЕСТЬ, но величина —
#     СЛОВО. Ровно это пишет контроль на бинаре ДО №496 (payload_axis=НЕТ_СЕРИИ),
#     и проверка на пустую строку такой вход пропускала в продуктовый вердикт:
#     строка одновременно говорила «ось НЕ НАПЕЧАТАНА» и «нагрузка ДОШЛА».
{ echo "events_delta=6"; echo "manifest_alerts=0"; echo "manifest_alerts_since=0"
  echo "manifest_alerts_delta=0"; echo "dedup_delta=0"; echo "ratelimit_delta=0"
  echo "payload_axis=НЕТ_СЕРИИ"; echo "payload_captured_delta=НЕИЗМЕРИМО"
  echo "payload_empty_delta=НЕИЗМЕРИМО"; echo "payload_detail=НЕИЗМЕРИМО"; } > "$H/tls-control-plaintext.txt"
_h496_word="$(_run "$H" B off)"
_check "ось продюсера названа СЛОВОМ (бинарь до №496) — НЕИЗМЕРИМ, а не провал детекта" "$_h496_word" 6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 словесная ось продюсера" "$(_line_of "$_h496_word" 6.4.3)" \
    "ОСИ ПРОДЮСЕРА в контроле нет" "НЕИЗМЕРИМО" "объявлять НЕ на чем"
_forbid_text "6.4.3 словесная ось продюсера" "$(_line_of "$_h496_word" 6.4.3)" \
    "нагрузка ДОШЛА до слоя правил"
# (и) №496: событий семейства payload не было ВООБЩЕ (0 захвачено, 0 пустых) при
#     ненулевом events_delta — events_total{type="tls"} считает и ja3/рукопожатие.
#     Вход правила tls_http_basic_auth в окне был пуст, и вердикт о слое правил
#     выносить не на чем; прежняя ветка объявляла тут продуктовый провал детекта.
{ echo "events_delta=6"; echo "manifest_alerts=0"; echo "manifest_alerts_since=0"
  echo "manifest_alerts_delta=0"; echo "dedup_delta=0"; echo "ratelimit_delta=0"
  echo "payload_axis=есть"; echo "payload_captured_delta=0"; echo "payload_empty_delta=0"
  echo "payload_detail=write_captured=0,write_empty=0,read_captured=0,read_empty=0"; } > "$H/tls-control-plaintext.txt"
_h496_nopay="$(_run "$H" B off)"
_check "событий семейства payload не было вовсе — НЕИЗМЕРИМ, а не провал детекта" "$_h496_nopay" 6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 нет payload-событий" "$(_line_of "$_h496_nopay" 6.4.3)" \
    "НИ ОДНО из них не семейства payload" "ja3" "выносить не на чем"
_forbid_text "6.4.3 нет payload-событий" "$(_line_of "$_h496_nopay" 6.4.3)" \
    "нагрузка ДОШЛА до слоя правил"
# №504: ПРЕДИКАТ ПОВТОРА ОБМЕНА в самом контроле. Живой заход 28.09.2026
# взял только ветвь «успех с первой попытки»; ветвь повтора живьём не срабатывала
# ни разу, и без этой фикстуры она была бы непроверенным кодом в живом приборе
# ([[helper-called-before-definition-is-silent-pass]] в форме «ветка есть, фикстуры нет»).
echo "--- №504: предикат повтора обмена (_w64_captured_delta) ---"
_w504_ctl="$(dirname "${BASH_SOURCE[0]}")/wave6.4-item5-item6-tls-controls.sh"
# Вытаскиваем ТОЛЬКО тело помощника: `source` всего файла занёс бы его
# `set -u` и запустил контроли ([[sourcing-lib-leaks-set-e]]).
_w504_fn=$(awk '/^_w64_captured_delta\(\) \{/,/^\}/' "$_w504_ctl")
if [ -z "$_w504_fn" ]; then
    _efail "№504: _w64_captured_delta не найдена в $_w504_ctl — предикат повтора непроверяем"
else
    eval "$_w504_fn"
    _w504_case() { # описание, before, after, ожидание
        local g
        g=$(_w64_captured_delta "$2" "$3")
        if [ "$g" = "$4" ]; then
            echo "    OK  $1 (получено '${g}')"
        else
            _efail "$1: получено '${g}', ожидалось '$4'"
        fi
    }
    #                                                        c_w z_w x_w c_r z_r x_r
    _w504_case "нагрузка не дошла — 0, обмен повторяется" \
        "0 0 0 0 0 0" "0 2 0 0 0 0" "0"
    _w504_case "нагрузка дошла write — >0, повтор прекращается" \
        "0 0 0 0 0 0" "1 2 0 0 0 0" "1"
    _w504_case "нагрузка дошла read — считается тоже (оба направления)" \
        "0 0 0 0 0 0" "0 0 0 3 0 0" "3"
    _w504_case "счётчики не с нуля — берётся ДЕЛЬТА, а не абсолют" \
        "7 4 1 2 0 0" "8 9 1 2 0 0" "1"
    _w504_case "отказы чтения растут, а захват нет — всё равно 0" \
        "0 0 0 0 0 0" "0 0 5 0 0 0" "0"
    # НЕЧИТАЕМАЯ ОСЬ — ПУСТАЯ СТРОКА, А НЕ НОЛЬ. Ноль запустил бы три
    # попытки обмена там, где величины просто нет, и приписал контролю цену
    # трёх обменов за отсутствующий прибор.
    _w504_case "оси нет (пустой before) — ПУСТО, не ноль" "" "0 2 0 0 0 0" ""
    _w504_case "оси нет (пустой after) — ПУСТО, не ноль" "0 0 0 0 0 0" "" ""
    _w504_case "секстет неполон четырьмя полями (бинарь до №504) — ПУСТО" \
        "0 0 0 0" "1 2 0 0" ""
fi

# (к) №504, ПЕРВАЯ ИЗ ДВУХ ПРИЧИН ПУСТОТЫ: ВСЯ пустота — вызовы
#     SSL_write с num<=0, отказов чтения буфера НОЛЬ. Это НЕ дефект
#     продюсера: обмен не отдал ни одного содержательного байта.
#     Ровно этот вход стоит в архиве w7A, и до №504 по нему печатался
#     ложный ПРОДУКТОВЫЙ вердикт.
{ echo "events_delta=2"; echo "manifest_alerts=0"; echo "manifest_alerts_since=0"
  echo "manifest_alerts_delta=0"; echo "dedup_delta=0"; echo "ratelimit_delta=0"
  echo "payload_axis=есть"; echo "payload_captured_delta=0"; echo "payload_empty_delta=2"
  echo "payload_detail=write_captured=0,write_zero_len=2,write_read_failed=0,read_captured=0,read_zero_len=0,read_read_failed=0"
  echo "payload_zero_len_delta=2"; echo "payload_read_failed_delta=0"
  echo "exchange_attempts=3"; echo "exchange_max_attempts=3"; } > "$H/tls-control-plaintext.txt"
_h504_zero="$(_run "$H" B off)"
_check "№504: вся пустота — num<=0, отказов чтения ноль — НЕИЗМЕРИМ, а не дефект продюсера" "$_h504_zero" 6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 обмен не отдал нагрузку" "$(_line_of "$_h504_zero" 6.4.3)" \
    "ОБМЕН НЕ ОТДАЛ НАГРУЗКУ" "num<=0" "отказов чтения буфера НОЛЬ" "чинить КОНТРОЛЬ" "3 раз(а) из 3"
# Сторож ложного продуктового вердикта на ТОЙ ЖЕ оси: строка не вправе
# назвать продюсера виновным на входе, где отказов чтения ноль.
_forbid_text "6.4.3 обмен не отдал нагрузку" "$(_line_of "$_h504_zero" 6.4.3)" \
    "дефект ПРОДЮСЕРА"
# (л) №504, ВТОРАЯ ПРИЧИНА: ядро видело num>0 и захватило ноль.
#     ТОЛЬКО здесь вердикт вправе объявить дефект продюсера.
{ echo "events_delta=6"; echo "manifest_alerts=0"; echo "manifest_alerts_since=0"
  echo "manifest_alerts_delta=0"; echo "dedup_delta=0"; echo "ratelimit_delta=0"
  echo "payload_axis=есть"; echo "payload_captured_delta=0"; echo "payload_empty_delta=6"
  echo "payload_detail=write_captured=0,write_zero_len=2,write_read_failed=4,read_captured=0,read_zero_len=0,read_read_failed=0"
  echo "payload_zero_len_delta=2"; echo "payload_read_failed_delta=4"
  echo "exchange_attempts=1"; echo "exchange_max_attempts=3"; } > "$H/tls-control-plaintext.txt"
_h504_rdf="$(_run "$H" B off)"
_check "№504: отказы чтения буфера ненулевые — ПРОВАЛЕН (дефект продюсера)" "$_h504_rdf" 6.4.3=FAIL 6.4.8=OK
_need_text "6.4.3 отказ чтения буфера" "$(_line_of "$_h504_rdf" 6.4.3)" \
    "дефект ПРОДЮСЕРА" "ОТКАЗ ЧТЕНИЯ буфера (bpf_probe_read_user) 4" "чинить продюсера, а не правило"
_forbid_text "6.4.3 отказ чтения буфера" "$(_line_of "$_h504_rdf" 6.4.3)" \
    "ОБМЕН НЕ ОТДАЛ НАГРУЗКУ"
# (д) ИЗОЛИРОВАННАЯ ВЕЛИЧИНА РЕШАЕТ ВЕРДИКТ, а не «весь стор»: старых
#     срабатываний в сторе 9, но ЭТОТ обмен дал 2 — судится по 2.
{ echo "events_delta=40"; echo "manifest_alerts=9"; echo "manifest_alerts_since=2"
  echo "manifest_alerts_delta=2"; echo "dedup_delta=0"; echo "ratelimit_delta=0"
  echo "payload_axis=есть"; echo "payload_captured_delta=38"; echo "payload_empty_delta=2"
  echo "payload_detail=write_captured=19,write_empty=1,read_captured=19,read_empty=1"; } > "$H/tls-control-plaintext.txt"
_h493_ok="$(_run "$H" B off)"
_check "изолированная дельта по отсечке даёт вердикт — ДОСТИГНУТО" "$_h493_ok" 6.4.3=OK 6.4.8=OK
_need_text "6.4.3 вердикт по отсечке" "$(_line_of "$_h493_ok" 6.4.3)" \
    "ЗА ОБМЕН по отсечке 2" "весь стор 9" "ось подавления предъявлена" "ВСЕ слои" \
    "ось продюсера" "нагрузку донесли 38"

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

# ── 18. МЕТКА 6.6.7 (цена `http_plaintext` НА ЗАПРОС, №490). Живёт в блоке
#    W648 (не в W66 — plan.md называл её местом W66-EMITTERS, это неточность
#    текста, не кода), и до 27.09.2026 у неё НЕ БЫЛО НИ ОДНОЙ ФИКСТУРЫ при
#    шести ветках. Заводятся все шесть — включая ту, ради которой открытый
#    вопрос 2 разбора №490 и решался: ПОЛ при нулевом входе.
#
#    Инвариант И2/И3 блока W648 («ровно девять вердиктных строк 6.4.0…6.4.8»)
#    метку 6.6.7 не считает, поэтому `_check` здесь не годится — проверка
#    идёт по СВОЕЙ строке, как у №455 с меткой 6.4.4.
#
# _mk_m667 <каталог> <ev0|-> <ev1|-> <collector_up|->  — снимки границ окна с
# серией http_plaintext; «-» у ev означает «файлов границ окна нет вовсе».
_mk_m667() {
    local d="$1" ev0="$2" ev1="$3" up="$4"
    mkdir -p "$d"; rm -f "$d/metrics-window-start.txt" "$d/metrics-window-end.txt"
    _mk_metrics "$d/metrics-live.txt" 2 "" "" "" "" 2
    [ "$ev0" = "-" ] && return
    {
        echo "ebpf_guard_events_total{type=\"tls\"} 10"
        echo "ebpf_guard_events_total{type=\"http_plaintext\"} $ev0"
    } > "$d/metrics-window-start.txt"
    {
        echo "ebpf_guard_events_total{type=\"tls\"} 30"
        echo "ebpf_guard_events_total{type=\"http_plaintext\"} $ev1"
        [ "$up" = "-" ] || echo "ebpf_guard_collector_up{collector=\"http_plaintext\"} $up"
    } > "$d/metrics-window-end.txt"
}
# _mk_pc667 <каталог> <scheduled> <holder_alive> <requests_ok> <requests_planned>
_mk_pc667() {
    local d="$1"; mkdir -p "$d"
    printf 'requests_planned=%s\nrequests_ok=%s\nscheduled=%s\nholder_alive_at_window_end=%s\nholder_comm=python3\nholder_pid=4242\nfire_result=success\ntracked_pids_at_window_end=1\ncollector_up_at_window_end=1\n' \
        "$5" "$4" "$2" "$3" > "$d/http-price-control.txt"
}
# _check667 <имя> <каталог> <ожидаемый класс> <обязательные подстроки…>
_check667() {
    local name="$1" art="$2" exp="$3"; shift 3
    local out line got want
    out="$(_run "$art" B off)"
    line=$(printf '%s\n' "$out" | grep -E "(^|[^0-9.])6\.6\.7[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" | tail -1)
    echo "--- фикстура 6.6.7: $name"
    local n
    n=$(printf '%s\n' "$out" | grep -cE "(^|[^0-9.])6\.6\.7[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)")
    [ "${n:-0}" -eq 1 ] || _efail "6.6.7/${name}: вердиктных строк ${n:-0} вместо одной"
    got=$(_cls "$line")
    if [ "$got" = "$exp" ]; then
        echo "    OK  6.6.7 = $got"
    else
        _efail "6.6.7/${name}: класс $got, ожидался $exp — строка: $(printf '%s' "$line" | cut -c1-190)"
    fi
    for want in "$@"; do
        if _text_ok "$line" "$want"; then
            echo "    OK  текст несёт «${want}»"
            _replay_note "6.6.7 ${name}" "$line" "$want"
        else
            _efail "6.6.7/${name}: в строке нет «${want}» — строка: $(printf '%s' "$line" | cut -c1-190)"
        fi
    done
}

echo
echo "=== №490: шесть веток метки 6.6.7 (цена http_plaintext на запрос) ==="
export W66_HTTP_PRICE_CONTROL=off
P667="$WORK/art667"; rm -rf "$P667"; mkdir -p "$P667"
_mk_m667 "$P667" 100 140 1
_check667 "контроль не поставлен — НЕ ЗАПРОШЕН, не цена 0" "$P667" NOTREQ "не назначается вакуумно"
export W66_HTTP_PRICE_CONTROL=on
_mk_pc667 "$P667" 0 1 5 5
_check667 "таймер запросов не поставлен — НЕИЗМЕРИМ" "$P667" FAIL "таймер_запросов_не_поставлен"
_mk_pc667 "$P667" 1 0 5 5
_check667 "держатель не дожил до конца окна — НЕИЗМЕРИМ" "$P667" FAIL "держатель_не_дожил_до_конца_окна"
_mk_pc667 "$P667" 1 1 0 5
_check667 "ни один запрос не получил 200 — НЕИЗМЕРИМ" "$P667" FAIL "ни_один_запрос_не_получил_200"
_mk_pc667 "$P667" 1 1 5 5
_mk_m667 "$P667" - - -
_check667 "снимки границ окна не сняты — НЕИЗМЕРИМ" "$P667" FAIL "снимки границ окна не сняты"
# ВЕТКА-ПОЛ (открытый вопрос 2 разбора №490): роль A обязана НЕ печатать цену.
_mk_m667 "$P667" 100 100 0
_check667 "вход пуст (роль A) — НЕИЗМЕРИМ, ПОЛ, а не цена 0.000" "$P667" FAIL     "ЦЕНА НЕ ДЕЛИТСЯ НА ОТСУТСТВУЮЩИЙ ВХОД" "объём окна БЕЗ коллектора" "collector_up=1"
_forbid_text "6.6.7 роль A не печатает цену" "$(_line_of "$(_run "$P667" B off)" 6.6.7)"     "ИЗМЕРЕНО" "0.000" "событий/запрос"
# ВЕТКА ЦЕНЫ (роль B): вход непустой — величина назначается.
_mk_m667 "$P667" 100 140 1
_check667 "вход непустой (роль B) — ИЗМЕРЕНО, цена назначена" "$P667" OK     "событий за окно 40" "успешных запросов 5" "8.000 событий/запрос" "requests_planned ОБЯЗАН совпасть"
unset W66_HTTP_PRICE_CONTROL

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

# ── ФИКСТУРНЫЙ ПРОГОН БЛОКА W66 (метки 6.6.1 и 6.6.2, ярус A волны 6.6). Отдельный
#    блок и харнесс: у W648/W64B/W65 свои инварианты числа меток.
if ! grep -q 'W66-EMITTERS-BEGIN' "$PIPE" || ! grep -q 'W66-EMITTERS-END' "$PIPE"; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: в $PIPE нет маркеров W66-EMITTERS-BEGIN/END — метки 6.6.1/6.6.2 вынимать нечем"
    exit 2
fi
sed -n '/W66-EMITTERS-BEGIN/,/W66-EMITTERS-END/p' "$PIPE" > "$WORK/block66.sh"
_block66_lines=$(wc -l < "$WORK/block66.sh")
if [ "${_block66_lines:-0}" -lt 40 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: между маркерами W66 всего ${_block66_lines} строк — блок вынут не тот"
    exit 2
fi
bash -n "$WORK/block66.sh" || { echo "СТОРОЖ ЭМИТТЕРОВ НЕИЗМЕРИМ: блок W66 не разбирается bash -n"; exit 2; }

# _run66 <каталог-ART> <файл снимка пролога> — гоняет блок W66. Отсутствие любого
# из файлов — ЗАКОННЫЙ вход (класс «снимка не было»).
_run66() {
    cat > "$WORK/harness66.sh" <<EOF66
set -u
ART="$1"
_w66_pro="$2"
_w648_role="${W66_TEST_ROLE:-B}"
EOF66
    cat "$WORK/block66.sh" >> "$WORK/harness66.sh"
    bash "$WORK/harness66.sh" 2>&1
}

# _check66 <метка> <имя> <вывод> <ожидаемый класс> — ровно одна вердиктная строка
# метки (И2/И3) и её класс; возвращает вердиктную строку.
_check66() {
    local lbl="$1" name="$2" out="$3" exp="$4" line got n
    echo "--- фикстура ${lbl}: $name" >&2
    n=$(printf '%s\n' "$out" | grep -cE "(^|[^0-9.])${lbl//./\\.}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)")
    [ "${n:-0}" -eq 1 ] || _efail "$name: метка $lbl напечатала ${n:-0} вердиктных строк вместо одной (И2/И3)"
    line=$(_line_of "$out" "$lbl")
    got=$(_cls "$line")
    if [ "$got" = "$exp" ]; then
        echo "    OK  $lbl = $got" >&2
    else
        _efail "$name: $lbl дал класс $got, ожидался $exp — строка: $(printf '%s' "$line" | cut -c1-200)" >&2
    fi
    printf '%s' "$line"
}

# _mk_drops <файл> <pst|-> <syscall_rr> <fileaccess_rr> <dns_rr> [parse_error-пары "коллектор=N …"] [up-пары "коллектор=N …"]
# Снимок /metrics ровно с теми сериями, что читает блок W66. pst «-» — строки
# process_start_time_seconds нет; пары parse_error пусты — серий нет ВООБЩЕ.
_mk_drops() {
    local f="$1" pst="$2" sy="$3" fa="$4" dn="$5" pe="${6:-}" up="${7:-}" qq="${8:-}" pair
    : > "$f"
    [ "$pst" != "-" ] && echo "process_start_time_seconds $pst" >> "$f"
    echo "ebpf_guard_event_queue_dropped_total 0" >> "$f"
    echo "ebpf_guard_events_dropped_total{collector=\"dns\",reason=\"ringbuf_to_router\"} $dn" >> "$f"
    echo "ebpf_guard_events_dropped_total{collector=\"fileaccess\",reason=\"path_denylist\"} 99999" >> "$f"
    echo "ebpf_guard_events_dropped_total{collector=\"fileaccess\",reason=\"ringbuf_to_router\"} $fa" >> "$f"
    echo "ebpf_guard_events_dropped_total{collector=\"syscall\",reason=\"ringbuf_to_router\"} $sy" >> "$f"
    for pair in $pe; do
        echo "ebpf_guard_events_dropped_total{collector=\"${pair%%=*}\",reason=\"parse_error\"} ${pair##*=}" >> "$f"
    done
    for pair in $up; do
        echo "ebpf_guard_collector_up{collector=\"${pair%%=*}\"} ${pair##*=}" >> "$f"
    done
    # Пункт 12 ревизии 6.6: ОТДЕЛЬНАЯ серия соответствия очередь↔коллектор. Пары
    # вида «коллектор:очередь=N». Пустой аргумент — серии в снимке НЕТ ВООБЩЕ
    # (бинарь до пункта 12), и это законный вход: эмиттер обязан назвать источник
    # словом, а не молча выдать зашитое зеркало кода за показание рантайма.
    for pair in $qq; do
        echo "ebpf_guard_events_dropped_by_queue_total{collector=\"${pair%%:*}\",queue=\"$(echo "${pair#*:}" | cut -d= -f1)\"} ${pair##*=}" >> "$f"
    done
}

echo
echo "=== ФИКСТУРНЫЙ ПРОГОН ВЕРДИКТНЫХ ВЕТОК 6.6.1 и 6.6.2 (блок из $PIPE, ${_block66_lines} строк) ==="

# mk661 <каталог> — четыре снимка с заданными потерями: старт(пролог) → окно → после.
# Ожидаемая сумма для «здоровой» пары: syscall 3656 на старте, окно +5, после +0;
# fileaccess 0 → 0 → 0 → 452.
_A661="$WORK/art661"; mkdir -p "$_A661"
_mk_drops "$WORK/pro661.txt"                  1790305396 3656 0   0
_mk_drops "$_A661/metrics-window-start.txt"   1790305396 3656 0   0
_mk_drops "$_A661/metrics-window-end.txt"     1790305396 3661 0   0
_mk_drops "$_A661/metrics-run-end.txt"        1790305396 3661 452 0
_t661_ok=$(_check66 6.6.1 "всплеск 3656 на старте, тождество сходится — ИЗМЕРЕНО с величиной" \
    "$(_run66 "$_A661" "$WORK/pro661.txt")" OK)
_need_text "6.6.1 стартовый всплеск: величина, разрез, очередь, тождество" "$_t661_ok" \
    "= 3656 событий" "syscall/ringbuf_to_router=3656" "очередь protected" \
    "старт 3656 + пролог 0 + окно 5 + после окна 452 = 4113 = абсолют run-end 4113" \
    "fileaccess/ringbuf_to_router=0/0/452"

# Всплеск в bulk-очереди: хоп называет очередь, а не «protected» по умолчанию.
_A661B="$WORK/art661b"; mkdir -p "$_A661B"
_mk_drops "$WORK/pro661b.txt"                  7 0 41 0
_mk_drops "$_A661B/metrics-window-start.txt"   7 0 41 0
_mk_drops "$_A661B/metrics-window-end.txt"     7 0 41 0
_mk_drops "$_A661B/metrics-run-end.txt"        7 0 41 0
_t661_bulk=$(_check66 6.6.1 "всплеск в fileaccess — очередь bulk названа рядом" \
    "$(_run66 "$_A661B" "$WORK/pro661b.txt")" OK)
_need_text "6.6.1 очередь bulk" "$_t661_bulk" "= 41 событий" "fileaccess/ringbuf_to_router=41" "очередь bulk"

# Ноль ВЗЯТОГО снимка — тоже ИЗМЕРЕНО, но с числом серий: отличим от «снимка не было».
_A661Z="$WORK/art661z"; mkdir -p "$_A661Z"
_mk_drops "$WORK/pro661z.txt"                  7 0 0 0
for _f in metrics-window-start metrics-window-end metrics-run-end; do _mk_drops "$_A661Z/$_f.txt" 7 0 0 0; done
_t661_zero=$(_check66 6.6.1 "нулевой всплеск при взятом снимке — ИЗМЕРЕНО, ноль читается нулём" \
    "$(_run66 "$_A661Z" "$WORK/pro661z.txt")" OK)
_need_text "6.6.1 ноль взятого снимка (величина и основание)" "$_t661_zero" "= 0 событий" "серий потерь в нём 4" "снимок пролога ВЗЯТ"

_A661N="$WORK/art661n"; mkdir -p "$_A661N"
_check66 6.6.1 "снимка пролога нет — НЕИЗМЕРИМ, а не ноль" \
    "$(_run66 "$_A661" "$WORK/net-takogo-fajla.txt")" FAIL >/dev/null
_t661_nowe=$(_check66 6.6.1 "нет metrics-window-end.txt — НЕИЗМЕРИМ с названным файлом" \
    "$(_run66 "$_A661N" "$WORK/pro661.txt")" FAIL)
_need_text "6.6.1 названа нехватка снимка" "$_t661_nowe" "снимка не было" "metrics-window-end.txt" "неотличимо от нуля"

_A661R="$WORK/art661r"; mkdir -p "$_A661R"
_mk_drops "$WORK/pro661r.txt"                  1790305396 3656 0 0
_mk_drops "$_A661R/metrics-window-start.txt"   1790305396 3656 0 0
_mk_drops "$_A661R/metrics-window-end.txt"     1790305396 3656 0 0
_mk_drops "$_A661R/metrics-run-end.txt"        1790399999 12   0 0
_t661_rst=$(_check66 6.6.1 "рестарт агента между снимками — НЕИЗМЕРИМ (абсолют чужого процесса)" \
    "$(_run66 "$_A661R" "$WORK/pro661r.txt")" FAIL)
_need_text "6.6.1 рестарт назван" "$_t661_rst" "process_start_time_seconds" "разный процесс" "3656"

_A661G="$WORK/art661g"; mkdir -p "$_A661G"
_mk_drops "$WORK/pro661g.txt"                  5 100 0 0
_mk_drops "$_A661G/metrics-window-start.txt"   5 100 0 0
_mk_drops "$_A661G/metrics-window-end.txt"     5 90  0 0
_mk_drops "$_A661G/metrics-run-end.txt"        5 100 0 0
_t661_neg=$(_check66 6.6.1 "счётчик уменьшился внутри снимков — тождество не сходится, НЕИЗМЕРИМ" \
    "$(_run66 "$_A661G" "$WORK/pro661g.txt")" FAIL)
_need_text "6.6.1 нарушение тождества названо серией" "$_t661_neg" "тождество интервалов не сошлось" "syscall/ringbuf_to_router" "интервал потерян снова"

_A661S="$WORK/art661s"; mkdir -p "$_A661S"
printf 'process_start_time_seconds 5\n' > "$WORK/pro661s.txt"
for _f in metrics-window-start metrics-window-end metrics-run-end; do cp "$WORK/pro661s.txt" "$_A661S/$_f.txt"; done
_t661_nos=$(_check66 6.6.1 "серий потерь в снимке нет вовсе — НЕИЗМЕРИМ, отсутствие серии не ноль" \
    "$(_run66 "$_A661S" "$WORK/pro661s.txt")" FAIL)
_need_text "6.6.1 нет серий" "$_t661_nos" "серий потерь нет в снимке" "не есть ноль"

# ── Пункт 12 ревизии 6.6: ИСТОЧНИК соответствия очередь↔коллектор. До правки он
# был зашит в эмиттер зеркалом defaultEventPriority (priority.go), и правка той
# функции молча развела бы эмиттер с кодом. Теперь очередь берётся ОТДЕЛЬНОЙ
# серией ebpf_guard_events_dropped_by_queue_total (не лейблом к
# events_dropped_total: лейбл пересортировал бы экспозицию и сломал бы якоря
# читателей, [[metric-label-added-breaks-awk-anchors]]), а зашитое зеркало
# осталось запасом для бинаря без серии. Строка обязана НАЗЫВАТЬ источник:
# «зашито» и «метрика» не выдаются друг за друга.
_A661Q="$WORK/art661q"; mkdir -p "$_A661Q"
_Q_AGREE="syscall:protected=3656 fileaccess:bulk=452"
_mk_drops "$WORK/pro661q.txt"                  1790305396 3656 0   0 "" "" ""
_mk_drops "$_A661Q/metrics-window-start.txt"   1790305396 3656 0   0 "" "" ""
_mk_drops "$_A661Q/metrics-window-end.txt"     1790305396 3661 0   0 "" "" ""
_mk_drops "$_A661Q/metrics-run-end.txt"        1790305396 3661 452 0 "" "" "$_Q_AGREE"
_t661_q=$(_check66 6.6.1 "серия очередей ЕСТЬ и согласна с зеркалом — источник назван МЕТРИКОЙ" \
    "$(_run66 "$_A661Q" "$WORK/pro661q.txt")" OK)
_need_text "6.6.1 источник очереди — метрика" "$_t661_q" \
    "syscall/ringbuf_to_router=3656 [очередь protected]" \
    "ИСТОЧНИК соответствия очередь↔коллектор — МЕТРИКА ebpf_guard_events_dropped_by_queue_total" \
    "рантайм, не зеркало кода" "разошлось с рантаймом у: -"

# Серии НЕТ ВООБЩЕ (все прежние фикстуры и оба архива 6.5 — именно этот вход):
# очередь берётся зеркалом кода, и строка это ГОВОРИТ, а не умалчивает.
_t661_qnone=$(_check66 6.6.1 "серии очередей в снимке нет — источник назван ЗАШИТЫМ зеркалом" \
    "$(_run66 "$_A661" "$WORK/pro661.txt")" OK)
_need_text "6.6.1 источник очереди — зашитое зеркало" "$_t661_qnone" \
    "ЗАШИТО В ЭМИТТЕР" "ebpf_guard_events_dropped_by_queue_total в снимке run-end НЕТ" \
    "бинарь до пункта 12" "зеркало defaultEventPriority"

# РАСХОЖДЕНИЕ: рантайм отправил fileaccess в protected (правка
# defaultEventPriority), зеркало эмиттера всё ещё говорит bulk. Вердикт остаётся
# ИЗМЕРЕНО — величина потерь от этого не меняется, — но строка ОБЯЗАНА назвать
# расхождение и имя коллектора, иначе правка priority.go остаётся молчаливой.
_A661QS="$WORK/art661qs"; mkdir -p "$_A661QS"
_mk_drops "$WORK/pro661qs.txt"                  1790305396 0 41 0 "" "" ""
_mk_drops "$_A661QS/metrics-window-start.txt"   1790305396 0 41 0 "" "" ""
_mk_drops "$_A661QS/metrics-window-end.txt"     1790305396 0 41 0 "" "" ""
_mk_drops "$_A661QS/metrics-run-end.txt"        1790305396 0 41 0 "" "" "fileaccess:protected=41"
_t661_qs=$(_check66 6.6.1 "рантайм развёл fileaccess с зеркалом эмиттера — расхождение НАЗВАНО в строке" \
    "$(_run66 "$_A661QS" "$WORK/pro661qs.txt")" OK)
_need_text "6.6.1 расхождение зеркала с рантаймом" "$_t661_qs" \
    "fileaccess/ringbuf_to_router=41 [очередь protected]" \
    "зеркало эмиттера разошлось с рантаймом у: fileaccess(метрика protected, зеркало эмиттера bulk)"

# Серия есть, но у коллектора-носителя потерь в ней НОЛЬ (счётчик по очередям
# родился позже самих потерь): смешанный вход — часть от метрики, часть от
# зеркала, и обе части названы.
_A661QZ="$WORK/art661qz"; mkdir -p "$_A661QZ"
_mk_drops "$WORK/pro661qz.txt"                  1790305396 3656 0   0 "" "" ""
_mk_drops "$_A661QZ/metrics-window-start.txt"   1790305396 3656 0   0 "" "" ""
_mk_drops "$_A661QZ/metrics-window-end.txt"     1790305396 3656 0   0 "" "" ""
_mk_drops "$_A661QZ/metrics-run-end.txt"        1790305396 3656 452 0 "" "" "syscall:protected=3656 fileaccess:bulk=0"
_t661_qz=$(_check66 6.6.1 "серия есть, у fileaccess в ней ноль — часть от метрики, часть от зеркала, обе названы" \
    "$(_run66 "$_A661QZ" "$WORK/pro661qz.txt")" OK)
_need_text "6.6.1 смешанный источник очереди" "$_t661_qz" \
    "МЕТРИКА ebpf_guard_events_dropped_by_queue_total, кроме [fileaccess/ringbuf_to_router" \
    "у них в серии нули, там очередь ЗАШИТА зеркалом кода"

# Зашитое зеркало в эмиттере обязано совпадать с defaultEventPriority в Go —
# тем же способом, каким 6.6.2 сверяет список коллекторов с ParseErrorCollectors.
# Это второй, ОФЛАЙННЫЙ слой: он краснеет на правке priority.go ещё до стенда,
# тогда как расхождение выше видно только на живом снимке.
_PRIO="$SETUP/../../internal/collector/priority.go"
_go_prio=$(awk '/^func defaultEventPriority\(/,/^\}/' "$_PRIO" 2>/dev/null \
    | grep -oE 'eventType != types\.Event[A-Za-z]+' | sed 's/.*types\.Event//' | tr 'A-Z' 'a-z')
_sh_prio=$(grep -oE 'hardq = \(c == "[a-z_]+" \? "bulk" : "protected"\)' "$WORK/block66.sh" \
    | grep -oE '"[a-z_]+" \?' | tr -d '"? ')
if [ ! -s "$_PRIO" ]; then
    echo "    --  сверка зашитого зеркала очередей с Go пропущена: internal/collector/priority.go рядом нет (архив копия, не дерево)"
elif [ -z "$_go_prio" ] || [ -z "$_sh_prio" ]; then
    _efail "пункт 12: defaultEventPriority в Go (${_go_prio:-НЕ РАЗОБРАН}) либо зеркало в эмиттере (${_sh_prio:-НЕ РАЗОБРАНО}) не читаются — сверять нечем"
elif [ "$_go_prio" != "$_sh_prio" ]; then
    _efail "пункт 12: зашитое зеркало эмиттера (bulk = ${_sh_prio}) разошлось с defaultEventPriority в Go (в bulk уходит ${_go_prio}) — запасная карта эмиттера лжёт на бинаре без серии очередей"
else
    echo "    OK  пункт 12: зашитое зеркало эмиттера (bulk = ${_sh_prio}) = defaultEventPriority в Go, и оно лишь ЗАПАС — при наличии серии очередь берётся метрикой"
fi
_sh_prio_mut=$(printf '%s\n' 'hardq = (c == "syscall" ? "bulk" : "protected")' \
    | grep -oE '"[a-z_]+" \?' | tr -d '"? ')
if [ "$_sh_prio_mut" != "$_go_prio" ]; then
    echo "    OK  пункт 12-негатив: подменённое зеркало (bulk = ${_sh_prio_mut}) этой сверкой КРАСНЕЕТ"
else
    _efail "пункт 12-негатив: сверка не различает зеркало fileaccess и syscall — она фиктивна"
fi

# ── 6.6.2. Один прогон — три снимка: ДО (пролог) и ПОСЛЕ (run-end) читает блок.
_UP="syscall=1 network=1 tls=1 dns=1 kmod=0"
_A662="$WORK/art662"; mkdir -p "$_A662"
for _f in metrics-window-start metrics-window-end; do _mk_drops "$_A662/$_f.txt" 5 0 0 0; done
_mk_drops "$WORK/pro662.txt"            5 0 0 0 "syscall=0 network=0 tls=0 fileaccess=0" "$_UP"
_mk_drops "$_A662/metrics-run-end.txt"  5 0 0 0 "syscall=0 network=0 tls=0 fileaccess=0" "$_UP"
_t662_ok=$(_check66 6.6.2 "ноль у всех коллекторов с up=1, серии материализованы — ДОСТИГНУТО" \
    "$(_run66 "$_A662" "$WORK/pro662.txt")" OK)
_need_text "6.6.2 состав по коллекторам" "$_t662_ok" \
    "у КАЖДОГО из 3 коллекторов" "collector_up=1 всего 4" "network" "syscall" "tls" "свой счётчик разбора): dns"

_A662F="$WORK/art662f"; mkdir -p "$_A662F"
for _f in metrics-window-start metrics-window-end; do _mk_drops "$_A662F/$_f.txt" 5 0 0 0; done
_mk_drops "$WORK/pro662f.txt"            5 0 0 0 "syscall=0 network=0 tls=0" "$_UP"
_mk_drops "$_A662F/metrics-run-end.txt"  5 0 0 0 "syscall=0 network=39 tls=0" "$_UP"
_t662_fail=$(_check66 6.6.2 "подложенный parse_error>0 у network — ПРОВАЛЕН с именем коллектора" \
    "$(_run66 "$_A662F" "$WORK/pro662f.txt")" FAIL)
_need_text "6.6.2 провал называет коллектора и дельту" "$_t662_fail" \
    "network=+39" "ДО 0" "ПОСЛЕ 39" "collector_up 1" "ПРОДУКТОВЫЙ"
# Красный не должен прятаться в классе неизмеримости: слово вердикта — ПРОВАЛЕН.
printf '%s' "$_t662_fail" | grep -q 'ПРОВАЛЕН' || _efail "6.6.2: подложенный parse_error>0 вынес не ПРОВАЛЕН — строка: $(printf '%s' "$_t662_fail" | cut -c1-160)"

# Тот же класс, что №473, но у parse_error: коллектор отбивает разбор С ПЕРВОГО
# СОБЫТИЯ, всплеск целиком укладывается ДО снимка пролога, и дельта прогона
# равна НУЛЮ. До правки эта фикстура получала ДОСТИГНУТО — то есть метка,
# заведённая ловить №471, на самом остром случае №471 печатала зелёное
# ([[losses-before-first-snapshot-are-unmeasured]]). Именно на эту ветку
# опирается смок item 10: рассинхрон 332→340 байт отбивает разбор с первого
# события, а не за окно.
_A662S="$WORK/art662s"; mkdir -p "$_A662S"
for _f in metrics-window-start metrics-window-end; do _mk_drops "$_A662S/$_f.txt" 5 0 0 0; done
_mk_drops "$WORK/pro662s.txt"            5 0 0 0 "syscall=3656 network=0 tls=0" "$_UP"
_mk_drops "$_A662S/metrics-run-end.txt"  5 0 0 0 "syscall=3656 network=0 tls=0" "$_UP"
_t662_start=$(_check66 6.6.2 "отбраковка разбора ДО первого снимка (дельта 0, абсолют 3656) — ПРОВАЛЕН, а не ДОСТИГНУТО" \
    "$(_run66 "$_A662S" "$WORK/pro662s.txt")" FAIL)
_need_text "6.6.2 всплеск разбора до первого снимка" "$_t662_start" \
    "syscall=3656" "ДО ПЕРВОГО СНИМКА" "№473" "ПРОДУКТОВЫЙ"
printf '%s' "$_t662_start" | grep -q 'ПРОВАЛЕН' || _efail "6.6.2: parse_error ДО первого снимка вынес не ПРОВАЛЕН — дельта слепа к интервалу №473, строка: $(printf '%s' "$_t662_start" | cut -c1-200)"
# И обратная половина: зелёная строка обязана СКАЗАТЬ, что этот интервал
# проверен, иначе ноль дельты снова читается как ноль всего прогона.
_need_text "6.6.2 зелёная строка называет проверенный интервал" "$_t662_ok" \
    "абсолют снимка пролога" "№473"

_A662O="$WORK/art662o"; mkdir -p "$_A662O"
for _f in metrics-window-start metrics-window-end; do _mk_drops "$_A662O/$_f.txt" 5 0 0 0; done
_mk_drops "$WORK/pro662o.txt"            5 0 0 0 "" "$_UP"
_mk_drops "$_A662O/metrics-run-end.txt"  5 0 0 0 "" "$_UP"
_t662_old=$(_check66 6.6.2 "серий parse_error нет ни ДО, ни ПОСЛЕ (бинарь до №476) — НЕИЗМЕРИМ, не ноль" \
    "$(_run66 "$_A662O" "$WORK/pro662o.txt")" FAIL)
_need_text "6.6.2 бинарь без материализации" "$_t662_old" "без материализации" "№476" "неотличимо от нуля" "syscall"

_A662P="$WORK/art662p"; mkdir -p "$_A662P"
for _f in metrics-window-start metrics-window-end; do _mk_drops "$_A662P/$_f.txt" 5 0 0 0; done
_mk_drops "$WORK/pro662p.txt"            5 0 0 0 "network=0 tls=0" "$_UP"
_mk_drops "$_A662P/metrics-run-end.txt"  5 0 0 0 "network=0 tls=0" "$_UP"
_t662_part=$(_check66 6.6.2 "у syscall (up=1) серии нет, у остальных есть — НЕИЗМЕРИМ с именем" \
    "$(_run66 "$_A662P" "$WORK/pro662p.txt")" FAIL)
_need_text "6.6.2 частичная материализация" "$_t662_part" "нет серии parse_error" "syscall" "судимы 2 из 4"

_A662B="$WORK/art662b"; mkdir -p "$_A662B"
for _f in metrics-window-start metrics-window-end; do _mk_drops "$_A662B/$_f.txt" 5 0 0 0; done
_mk_drops "$WORK/pro662b.txt"            5 0 0 0 "network=0 tls=0" "$_UP"
_mk_drops "$_A662B/metrics-run-end.txt"  5 0 0 0 "network=0 tls=0 syscall=7" "$_UP"
_t662_born=$(_check66 6.6.2 "серии нет в снимке ДО, родилась за прогон со значением 7 — ПРОВАЛЕН, ДО названо словом" \
    "$(_run66 "$_A662B" "$WORK/pro662b.txt")" FAIL)
_need_text "6.6.2 отсутствие серии ДО названо" "$_t662_born" "syscall=+7" "ДО серии нет" "ПОСЛЕ 7"

_A662Q="$WORK/art662q"; mkdir -p "$_A662Q"
for _f in metrics-window-start metrics-window-end; do _mk_drops "$_A662Q/$_f.txt" 5 0 0 0; done
_mk_drops "$WORK/pro662q.txt"            5 0 0 0 "network=0 tls=0" "$_UP"
_mk_drops "$_A662Q/metrics-run-end.txt"  5 0 0 0 "network=0 tls=0 syscall=0" "$_UP"
_t662_born0=$(_check66 6.6.2 "серии нет в снимке ДО, ПОСЛЕ нуль — ДОСТИГНУТО, отсутствие ДО названо" \
    "$(_run66 "$_A662Q" "$WORK/pro662q.txt")" OK)
_need_text "6.6.2 ДО отсутствовала, ноль" "$_t662_born0" "серия в снимке ДО отсутствовала у: syscall"

_check66 6.6.2 "снимка пролога нет — НЕИЗМЕРИМ" \
    "$(_run66 "$_A662" "$WORK/net-takogo-fajla.txt")" FAIL >/dev/null
_A662U="$WORK/art662u"; mkdir -p "$_A662U"
for _f in metrics-window-start metrics-window-end; do _mk_drops "$_A662U/$_f.txt" 5 0 0 0; done
_mk_drops "$WORK/pro662u.txt"            5 0 0 0 "network=0" "network=0 syscall=0"
_mk_drops "$_A662U/metrics-run-end.txt"  5 0 0 0 "network=0" "network=0 syscall=0"
_check66 6.6.2 "ни у одного коллектора up=1 — НЕИЗМЕРИМ, ось пуста" \
    "$(_run66 "$_A662U" "$WORK/pro662u.txt")" FAIL >/dev/null

# Список коллекторов эмиттера обязан совпадать с ParseErrorCollectors в Go (тот же
# набор, что и вызовы RecordDropped(…, "parse_error"), закреплён Go-тестом).
_go_pe=$(awk '/^var ParseErrorCollectors = \[\]string\{/,/^\}/' "$SETUP/../../internal/exporter/prometheus.go" 2>/dev/null \
    | grep -oE '"[a-z_0-9]+"' | tr -d '"' | sort | tr '\n' ' ')
_sh_pe=$(sed -n 's/^_w66_pe_expected="\(.*\)"$/\1/p' "$WORK/block66.sh" | tr ' ' '\n' | sort | tr '\n' ' ')
if [ ! -s "$SETUP/../../internal/exporter/prometheus.go" ]; then
    echo "    --  сверка списка parse_error с Go пропущена: internal/exporter/prometheus.go рядом нет (архив копия, не дерево)"
elif [ -z "$_go_pe" ]; then
    _efail "6.6.2: список ParseErrorCollectors в Go не разобран — сверять нечем"
elif [ "$_go_pe" != "$_sh_pe" ]; then
    _efail "6.6.2: список коллекторов эмиттера (${_sh_pe}) расходится с ParseErrorCollectors в Go (${_go_pe})"
else
    echo "    OK  6.6.2: список коллекторов эмиттера = ParseErrorCollectors в Go (${_go_pe})"
fi

# ── 6.6.3: разрез оси TLS по семействам (item 3). Снимки: window-start / window-end /
# run-end с сериями by_family и events_total{type="tls"}; events_total даётся ДВУМЯ
# сериями (лейблы pod/namespace/node) — читатель обязан СУММИРОВАТЬ.
# _mk_fam <файл> <payload> <ja3> <unknown> <events_a> <events_b> [-]: «-» вместо числа — серии нет.
_mk_fam() {
    local f="$1"; : > "$f"
    [ "$2" != "-" ] && echo "ebpf_guard_tls_events_by_family_total{family=\"payload\"} $2" >> "$f"
    [ "$3" != "-" ] && echo "ebpf_guard_tls_events_by_family_total{family=\"ja3\"} $3" >> "$f"
    [ "$4" != "-" ] && echo "ebpf_guard_tls_events_by_family_total{family=\"unknown\"} $4" >> "$f"
    echo "ebpf_guard_events_total{type=\"tls\",pod=\"\",namespace=\"\",node=\"n1\"} $5" >> "$f"
    echo "ebpf_guard_events_total{type=\"tls\",pod=\"web\",namespace=\"d\",node=\"n1\"} $6" >> "$f"
    echo "ebpf_guard_events_total{type=\"syscall\",pod=\"\",namespace=\"\",node=\"n1\"} 99999" >> "$f"
}
_A663="$WORK/art663"; mkdir -p "$_A663"
_mk_fam "$_A663/metrics-window-start.txt" 2 0 0 1 1
_mk_fam "$_A663/metrics-window-end.txt"   8 0 0 4 4
_mk_fam "$_A663/metrics-run-end.txt"      9 0 0 4 5
_t663_ok=$(_check66 6.6.3 "разрез payload=6 ja3=0 unknown=0, сумма сходится (две серии events_total) — ИЗМЕРЕНО" \
    "$(_run66 "$_A663" "")" OK)
_need_text "6.6.3 разрез, инвариант, структурный ноль ja3" "$_t663_ok" \
    "payload=6 ja3=0 unknown=0" "сумма 6 = events_total 6" "сумма 9 = events_total 9" \
    "СТРУКТУРНЫЙ ноль" "6.4.5" "не вердикт детекта" "СОБЫТИЙ оси"

_A663J="$WORK/art663j"; mkdir -p "$_A663J"
_mk_fam "$_A663J/metrics-window-start.txt" 2 0 0 1 1
_mk_fam "$_A663J/metrics-window-end.txt"   6 3 1 5 5
_mk_fam "$_A663J/metrics-run-end.txt"      6 3 1 5 5
_t663_j=$(_check66 6.6.3 "ja3=3, unknown=1 — ИЗМЕРЕНО, unknown назван отдельным рядом" \
    "$(_run66 "$_A663J" "")" OK)
_need_text "6.6.3 ja3 кормится, unknown назван" "$_t663_j" "ja3=3" "unknown=1" "БЕЗ TLS-деталей" "JA3-семейство кормится"

# ── Пункт 16 ревизии 6.6: ДОПУСК гонки двух счётчиков, названный числом.
# events_total и by_family инкрементируются двумя вызовами подряд (main.go), и
# скрейп МЕЖДУ ними видит расхождение на одно событие при исправном приборе.
# Величина допуска выведена из кода, а не назначена: processEvent зовётся из
# ОДНОЙ горутины, значит в полёте не более одного события → снимок ±1, дельта
# окна (разность двух снимков) ±2. Допуск симметричен: порядок сбора серий в
# registry.Gather не задан, так что расхождение бывает и +1, и −1.
# Сторож требует, чтобы допуск был НАЗВАН в строке, и в зелёной строке тоже —
# «сошёлся ровно» и «сошёлся внутри допуска» не читаются одинаково.
_A663T1="$WORK/art663t1"; mkdir -p "$_A663T1"
_mk_fam "$_A663T1/metrics-window-start.txt" 2 0 0 1 1
_mk_fam "$_A663T1/metrics-window-end.txt"   8 0 0 4 4
_mk_fam "$_A663T1/metrics-run-end.txt"      9 0 0 4 4
_t663_t1=$(_check66 6.6.3 "абсолют расходится на +1 (скрейп между двумя инкрементами) — ИЗМЕРЕНО, допуск НАЗВАН" \
    "$(_run66 "$_A663T1" "")" OK)
_need_text "6.6.3 допуск ±1 по абсолюту назван" "$_t663_t1" \
    "сошёлся ВНУТРИ ДОПУСКА, а не ровно" \
    "допуск гонки двух счётчиков: снимок ±1, дельта окна ±2" \
    "одна горутина processEvent" "расхождение абсолюта 1"

# Расхождение ровно 0 — зелёная строка обязана СКАЗАТЬ, что допуск не брался.
_need_text "6.6.3 ровное схождение отличимо от взятого допуска" "$_t663_ok" \
    "сошёлся РОВНО дважды" "расхождение 0 и 0" "ДОПУСК НЕ ПОТРЕБОВАЛСЯ"

# Расхождение −1 по абсолюту (скрейп застал by_family первой) — тот же допуск.
_A663T2="$WORK/art663t2"; mkdir -p "$_A663T2"
_mk_fam "$_A663T2/metrics-window-start.txt" 2 0 0 1 1
_mk_fam "$_A663T2/metrics-window-end.txt"   8 0 0 4 4
_mk_fam "$_A663T2/metrics-run-end.txt"      9 0 0 5 5
_t663_t2=$(_check66 6.6.3 "абсолют расходится на −1 (обратный порядок сбора серий) — ИЗМЕРЕНО, допуск симметричен" \
    "$(_run66 "$_A663T2" "")" OK)
_need_text "6.6.3 допуск симметричен" "$_t663_t2" "сошёлся ВНУТРИ ДОПУСКА" "расхождение абсолюта -1"

# Расхождение 2 по абсолюту — ВЫШЕ допуска снимка: НЕИЗМЕРИМ, и строка называет
# и расхождение, и допуск, из-за которого он не покрыт.
_A663T3="$WORK/art663t3"; mkdir -p "$_A663T3"
_mk_fam "$_A663T3/metrics-window-start.txt" 2 0 0 1 1
_mk_fam "$_A663T3/metrics-window-end.txt"   8 0 0 4 4
_mk_fam "$_A663T3/metrics-run-end.txt"      9 0 0 4 3
_t663_t3=$(_check66 6.6.3 "абсолют расходится на +2 — ВЫШЕ допуска снимка, НЕИЗМЕРИМ" \
    "$(_run66 "$_A663T3" "")" FAIL)
_need_text "6.6.3 расхождение выше допуска названо" "$_t663_t3" \
    "инвариант суммы не сошёлся по абсолюту run-end" "расхождение 2 ВЫШЕ допуска" \
    "допуск гонки двух счётчиков: снимок ±1"

# Дельта окна: допуск ±2 (две границы окна, у каждой свой ±1). 2 — внутри, 3 — нет.
_A663T4="$WORK/art663t4"; mkdir -p "$_A663T4"
# Абсолют run-end сходится РОВНО (8 = 4+4), расходится только дельта окна:
# 8−2 = 6 по семействам против 6−2 = 4 по events_total, то есть +2 — ровно допуск
# дельты. Иначе цепочка упала бы раньше, на абсолюте, и ветка дельты не проверялась.
_mk_fam "$_A663T4/metrics-window-start.txt" 2 0 0 1 1
_mk_fam "$_A663T4/metrics-window-end.txt"   8 0 0 3 3
_mk_fam "$_A663T4/metrics-run-end.txt"      8 0 0 4 4
_t663_t4=$(_check66 6.6.3 "дельта окна расходится на +2 — внутри допуска дельты, ИЗМЕРЕНО" \
    "$(_run66 "$_A663T4" "")" OK)
_need_text "6.6.3 допуск дельты окна ±2" "$_t663_t4" "сошёлся ВНУТРИ ДОПУСКА" "дельты 2"

_A663T5="$WORK/art663t5"; mkdir -p "$_A663T5"
# Абсолют сходится ровно (9 = 4+5), дельта окна расходится на +3: 9−2 = 7 против
# 6−2 = 4 — на единицу выше допуска дельты.
_mk_fam "$_A663T5/metrics-window-start.txt" 2 0 0 1 1
_mk_fam "$_A663T5/metrics-window-end.txt"   9 0 0 3 3
_mk_fam "$_A663T5/metrics-run-end.txt"      9 0 0 4 5
_t663_t5=$(_check66 6.6.3 "дельта окна расходится на +3 — ВЫШЕ допуска дельты, НЕИЗМЕРИМ" \
    "$(_run66 "$_A663T5" "")" FAIL)
_need_text "6.6.3 дельта выше допуска названа" "$_t663_t5" \
    "инвариант суммы не сошёлся по дельте окна" "расхождение 3 ВЫШЕ допуска" "дельта окна ±2"

# Величина допуска не вправе разойтись с кодом: processEvent зовётся из одной
# горутины, и число «±1» в эмиттере опирается ровно на это. Если вызовы
# processEvent разъедутся по горутинам, допуск станет мал, и это надо ловить
# офлайн, а не ложным НЕИЗМЕРИМ на стенде.
_MAIN="$SETUP/../../cmd/ebpf-guard/main.go"
if [ ! -s "$_MAIN" ]; then
    echo "    --  сверка числа допуска с числом горутин пропущена: cmd/ebpf-guard/main.go рядом нет (архив копия, не дерево)"
else
    # Вызов processEvent, стоящий под `go `, сделал бы счёт событий параллельным.
    _pe_go=$(grep -nE '^[[:space:]]*go[[:space:]]+(func)?.*processEvent\(' "$_MAIN" | wc -l | tr -d ' ')
    _pe_all=$(grep -cE '[^a-zA-Z_]processEvent\(' "$_MAIN" | tr -d ' ')
    if [ "$_pe_go" -ne 0 ]; then
        _efail "пункт 16: в main.go есть ${_pe_go} вызов(ов) processEvent под \`go\` — счёт событий больше не однопоточен, допуск ±1 в эмиттере 6.6.3 стал мал"
    elif [ "$_pe_all" -lt 2 ]; then
        _efail "пункт 16: вызовы processEvent в main.go не разобраны (${_pe_all}) — обосновать число допуска нечем"
    else
        echo "    OK  пункт 16: ни один из ${_pe_all} вызовов processEvent не стоит под \`go\` — счёт событий однопоточен, допуск снимка ±1 обоснован кодом"
    fi
fi
_pe_go_mut=$(printf '%s\n' '			go processEvent(ctx, event, eventLog)' | grep -cE '^[[:space:]]*go[[:space:]]+(func)?.*processEvent\(')
if [ "${_pe_go_mut:-0}" -ge 1 ]; then
    echo "    OK  пункт 16-негатив: вызов processEvent под \`go\` этим предикатом ЛОВИТСЯ (иначе сверка была бы тождественно зелёной)"
else
    _efail "пункт 16-негатив: предикат не видит processEvent под \`go\` — обоснование допуска фиктивно"
fi

_A663D="$WORK/art663d"; mkdir -p "$_A663D"
_mk_fam "$_A663D/metrics-window-start.txt" 2 0 0 1 1
_mk_fam "$_A663D/metrics-window-end.txt"   8 0 0 4 4
_mk_fam "$_A663D/metrics-run-end.txt"      9 0 0 4 9
_t663_d=$(_check66 6.6.3 "sum(by_family)=9 против events_total=13 — НЕИЗМЕРИМ, расхождение названо числами" \
    "$(_run66 "$_A663D" "")" FAIL)
_need_text "6.6.3 расхождение суммы названо" "$_t663_d" "инвариант суммы не сошёлся" "sum(by_family)=9" "events_total{type=\"tls\"}=13"

_A663W="$WORK/art663w"; mkdir -p "$_A663W"
_mk_fam "$_A663W/metrics-window-start.txt" 2 0 0 1 1
_mk_fam "$_A663W/metrics-window-end.txt"   8 0 0 2 2
_mk_fam "$_A663W/metrics-run-end.txt"      8 0 0 2 2
_check66 6.6.3 "абсолют сходится, дельта окна нет (окно 6 против 2) — НЕИЗМЕРИМ" \
    "$(_run66 "$_A663W" "")" FAIL >/dev/null

_A663O="$WORK/art663o"; mkdir -p "$_A663O"
for _f in metrics-window-start metrics-window-end metrics-run-end; do
    echo 'ebpf_guard_events_total{type="tls",pod="",namespace="",node="n1"} 3' > "$_A663O/$_f.txt"
done
_t663_o=$(_check66 6.6.3 "серии by_family нет ни в одном снимке (бинарь до волны 6.5) — НЕИЗМЕРИМ, не ноль" \
    "$(_run66 "$_A663O" "")" FAIL)
_need_text "6.6.3 бинарь без серии" "$_t663_o" "серии tls_events_by_family_total нет" "неотличимо от нуля"

_A663P="$WORK/art663p"; mkdir -p "$_A663P"
_mk_fam "$_A663P/metrics-window-start.txt" 2 0 - 1 1
_mk_fam "$_A663P/metrics-window-end.txt"   2 0 - 1 1
_mk_fam "$_A663P/metrics-run-end.txt"      2 0 - 1 1
_t663_p=$(_check66 6.6.3 "нет серии unknown при двух других — НЕИЗМЕРИМ с именем семейства" \
    "$(_run66 "$_A663P" "")" FAIL)
_need_text "6.6.3 частичная серия" "$_t663_p" "нет серии" "unknown"

_A663R="$WORK/art663r"; mkdir -p "$_A663R"
_mk_fam "$_A663R/metrics-window-start.txt" 5 0 0 1 4
_mk_fam "$_A663R/metrics-window-end.txt"   2 0 0 1 1
_mk_fam "$_A663R/metrics-run-end.txt"      2 0 0 1 1
_t663_r=$(_check66 6.6.3 "счётчик payload убыл 5→2 (рестарт) — НЕИЗМЕРИМ" \
    "$(_run66 "$_A663R" "")" FAIL)
_need_text "6.6.3 рестарт назван" "$_t663_r" "убыл внутри окна" "payload(5→2)"

_check66 6.6.3 "нет metrics-run-end.txt — НЕИЗМЕРИМ, а не ноль" \
    "$(_run66 "$WORK/art663_missing" "")" FAIL >/dev/null

_A663A="$WORK/art663a"; mkdir -p "$_A663A"
_mk_fam "$_A663A/metrics-window-start.txt" 0 0 0 0 0
_mk_fam "$_A663A/metrics-window-end.txt"   0 0 0 0 0
_mk_fam "$_A663A/metrics-run-end.txt"      0 0 0 0 0
_t663_a=$(_check66 6.6.3 "роль A, TLS выключен: серии материализованы, нули по построению — ИЗМЕРЕНО" \
    "$(W66_TEST_ROLE=A _run66 "$_A663A" "")" OK)
_need_text "6.6.3 роль A" "$_t663_a" "прогон A" "payload=0 ja3=0 unknown=0"
_mk_fam "$_A663A/metrics-window-end.txt"   3 0 0 3 0
_mk_fam "$_A663A/metrics-run-end.txt"      3 0 0 3 0
_check66 6.6.3 "роль A, а TLS-события идут — ПРОВАЛЕН (вход загрязнён)" \
    "$(W66_TEST_ROLE=A _run66 "$_A663A" "")" FAIL >/dev/null

# Роль B и разрез ВЕСЬ в нулях — тот же вид, что у мёртвого коллектора
# (№436/№471, [[collector-loadobjects-is-a-stub]]). Строка обязана различать два
# случая ВНУТРИ СЕБЯ, по монотонному счётчику привязок и collector_up{tls};
# здоровье читается из ТОГО ЖЕ снимка run-end, что и разрез.
# _mk_health <файл> <collector_up|-> <attach_success|->
_mk_health() {
    [ "$2" != "-" ] && echo "ebpf_guard_collector_up{collector=\"tls\"} $2" >> "$1"
    [ "$3" != "-" ] && echo "ebpf_guard_tls_attach_success_total $3" >> "$1"
    return 0
}
_A663Z="$WORK/art663z"; mkdir -p "$_A663Z"
for _f in metrics-window-start metrics-window-end metrics-run-end; do
    _mk_fam "$_A663Z/$_f.txt" 0 0 0 0 0
done
_mk_health "$_A663Z/metrics-run-end.txt" 1 0
_t663_z=$(_check66 6.6.3 "роль B, нули И привязок 0 при collector_up{tls}=1 — НЕИЗМЕРИМ (ноль про прибор, не про трафик)" \
    "$(_run66 "$_A663Z" "")" FAIL)
_need_text "6.6.3 мёртвый коллектор не читается тишиной" "$_t663_z" \
    "ebpf_guard_tls_attach_success_total=0" "collector_up{tls}=1" "НЕ есть" "не привязался ни к одному процессу"

# Обратная половина: те же нули, но привязка БЫЛА — это уже величина, и строка
# обязана предъявить, ЧЕМ она отличается от предыдущей.
_A663Z2="$WORK/art663z2"; mkdir -p "$_A663Z2"
for _f in metrics-window-start metrics-window-end metrics-run-end; do
    _mk_fam "$_A663Z2/$_f.txt" 0 0 0 0 0
done
_mk_health "$_A663Z2/metrics-run-end.txt" 1 4
_t663_z2=$(_check66 6.6.3 "роль B, нули при 4 привязках — ИЗМЕРЕНО, тишина TLS названа тишиной" \
    "$(_run66 "$_A663Z2" "")" OK)
_need_text "6.6.3 тишина TLS отделена от мёртвого коллектора" "$_t663_z2" \
    "тишина TLS" "НЕ мёртвый коллектор" "привязок за жизнь процесса 4" "collector_up{tls}=1"

# Серий здоровья нет вовсе (бинарь до №449): отсутствие НЕ читается нулём и не
# читается числом — оно называется словами ([[metric-anchor-must-carry-full-series-name]]).
_A663Z3="$WORK/art663z3"; mkdir -p "$_A663Z3"
for _f in metrics-window-start metrics-window-end metrics-run-end; do
    _mk_fam "$_A663Z3/$_f.txt" 0 0 0 0 0
done
_t663_z3=$(_check66 6.6.3 "роль B, нули, серий здоровья НЕТ — ИЗМЕРЕНО, отсутствие названо словами" \
    "$(_run66 "$_A663Z3" "")" OK)
_need_text "6.6.3 отсутствие серии здоровья названо" "$_t663_z3" "привязок за жизнь процесса СЕРИИ НЕТ" "collector_up{tls}=СЕРИИ НЕТ"

# ── 6.6.4 (item 8, №479; ось comm — item 7 ревизии 6.6): атрибуция остатка
# объёма http_plaintext. Вход — сторожевой файл контроля 6.5 и его .attr
# (снимок после осадки, включая РАЗРЕЗ ПО comm).
# _mk_h664 <каталог> <events_delta|-> <settled|-> <residual|-> <other|-> [class] [by_comm|-] [ovf_delta]
# by_comm «-» значит: серии ebpf_guard_http_plaintext_events_by_comm_total в
# снимке НЕТ ВООБЩЕ (бинарь до item 7) — это законный вход и отдельный класс.
_mk_h664() {
    local d="$1"; mkdir -p "$d"; rm -f "$d/http-control-plaintext.txt" "$d/http-control-plaintext.txt.attr"
    if [ "${6:-}" != "" ]; then echo "class=$6" > "$d/http-control-plaintext.txt"; return; fi
    printf 'events_delta=%s\ntracked_pids=1\nrequests_ok=3\nholder_comm=python3\n' "$2" > "$d/http-control-plaintext.txt"
    [ "$3" = "-" ] && return
    local bc="${7:--}" ovf="${8:-0}" present=1 sum=0
    [ "$bc" = "-" ] && present=0
    if [ "$present" = "1" ]; then
        sum=$(printf '%s' "$bc" | awk '{ n = split($0, A, " "); s = 0; for (i = 1; i <= n; i++) { if (A[i] == "") continue; p = index(A[i], "="); s += substr(A[i], p+1) + 0 } printf "%d", s }')
    fi
    printf 'settled_delta=%s\nsettled_after_s=30\nresidual=%s\nother_attached=%s\ntracked_pids_settled=1\nby_comm_present=%s\nby_comm_delta=%s\nby_comm_sum=%s\ncomm_overflow_present=1\ncomm_overflow_delta=%s\n' \
        "$3" "$4" "$5" "$present" "$bc" "$sum" "$ovf" > "$d/http-control-plaintext.txt.attr"
}
_A664="$WORK/art664"
rm -rf "$_A664"; mkdir -p "$_A664"
_check66 6.6.4 "контроль не поставлен — НЕ ЗАПРОШЕН, не ДОСТИГНУТО" "$(_run66 "$_A664" "")" NOTREQ >/dev/null
_mk_h664 "$_A664" - - - - "коллектор_выключен_конфигом_серии_нет"
_t664_c=$(_check66 6.6.4 "класс назван контролем — НЕИЗМЕРИМ" "$(_run66 "$_A664" "")" FAIL)
_need_text "6.6.4 класс контроля" "$_t664_c" "класс НАЗВАН контролем" "коллектор_выключен_конфигом"
_mk_h664 "$_A664" 9 -
_t664_n=$(_check66 6.6.4 "нет снимка после осадки — НЕИЗМЕРИМ" "$(_run66 "$_A664" "")" FAIL)
_need_text "6.6.4 нет осадки" "$_t664_n" "снимка ПОСЛЕ осадки не было" "недосчитал 30 событий из 39"
_mk_h664 "$_A664" 0 0 0 -
_check66 6.6.4 "контроль событий не дал — НЕИЗМЕРИМ" "$(_run66 "$_A664" "")" FAIL >/dev/null
_mk_h664 "$_A664" 9 9 0 - "" "python3=9"
_t664_z=$(_check66 6.6.4 "остаток 0 — ИЗМЕРЕНО, флаг false" "$(_run66 "$_A664" "")" OK)
_need_text "6.6.4 остаток 0" "$_t664_z" "9 событий" "объяснённых контролем 9" "остаток 0" "остаётся false"

# Item 7 ревизии 6.6, ветка 1: остаток есть, а СЕРИИ разреза нет вовсе. Это не
# «остаток не назван», а «назвать его нечем в принципе» — класс обязан отличаться.
_mk_h664 "$_A664" 9 39 30 "4242:node,4250:nginx" "" "-"
_t664_nos=$(_check66 6.6.4 "остаток 30, серии by_comm нет — НЕИЗМЕРИМ, названо отсутствие серии" "$(_run66 "$_A664" "")" FAIL)
_need_text "6.6.4 нет серии разреза" "$_t664_nos" \
    "серии ebpf_guard_http_plaintext_events_by_comm_total в снимке НЕТ" "бинарь до item 7" \
    "неатрибутируем В ПРИНЦИПЕ" "остаток 30" "кандидаты из журнала привязок: 4242:node,4250:nginx"

# Ветка 2: разрез ЕСТЬ, но лимитер свернул часть в comm="other" — «не назван» и
# «назван, да имя потеряно» неотличимы, поэтому не ДОСТИГНУТО.
_mk_h664 "$_A664" 9 39 30 - "" "python3=9 other=30" 7
_t664_ovf=$(_check66 6.6.4 "разрез свёрнут лимитером — НЕИЗМЕРИМ, число свёрнутых названо" "$(_run66 "$_A664" "")" FAIL)
_need_text "6.6.4 разрез неполон" "$_t664_ovf" \
    "разрез по comm НЕПОЛОН" "лимитер свернул 7 серий" "ebpf_guard_http_plaintext_comm_overflow_total" \
    "атрибутирован-но-свёрнут" "python3=9 other=30"

# Ветка 3: сумма разреза не равна settled_delta — разрез считает ДРУГУЮ
# популяцию, и вычитать остаток из несходящихся величин нельзя.
_mk_h664 "$_A664" 9 39 30 - "" "python3=9 node=12"
_t664_pop=$(_check66 6.6.4 "сумма разреза ≠ settled_delta — НЕИЗМЕРИМ, обе величины названы" "$(_run66 "$_A664" "")" FAIL)
_need_text "6.6.4 разрез про другую популяцию" "$_t664_pop" \
    "считает ДРУГУЮ популяцию" "сумма разреза 21 против settled_delta 39" "вычитать остаток из несходящихся величин нельзя"

# Ветка 4 — ТА, РАДИ КОТОРОЙ ЗАВЕДЁН item 7: остаток НАЗВАН осью comm, разрез
# полон и сходится с settled_delta. Метка впервые способна вынести ДОСТИГНУТО.
_mk_h664 "$_A664" 9 39 30 "4242:node,4250:nginx" "" "nginx=18 node=12 python3=9"
_t664_ok=$(_check66 6.6.4 "остаток назван осью comm, разрез полон — ДОСТИГНУТО" "$(_run66 "$_A664" "")" OK)
_need_text "6.6.4 остаток назван осью comm" "$_t664_ok" \
    "6.6.4 ДОСТИГНУТО" "остаток НАЗВАН осью comm" "остаток 30" \
    "nginx=18 node=12 python3=9" "сумма разреза 39 = settled_delta 39" "разрез ПОЛОН" \
    "свёрнутых в comm=\"other\" за интервал 0" "метрикой, а не догадкой"

# ── 6.6.5 (item 7, №478): kmod. _mk_k665 <каталог> <up> <lsm> <errno> <before> <after> [class]
_mk_k665() {
    local d="$1"; mkdir -p "$d"; rm -f "$d/kmod-control.txt"
    if [ "${7:-}" != "" ]; then echo "class=$7" > "$d/kmod-control.txt"; return; fi
    printf 'kmod_up=%s\nlsm=%s\nerrno=%s\nerrno_name=Bad_file_descriptor\nrc=-1\ncomm=python3\nrule=rootkit_init_module_syscall\nalerts_before=%s\nalerts_after=%s\nalerts_delta=%s\n' \
        "$2" "$3" "$4" "$5" "$6" "$(( $6 - $5 ))" > "$d/kmod-control.txt"
}
_A665="$WORK/art665"; rm -rf "$_A665"; mkdir -p "$_A665"
_check66 6.6.5 "контроль не поставлен — НЕ ЗАПРОШЕН" "$(_run66 "$_A665" "")" NOTREQ >/dev/null
_mk_k665 "$_A665" - - - - - "нагрузка_не_напечатала_errno_вызов_не_дошёл_до_ядра"
_t665_c=$(_check66 6.6.5 "класс назван контролем — НЕИЗМЕРИМ" "$(_run66 "$_A665" "")" FAIL)
_need_text "6.6.5 класс контроля" "$_t665_c" "класс НАЗВАН контролем" "не_напечатала_errno"
_mk_k665 "$_A665" 0 "lockdown,capability,landlock,yama,apparmor" 9 3 4
_t665_ok=$(_check66 6.6.5 "up=0 без bpf в LSM, EBADF, +1 алерт двойника — ДОСТИГНУТО (обе половины)" "$(_run66 "$_A665" "")" OK)
_need_text "6.6.5 обе половины" "$_t665_ok" "обе половины предъявлены" "collector_up{kmod}=0" "bpf: НЕТ" "ИНЕРТНЫ" "errno=9" "Bad_file_descriptor" "модуль НЕ загружен" "3→4"
_mk_k665 "$_A665" 0 "lockdown,capability,yama" 9 3 3
_t665_d=$(_check66 6.6.5 "EBADF дошёл, алертов не прибавилось — ПРОВАЛЕН (двойник мёртв)" "$(_run66 "$_A665" "")" FAIL)
_need_text "6.6.5 двойник мёртв" "$_t665_d" "двойник" "мёртв" "НЕ детектируется совсем" "3→3"
_mk_k665 "$_A665" 1 "lockdown,capability,yama" 9 3 4
_t665_l=$(_check66 6.6.5 "up=1 без bpf в LSM — ПРОВАЛЕН (лжёт единицей)" "$(_run66 "$_A665" "")" FAIL)
_need_text "6.6.5 ложная единица" "$_t665_l" "лжёт единицей" "№438"
_mk_k665 "$_A665" 0 "lockdown,bpf,yama" 9 3 4
_check66 6.6.5 "up=0 при bpf в LSM — ПРОВАЛЕН (ридеры не поднялись)" "$(_run66 "$_A665" "")" FAIL >/dev/null
_mk_k665 "$_A665" 1 "lockdown,bpf,yama" 9 3 4
_t665_b=$(_check66 6.6.5 "ядро с bpf-LSM, up=1 — ДОСТИГНУТО, kmod живы, а cgroup_esc всё равно инертны (№494)" "$(_run66 "$_A665" "")" OK)
# №494: на ядре с bpf в списке LSM оживают СЕМЬ правил kmod, но НЕ два cgroup_esc —
# их продюсер висит на SEC(lsm/cgroup_attach_task), а такого хука нет ни в v5.15,
# ни в v6.12, ни в master (ноль хуков со словом cgroup в lsm_hook_defs.h). Строка
# обязана различать две группы В СЕБЕ: прежняя писала «7 правил kmod и 2 cgroup_esc
# живы» и на таком ядре лгала про вторую группу.
_need_text "6.6.5 bpf есть" "$_t665_b" "bpf: есть" "живы" \
    "2 правила cgroup_esc ИНЕРТНЫ НА ЛЮБОМ ядре" "lsm/cgroup_attach_task" "№494"
# Нечитаемый список LSM: половина (а) судится СРАВНЕНИЕМ up со списком, поэтому
# пустой список — не «bpf нет», а отсутствие свойства мира на руках. Класс
# обязан назвать КОНТРОЛЬ (у него список в руках), а не эмиттер — поэтому тут
# проверяются обе стороны: ветка эмиттера на класс и сама строка отказа в
# контроле ([[verdict-zero-needs-its-class-presented]]).
_mk_k665 "$_A665" - - - - - "список_LSM_ядра_не_прочитан_sys_kernel_security_lsm_недоступен"
_t665_nolsm=$(_check66 6.6.5 "список LSM ядра не прочитан — НЕИЗМЕРИМ, а не «bpf нет»" "$(_run66 "$_A665" "")" FAIL)
_need_text "6.6.5 список LSM не прочитан" "$_t665_nolsm" "класс НАЗВАН контролем" "список_LSM_ядра_не_прочитан"
_KMODC="$(dirname "$PIPE")/wave6.6-kmod-control.sh"
if [ -r "$_KMODC" ]; then
    grep -q 'список_LSM_ядра_не_прочитан' "$_KMODC" \
        || _efail "6.6.5: контроль kmod НЕ называет класс при нечитаемом /sys/kernel/security/lsm — пустой список уйдёт в эмиттер и прочитается как «bpf отсутствует»"
    echo "    OK  6.6.5: контроль kmod называет класс при нечитаемом списке LSM (не выдаёт пустое за «bpf нет»)"
else
    _efail "6.6.5: $_KMODC не найден — сторож на нечитаемый список LSM проверить нечем"
fi

# ── 6.6.6 (зонд №488): упакованная раскладка ClientHello предъявляется
#    АРХИВИРУЕМЫМИ файлами. Фикстуры гоняют обе половины и все классы
#    неизмеримости: ни одна ветка эмиттера не имеет права быть непроверяемой
#    ([[guard-exculpating-token-must-not-be-its-own-comment]]).
#
# _mk_m666 <файл> <ja3|-> <payload|-> <unknown|-> <parse_error|-> <tls_events|->
#    Снимок /metrics ровно с теми сериями, что читает эмиттер; «-» — серии в
#    снимке НЕТ ВООБЩЕ (законный вход: счётчик с лейблом рождается первым
#    инкрементом, и «нет серии» обязано быть отличимо от нуля).
_mk_m666() {
    local f="$1"; : > "$f"
    [ "$2" != "-" ] && echo "ebpf_guard_tls_events_by_family_total{family=\"ja3\"} $2" >> "$f"
    [ "$3" != "-" ] && echo "ebpf_guard_tls_events_by_family_total{family=\"payload\"} $3" >> "$f"
    [ "$4" != "-" ] && echo "ebpf_guard_tls_events_by_family_total{family=\"unknown\"} $4" >> "$f"
    [ "$5" != "-" ] && echo "ebpf_guard_events_dropped_total{collector=\"tlsfingerprint\",reason=\"parse_error\"} $5" >> "$f"
    [ "$6" != "-" ] && echo "ebpf_guard_events_total{type=\"tls\"} $6" >> "$f"
    return 0
}
# _mk_e666 <каталог> [sha] — копия ожиданий в архиве. Отпечатки берутся из
# НАСТОЯЩЕГО файла ожиданий рядом с зондом: фикстура не имеет права выписывать
# свои — тогда она проверяла бы сама себя, а не сверку прогона с ожиданиями.
_EXP666="$(dirname "$PIPE")/wave6.6-ja3-probe.expect"
_E666_JA3=$(awk -F= '$1=="ja3"{print $2}' "$_EXP666" 2>/dev/null)
_E666_JA4=$(awk -F= '$1=="ja4"{print $2}' "$_EXP666" 2>/dev/null)
_E666_SHA=$(awk -F= '$1=="payload_sha256"{print $2}' "$_EXP666" 2>/dev/null)
_E666_LEN=$(awk -F= '$1=="payload_len"{print $2}' "$_EXP666" 2>/dev/null)
if [ -z "$_E666_JA3" ] || [ -z "$_E666_JA4" ] || [ -z "$_E666_SHA" ]; then
    _efail "6.6.6: файл ожиданий зонда ($_EXP666) не найден либо не несёт ja3/ja4/payload_sha256 — сверять фикстурам нечем"
fi
_mk_e666() { cp "$_EXP666" "$1/ja3-probe-expect.txt"; }
# _mk_j666 <каталог> <pid> <sent> <строк журнала> <pids> <ja3> <ja4> <sha>
_mk_j666() {
    printf 'sender_pid=%s\nsender_comm=python3\nsent=%s\npayload_len=%s\npayload_sha256=%s\nsettle_s=5\ncollector_up=1\njournal_lines=%s\njournal_pids=%s\nja3_observed=%s\nja4_observed=%s\n' \
        "$2" "$3" "$_E666_LEN" "$8" "$4" "$5" "$6" "$7" > "$1/ja3-probe.txt"
}

_A666="$WORK/art666"; rm -rf "$_A666"; mkdir -p "$_A666"
_check66 6.6.6 "зонд не поставлен — НЕ ЗАПРОШЕН" "$(_run66 "$_A666" "")" NOTREQ >/dev/null

echo "class=серии_collector_up_tlsfingerprint_нет_коллектор_не_поднят_на_этом_прогоне_зонд_не_ставится" > "$_A666/ja3-probe.txt"
_t666_c=$(_check66 6.6.6 "класс назван зондом — НЕИЗМЕРИМ" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 класс зонда" "$_t666_c" "класс НАЗВАН зондом" "collector_up_tlsfingerprint_нет"

# Один снимок вместо двух: дельты считать не из чего, и пустой снимок молча
# стал бы нулями ([[empty-metric-snapshot-is-silently-zero]]).
_mk_j666 "$_A666" 2099987 3 3 2099987 "$_E666_JA3" "$_E666_JA4" "$_E666_SHA"
_mk_e666 "$_A666"
rm -f "$_A666/metrics-ja3-probe-after.txt"
_mk_m666 "$_A666/metrics-ja3-probe-before.txt" 0 0 0 0 100
_t666_s=$(_check66 6.6.6 "снимок один — НЕИЗМЕРИМ" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 снимков не два" "$_t666_s" "снимков метрик зонда не два" "пустой снимок молча стал бы нулями"

_mk_m666 "$_A666/metrics-ja3-probe-after.txt" 3 0 0 0 103
rm -f "$_A666/ja3-probe-expect.txt"
_t666_e=$(_check66 6.6.6 "копии ожиданий в архиве нет — НЕИЗМЕРИМ" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 ожиданий нет" "$_t666_e" "ja3-probe-expect.txt" "задним числом"

# Нагрузку подменили: отпечатки ожидаются для ДРУГИХ байт, и сверка стала бы
# пустой — тождество нагрузки проверяется ДО отпечатков.
_mk_e666 "$_A666"
_mk_j666 "$_A666" 2099987 3 3 2099987 "$_E666_JA3" "$_E666_JA4" "0000000000000000000000000000000000000000000000000000000000000000"
_t666_sha=$(_check66 6.6.6 "sha256 нагрузки не сошёлся — НЕИЗМЕРИМ" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 тождество нагрузки" "$_t666_sha" "тождество нагрузки не сошлось" "ДРУГИХ байт"

# Серии семейств нет НИ В ОДНОМ снимке (бинарь до item 7 волны 6.5).
_mk_j666 "$_A666" 2099987 3 3 2099987 "$_E666_JA3" "$_E666_JA4" "$_E666_SHA"
_mk_m666 "$_A666/metrics-ja3-probe-before.txt" - - - 0 100
_mk_m666 "$_A666/metrics-ja3-probe-after.txt"  - - - 0 103
_t666_nos=$(_check66 6.6.6 "серии семейств нет — НЕИЗМЕРИМ, а не ноль" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 нет серии семейства" "$_t666_nos" "нет НИ В ОДНОМ из двух снимков" "неотличимо от нуля"

# Байты не доехали: коллектор поднят, отправлено 3, семейство не выросло.
_mk_m666 "$_A666/metrics-ja3-probe-before.txt" 0 0 0 0 100
_mk_m666 "$_A666/metrics-ja3-probe-after.txt"  0 0 0 0 100
_t666_z=$(_check66 6.6.6 "дельта семейства 0 — ПРОВАЛЕН (продуктовый)" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 байты не доехали" "$_t666_z" "класс ПРОДУКТОВЫЙ" "__x64_sys_sendto" "НЕ нагрузку"

# Подпись СДВИНУТОЙ раскладки: часть записей ушла в payload.
_mk_m666 "$_A666/metrics-ja3-probe-after.txt" 1 2 0 0 103
_t666_sh=$(_check66 6.6.6 "часть записей в payload — ПРОВАЛЕН (сдвиг раскладки)" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 подпись сдвига" "$_t666_sh" "подпись СДВИНУТОЙ раскладки" "payload 2" "№488"

# Отбраковка парсера выросла на ФИКСИРОВАННОЙ нагрузке.
_mk_m666 "$_A666/metrics-ja3-probe-after.txt" 3 0 0 2 103
_t666_pe=$(_check66 6.6.6 "parse_error вырос — ПРОВАЛЕН" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 отбраковка парсера" "$_t666_pe" "parse_error" "выросла на 2" "не принял вовсе"

# Половина (а) взята, половина (б) не снята: журнал молчит (уровень не debug).
_mk_m666 "$_A666/metrics-ja3-probe-after.txt" 3 0 0 0 103
_mk_j666 "$_A666" 2099987 3 0 "-" "-" "-" "$_E666_SHA"
_t666_nj=$(_check66 6.6.6 "журнал молчит — НЕИЗМЕРИМ (половина (б) не снята)" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 журнал молчит" "$_t666_nj" "половина (а) взята" "половина (б) НЕ СНЯТА" "debug" "pid правдоподобен"

# Атрибуция: в событиях ЧУЖОЙ pid рядом со своим — сверка ТОЧНАЯ.
_mk_j666 "$_A666" 2099987 3 4 "2099987,104729" "$_E666_JA3" "$_E666_JA4" "$_E666_SHA"
_t666_ap=$(_check66 6.6.6 "иной pid в событиях — ПРОВАЛЕН (атрибуция)" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 атрибуция pid" "$_t666_ap" "АТРИБУЦИЯ" "2099987,104729" "старшей половины timestamp"

# Отпечаток не тот при сошедшемся sha256 — значит сдвиг или обрезание data.
_mk_j666 "$_A666" 2099987 3 3 2099987 "ffffffffffffffffffffffffffffffff" "$_E666_JA4" "$_E666_SHA"
_t666_fp=$(_check66 6.6.6 "отпечаток не тот при сошедшемся sha — ПРОВАЛЕН (раскладка)" "$(_run66 "$_A666" "")" FAIL)
_need_text "6.6.6 отпечаток не тот" "$_t666_fp" "РАСКЛАДКА" "ffffffffffffffffffffffffffffffff" "сдвиг или обрезание"

# ДОСТИГНУТО, и это ЖИВАЯ форма: серия {family="ja3"} рождается ПЕРВЫМ
# инкрементом, поэтому в снимке ДО её нет вовсе, а дельта всё равно читается.
_mk_m666 "$_A666/metrics-ja3-probe-before.txt" - 0 0 0 100
_mk_m666 "$_A666/metrics-ja3-probe-after.txt"  3 0 0 0 103
_mk_j666 "$_A666" 2099987 3 3 2099987 "$_E666_JA3" "$_E666_JA4" "$_E666_SHA"
_t666_ok=$(_check66 6.6.6 "обе половины предъявлены, серия рождена первым инкрементом — ДОСТИГНУТО" "$(_run66 "$_A666" "")" OK)
_need_text "6.6.6 обе половины" "$_t666_ok" "ПРЕДЪЯВЛЕНА двумя половинами" \
    "= 3 на 3 отправленных" "payload 0 и unknown 0" "РОВНО pid отправителя 2099987" \
    "$_E666_JA3" "$_E666_JA4" "НЕ покрытие коллектора" "№381 не переоткрыта"

# ── ПОЛНОТА РЕЕСТРА НЕМОТЫ (волна 7, item б1, 28.09.2026). Семейств немоты у
#    агента ЧЕТЫРЕ, а шаблон собирателя `env-muteness-6.4.txt` знал ТРИ: строку
#    item 8 (ось типа события, №494) агент печатал живьём, а реестр в архиве её
#    не нёс — читалось «семейств три». Сторож полноты сравнивает журнал с
#    реестром ПО ТЕКСТУ msg, а не по нашему же шаблону, и проверяется здесь на
#    четырёх входах: полный реестр, потерянное семейство, пустой журнал, пустой
#    реестр при непустом журнале.
_w7m_pipe="$PIPE"
_w7m_fn=$(awk '/^_w7_mute_families\(\) \{/,/^\}/' "$_w7m_pipe"; awk '/^_w7_mute_missing_families\(\) \{/,/^\}/' "$_w7m_pipe")
if ! printf '%s' "$_w7m_fn" | grep -q '_w7_mute_missing_families'; then
    _efail "полнота реестра немоты: помощников _w7_mute_families/_w7_mute_missing_families нет в $_w7m_pipe — сторож непроверяем"
fi
eval "$_w7m_fn"
_W7M="$WORK/w7mute"; rm -rf "$_W7M"; mkdir -p "$_W7M"
_w7m_line() { printf '%s {"time":"t","level":"WARN","msg":"rules: %s","count":1}\n' "Sep 28 03:54:42 h ebpf-guard[1]:" "$1"; }
{
    _w7m_line "syscall rules with no reachable nr in the kernel allowlist"
    _w7m_line "file rules whose op condition names no operation any hook produces"
    _w7m_line "network rules whose proto condition names no protocol any hook produces"
    _w7m_line "rules standing on an event type this build has no producer for"
    echo 'Sep 28 03:54:43 h ebpf-guard[1]: {"msg":"kmod: cgroup escape collector unavailable"}'
} > "$_W7M/journal.txt"
# (1) Реестр полон — потерь ноль.
cp "$_W7M/journal.txt" "$_W7M/reg-full.txt"
_w7m_n=$(_w7_mute_missing_families "$_W7M/journal.txt" "$_W7M/reg-full.txt" | grep -c . || true)
if [ "${_w7m_n:-0}" -eq 0 ]; then
    echo "    OK  полнота реестра немоты: полный реестр — потерь 0"
else
    _efail "полнота реестра немоты: на полном реестре сторож нашёл ${_w7m_n} потерь — он даёт ложный красный"
fi
# (2) Потеряно РОВНО то семейство, на котором дефект и был найден.
grep -v "no producer for" "$_W7M/journal.txt" > "$_W7M/reg-lost.txt"
_w7m_lost=$(_w7_mute_missing_families "$_W7M/journal.txt" "$_W7M/reg-lost.txt")
if [ "$(printf '%s\n' "$_w7m_lost" | grep -c . || true)" -eq 1 ] && printf '%s' "$_w7m_lost" | grep -q "no producer for"; then
    echo "    OK  полнота реестра немоты: потерянное семейство НАЗВАНО — $(printf '%s' "$_w7m_lost" | cut -c1-70)"
else
    _efail "полнота реестра немоты: потеря семейства item 8 не поймана либо не названа — получено «${_w7m_lost}»"
fi
# (3) Пустой журнал: терять нечего, и это НЕ красный (агент мог не напечатать ни
#     одного семейства — законный вход, например каталог без немых правил).
: > "$_W7M/journal-empty.txt"
_w7m_e=$(_w7_mute_missing_families "$_W7M/journal-empty.txt" "$_W7M/reg-full.txt" | grep -c . || true)
if [ "${_w7m_e:-0}" -eq 0 ]; then
    echo "    OK  полнота реестра немоты: пустой журнал — потерь 0 (ложного красного нет)"
else
    _efail "полнота реестра немоты: на пустом журнале сторож нашёл потери — сравнение идёт не в ту сторону"
fi
# (4) Пустой реестр при непустом журнале — потеряны ВСЕ четыре семейства.
: > "$_W7M/reg-empty.txt"
_w7m_all=$(_w7_mute_missing_families "$_W7M/journal.txt" "$_W7M/reg-empty.txt" | grep -c . || true)
if [ "${_w7m_all:-0}" -eq 4 ]; then
    echo "    OK  полнота реестра немоты: пустой реестр — потеряны все 4 семейства (ноль строк реестра не читается как «нечего терять»)"
else
    _efail "полнота реестра немоты: пустой реестр дал ${_w7m_all} потерь вместо 4"
fi
# (5) Шаблон собирателя в пайплайне обязан знать ВСЕ четыре семейства: сторож
#     выше поймает отставание на прогоне, а эта сверка — ещё до стенда.
for _w7m_pat in "no reachable nr in the kernel allowlist" "file rules whose op condition names no operation any hook produces" "proto condition names no protocol any hook produces" "rules standing on an event type this build has no producer for"; do
    if grep -q -- "$_w7m_pat" "$_w7m_pipe"; then
        echo "    OK  шаблон реестра немоты знает семейство «$(printf '%s' "$_w7m_pat" | cut -c1-40)…»"
    else
        _efail "шаблон реестра немоты НЕ знает семейство «${_w7m_pat}» — архив снова понесёт неполный реестр"
    fi
done

# ── 6.6.8 (цена `collectors.tls_fingerprint` ЗА ОКНО, решение 28.09.2026).
#    Восемь веток эмиттера, у каждой фикстура: ветка без фикстуры равна
#    отсутствующей ([[guard-exculpating-token-must-not-be-its-own-comment]]).
#    Два предмета проверяются отдельно от классов:
#      — РОЛЬ A не имеет права напечатать число ценой (иначе ноль выключенного
#        коллектора уедет в plan.md как «бесплатен»);
#      — ja3-подмножество объёма берётся ПО МАНИФЕСТУ и через карту
#        переименований Rego: объём правила семейства plaintext на той же оси
#        {event_type="tls"} ценой этого коллектора НЕ является (№503), а
#        переименованное Rego ja3-правило — является (№400/№401).
#
# _mk_w668 <каталог> <файл> <ja3|-> <up|-> <строки «rule=N» объёма tls> [строки «новое=базовое» переименований]
_mk_w668() {
    local d="$1" f="$2" ja3="$3" up="$4" vols="$5" rens="${6:-}" pair
    mkdir -p "$d"; : > "$d/$f"
    [ "$ja3" != "-" ] && echo "ebpf_guard_tls_events_by_family_total{family=\"ja3\"} $ja3" >> "$d/$f"
    [ "$up"  != "-" ] && echo "ebpf_guard_collector_up{collector=\"tlsfingerprint\"} $up" >> "$d/$f"
    for pair in $vols; do
        echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"tls\",rule_id=\"${pair%%=*}\"} ${pair##*=}" >> "$d/$f"
    done
    for pair in $rens; do
        echo "ebpf_guard_alert_rule_id_renamed_total{base_rule_id=\"${pair##*=}\",rule_id=\"${pair%%=*}\"} 1" >> "$d/$f"
    done
    return 0
}
# Манифест фикстуры — КОПИЯ БОЕВОГО, а не выписанный рукой список: иначе
# фикстура проверяла бы собственную выдумку, а не разбор того файла, который
# уезжает на стенд ([[archive-carries-its-own-guard-copy]]).
_MAN668="$(dirname "$PIPE")/attacks/tls-rule-ids.txt"
[ -s "$_MAN668" ] || _efail "6.6.8: боевого манифеста $_MAN668 нет — фикстурам нечего разбирать"
_M668_JA3=$(awk '/^#[[:space:]]*ja3/{s=1;next} /^#[[:space:]]*plaintext/{s=0;next} /^[[:space:]]*(#|$)/{next} s' "$_MAN668" | head -1)
_M668_PLN=$(awk '/^#[[:space:]]*plaintext/{s=1;next} /^#[[:space:]]*ja3/{s=0;next} /^[[:space:]]*(#|$)/{next} s' "$_MAN668" | head -1)
_M668_N=$(awk '/^#[[:space:]]*ja3/{s=1;next} /^#[[:space:]]*plaintext/{s=0;next} /^[[:space:]]*(#|$)/{next} s' "$_MAN668" | wc -l | tr -d ' ')
[ -n "$_M668_JA3" ] && [ -n "$_M668_PLN" ] || _efail "6.6.8: в манифесте $_MAN668 не найдены обе секции (ja3/plaintext)"
echo "    (6.6.8: манифест боевой — секция ja3 несёт ${_M668_N} id, образец ja3=${_M668_JA3}, образец plaintext=${_M668_PLN})"

_A668="$WORK/art668"
# _init668 <ja3-до> <up-до> <объём-до> <ja3-после> <up-после> <объём-после> [переименования] — пара снимков границ окна + манифест.
_init668() {
    rm -rf "$_A668"; mkdir -p "$_A668"
    cp "$_MAN668" "$_A668/tls-rule-ids.txt"
    _mk_w668 "$_A668" metrics-window-start.txt "$1" "$2" "$3" "${7:-}"
    _mk_w668 "$_A668" metrics-window-end.txt   "$4" "$5" "$6" "${7:-}"
}
# _probe668 <дельта ja3 зонда|off> — свидетель живости прибора (зонд №488).
_probe668() {
    rm -f "$_A668/ja3-probe.txt" "$_A668/metrics-ja3-probe-before.txt" "$_A668/metrics-ja3-probe-after.txt" "$_A668/ja3-probe-expect.txt"
    [ "$1" = "off" ] && return 0
    _mk_e666 "$_A668"
    _mk_m666 "$_A668/metrics-ja3-probe-before.txt" 0 0 0 0 100
    _mk_m666 "$_A668/metrics-ja3-probe-after.txt" "$1" 0 0 0 "$((100 + $1))"
    _mk_j666 "$_A668" 2099987 3 3 2099987 "$_E666_JA3" "$_E666_JA4" "$_E666_SHA"
    return 0
}

echo
echo "=== ЦЕНА tls_fingerprint: восемь веток метки 6.6.8 ==="
_init668 0 1 "" 0 1 ""
rm -f "$_A668/metrics-window-start.txt" "$_A668/metrics-window-end.txt"
_probe668 3
_t668_a=$(_check66 6.6.8 "снимков границ окна нет — НЕИЗМЕРИМ" "$(_run66 "$_A668" "")" FAIL)
_need_text "6.6.8 нет снимков" "$_t668_a" "снимки метрик границ окна не сняты" "вакуумным нулём не печатается"

_init668 0 1 "" 0 1 ""
rm -f "$_A668/tls-rule-ids.txt"
_probe668 3
_t668_b=$(_check66 6.6.8 "манифеста нет — НЕИЗМЕРИМ (ось rule_id, а не event_type)" "$(_run66 "$_A668" "")" FAIL)
_need_text "6.6.8 нет манифеста" "$_t668_b" "манифеста tls-rule-ids.txt нет" "смешивает 10 правил ja3 с 13 правилами plaintext"

_init668 - 1 "" - 1 ""
_probe668 3
_t668_c=$(_check66 6.6.8 "серии семейства ja3 нет в снимках — НЕИЗМЕРИМ" "$(_run66 "$_A668" "")" FAIL)
_need_text "6.6.8 нет серии" "$_t668_c" "нет в одном из снимков границ окна" "неотличимо от её нуля"

_init668 9 1 "" 4 1 ""
_probe668 3
_t668_d=$(_check66 6.6.8 "счётчик семейства убыл — НЕИЗМЕРИМ (рестарт)" "$(_run66 "$_A668" "")" FAIL)
_need_text "6.6.8 убыль" "$_t668_d" "УБЫЛ внутри окна" "дельта через рестарт бессмысленна"

# РОЛЬ A. Серии collector_up{tlsfingerprint} нет вовсе — ровно то, что стоит в
# архиве collect-6.4-w504 (коллектор выключен, коллектор не строится, серии
# нет). Ненулевая дельта при этом — загрязнённый вход, а не цена.
_init668 0 - "" 5 - ""
_probe668 off
_t668_e=$(_check66 6.6.8 "роль A, а семейство выросло — ПРОВАЛЕН (вход загрязнён)" "$(_run66 "$_A668" "")" FAIL)
_need_text "6.6.8 роль A загрязнена" "$_t668_e" "роль A" "СЕРИИ НЕТ" "вход роли A загрязнён" "пара A/B недоказуема"

_init668 0 - "tls_http_basic_auth=7" 0 - "tls_http_basic_auth=19"
_probe668 off
_t668_f=$(_check66 6.6.8 "роль A чистая — НЕИЗМЕРИМ, опорная половина, НЕ цена 0" "$(_run66 "$_A668" "")" FAIL)
_need_text "6.6.8 роль A" "$_t668_f" "роль A" "цена ЭТОГО прогона неизмерима" "ноль ценой печатать запрещено" \
    "= 12" "Цену назначает ВТОРОЙ прогон пары"
_forbid_text "6.6.8 роль A не печатает цену" "$_t668_f" "ИЗМЕРЕНО" "цена в СОБЫТИЯХ" "цена в АЛЕРТАХ"

# РОЛЬ B, НОЛЬ. Без зонда ноль неотличим от мёртвого прибора — НЕИЗМЕРИМ.
_init668 0 1 "" 0 1 ""
_probe668 off
_t668_g=$(_check66 6.6.8 "роль B, ноль без свидетеля живости — НЕИЗМЕРИМ" "$(_run66 "$_A668" "")" FAIL)
_need_text "6.6.8 ноль без зонда" "$_t668_g" "свидетеля живости прибора нет" "не ставился" "назначила бы цену прибору, а не продукту"
_forbid_text "6.6.8 ноль без зонда не цена" "$_t668_g" "ИЗМЕРЕНО"

# Зонд ПОСТАВЛЕН и дал ноль — это НЕ свидетель, это мёртвый прибор.
_init668 0 1 "" 0 1 ""
_probe668 0
_t668_h=$(_check66 6.6.8 "зонд поставлен и дал ноль — свидетелем НЕ считается" "$(_run66 "$_A668" "")" FAIL)
_need_text "6.6.8 зонд дал ноль" "$_t668_h" "прибор НЕ подтверждён живым"

# РОЛЬ B, НОЛЬ СО СВИДЕТЕЛЕМ — законная величина: цена за окно 0/0.
_init668 0 1 "tls_http_basic_auth=7" 0 1 "tls_http_basic_auth=19"
_probe668 3
_t668_i=$(_check66 6.6.8 "роль B, ноль при живом зонде — ИЗМЕРЕНО, 0 событий и 0 алертов" "$(_run66 "$_A668" "")" OK)
_need_text "6.6.8 ноль со свидетелем" "$_t668_i" "цена в СОБЫТИЯХ = 0" "цена в АЛЕРТАХ = 0" \
    "= 12" "он НЕ цена" "kprobe висит на КАЖДОМ sendto(2)" "цена НА ClientHello этим прогоном НЕ назначается"

# РОЛЬ B, ЦЕНА НАЗНАЧЕНА. Объём считают ТРИ правила: ja3-правило манифеста,
# ja3-правило, ПЕРЕИМЕНОВАННОЕ Rego (обязано зачесться), и правило семейства
# plaintext (обязано НЕ зачестись — оно кормится другим коллектором).
_init668 10 1 "${_M668_JA3}=4 rego_renamed_ja3=1 ${_M668_PLN}=100" \
         16 1 "${_M668_JA3}=9 rego_renamed_ja3=6 ${_M668_PLN}=140" \
         "rego_renamed_ja3=tls_ja3_sliver_default"
_probe668 3
_t668_j=$(_check66 6.6.8 "роль B, цена назначена — ИЗМЕРЕНО, двумя числами" "$(_run66 "$_A668" "")" OK)
_need_text "6.6.8 цена" "$_t668_j" "цена в СОБЫТИЯХ = 6" "цена в АЛЕРТАХ = 10" \
    "${_M668_JA3}=5" "rego_renamed_ja3=5" "rego_renamed_ja3<-tls_ja3_sliver_default" \
    "= 50" "ценой НЕ является (№503)"
_forbid_text "6.6.8 правило plaintext не в цене" "$_t668_j" "${_M668_PLN}="


# ── 6.6.9 (цена порции оси `nr` и падение немоты, item б3 волны 7).
#    Тринадцать веток эмиттера, у каждой фикстура. Три предмета проверяются
#    отдельно от классов:
#      — РОЛЬ A не имеет права напечатать число ценой (иначе ноль закрытого
#        номера уедет в plan.md как «порция бесплатна»);
#      — НАБОР ЛЕЙБЛОВ ОСИ есть аллоулист прогона: полуоткрытая порция обязана
#        давать НЕИЗМЕРИМ, а не цену не той порции;
#      — ПАДЕНИЕ НЕМОТЫ проверяется ЖИВЫМ реестром, и правило порции, оставшееся
#        в реестре при открытых номерах, обязано быть ПРОВАЛОМ, а не молчанием.
#
# Манифест фикстуры — КОПИЯ БОЕВОГО ([[archive-carries-its-own-guard-copy]]):
# состав порции генерируется tools/rules-audit/nr-portions.py и рукой не пишется.
_MAN669="$(dirname "$PIPE")/attacks/wave7-nr-portions.txt"
[ -s "$_MAN669" ] || _efail "6.6.9: боевого манифеста $_MAN669 нет — фикстурам нечего разбирать"
_M669_NRS=$(awk '$1 == "P1" && $2 == "NR" { print $3 }' "$_MAN669")
_M669_RULES=$(awk '$1 == "P1" && $2 == "RULE" { print $3 }' "$_MAN669")
_M669_NN=$(printf '%s\n' "$_M669_NRS" | grep -c . || true)
_M669_NR=$(printf '%s\n' "$_M669_RULES" | grep -c . || true)
[ "${_M669_NN:-0}" -gt 0 ] && [ "${_M669_NR:-0}" -gt 0 ] \
    || _efail "6.6.9: в манифесте $_MAN669 нет порции 1 (номеров ${_M669_NN}, правил ${_M669_NR})"
echo "    (6.6.9: манифест боевой — порция 1 несёт ${_M669_NN} номеров и ${_M669_NR} правил, образец правила $(printf '%s' "$_M669_RULES" | head -1))"

_A669="$WORK/art669"
# _mk_w669 <файл> <axis: списком «nr=знач», «-» = серии нет вовсе> <строки «rule=N» объёма syscall> [переименования]
_mk_w669() {
    local f="$1" axis="$2" vols="$3" rens="${4:-}" pair
    : > "$f"
    if [ "$axis" != "-" ]; then
        for pair in $axis; do
            echo "ebpf_guard_syscall_events_by_nr_total{nr=\"${pair%%=*}\"} ${pair##*=}" >> "$f"
        done
    fi
    for pair in $vols; do
        echo "ebpf_guard_alert_volume_by_event_type_total{event_type=\"syscall\",rule_id=\"${pair%%=*}\"} ${pair##*=}" >> "$f"
    done
    for pair in $rens; do
        echo "ebpf_guard_alert_rule_id_renamed_total{base_rule_id=\"${pair##*=}\",rule_id=\"${pair%%=*}\"} 1" >> "$f"
    done
    return 0
}
# _axis669 <открыта порция: yes|no|half> <значение на номер> — набор лейблов оси
# так, как его объявляет рантайм: базовый аллоулист всегда, номера порции — по
# роли. Базовые номера берутся из строки BASELINE того же манифеста.
_axis669() {
    local mode="$1" val="$2" out="" n i=0
    for n in $(awk '$1 == "BASELINE" && $2 == "NR" { gsub(/,/, " ", $3); print $3 }' "$_MAN669"); do
        out="${out}${n}=0 "
    done
    out="${out}other=0 unset=0 "
    if [ "$mode" != "no" ]; then
        for n in $_M669_NRS; do
            i=$((i + 1))
            [ "$mode" = "half" ] && [ "$i" -gt 2 ] && break
            out="${out}${n}=${val} "
        done
    fi
    printf '%s' "$out"
}
# _reg669 <правила, стоящие в реестре как немые> — копия строки реестра немоты
# в форме агента (JSON slog), с семейством оси `nr`.
_reg669() {
    local ids="" r
    for r in $1; do ids="${ids}${ids:+,}\"${r}\""; done
    printf '{"time":"2026-09-29T03:00:00Z","level":"WARN","msg":"rules: syscall rules with no reachable nr in the kernel allowlist","count":%d,"rule_ids":[%s]}\n' \
        "$(printf '%s\n' $1 | grep -c . || true)" "$ids" > "$_A669/env-muteness-6.4.txt"
}
# _init669 <режим оси> <значение до> <значение после> <объём до> <объём после> <немые правила> [переименования]
_init669() {
    rm -rf "$_A669"; mkdir -p "$_A669"
    cp "$_MAN669" "$_A669/wave7-nr-portions.txt"
    _mk_w669 "$_A669/metrics-window-start.txt" "$(_axis669 "$1" "$2")" "$4" "${7:-}"
    _mk_w669 "$_A669/metrics-window-end.txt"   "$(_axis669 "$1" "$3")" "$5" "${7:-}"
    _reg669 "$6"
}
# _run669 <порция> — блок W66 с объявленной порцией; ART тот же.
_run669() { W7_PORTION="$1" _run66 "$_A669" ""; }

echo
echo "=== ЦЕНА ПОРЦИИ ОСИ nr: семнадцать веток метки 6.6.9 (13 на целой порции + 4 на ЧАСТИЧНОЙ, №514) ==="
_init669 no 0 0 "" "" "$_M669_RULES"
_t669_a=$(_check66 6.6.9 "порция не объявлена — НЕ ЗАПРОШЕН" "$(_run669 "")" NOTREQ)
_need_text "6.6.9 без W7_PORTION" "$_t669_a" "W7_PORTION не объявлен" "намерение объявляется"
_forbid_text "6.6.9 без W7_PORTION не печатает цену" "$_t669_a" "цена в СОБЫТИЯХ" "цена в АЛЕРТАХ"

_init669 no 0 0 "" "" "$_M669_RULES"
rm -f "$_A669/wave7-nr-portions.txt"
_t669_b=$(_check66 6.6.9 "манифеста порций нет — НЕИЗМЕРИМ" "$(_run669 1)" FAIL)
_need_text "6.6.9 нет манифеста" "$_t669_b" "манифеста порций wave7-nr-portions.txt нет" "генерируется tools/rules-audit/nr-portions.py"

_init669 no 0 0 "" "" "$_M669_RULES"
_t669_c=$(_check66 6.6.9 "порции 9 в манифесте нет — НЕИЗМЕРИМ" "$(_run669 9)" FAIL)
_need_text "6.6.9 чужая порция" "$_t669_c" "в манифесте нет порции '9'" "допустимы порции 1|2|3"

_init669 no 0 0 "" "" "$_M669_RULES"
rm -f "$_A669/metrics-window-start.txt" "$_A669/metrics-window-end.txt"
_t669_d=$(_check66 6.6.9 "снимков окна нет — НЕИЗМЕРИМ" "$(_run669 1)" FAIL)
_need_text "6.6.9 нет снимков" "$_t669_d" "снимков окна нет" "молча стал бы нулями"

_init669 no 0 0 "" "" "$_M669_RULES"
# Снимки НЕПУСТЫ — иначе ветка «серии нет» была бы неотличима от ветки «снимков
# нет» и фикстура проверяла бы чужой класс.
_mk_w669 "$_A669/metrics-window-start.txt" - "sigma_setuid_syscall=7"
_mk_w669 "$_A669/metrics-window-end.txt"   - "sigma_setuid_syscall=9"
_t669_e=$(_check66 6.6.9 "серии оси нет — НЕИЗМЕРИМ (бинарь до item б3)" "$(_run669 1)" FAIL)
_need_text "6.6.9 нет серии" "$_t669_e" "ebpf_guard_syscall_events_by_nr_total в снимках окна НЕТ" "бинарь ДО item б3"

_init669 no 0 0 "" "" "$_M669_RULES"
_mk_w669 "$_A669/metrics-window-start.txt" "$(_axis669 no 0)" ""
_mk_w669 "$_A669/metrics-window-end.txt"   "$(printf '%s' "$(_axis669 no 0)" | sed 's/unset=0/unset=17/')" ""
_t669_f=$(_check66 6.6.9 "бакет unset рос — НЕИЗМЕРИМ (ось не объявлена)" "$(_run669 1)" FAIL)
_need_text "6.6.9 unset" "$_t669_f" "ось \`nr\` рантаймом НЕ объявлена" "СОБЫТИЙ в бакете nr=\"unset\" 17"

_init669 no 0 0 "" "" "$_M669_RULES"
rm -f "$_A669/env-muteness-6.4.txt"
_t669_g=$(_check66 6.6.9 "реестра немоты нет — НЕИЗМЕРИМ" "$(_run669 1)" FAIL)
_need_text "6.6.9 нет реестра" "$_t669_g" "реестра немоты env-muteness-6.4.txt нет в \$ART" "метрика про немоту не знает"

_init669 yes 9 4 "" "" ""
_t669_h=$(_check66 6.6.9 "счётчик оси убыл — НЕИЗМЕРИМ (рестарт)" "$(_run669 1)" FAIL)
_need_text "6.6.9 убыль" "$_t669_h" "счётчик УБЫЛ внутри окна" "дельта через рестарт бессмысленна"

_init669 no 0 0 "sigma_setuid_syscall=7" "sigma_setuid_syscall=19" "$_M669_RULES"
_t669_i=$(_check66 6.6.9 "роль A чистая — НЕИЗМЕРИМ, опорная половина, НЕ цена 0" "$(_run669 1)" FAIL)
_need_text "6.6.9 роль A" "$_t669_i" "роль A" "цена ЭТОГО прогона неизмерима" "ноль ценой печатать запрещено" \
    "стоят в реестре немоты" "{event_type=\"syscall\"} за окно БЕЗ порции = 12"
_forbid_text "6.6.9 роль A не печатает цену" "$_t669_i" "ИЗМЕРЕНО" "цена в СОБЫТИЯХ" "цена в АЛЕРТАХ"

_init669 no 0 0 "" "" "$(printf '%s\n' "$_M669_RULES" | tail -n +2)"
_t669_j=$(_check66 6.6.9 "роль A, правило порции НЕ в реестре — ПРОВАЛЕН" "$(_run669 1)" FAIL)
_need_text "6.6.9 роль A неполна" "$_t669_j" "ПРОВАЛЕН" "в реестре немоты стоят не все её правила" "немо НЕ по причине закрытого номера"

_init669 half 0 5 "" "" "$_M669_RULES"
_t669_k=$(_check66 6.6.9 "порция открыта наполовину — НЕИЗМЕРИМ" "$(_run669 1)" FAIL)
_need_text "6.6.9 полуоткрытая порция" "$_t669_k" "аллоулист прогона и манифест РАЗОШЛИСЬ" "в оси объявлено 2"

_init669 yes 0 5 "" "" "$(printf '%s\n' "$_M669_RULES" | head -1)"
_t669_l=$(_check66 6.6.9 "роль B, правило осталось немым — ПРОВАЛЕН" "$(_run669 1)" FAIL)
_need_text "6.6.9 роль B немота осталась" "$_t669_l" "ПРОВАЛЕН" "в реестре немоты ОСТАЛИСЬ правила порции" "доля silent на этом прогоне НЕ упала"

# Роль B годная: цена названа ДВУМЯ числами, и алерт переименованного Rego
# правила порции зачтён (№400/№401), а чужое правило той же оси — нет (№503).
_M669_R1=$(printf '%s' "$_M669_RULES" | head -1)
_init669 yes 0 5 "${_M669_R1}=2 sigma_setuid_syscall=100" "${_M669_R1}=6 sigma_setuid_syscall=140 ${_M669_R1}_rego=9" "" "${_M669_R1}_rego=${_M669_R1}"
_t669_m=$(_check66 6.6.9 "роль B — ИЗМЕРЕНО, цена двумя числами" "$(_run669 1)" OK)
_need_text "6.6.9 роль B" "$_t669_m" "ИЗМЕРЕНО" "цена в СОБЫТИЯХ = $((5 * _M669_NN))" "по номерам СОБЫТИЙ" \
    "цена в АЛЕРТАХ = 13" "переименованные Rego зачтены: ${_M669_R1}_rego<-${_M669_R1}" \
    "Немота УПАЛА на ${_M669_NR} правил" "nr=\"other\" за окно 0" "ценой НЕ является (№503)"
_forbid_text "6.6.9 роль B не считает чужое правило оси" "$_t669_m" "sigma_setuid_syscall=40"

# ── ЧАСТИЧНАЯ ПОРЦИЯ (№514). Все тринадцать фикстур выше сняты на порции 1, у
# которой отвергнутых номеров НЕТ — поэтому они не могли увидеть, что эмиттер
# считает законное отсутствие отвергнутого номера за полуоткрытую порцию. Живой
# прогон роли B порции 3 дал на этом НЕИЗМЕРИМ. Ниже — порция с отвергнутыми.
_M669_P2N=$(awk '$1 == "P2" && $2 == "NR" { print $3 }' "$_MAN669")
_M669_P2REJ=$(awk '$1 == "P2" && $2 == "REJECTED" { print $3 }' "$_MAN669")
_M669_P2RULES=$(awk '$1 == "P2" && $2 == "RULE" { print $3 }' "$_MAN669")
_M669_P2KEEP=$(awk '$1 == "P2" && $2 == "MUTERULE" { print $3 }' "$_MAN669")
_M669_P2OPEN=""
for _n in $_M669_P2N; do
    case " $(printf '%s ' $_M669_P2REJ)" in *" $_n "*) ;; *) _M669_P2OPEN="${_M669_P2OPEN}${_n} " ;; esac
done
_M669_P2ON=$(printf '%s\n' $_M669_P2OPEN | grep -c . || true)
_M669_P2RN=$(printf '%s\n' $_M669_P2RULES | grep -c . || true)
[ "${_M669_P2ON:-0}" -gt 0 ] && [ -n "$_M669_P2REJ" ] && [ -n "$_M669_P2KEEP" ] \
    || _efail "6.6.9: у порции 2 в манифесте нет отвергнутых номеров или осознанно немых правил — фикстурам частичной порции нечего проверять"
echo "    (6.6.9: порция 2 — открывается ${_M669_P2ON} номеров из $(printf '%s\n' $_M669_P2N | grep -c .), отвергнуто $(printf '%s' "$_M669_P2REJ" | tr '\n' ' '), немыми по решению остаётся $(printf '%s' "$_M669_P2KEEP" | tr '\n' ' '))"

# _axis669p2 <значение> <какие номера открыть: open|half|withrej> — ось для порции 2
_axis669p2() {
    local val="$1" mode="$2" out="" n i=0
    for n in $(awk '$1 == "BASELINE" && $2 == "NR" { gsub(/,/, " ", $3); print $3 }' "$_MAN669"); do
        out="${out}${n}=0 "
    done
    for n in $_M669_NRS; do out="${out}${n}=0 "; done
    out="${out}other=0 unset=0 "
    for n in $_M669_P2OPEN; do
        i=$((i + 1))
        [ "$mode" = "half" ] && [ "$i" -gt 1 ] && break
        out="${out}${n}=${val} "
    done
    if [ "$mode" = "withrej" ]; then
        out="${out}$(printf '%s' "$_M669_P2REJ" | head -1)=${val} "
    fi
    printf '%s' "$out"
}
_init669p2() { # <до> <после> <режим> <объём до> <объём после> <немые правила>
    rm -rf "$_A669"; mkdir -p "$_A669"
    cp "$_MAN669" "$_A669/wave7-nr-portions.txt"
    _mk_w669 "$_A669/metrics-window-start.txt" "$(_axis669p2 "$1" "$3")" "$4"
    _mk_w669 "$_A669/metrics-window-end.txt"   "$(_axis669p2 "$2" "$3")" "$5"
    _reg669 "$6"
}

# (14) Частичная порция снята ВЕРНО: открыты все НЕотвергнутые номера, купленные
# правила из реестра ушли, а осознанно немое в нём осталось — это ИЗМЕРЕНО.
_M669_P2R1=$(printf '%s' "$_M669_P2RULES" | head -1)
_init669p2 0 7 open "${_M669_P2R1}=1" "${_M669_P2R1}=5" "$_M669_P2KEEP"
_t669_n=$(_check66 6.6.9 "частичная порция: открыто всё неотвергнутое — ИЗМЕРЕНО" "$(W7_PORTION=2 _run66 "$_A669" "")" OK)
_need_text "6.6.9 частичная порция ИЗМЕРЕНО" "$_t669_n" "ИЗМЕРЕНО" \
    "цена в СОБЫТИЯХ = $((7 * _M669_P2ON))" "Немота УПАЛА на ${_M669_P2RN} правил" \
    "Отвергнутых номеров порции, НЕ открывавшихся в этой паре: $(printf '%s' "$_M669_P2REJ" | tr '\n' ' ')" \
    "остающихся немыми ПО РЕШЕНИЮ: $(printf '%s' "$_M669_P2KEEP" | tr '\n' ' ')"

# (15) Та же порция, но открыт НЕ ВЕСЬ неотвергнутый состав — это по-прежнему
# полуоткрытая порция, и НЕИЗМЕРИМ обязан остаться.
_init669p2 0 7 half "" "" "$_M669_P2KEEP"
_t669_o=$(_check66 6.6.9 "частичная порция: открыт не весь неотвергнутый состав — НЕИЗМЕРИМ" "$(W7_PORTION=2 _run66 "$_A669" "")" FAIL)
_need_text "6.6.9 частичная порция полуоткрыта" "$_t669_o" "аллоулист прогона и манифест РАЗОШЛИСЬ" "в оси объявлено 1"

# (16) Обратная ошибка: прогон открыл ОТВЕРГНУТЫЙ номер. Число цены сошлось бы,
# а состав — нет, поэтому это ПРОВАЛ, а не ИЗМЕРЕНО.
_init669p2 0 7 withrej "" "" "$_M669_P2KEEP"
_t669_p=$(_check66 6.6.9 "прогон открыл отвергнутый номер — ПРОВАЛЕН" "$(W7_PORTION=2 _run66 "$_A669" "")" FAIL)
_need_text "6.6.9 открыт отвергнутый" "$_t669_p" "ПРОВАЛЕН" "ОТВЕРГНУТЫЕ решением порции 2" "не вправе его отменять молча"

# (17) Осознанно немое правило оказалось ДОСТИЖИМЫМ (в реестре его нет): отказ по
# номеру немоту не удержал, и запись манифеста лжёт.
_init669p2 0 7 open "" "" ""
_t669_q=$(_check66 6.6.9 "осознанно немое правило достижимо — ПРОВАЛЕН" "$(W7_PORTION=2 _run66 "$_A669" "")" FAIL)
_need_text "6.6.9 немое по решению достижимо" "$_t669_q" "ПРОВАЛЕН" "остающиеся немыми ПО РЕШЕНИЮ" "в реестре немоты ОТСУТСТВУЮТ"

# ── item 4 (№480): единица величины стоит рядом с осью. Каждое упоминание
# {event_type="tls"} в вердиктной строке echo обязано иметь слово «алертов»/«событий»
# (регистр не важен) в 40 символах ДО него — иначе одна и та же запись оси значит 2 и 6
# в одном логе. Источник читается ТЕКСТОМ (6.3L.6, 6.4.1, 6.4.6, 6.6.3 разом).
_w480_check() { # <файл> → печатает строки-нарушители
    grep -nE '^[[:space:]]*echo "(OK|FAIL|НЕИЗМЕРИМ|НЕ ЗАПРОШЕН[^:]*): 6\.' "$1" \
      | grep -F 'event_type=\"tls\"}' \
      | grep -viE '(алертов|событий)[^{]{0,40}\{event_type=\\"tls\\"\}' || true
}
_w480_bad=$(_w480_check "$PIPE")
if [ -z "$_w480_bad" ]; then
    echo "    OK  №480: у каждой вердиктной строки с {event_type=\"tls\"} единица (алертов/событий) стоит рядом с осью"
else
    _efail "№480: {event_type=\"tls\"} без слова «алертов»/«событий» рядом — $(printf '%s' "$_w480_bad" | cut -c1-160 | head -3)"
fi
_w480_mut="$WORK/w480-mut.sh"
sed 's/вход ноды, СОБЫТИЙ оси {event_type/вход ноды {event_type/' "$PIPE" > "$_w480_mut"
if [ -n "$(_w480_check "$_w480_mut")" ]; then
    echo "    OK  №480-негатив: снятое слово единицы у 6.4.1 краснеет"
else
    _efail "№480-негатив: сторож не покраснел на 6.4.1 без слова единицы — он бесполезен"
fi

# ── №480, вторая половина (пункт 13 ревизии 6.6): единица не только СТОИТ рядом
# с осью, но и ВЕРНА — сверяется с СЕРИЕЙ-ИСТОЧНИКОМ напечатанной величины.
# Прежний сторож ловил лишь ОТСУТСТВИЕ слова, поэтому «АЛЕРТОВ» над дельтой
# events_total читалось зелёным: единица есть, и она лжёт. Серию даёт тот же
# разбор _assign_map, что и у №460 (многострочные тела, наследование через
# `read -r <<<`), плюс арифметическая протяжка `VAR=$(( a - b ))`.
# Карта единиц объёмная: alert_volume_by_event_type_total/alerts_total →
# «алертов», events_total/tls_events_by_family_total → «событий». Прочие серии
# (collector_up, tls_attach_success_total) единицы НЕ несут и в сверку не
# входят — иначе 6.6.3 разъехалась бы на gauge здоровья.
# Ось сверки — ОБЕ объёмные оси, а не только TLS. Метка 6.6.9 (item б3 волны 7)
# несёт ту же пару единиц на оси {event_type="syscall"}, и сторож, знающий одну
# ось, к ней просто не применялся бы — то есть новая метка родилась бы без
# проверки, которой уже платили за 6.6.8 ([[fixes-must-migrate-to-sibling-controls]]).
_w480_axis_lines() { # <файл> → вердиктные строки с объёмной осью {event_type=…}
    grep -nE '^[[:space:]]*echo "(OK|FAIL|НЕИЗМЕРИМ|ИЗМЕРЕНО|НЕ ЗАПРОШЕН[^:]*): 6\.' "$1" \
      | grep -E 'event_type=\\"(tls|syscall)\\"}' || true
}
_w480_unit_of_series() { # <серия> → алертов | событий | «» (серия не объёмная)
    case "$1" in
        ebpf_guard_alert_volume_by_event_type_total|ebpf_guard_alerts_total) printf 'алертов' ;;
        ebpf_guard_events_total|ebpf_guard_tls_events_by_family_total|ebpf_guard_syscall_events_by_nr_total) printf 'событий' ;;
        *) printf '' ;;
    esac
}
# _w480_unit_audit <файл> → по строке на метку-нарушителя:
#   «WRONG<TAB>метка<TAB>ожидаемая единица<TAB>сколько строк»
#   «AMB<TAB>метка<TAB>причина<TAB>-»
_w480_unit_audit() {
    local f="$1" units="$WORK/w480-units.$$.tsv" round=0 added=0
    local name sig site series unit lhs ref ru line lab lines lunits n bad seen=""
    : > "$units"
    while IFS=$'\t' read -r name sig site; do
        series="${sig%%~*}"; unit=$(_w480_unit_of_series "$series")
        [ -n "$unit" ] && printf '%s\t%s\n' "$name" "$unit" >> "$units"
    done < <(_assign_map "$f")
    # Арифметическая протяжка до неподвижной точки: VAR=$(( … refs … )) наследует
    # единицу слагаемых (6.4.1 печатает _w648_delta, а серию несут ev0/ev1).
    while [ "$round" -lt 6 ]; do
        round=$((round + 1)); added=0
        while IFS= read -r line; do
            lhs=$(printf '%s' "$line" | sed -n 's/^[[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\)=\$((.*/\1/p')
            [ -n "$lhs" ] || continue
            for ref in $(printf '%s' "$line" | sed 's/^[^=]*=//' | grep -oE '_w[A-Za-z0-9_]+' | sort -u); do
                [ "$ref" = "$lhs" ] && continue
                for ru in $(awk -F'\t' -v n="$ref" '$1==n{print $2}' "$units" | sort -u); do
                    if ! awk -F'\t' -v n="$lhs" -v u="$ru" '$1==n && $2==u{f=1} END{exit(f?0:1)}' "$units"; then
                        printf '%s\t%s\n' "$lhs" "$ru" >> "$units"; added=1
                    fi
                done
            done
        done < <(grep -E '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=\$\(\(' "$f")
        [ "$added" -eq 0 ] && break
    done
    # Сверка ПО ВЕЛИЧИНЕ, а не по метке (обобщение 28.09.2026, вход — метка
    # 6.6.8). Прежнее правило звучало «у метки один источник объёма, значит
    # одна единица» и печатало AMB, как только в строке встречались обе. Оно
    # верно ровно до первой метки, которая ОБЯЗАНА нести две: цена коллектора
    # называется парой чисел — в событиях и в алертах, — и запрет на вторую
    # единицу заставлял бы либо снять с оси её имя, либо не печатать одну из
    # величин. Правило заменено на СТРОГО БОЛЕЕ СИЛЬНОЕ: у КАЖДОЙ печатаемой
    # величины, чья серия объёмная, единицей считается БЛИЖАЙШЕЕ слово
    # «алертов/событий» СЛЕВА от неё в той же строке, и оно обязано совпасть с
    # единицей её серии. Прежнее правило пропускало вторую величину строки
    # молча (ровно негатив 3: «АЛЕРТОВ … = ${tls_d} при ${ev1}» — единица
    # стоит у первой, вторая не покрыта ничем); новое ловит и его, и всё, что
    # ловило старое.
    # «Ни одной объёмной серии в строках метки» остаётся AMB: ноль величин
    # неотличим от «прибор про это не знает» (негатив 4).
    while IFS= read -r line; do
        lab=$(printf '%s' "$line" | sed -n 's/^[0-9]*:[[:space:]]*echo "[^:]*: \(6\.[0-9A-Za-z.]*\) .*/\1/p')
        [ -n "$lab" ] || continue
        case " $seen " in *" $lab "*) continue ;; esac
        seen="$seen $lab"
        lines=$(_w480_axis_lines "$f" | grep -E "^[0-9]+:[[:space:]]*echo \"[^:]*: ${lab//./\\.} ")
        lunits=$(printf '%s\n' "$lines" | grep -oE '_w[A-Za-z0-9_]+' | sort -u \
            | while IFS= read -r v; do awk -F'\t' -v n="$v" '$1==n{print $2}' "$units"; done | sort -u)
        n=$(printf '%s\n' "$lunits" | grep -c . || true)
        if [ "$n" -eq 0 ]; then
            printf 'AMB\t%s\t%s\t-\n' "$lab" "серии-источника объёма в строках метки нет"
            continue
        fi
        # Разбор строки СЛЕВА НАПРАВО: слова-единицы и имена переменных берутся
        # одним проходом, поэтому «ближайшее слева» есть именно ближайшее, а не
        # первое в строке. Формы слова перечислены явно: tolower() в BSD awk
        # побайтовый и кириллицу не понижает.
        printf '%s\n' "$lines" | awk -v U="$units" '
            BEGIN {
                while ((getline l < U) > 0) { split(l, a, "\t"); unit[a[1]] = a[2] }
            }
            {
                s = $0; cur = ""
                while (match(s, /алерт|Алерт|АЛЕРТ|событ|Событ|СОБЫТ|_w[A-Za-z0-9_]+/)) {
                    tok = substr(s, RSTART, RLENGTH)
                    s = substr(s, RSTART + RLENGTH)
                    if (tok ~ /^_w/) {
                        if (!(tok in unit)) continue
                        if (cur == "") { bad[unit[tok]]++; continue }
                        if (cur != unit[tok]) bad[unit[tok]]++
                    } else if (tok ~ /^(алерт|Алерт|АЛЕРТ)/) cur = "алертов"
                    else cur = "событий"
                }
            }
            END { for (u in bad) printf "%s\t%d\n", u, bad[u] }
        ' | while IFS=$'\t' read -r u cnt; do
            printf 'WRONG\t%s\t%s\t%s\n' "$lab" "$u" "$cnt"
        done
    done < <(_w480_axis_lines "$f")
    rm -f "$units"
}

_w480_audit=$(_w480_unit_audit "$PIPE")
if [ -z "$_w480_audit" ]; then
    echo "    OK  №480/верность: у каждой метки с объёмной осью {event_type=…} единица СОВПАДАЕТ с серией-источником величины (6.3L.6, 6.4.1, 6.4.6, 6.6.3 на оси tls, 6.6.9 на оси syscall)"
else
    _efail "№480/верность: единица разошлась с серией-источником — $(printf '%s' "$_w480_audit" | tr '\n' ';')"
fi
# Негативы: слово подменено на ПРОТИВОПОЛОЖНОЕ у одной метки — обязан краснеть
# (пункт 13 ревизии требует именно этой проверки), и в обе стороны карты.
sed 's/вход ноды, СОБЫТИЙ оси {event_type/вход ноды, АЛЕРТОВ оси {event_type/' "$PIPE" > "$WORK/w480-u1.sh"
if _w480_unit_audit "$WORK/w480-u1.sh" | grep -q '^WRONG.*6\.4\.1.*событий'; then
    echo "    OK  №480/верность-негатив 1: «СОБЫТИЙ»→«АЛЕРТОВ» у 6.4.1 краснеет с НАЗВАННОЙ верной единицей (событий, источник events_total)"
else
    _efail "№480/верность-негатив 1: подмена единицы у 6.4.1 не покраснела — сверка с серией фиктивна"
fi
sed 's/объём алертов оси {event_type/объём событий оси {event_type/' "$PIPE" > "$WORK/w480-u2.sh"
if _w480_unit_audit "$WORK/w480-u2.sh" | grep -q '^WRONG.*6\.4\.6.*алертов'; then
    echo "    OK  №480/верность-негатив 2: «алертов»→«событий» у 6.4.6 краснеет (источник alert_volume_by_event_type_total)"
else
    _efail "№480/верность-негатив 2: обратная подмена единицы у 6.4.6 не покраснела — карта серий односторонняя"
fi
# Две оставшиеся ветки вердикта сторожа — со сверкой НАПЕЧАТАННОГО ТЕКСТА.
cp "$PIPE" "$WORK/w480-u3.sh"
printf '%s\n' '    echo "OK: 6.9.8 ИЗМЕРЕНО: АЛЕРТОВ оси {event_type=\"tls\"} = ${_w648_tls_d} при ${_w648_ev1}"' >> "$WORK/w480-u3.sh"
# Негатив 3 ПОСЛЕ обобщения 28.09.2026 (вход — метка 6.6.8) читается точнее, чем
# до него: строка «АЛЕРТОВ оси … = ${tls_d} при ${ev1}» не «неоднозначна» — в ней
# НАЗВАНА конкретная непокрытая величина, у которой ближайшее слово слева
# («АЛЕРТОВ») не её единица (${ev1} — дельта events_total, то есть «событий»).
# Прежнее правило печатало AMB по метке и второй величины не разбирало вовсе.
if _w480_unit_audit "$WORK/w480-u3.sh" | grep -q '^WRONG.*6\.9\.8.*событий'; then
    echo "    OK  №480/верность-негатив 3: вторая величина строки, у которой ближайшая слева единица ЧУЖАЯ, названа с её верной единицей (событий)"
else
    _efail "№480/верность-негатив 3: строка, печатающая алерты и события разом, прошла сверку — вторая величина не покрыта ничем"
fi
cp "$PIPE" "$WORK/w480-u4.sh"
printf '%s\n' '    echo "OK: 6.9.9 ИЗМЕРЕНО: АЛЕРТОВ оси {event_type=\"tls\"} = ${_w999_bogus}"' >> "$WORK/w480-u4.sh"
if _w480_unit_audit "$WORK/w480-u4.sh" | grep -q '^AMB.*6\.9\.9.*серии-источника объёма в строках метки нет'; then
    echo "    OK  №480/верность-негатив 4: величина из переменной БЕЗ серии-источника не выдаётся за сверенную (ноль ≠ «прибор про это не знает»)"
else
    _efail "№480/верность-негатив 4: метка без серии-источника прошла сверку молча — сторож считает неизвестное верным"
fi

# ── РЕПЛЕЙ НА РЕАЛЬНЫХ АРХИВАХ 6.5 (критерий выхода 1 и 2 волны 6.6): 6.6.1 обязана
#    напечатать 908 и 3656; 6.6.2 на этих архивах — НЕИЗМЕРИМ «без материализации»
#    (бинарь 6.5 серий не заводил), а подложенный parse_error её краснит.
_REPO_LOGS="${W66_ARCHIVES_DIR:-$SETUP/../../server-logs}"
_rep66_done=0
for _pair in "item8:908" "item5:3656"; do
    _arc="$_REPO_LOGS/collect-6.5-${_pair%%:*}"; _want="${_pair##*:}"
    if [ ! -s "$_arc/metrics-prologue-start-6.4.txt" ] || [ ! -s "$_arc/controls/artifacts/metrics-run-end.txt" ]; then
        echo "    --  реплей на архиве collect-6.5-${_pair%%:*} пропущен: архива нет на этой машине (${_arc})"
        continue
    fi
    _rep66_done=$((_rep66_done + 1))
    _rout=$(_run66 "$_arc/controls/artifacts" "$_arc/metrics-prologue-start-6.4.txt")
    _l1=$(_check66 6.6.1 "реплей collect-6.5-${_pair%%:*}: стартовый всплеск ${_want}" "$_rout" OK)
    _text_ok "$_l1" "= ${_want} событий" "syscall/ringbuf_to_router=${_want}" "очередь protected" \
        && echo "    OK  реплей collect-6.5-${_pair%%:*}: 6.6.1 напечатала ${_want}" \
        || _efail "реплей collect-6.5-${_pair%%:*}: 6.6.1 не напечатала ${_want} — строка: $(printf '%s' "$_l1" | cut -c1-200)"
    _l2=$(_check66 6.6.2 "реплей collect-6.5-${_pair%%:*}: бинарь 6.5 без серий parse_error — НЕИЗМЕРИМ по построению" "$_rout" FAIL)
    _text_ok "$_l2" "без материализации" || _efail "реплей collect-6.5-${_pair%%:*}: 6.6.2 не назвала класс «без материализации» — строка: $(printf '%s' "$_l2" | cut -c1-200)"
    # Негативный реплей: на копии архива подкладываем parse_error>0 (и нули для
    # прочих) — метка обязана покраснеть и назвать коллектор по имени.
    _neg="$WORK/rep66neg-${_pair%%:*}"; rm -rf "$_neg"; mkdir -p "$_neg"
    cp "$_arc/controls/artifacts/"metrics-window-*.txt "$_arc/controls/artifacts/metrics-run-end.txt" "$_neg/"
    cp "$_arc/metrics-prologue-start-6.4.txt" "$_neg/pro.txt"
    for _c in syscall network tls; do echo "ebpf_guard_events_dropped_total{collector=\"$_c\",reason=\"parse_error\"} 0" >> "$_neg/pro.txt"; done
    cp "$_neg/metrics-run-end.txt" "$_neg/re.txt"
    for _c in syscall tls; do echo "ebpf_guard_events_dropped_total{collector=\"$_c\",reason=\"parse_error\"} 0" >> "$_neg/metrics-run-end.txt"; done
    echo "ebpf_guard_events_dropped_total{collector=\"network\",reason=\"parse_error\"} 12" >> "$_neg/metrics-run-end.txt"
    _nl=$(_check66 6.6.2 "негативный реплей collect-6.5-${_pair%%:*}: подложенный parse_error network=12" "$(_run66 "$_neg" "$_neg/pro.txt")" FAIL)
    if printf '%s' "$_nl" | grep -q 'ПРОВАЛЕН' && _text_ok "$_nl" "network=+12"; then
        echo "    OK  негативный реплей collect-6.5-${_pair%%:*}: 6.6.2 краснеет и называет network"
    else
        _efail "негативный реплей collect-6.5-${_pair%%:*}: подложенный parse_error не дал ПРОВАЛЕН с network — строка: $(printf '%s' "$_nl" | cut -c1-200)"
    fi
done

# ── ITEM 2. Сверка НАПЕЧАТАННОГО ТЕКСТА. Один здоровый прогон B даёт все
#    девять строк 6.4.x; отдельный снимок 6.4.B — все шесть строк 6.4B.x. У
#    КАЖДОЙ строки требуются содержательные имена и числа, а не общий класс.
echo
echo "=== ITEM 2: сверка НАПЕЧАТАННОГО ТЕКСТА (имена и числа), 6.4.0…6.4.8 + 6.4B.0…6.4B.5 + 6.5.1 ==="
TX="$WORK/artTX"; mkdir -p "$TX/baseline"
_mk_metrics "$TX/metrics-live.txt" 3 "no_symbols=1" "" "" "" 2
_mk_metrics "$TX/metrics-window-start.txt" "" "" 100 40 90
_mk_metrics "$TX/metrics-window-end.txt"   "" "" 260 55 210
# ЖИВАЯ форма контроля item 5 ПОСЛЕ №493: пять величин, включая изолированную
# дельту стора по отсечке и два среза подавления.
{ echo "events_delta=160"; echo "manifest_alerts=6"; echo "manifest_alerts_delta=2"
  echo "manifest_alerts_since=2"; echo "cut_epoch=1790509000.123456789"
  echo "dedup_delta=0"; echo "ratelimit_delta=0"; } > "$TX/tls-control-plaintext.txt"
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
    "+160" "ЗА ОБМЕН по отсечке 2" "срез дедупа 0" "срез лимитера 0"
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
_W64_TEXT_LABELS="6.4.0 6.4.1 6.4.2 6.4.3 6.4.4 6.4.5 6.4.6 6.4.7 6.4.8 6.4B.0 6.4B.1 6.4B.2 6.4B.3 6.4B.4 6.4B.5 6.5.1 6.6.1 6.6.2 6.6.3 6.6.4 6.6.5 6.6.6"
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

# №474: величину потерь даёт ТОЛЬКО метрика. Ни один живой контроль потерь не
# вправе судить величину по журналу (dropLogger недосчитывал 1 из 3656).
# №485: первая ветка прежнего сторожа была МЕРТВА. Оправдывающей подстрокой был
# '№474: ВЕЛИЧИНУ' — а это САМ КОММЕНТАРИЙ правки, он лежит в обоих живых
# файлах навсегда. Запрещённая формулировка могла вернуться в ПЕЧАТНУЮ строку
# вердикта, и сторож оставался зелёным (проверено мутацией). Предикат теперь
# отделяет печатную строку от комментария, и мутационно проверяется НА СЕБЕ
# синтетическими образцами ниже — без правки реального файла руками.
_w474_printed_hit() {
    awk '
        { l = $0; sub(/^[ \t]*/, "", l) }
        l ~ /^#/ { next }
        index(l, "ни метрика, ни журнал") == 0 && index(l, "ни журнал, ни метрика") == 0 { next }
        l ~ /(^|[^A-Za-z0-9_])(pass|die|warn|echo|printf)[ \t]/ { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$1"
}
_w474_log_predicate_hit() {
    grep -Eq '\[ "\$_w[0-9a-z]+_dr" -gt 0 \] \|\| \[ "\$_w[0-9a-z]+_jdr" -gt 0 \]' "$1"
}
# Самопроверка предиката (№485): печатная строка ловится, комментарий — нет.
printf '%s\n' '    pass "6.2.9.0 ДОСТИГНУТО: за окно ни метрика, ни журнал не показали потерь"' > "$WORK/w474-printed.sh"
printf '%s\n' '# контроль, читавший «ни метрика, ни журнал», недосчитывал на три порядка' \
               '# №474: ВЕЛИЧИНУ потерь даёт ТОЛЬКО метрика' > "$WORK/w474-comment.sh"
printf '%s\n' 'if [ "$_w63_dr" -gt 0 ] || [ "$_w63_jdr" -gt 0 ]; then' > "$WORK/w474-pred.sh"
printf '%s\n' 'if [ "$_w63_dr" -gt 0 ]; then' > "$WORK/w474-nopred.sh"
if _w474_printed_hit "$WORK/w474-printed.sh"; then
    echo "    OK  №485-самопроверка: печатная строка вердикта с «ни метрика, ни журнал» ловится"
else
    _efail "№485-самопроверка: предикат НЕ ловит запрещённую формулировку в печатной строке — сторож фиктивен"
fi
if _w474_printed_hit "$WORK/w474-comment.sh"; then
    _efail "№485-самопроверка: предикат краснеет на КОММЕНТАРИИ — ложная тревога на самой записи правки"
else
    echo "    OK  №485-самопроверка: комментарий с той же фразой предикат НЕ краснит"
fi
if _w474_log_predicate_hit "$WORK/w474-pred.sh" && ! _w474_log_predicate_hit "$WORK/w474-nopred.sh"; then
    echo "    OK  №485-самопроверка: предикат «метрика ИЛИ журнал» ловит дизъюнкцию и молчит на одной метрике"
else
    _efail "№485-самопроверка: предикат дизъюнкции не различает «dr||jdr» и «dr» — вторая ветка сторожа фиктивна"
fi
# Слой (а): живой путь 6.4-пайплайна чист по ОБЕИМ приметам.
for _f474 in wave6.3-controls.sh wave6.2.6-controls.sh; do
    if _w474_printed_hit "$SETUP/$_f474"; then
        _efail "№474: $_f474 печатает вердикт «ни метрика, ни журнал» — журнал не счётчик величины"
    elif _w474_log_predicate_hit "$SETUP/$_f474"; then
        _efail "№474: $_f474 снова берёт величину потерь как «метрика ИЛИ журнал»"
    else
        echo "    OK  №474: $_f474 — величину потерь даёт метрика, журнал только сэмпл причины"
    fi
done
# Слой (б), №485: состав файлов-НОСИТЕЛЕЙ исторической формулировки заморожен.
# Контроли 6.2.1…6.2.5 лежат вне живого пути и НЕ правятся: их печатный текст
# держат реестр №461 и реплеи старых архивов. Но новый носитель — краснеет.
_w474_hist_expected="wave6.2.1-controls.sh wave6.2.2-controls.sh wave6.2.3-controls.sh wave6.2.4-controls.sh wave6.2.5-controls.sh"
_w474_carriers=""
for _f474b in "$SETUP"/wave*-controls.sh "$SETUP"/run-6.4-pipeline.sh "$SETUP"/wave6.6-kmod-control.sh "$SETUP"/wave6.5-item5-http-control.sh; do
    [ -f "$_f474b" ] || continue
    if _w474_printed_hit "$_f474b" || _w474_log_predicate_hit "$_f474b"; then
        _w474_carriers="$_w474_carriers $(basename "$_f474b")"
    fi
done
_w474_carriers="$(printf '%s\n' $_w474_carriers | sort | tr '\n' ' ' | sed 's/ *$//')"
_w474_hist_norm="$(printf '%s\n' $_w474_hist_expected | sort | tr '\n' ' ' | sed 's/ *$//')"
if [ "$_w474_carriers" = "$_w474_hist_norm" ]; then
    echo "    OK  №485: носителей формулировки «метрика ИЛИ журнал» ровно пять исторических (6.2.1…6.2.5), новых не появилось"
else
    _efail "№485: состав носителей формулировки «метрика ИЛИ журнал» изменился — есть [$_w474_carriers], историческая пятёрка [$_w474_hist_norm]"
fi

echo
# ── 6.7.1 (куплено правил N, предъявлено детектом M — задача П волны 7).
#    Десять веток. Предмет, который проверяется ОТДЕЛЬНО от классов: два НУЛЯ НЕ
#    СЛИВАЮТСЯ — правило, которому контроль не заведён (NOCTL), и правило, которое
#    промолчало под доказавшим себя контролем (SILENT), называются в разных полях
#    одной строки и дают разные вердиктные слова. Манифест — КОПИЯ БОЕВОГО: состав
#    «куплено» — строки RULE, а не список, вписанный сюда рукой.
_A671="$WORK/art671"
_B671=$(awk '$1 ~ /^P[0-9]+$/ && $2 == "RULE" && !($3 in s) { s[$3] = 1; print $3 }' "$_MAN669")
# Состав «куплено» в боевом манифесте — РОВНО десять правил волны 7 (задача П): строки UNBOUGHT
# и комментарий шапки с тем же вторым словом в него не входят (первая версия эмиттера их
# засчитала — семнадцать вместо десяти — и поймал это именно этот сторож).
[ "$(printf '%s\n' "$_B671" | grep -c . || true)" = 10 ] || _efail "6.7.1: купленных правил в боевом манифесте не десять"
_B671_UNB=$(awk '$1 == "UNBOUGHT" && $2 == "RULE" { print $3 }' "$_MAN669" | head -1)
[ -n "$_B671_UNB" ] || _efail "6.7.1: в боевом манифесте нет ни одной строки UNBOUGHT — фикстура не видит вид строки, который эмиттер обязан не засчитать"
_B671_N=$(printf '%s\n' "$_B671" | grep -c . || true)
[ "${_B671_N:-0}" -ge 3 ] || _efail "6.7.1: в боевом манифесте купленных правил ${_B671_N:-0} — фикстурам нечего разбирать"
_B671_1=$(printf '%s\n' "$_B671" | sed -n 1p); _B671_2=$(printf '%s\n' "$_B671" | sed -n 2p); _B671_3=$(printf '%s\n' "$_B671" | sed -n 3p)
echo "    (6.7.1: манифест боевой — купленных правил ${_B671_N}, образцы: ${_B671_1} ${_B671_2} ${_B671_3})"
# _init671 <override: «правило=КЛАСС …» | -> [пропуск: правила БЕЗ строки контроля]
_init671() {
    local ov="$1" skip="${2:-}" r c pair
    rm -rf "$_A671"; mkdir -p "$_A671"
    cp "$_MAN669" "$_A671/wave7-nr-portions.txt"
    : > "$_A671/bought-rules-controls.txt"
    for r in $_B671; do
        case " $skip " in *" $r "*) continue ;; esac
        c=SHOWN
        for pair in $ov; do [ "${pair%%=*}" = "$r" ] && c="${pair##*=}"; done
        echo "rule=$r class=$c payload_nr=1 pids=100 comm=python3 shown=1 swallowed=0 events_nr_delta=5 rc=0" >> "$_A671/bought-rules-controls.txt"
    done
}
_run671() { W7_BOUGHT_CONTROLS="${1:-on}" _run66 "$_A671" ""; }

_init671 ""
rm -f "$_A671/wave7-nr-portions.txt"
_t671_a=$(_check66 6.7.1 "манифеста порций нет — НЕИЗМЕРИМ" "$(_run671)" FAIL)
_need_text "6.7.1 нет манифеста" "$_t671_a" "манифеста порций wave7-nr-portions.txt нет" "называть его руками запрещено"

_init671 ""; rm -f "$_A671/bought-rules-controls.txt"
_t671_b=$(_check66 6.7.1 "тумблера нет и файла нет — НЕ ЗАПРОШЕН" "$(_run671 off)" NOTREQ)
_need_text "6.7.1 не запрошен" "$_t671_b" "W7_BOUGHT_CONTROLS не включён" "предъявленность детектом не снималась"
_forbid_text "6.7.1 не запрошен не печатает числа" "$_t671_b" "предъявлено детектом"

_init671 ""; rm -f "$_A671/bought-rules-controls.txt"
_t671_c=$(_check66 6.7.1 "тумблер включён, файла нет — НЕИЗМЕРИМ" "$(_run671 on)" FAIL)
_need_text "6.7.1 файла нет" "$_t671_c" "контроль не отработал" "ноль по правилам читать нечем"

_init671 ""; echo "class=observer_tree_armed" > "$_A671/bought-rules-controls.txt"
_t671_d=$(_check66 6.7.1 "глобальный класс — НЕИЗМЕРИМ с названным классом" "$(_run671)" FAIL)
_need_text "6.7.1 глобальный класс" "$_t671_d" "class=observer_tree_armed" "нулём он не становится"
_forbid_text "6.7.1 глобальный класс не печатает предъявленность" "$_t671_d" "предъявлено детектом"

_init671 ""
_t671_e=$(_check66 6.7.1 "все купленные предъявлены — ДОСТИГНУТО" "$(_run671)" OK)
_need_text "6.7.1 все предъявлены" "$_t671_e" "куплено правил ${_B671_N}, предъявлено детектом ${_B671_N}" "алерт найден по pid нагрузки"
_forbid_text "6.7.1 все предъявлены не называет недостающих" "$_t671_e" "SILENT" "NOCTL"

_init671 "${_B671_2}=SILENT"
_t671_f=$(_check66 6.7.1 "одно правило SILENT — ПРОВАЛЕН" "$(_run671)" FAIL)
_need_text "6.7.1 SILENT" "$_t671_f" "ПРОВАЛЕН" "куплено правил ${_B671_N}, предъявлено детектом $((_B671_N - 1))" \
    "(SILENT) 1: ${_B671_2}" "(NOCTL) 0: -" "продуктовый"
_forbid_text "6.7.1 SILENT не сказан словом неизмеримо" "$_t671_f" "НЕИЗМЕРИМ"

_init671 "" "${_B671_3}"
_t671_g=$(_check66 6.7.1 "у правила нет контроля — НЕИЗМЕРИМ, НЕ провал" "$(_run671)" FAIL)
_need_text "6.7.1 NOCTL" "$_t671_g" "НЕИЗМЕРИМ" "предъявлено детектом $((_B671_N - 1))" "(NOCTL) 1: ${_B671_3}" "(SILENT) 0: -"
_forbid_text "6.7.1 NOCTL не объявлен провалом правила" "$_t671_g" "ПРОВАЛЕН" "продуктовый"

_init671 "${_B671_1}=SILENT" "${_B671_3}"
_t671_h=$(_check66 6.7.1 "SILENT и NOCTL вместе — ПРОВАЛЕН, оба поимённо в РАЗНЫХ полях" "$(_run671)" FAIL)
_need_text "6.7.1 SILENT+NOCTL" "$_t671_h" "ПРОВАЛЕН" "(SILENT) 1: ${_B671_1}" "(NOCTL) 1: ${_B671_3}"

_init671 "${_B671_1}=NO_EVENT ${_B671_2}=INSTRUMENT ${_B671_3}=NOT_OPEN"
_t671_i=$(_check66 6.7.1 "приборные классы без SILENT — НЕИЗМЕРИМ" "$(_run671)" FAIL)
_need_text "6.7.1 приборные" "$_t671_i" "НЕИЗМЕРИМ" "(NO_EVENT) 1: ${_B671_1}" "(INSTRUMENT) 1: ${_B671_2}" "(NOT_OPEN) 1: ${_B671_3}" "(SILENT) 0: -"
_forbid_text "6.7.1 приборные не названы провалом" "$_t671_i" "ПРОВАЛЕН"

# Правило из UNBOUGHT не входит в «куплено», даже если контроль на него заведён и показал SHOWN.
_init671 ""
echo "rule=${_B671_UNB} class=SHOWN payload_nr=1 pids=1 comm=python3 shown=1 swallowed=0 events_nr_delta=1 rc=0" >> "$_A671/bought-rules-controls.txt"
_t671_k=$(_check66 6.7.1 "правило из UNBOUGHT не раздувает «куплено» — ДОСТИГНУТО на десяти" "$(_run671)" OK)
_need_text "6.7.1 UNBOUGHT не куплено" "$_t671_k" "куплено правил ${_B671_N}, предъявлено детектом ${_B671_N}"

_init671 "${_B671_2}=SWALLOWED"
_t671_j=$(_check66 6.7.1 "съедено лимитером — НЕИЗМЕРИМ" "$(_run671)" FAIL)
_need_text "6.7.1 SWALLOWED" "$_t671_j" "(SWALLOWED) 1: ${_B671_2}" "лимитером или дедупом"

# ── СТОРОЖ ПОРЯДКА: вызов вспомогательной функции РАНЬШЕ её определения.
#    bash в таком случае печатает «command not found» и идёт дальше, поэтому
#    проверка молча не исполняется, а сторож заканчивает словами «расхождений 0»
#    (так девять сверок текста 6.4.3 были мертвы). Инвариант статический: для
#    каждой функции файла первая строка ВЫЗОВА обязана быть ниже строки
#    ОПРЕДЕЛЕНИЯ.
echo
echo "=== СТОРОЖ ПОРЯДКА: ни один вызов не стоит выше своего определения ==="
_order_bad=$(awk '
    /^[[:space:]]*_[A-Za-z0-9_]+\(\)[[:space:]]*\{/ {
        name = $0; sub(/^[[:space:]]*/, "", name); sub(/\(\).*/, "", name)
        if (!(name in def)) def[name] = NR
        next
    }
    {
        line = $0
        sub(/^[[:space:]]*/, "", line)
        if (line ~ /^#/) next
        # первое слово строки и вызовы внутри $( … )
        while (match(line, /(^|\$\()[[:space:]]*_[A-Za-z0-9_]+[[:space:]]/)) {
            tok = substr(line, RSTART, RLENGTH)
            gsub(/[[:space:]]|\$\(/, "", tok)
            if (!(tok in first) ) first[tok] = NR
            line = substr(line, RSTART + RLENGTH)
        }
    }
    END {
        for (n in first)
            if ((n in def) && first[n] < def[n])
                printf "%s: вызов на строке %d, определение на строке %d\n", n, first[n], def[n]
    }' "$0")
if [ -n "$_order_bad" ]; then
    _efail "порядок: вызов раньше определения — проверка НЕ ИСПОЛНЯЕТСЯ, bash печатает «command not found» и идёт дальше:"
    printf '%s\n' "$_order_bad" | sed 's/^/        /'
else
    echo "    OK  порядок: все вызовы ниже своих определений"
fi

if [ "$FAILS" -gt 0 ]; then
    echo "СТОРОЖ ЭМИТТЕРОВ ПРОВАЛЕН: расхождений $FAILS"
    exit 1
fi
echo "СТОРОЖ ЭМИТТЕРОВ ПРОЙДЕН: 12 фикстур 6.6.1 (включая 4 на ИСТОЧНИК соответствия очередь↔коллектор, пункт 12: метрика, зашитое зеркало, расхождение зеркала с рантаймом, смешанный источник) + 2 сверки зеркала с defaultEventPriority в Go (с негативом) + 10 фикстур 6.6.2 (включая всплеск разбора ДО первого снимка, №473-класс) + 13 проверок 6.6.3 + 6 проверок НАЗВАННОГО допуска гонки двух счётчиков (пункт 16: ±1 по абсолюту в обе стороны, ровное схождение отличимо от взятого допуска, +2 выше допуска снимка, ±2 по дельте окна, +3 выше него) + 2 сверки числа допуска с однопоточностью processEvent в Go (с негативом) (разрез, инвариант суммы, бинарь без серии, роль A, и роль B с НУЛЕВЫМ разрезом в трёх видах: мёртвый коллектор при привязках 0 — НЕИЗМЕРИМ, тишина TLS при привязках 4 — ИЗМЕРЕНО, отсутствие серий здоровья названо словами) + сторож единицы №480 с негативом (включая подложенный parse_error и бинарь без материализации) + 5 проверок ВЕРНОСТИ единицы №480 (единица сверена с серией-источником через _assign_map и арифметическую протяжку; негативы: подмена слова в обе стороны у 6.4.1 и 6.4.6, вторая величина строки с ЧУЖОЙ ближайшей единицей — обобщение 28.09.2026, сверка стала повеличинной вместо пометочной, величина из переменной без серии-источника) + сверка списка коллекторов с Go + реплей 6.6.1/6.6.2 на реальных архивах 6.5 (908, 3656) с негативным реплеем + 13 фикстур 6.6.6 (зонд №488: класс зонда, один снимок вместо двух, нет копии ожиданий, подменённая нагрузка, нет серии семейств, байты не доехали, подпись сдвига раскладки, выросшая отбраковка, молчащий журнал, чужой pid, чужой отпечаток, ДОСТИГНУТО на серии, рождённой первым инкрементом) + 22 фикстуры 6.4.x (включая 5 на ОСЬ ПОДАВЛЕНИЯ 6.4.3, №493: архив без оси, срез дедупа, срез лимитера, продуктовый провал при нулевых слоях, вердикт по изолированной отсечке при непустом сторе, и 4 на ОСЬ ПРОДЮСЕРА, №496: архив без ключей оси — НЕИЗМЕРИМ, ось названа СЛОВОМ на бинаре до №496 — НЕИЗМЕРИМ, события с пустой нагрузкой — провал продюсера, событий семейства payload не было вовсе — НЕИЗМЕРИМ; 8 проверок предиката повтора обмена _w64_captured_delta (№504: повтор, прекращение по write и по read, дельта а не абсолют, рост отказов не считается захватом, и ТРИ негатива на пустую ось — ПУСТО, а не ноль) + 2 на РАЗРЕЗ ПРИЧИН ПУСТОТЫ, №504: вся пустота — num<=0 при нуле отказов чтения — НЕИЗМЕРИМ с запретом слова «дефект ПРОДЮСЕРА», ненулевые отказы чтения — продуктовый провал) + 7 фикстур 6.6.7 (№490, цена http_plaintext на запрос: не запрошен, таймер не поставлен, держатель не дожил, ноль ответов 200, снимки границ не сняты, ПОЛ при пустом входе — роль A не печатает число-цену, и назначенная цена роли B) + 10 фикстур 6.6.8 (цена tls_fingerprint за окно: нет снимков границ, нет манифеста, нет серии семейства, убыль счётчика через рестарт, роль A с загрязнённым входом, роль A чистая — опорная половина БЕЗ числа-цены, роль B с нулём БЕЗ свидетеля живости, зонд поставлен и дал ноль — свидетелем не считается, роль B с нулём при живом зонде — ИЗМЕРЕНО 0/0, роль B с назначенной ценой двумя числами, где ja3-правило зачтено ПО МАНИФЕСТУ и через переименование Rego, а правило plaintext на той же оси НЕ зачтено) + 17 фикстур 6.6.9 (цена порции оси nr, item б3 волны 7: порция не объявлена — НЕ ЗАПРОШЕН, нет манифеста порций, порции нет в манифесте, нет снимков окна, нет серии собственной оси — бинарь до item б3, рост бакета nr=\"unset\" — ось не объявлена рантаймом, нет реестра немоты, убыль счётчика через рестарт, роль A чистая — опорная половина БЕЗ числа-цены, роль A с правилом порции вне реестра — ПРОВАЛ, порция открыта наполовину — НЕИЗМЕРИМ, роль B с правилом, оставшимся немым — ПРОВАЛ, и роль B с ценой двумя числами, где алерт переименованного Rego правила порции зачтён, а чужое правило той же оси нет; и ЧЕТЫРЕ на ЧАСТИЧНУЮ порцию, №514: открыто всё неотвергнутое — ИЗМЕРЕНО с названными отвергнутыми номерами и осознанно немыми правилами, открыт не весь неотвергнутый состав — НЕИЗМЕРИМ, прогон открыл ОТВЕРГНУТЫЙ номер — ПРОВАЛ, осознанно немое правило оказалось достижимым — ПРОВАЛ) + 9 проверок ПОЛНОТЫ РЕЕСТРА НЕМОТЫ (волна 7 item б1: полный реестр, потерянное семейство названо, пустой журнал не краснит, пустой реестр теряет все 4, и четыре сверки шаблона собирателя с именами семейств) + 4 фикстуры классов 6.4.4 (№455) + 13 фикстур 6.4.B (включая именованный состав оси, №458) + ${_g461_n} сверок НАПЕЧАТАННОГО ТЕКСТА (№461, включая 6.5.1) с реестром реплея + 9 негативных образцов №460 (одно- и многострочный дубль, повторное вычисление, гибрид read+awk с пробелом и без, разное написание предиката, переставленные и одинаковые ветки awk, раннее закрытие тела в кавычке уносило хвост с печатной величиной) + 1 негатив полноты разбора №460 (незакрытое тело: печатная серийная величина выпала из подписи) + 1 негатив КРАСНОЙ ВЕТКИ полноты разбора №460 (_check460_complete на незакрытом теле: ненулевой код и красная формулировка, зелёная ветка запрещена — чувствителен к удалению return 1) + 1 позитив #-комментариев (тело с НЕПАРНОЙ ( в комментарии закрывается НАСТОЯЩЕЙ скобкой) + 9 прямых сверок #-комментариев в _paren_delta (скобка в комментарии тело не закрывает и не открывает; # внутри слова/кавычек — не комментарий; __#__ после ), >, < — тоже комментарий) + 1 позитивная сверка №460 на label-селектор (агрегат ≠ именованная выборка, ложного красного нет) + 2 самопроверки полноты разбора (пункт 3: живой блок разобран целиком) + 2 сверки полноты подписи (ВСЕ печатные серийные величины в разборе, а не зашитый список) + ${_rep_n} негативных реплеев текста по РЕАЛЬНЫМ ожиданиям (включая №455 и №457) + 2 негативные самопроверки механизма сверки (пустой набор, пропуск подстроки) + 2 негатива №461 (пропущенная метка, пустой реестр) + два сторожа №373 + 6 проверок достижимости + 5 проверок №469 (тождество бинаря вне \$ART, копия на сборке, имя от роли, негатив на исторической строке, реестр архива) + 2 сторожа №474 живого пути и 4 проверки №485 (три самопроверки предиката: печатная строка ловится, комментарий не краснит, дизъюнкция отличима от одной метрики; плюс замороженный состав пяти исторических носителей), расхождений 0"
