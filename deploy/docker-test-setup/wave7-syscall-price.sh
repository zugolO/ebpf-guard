#!/bin/bash
# wave7-syscall-price.sh — ЦЕНА 19 SYSCALL'ОВ ОСИ `nr` ДО ИХ ОТКРЫТИЯ
# (волна 7, item б2, постановка 28.09.2026).
#
# ЗАЧЕМ. Двенадцать правил оси `nr` немы потому, что их номера отсутствуют в
# `bpf.kernel_filter.monitored_syscalls`, и это единственная из трёх осей
# немоты, которая ОТКРЫВАЕТСЯ ПРАВКОЙ КОНФИГА (две другие — `file.op` и
# `proto` — продюсера не имеют вовсе и переразмечены в
# `document-as-structurally-inert`, item б1). Открывать их разом нельзя: среди
# 19 требуемых номеров есть ГОРЯЧИЕ — nanosleep(35), mprotect(10), prctl(157),
# clone(56), fork(57). Ставка на «наверное, nanosleep дорогой» — это цена,
# назначенная рассуждением; здесь она назначается ЗАМЕРОМ
# ([[gate-unit-replaced-by-price-per-node-event]] в применении к открытию оси).
#
# ПОЧЕМУ bpftrace, А НЕ ПРАВКА ПРОДУКТА. Частоту каждого номера на этой самой
# ноде можно снять НЕ ТРОГАЯ продукт: ни пересборки, ни рестарта, ни обнуления
# базы дрейфа ([[ab-toggle-measures-the-restart]]). bpftrace — независимый
# свидетель того же хука, и он уже закрывал вопросы, которые чтение исходника
# не закрывало ([[bpftrace-is-the-second-witness]]).
#
# ЧТО ЭТО ЗА ВЕЛИЧИНА И ЧЕМ ОНА НЕ ЯВЛЯЕТСЯ. Замер даёт число ВЫЗОВОВ syscall'а
# на ноде за окно — то есть ПОТОЛОК числа событий, которые ядерный фильтр стал
# бы пропускать наверх после открытия номера. Это НЕ число алертов: событие
# дальше проходит правила, дедуп и лимитер, каждый из которых режет
# ([[dedup-is-third-suppression-layer]]). Поэтому потолок — вход решения, а
# вердикт по каждой порции всё равно даёт ПАРА A/B на одном бинаре.
#
# ВКЛАД ИЗМЕРИТЕЛЯ НАЗЫВАЕТСЯ, А НЕ ВЫЧИТАЕТСЯ МОЛЧА. Разрез по comm печатается
# рядом с каждым номером: ядерный фильтр продукта исключает дерево агента
# ([[observer-exclusion-blinds-controls]]), а bpftrace — нет, поэтому вызовы
# самого агента, bpftrace и ssh-сессии видны здесь и НЕ видны продукту. Читать
# потолок без этого разреза значит записать измеритель в цену
# ([[gate-value-can-be-entirely-measurer]]).
#
# Вход:  W7_PRICE_SECS (умолчание 60), W7_PRICE_ART (умолчание
#        /var/lib/w7-syscall-price), W7_PRICE_CSV (умолчание — csv аудита в дереве).
# Выход: $W7_PRICE_ART/syscall-price.txt — по строке на номер:
#        nr=<n> name=<имя> calls=<N> per_min=<N/мин> rules=<id,…> top_comms=<comm:N,…>
#        плюс total_sys_enter=<N> и window_s=<N>.

set -u
export PATH=$PATH:/usr/local/bin:/usr/local/go/bin

W7_PRICE_SECS="${W7_PRICE_SECS:-60}"
W7_PRICE_ART="${W7_PRICE_ART:-/var/lib/w7-syscall-price}"
_SELF_DIR=$(cd "$(dirname "$0")" && pwd)
W7_PRICE_CSV="${W7_PRICE_CSV:-$_SELF_DIR/../../docs/rules-audit-2026-09-27.csv}"
_OUT="$W7_PRICE_ART/syscall-price.txt"

mkdir -p "$W7_PRICE_ART" 2>/dev/null
_class() { printf 'class=%s\n' "$1" > "$_OUT"; echo "  ЦЕНА ОСИ nr: КЛАСС НАЗВАН — $1"; exit 0; }

# Имена номеров — для читаемости отчёта, величину они не несут. x86_64.
_name_of() {
    case "$1" in
        10) echo mprotect ;; 35) echo nanosleep ;; 37) echo alarm ;; 41) echo socket ;;
        56) echo clone ;; 57) echo fork ;; 62) echo kill ;; 83) echo mkdir ;;
        88) echo symlink ;; 132) echo utime ;; 135) echo personality ;; 157) echo prctl ;;
        162) echo sync ;; 206) echo io_setup ;; 235) echo utimes ;; 238) echo set_mempolicy ;;
        258) echo mkdirat ;; 280) echo utimensat ;; 317) echo seccomp ;;
        *) echo "nr$1" ;;
    esac
}

# _w7p_calls <файл вывода bpftrace> <nr> — число вызовов номера за окно, СУММОЙ
# по разрезу `comm`. Отдельной карты по id больше нет: bpftrace 0.14 на этом
# ядре не грузит ни программу с предикатом из 19 сравнений («Error loading
# program»), ни `BEGIN` для карты-фильтра («Could not resolve symbol:
# BEGIN_trigger»), поэтому берётся ОДИН зонд без предиката, а разбор считает
# сам. Сумма по comm тождественна счётчику по id: каждый посчитанный вызов
# попадает ровно в одну ячейку (id, comm).
_w7p_calls() {
    awk -v nr="$2" '
        {
            if (match($0, /^@c\[[0-9]+,[ ]?/) != 1) next
            id = $0; sub(/^@c\[/, "", id); sub(/,.*$/, "", id)
            if (id + 0 != nr + 0) next
            if (match($0, /\]:[ \t]+[0-9]+[ \t]*$/) == 0) next
            cnt = substr($0, RSTART + 2); gsub(/[^0-9]/, "", cnt)
            s += cnt
        }
        END { printf "%d", s + 0 }
    ' "$1"
}
# _w7p_top_comms <файл вывода bpftrace> <nr> — три самых частых comm по номеру,
# «comm:N,comm:N,comm:N». Разбирается ВСЯ строка, а не $1: многоключевую карту
# bpftrace печатает как «@c[10, bash]: 5» — С ПРОБЕЛОМ после запятой, — и
# разбиение по полям рвёт ключ на «@c[10,» и «bash]:». Ровно тот класс, что
# [[attr-value-containing-equals-breaks-F-split]], только разделитель другой.
_w7p_top_comms() {
    awk -v nr="$2" '
        {
            if (match($0, /^@c\[[0-9]+,[ ]?/) != 1) next
            key = substr($0, RLENGTH + 1)
            id  = $0; sub(/^@c\[/, "", id); sub(/,.*$/, "", id)
            if (id + 0 != nr + 0) next
            if (match(key, /\]:[ \t]+[0-9]+[ \t]*$/) == 0) next
            cnt = substr(key, RSTART + 2); gsub(/[^0-9]/, "", cnt)
            comm = substr(key, 1, RSTART - 1)
            printf "%s:%s\n", comm, cnt
        }
    ' "$1" | sort -t: -k2,2nr | head -3 | tr '\n' ',' | sed 's/,$//'
}
# _w7p_report <файл вывода bpftrace> <total> — таблица величин на stdout.
# Отдельной функцией затем, чтобы разбор проверялся ФИКСТУРОЙ на mac, без
# стенда и без bpftrace ([[gate-offline-replay-on-mac]]).
_w7p_report() {
    local bt="$1" total="$2" nr rules calls permin tops
    echo "window_s=$W7_PRICE_SECS"
    echo "total_sys_enter=$total"
    echo "csv=$W7_PRICE_CSV"
    printf '%s\n' "$_NRS" | while read -r nr rules; do
        calls=$(_w7p_calls "$bt" "$nr")
        permin=$(awk -v c="$calls" -v s="$W7_PRICE_SECS" 'BEGIN{printf "%.1f", (s>0)? c*60.0/s : 0}')
        tops=$(_w7p_top_comms "$bt" "$nr")
        echo "nr=$nr name=$(_name_of "$nr") calls=$calls per_min=$permin rules=$rules top_comms=${tops:--}"
    done
}

# ── САМОПРОВЕРКА РАЗБОРА (--self-test): без стенда, без bpftrace, на mac.
#    Проверяется ровно то, что ломалось: пробел после запятой в ключе
#    многоключевой карты, сортировка comm по величине, номер без вызовов
#    (ноль, а не пропуск строки), и что нули НЕ печатаются прочерком.
if [ "${1:-}" = "--self-test" ]; then
    _st_fail=0
    _st_dir=$(mktemp -d)
    W7_PRICE_SECS=30
    W7_PRICE_CSV="самопроверка"
    _NRS="10 sigma_mprotect_exec_heap
35 web_blind_sqli_heuristic
317 sigma_seccomp_filter_install"
    cat > "$_st_dir/bt.txt" <<'BT'
@all: 900

@c[10, bash]: 20
@c[10, ebpf-guard]: 90
@c[10, sshd]: 10
@c[10, cron]: 3
@c[35, bpftrace]: 4
@c[101, bash]: 777
BT
    _st_out=$(_w7p_report "$_st_dir/bt.txt" 900)
    _st_chk() { # <имя> <ожидаемая подстрока>
        if printf '%s\n' "$_st_out" | grep -qF -- "$2"; then
            echo "    OK  $1"
        else
            echo "    ПРОВАЛ: $1 — в отчёте нет «$2»"; _st_fail=1
        fi
    }
    # Ключ с ПРОБЕЛОМ разобран, comm отсортированы по величине, срез — три.
    _st_chk "разрез по comm с пробелом в ключе" "top_comms=ebpf-guard:90,bash:20,sshd:10"
    # Число вызовов — СУММА по разрезу, а не одна ячейка: 20+90+10+3 = 123.
    # Срез top_comms при этом остаётся ТРЁХ строк, и сумма ему не равна —
    # частая ловушка «взять первое число из разреза за величину».
    _st_chk "вызовы суммируются по всем comm, а не берутся из среза" "calls=123"
    # per_min считается от окна, а не от минуты: 123 вызова за 30с = 246/мин.
    _st_chk "per_min от длины окна" "nr=10 name=mprotect calls=123 per_min=246.0"
    # Номер, которого НЕТ в списке аудита, в отчёт не попадает, даже если он
    # самый частый в замере: мерится названный набор, а не что попало.
    if printf '%s\n' "$_st_out" | grep -q "nr=101"; then
        echo "    ПРОВАЛ: номер вне набора аудита попал в отчёт"; _st_fail=1
    else
        echo "    OK  номер вне набора аудита (101, 777 вызовов) в отчёт НЕ попал"
    fi
    _st_chk "малая частота не теряется" "nr=35 name=nanosleep calls=4 per_min=8.0"
    # Номер, которого в замере НЕ БЫЛО: строка обязана быть, с нулём и прочерком
    # — «нет строки» читалось бы как «номер не мерили».
    _st_chk "номер без вызовов даёт НОЛЬ, а не отсутствие строки" "nr=317 name=seccomp calls=0 per_min=0.0"
    _st_chk "у номера без вызовов разрез назван прочерком" "top_comms=-"
    _st_chk "вклад измерителя ВИДЕН в разрезе" "bpftrace:4"
    _st_chk "окно и знаменатель в отчёте" "total_sys_enter=900"
    rm -rf "$_st_dir"
    if [ "$_st_fail" = "0" ]; then
        echo "САМОПРОВЕРКА РАЗБОРА ПРОЙДЕНА: 9 проверок, расхождений 0"
        exit 0
    fi
    echo "САМОПРОВЕРКА РАЗБОРА ПРОВАЛЕНА"
    exit 1
fi


command -v bpftrace >/dev/null 2>&1 || _class "bpftrace_не_установлен_замер_не_ставится"
[ "$(id -u)" = "0" ] || _class "не_root_bpftrace_не_поднимется"

# СОСТАВ НОМЕРОВ БЕРЁТСЯ ИЗ АУДИТА, А НЕ ВЫПИСЫВАЕТСЯ РУКОЙ. Список, живущий в
# скрипте копией, разъезжается с csv в первую же правку правил, и замер тогда
# называет цену НЕ ТОГО набора ([[verdict-input-must-be-computed-by-emitter]]).
[ -s "$W7_PRICE_CSV" ] || _class "csv_аудита_не_найден_${W7_PRICE_CSV##*/}_состав_номеров_брать_неоткуда"
_NRS=$(python3 - "$W7_PRICE_CSV" <<'PY'
import csv, sys, collections
need = collections.defaultdict(set)
for r in csv.DictReader(open(sys.argv[1])):
    if r["dead_axis"] != "nr":
        continue
    for tok in r["dead_tokens"].split(","):
        tok = tok.strip()
        if tok.isdigit():
            need[int(tok)].add(r["rule_id"])
for nr in sorted(need):
    print("%d %s" % (nr, ",".join(sorted(need[nr]))))
PY
)
[ -n "$_NRS" ] || _class "в_csv_нет_ни_одной_строки_dead_axis_nr_нечего_мерить"
_N=$(printf '%s\n' "$_NRS" | grep -c .)
echo "--- ЦЕНА ОСИ nr (item б2): ${_N} номеров из $(basename "$W7_PRICE_CSV"), окно ${W7_PRICE_SECS}с, bpftrace ---"

# ОДИН ЗОНД, БЕЗ ПРЕДИКАТА И БЕЗ `BEGIN` — и это не упрощение, а вынужденная
# форма, найденная на стенде (ebaka2, bpftrace v0.14.0). Две очевидные формы
# отказывают ЖИВЬЁ: программа с предикатом из 19 сравнений `args->id==N||…` не
# грузится вовсе («ERROR: Error loading program: tracepoint:raw_syscalls:
# sys_enter»), а карта-фильтр, заполняемая в `BEGIN`, падает на самом
# `BEGIN` («Could not resolve symbol: /proc/self/exe:BEGIN_trigger»). Обе
# проверены по отдельности: минимальный зонд и ДВА зонда на одном tracepoint
# работают, значит дело в предикате и в BEGIN, а не в tracepoint'е.
# Отбор номеров перенесён в РАЗБОР: карта (id, comm) собирается по всем
# syscall'ам, а нужные 19 берутся из неё суммой. Цена этой формы названа:
# карта шире (на этой ноде 166 ячеек за 5 с), зато программа грузится.
_BT="$W7_PRICE_ART/bpftrace-raw.txt"
bpftrace -e "
tracepoint:raw_syscalls:sys_enter { @all = count(); @c[args->id, comm] = count(); }
interval:s:${W7_PRICE_SECS} { exit(); }
" > "$_BT" 2>"$W7_PRICE_ART/bpftrace-err.txt"
_rc=$?
[ "$_rc" = "0" ] || _class "bpftrace_вернул_rc=${_rc}_см_bpftrace-err.txt"
[ -s "$_BT" ] || _class "bpftrace_ничего_не_напечатал_замер_пуст"

_total=$(awk '/^@all:/{print $2}' "$_BT")
[ -n "${_total:-}" ] || _class "в_выводе_bpftrace_нет_@all_окно_не_состоялось"
_w7p_report "$_BT" "$_total" > "$_OUT"

echo "  всего sys_enter за окно: $_total"
printf '  %-5s %-16s %10s %10s  %s\n' nr name calls per_min top_comms
grep '^nr=' "$_OUT" | while IFS= read -r l; do
    printf '  %-5s %-16s %10s %10s  %s\n' \
        "$(printf '%s' "$l" | sed -n 's/.*nr=\([0-9]*\).*/\1/p')" \
        "$(printf '%s' "$l" | sed -n 's/.*name=\([^ ]*\).*/\1/p')" \
        "$(printf '%s' "$l" | sed -n 's/.*calls=\([0-9]*\).*/\1/p')" \
        "$(printf '%s' "$l" | sed -n 's/.*per_min=\([0-9.]*\).*/\1/p')" \
        "$(printf '%s' "$l" | sed -n 's/.*top_comms=\(.*\)$/\1/p')"
done
echo "  величины: $_OUT"
