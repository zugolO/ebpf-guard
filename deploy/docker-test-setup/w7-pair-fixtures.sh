#!/usr/bin/env bash
# w7-pair-fixtures.sh — фикстуры аппарата пары A/B порции оси `nr` (долг Д волны 7):
# патчер роли B, драйвер, ожидатель. Исполняется на mac и на стенде, стенда не требует.
#
# Данные фикстуры СОДЕРЖАТ все виды строк манифеста, включая REJECTED, и СПИСОК
# path_denylist ПОСЛЕ monitored_syscalls (правило 1 постановки: зелёный сторож на
# данных без нужной строки значит лишь «случай не встречался», №514).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d /tmp/w7pair.XXXXXX); trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { echo "  OK    $1"; }
bad() { echo "  FAIL  $1"; FAIL=1; }
chk() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# ── синтетический репозиторий: базовый список 5, порция 9 = 3 номера, один отвергнут
R="$T/repo"; S="$R/deploy/docker-test-setup"
mkdir -p "$R/internal/bpf" "$S/attacks"
cat > "$R/internal/bpf/sampling.go" <<'GO'
package bpf

func DefaultMonitoredSyscalls() []int {
	return []int{
		59,  // execve
		322, // execveat
		101, // ptrace
		126, // capset
		308, // setns
	}
}
GO
cat > "$S/attacks/wave7-nr-portions.txt" <<'MAN'
P9 NR 17
P9 PRICE 17=3  # pread64
P9 NR 18
P9 PRICE 18=9  # pwrite64
P9 NR 19
P9 PRICE 19=1  # readv
P9 REJECTED 19  # readv: отвергнут решением
P9 RULE some_rule
P1 NR 5
MAN
cp "$HERE/config-test.yaml" "$S/config-test.yaml"
cp "$HERE/w7-roleB-patch.py" "$HERE/w7-pair-driver.sh" "$S/"
CFGCOPY="$T/cfg.yaml"; cp "$S/config-test.yaml" "$CFGCOPY"

echo "[Д1] патчер роли B на КОПИИ конфига"
out=$(W7_REPO="$R" python3 "$S/w7-roleB-patch.py" 9 "$CFGCOPY" 2>&1); rc=$?
chk "патчер rc=0" "[ $rc -eq 0 ]"
chk "состав 5 базовых + 2 открытых = 7 (отвергнутый 19 не открыт)" "echo '$out' | grep -q '= 7 номеров'"
chk "отвергнутый 19 в конфиг не попал" "! grep -qE '^      - 19 ' '$CFGCOPY'"
chk "17 и 18 в конфиге" "grep -qE '^      - 17 ' '$CFGCOPY' && grep -qE '^      - 18 ' '$CFGCOPY'"
chk "оригинал в git-копии не тронут (патчер правит только переданную копию)" "! grep -q monitored_syscalls '$S/config-test.yaml'"

echo "[Д1] ловушка №513: счётчик без терминатора списка"
# Тот самый awk, что считал 37 вместо 34: БЕЗ терминатора.
naive=$(awk '/monitored_syscalls:/{f=1;next} f&&/^      - /{n++} END{print n+0}' "$CFGCOPY")
# Тот, что был в драйвере после правки: с терминатором.
term=$(awk '/monitored_syscalls:/{f=1;next} f&&/^ *[^ #-]/{f=0} f&&/^      - /{n++} END{print n+0}' "$CFGCOPY")
chk "фикстура ВИДИТ ловушку: наивный счётчик ≠ 7 (втянул path_denylist), получил $naive" "[ '$naive' != 7 ]"
chk "счётчик с терминатором = 7" "[ '$term' = 7 ]"
chk "драйвер не считает состав по тексту конфига (Д3)" "! grep -q 'monitored_syscalls:/{f=1' '$HERE/w7-pair-driver.sh'"
chk "драйвер читает состав у рантайма (лейбл nr в снимке)" "grep -q 'ebpf_guard_syscall_events_by_nr_total{nr=' '$HERE/w7-pair-driver.sh'"
# патчер, у которого счётчик возвращён к наивному, обязан падать на ассерте перечитывания
python3 - "$HERE/w7-roleB-patch.py" "$T/mut.py" <<'PY'
import sys
s = open(sys.argv[1], encoding="utf-8").read()
# мутация: счётчик теряет терминатор (break → pass)
assert "        else:\n            break\n" in s, "мутируемое место не найдено — фикстура мертва"
open(sys.argv[2], "w", encoding="utf-8").write(s.replace("        else:\n            break\n", "        else:\n            pass\n", 1))
PY
cp "$S/config-test.yaml" "$T/cfg2.yaml"
W7_REPO="$R" python3 "$T/mut.py" 9 "$T/cfg2.yaml" >/dev/null 2>&1; mrc=$?
chk "патчер с возвращённым счётчиком БЕЗ терминатора краснеет (rc≠0)" "[ $mrc -ne 0 ]"

echo "[Д1] номер порции уже в дереве"
cp "$S/config-test.yaml" "$T/cfg3.yaml"
printf 'P8 NR 59\nP8 PRICE 59=1  # execve\n' >> "$S/attacks/wave7-nr-portions.txt"
W7_REPO="$R" python3 "$S/w7-roleB-patch.py" 8 "$T/cfg3.yaml" >/dev/null 2>&1; orc=$?
chk "перекрытие с деревом → отказ, конфиг цел" "[ $orc -ne 0 ] && ! grep -q monitored_syscalls '$T/cfg3.yaml'"

echo "[Д2] драйвер: плановые границы окон"
L="$T/log"; cp "$S/config-test.yaml" "$T/cfgd.yaml"
W7_REPO="$R" W7_SETUP="$S" W7_LOGDIR="$L" W7_CFG="$T/cfgd.yaml" W7_PAIR_DRYRUN=1 bash "$S/w7-pair-driver.sh" 9 >/dev/null 2>&1; drc=$?
P="$L/w7-pair-P9.plan"
g() { sed -n "s/^$1=//p" "$P"; }
chk "драйвер rc=0 в сухом прогоне" "[ $drc -eq 0 ]"
chk "план опубликован" "[ -s '$P' ]"
chk "план несёт ключи границ обеих ролей (>=12 строк)" "[ \$(grep -cE '^(A|B)_(START|WINDOW_START|WINDOW_END|END)=[0-9]+\$|^SAFE_AFTER=[0-9]+\$|^MARKER=|^ROLE_SECS=|^PLAN_EPOCH=' '$P') -ge 12 ]"
chk "окно A внутри роли A" "[ \$(g A_START) -le \$(g A_WINDOW_START) ] && [ \$(g A_WINDOW_END) -le \$(g A_END) ]"
chk "окно B внутри роли B и после роли A" "[ \$(g A_END) -le \$(g B_START) ] && [ \$(g B_WINDOW_END) -le \$(g B_END) ]"
chk "SAFE_AFTER позже конца роли B" "[ \$(g SAFE_AFTER) -gt \$(g B_END) ]"
chk "пара старт→SAFE_AFTER ≈ 1 ч 55 мин (6900 с ±180)" "d=\$(( \$(g SAFE_AFTER) - \$(g A_START) )); [ \$d -ge 6720 ] && [ \$d -le 7080 ]"
chk "маркер записан драйвером" "[ -s '$L/W669-PAIR-P9-DONE' ]"
chk "роль B в сухом прогоне пропатчила копию (7 номеров)" "grep -q '= 7 номеров' '$L/w669-pair-driver-P9.log'"

echo "[Д2] ожидатель: двухфазный, на стенд до SAFE_AFTER не заходит"
SSHLOG="$T/ssh.log"; CLK="$T/clock"; echo 1000 > "$CLK"; : > "$SSHLOG"
cat > "$T/fakessh" <<FS
#!/bin/bash
echo "\$(cat $CLK) \$*" >> "$SSHLOG"
case "\$*" in
  *w7-pair-driver.sh*) printf 'PORTION=9\nSAFE_AFTER=1500\nMARKER=/root/M\n' ;;
  *"test -s"*) n=\$(grep -c 'test -s' "$SSHLOG"); [ "\$n" -ge 3 ] ;;
esac
FS
cat > "$T/fakesleep" <<FS
#!/bin/bash
echo "\$1" >> "$T/sleeps"; echo \$(( \$(cat $CLK) + \$1 )) > "$CLK"
FS
chmod +x "$T/fakessh" "$T/fakesleep"
W7_SSH="$T/fakessh" W7_SLEEP_CMD="$T/fakesleep" W7_NOW_CMD="cat $CLK" W7_POLL_SECS=60 bash "$HERE/w7-pair-run.sh" 9 >"$T/wait.out" 2>&1; wrc=$?
chk "ожидатель rc=0 (маркер появился)" "[ $wrc -eq 0 ]"
chk "первый sleep = SAFE_AFTER − now = 500 с, ЛОКАЛЬНО" "[ \$(head -1 '$T/sleeps') = 500 ]"
pre=$(awk '$1 < 1500' "$SSHLOG" | wc -l | tr -d ' ')
chk "до SAFE_AFTER на стенд заходили ровно один раз (запуск), не опрашивали" "[ $pre -eq 1 ]"
chk "опросов маркера 3 (появился на третьем)" "[ \$(grep -c 'test -s' '$SSHLOG') -eq 3 ]"
# плана нет → ожидатель отказывается ждать вслепую
cat > "$T/fakessh2" <<'FS'
#!/bin/bash
:
FS
chmod +x "$T/fakessh2"
W7_SSH="$T/fakessh2" W7_SLEEP_CMD="$T/fakesleep" W7_NOW_CMD="cat $CLK" bash "$HERE/w7-pair-run.sh" 9 >/dev/null 2>&1; nrc=$?
chk "без плана окон ожидатель отказывает (rc=1), вслепую не ждёт" "[ $nrc -eq 1 ]"

echo
if [ "$FAIL" -eq 0 ]; then echo "w7-pair-fixtures: расхождений 0"; else echo "w7-pair-fixtures: ЕСТЬ РАСХОЖДЕНИЯ"; fi
exit "$FAIL"
