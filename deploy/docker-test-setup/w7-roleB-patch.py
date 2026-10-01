# Вписывает в config-test.yaml аллоулист роли B для ОДНОЙ порции: текущий
# эффективный список (то есть DefaultMonitoredSyscalls(), состояние дерева)
# плюс номера ЭТОЙ порции. Ни один номер не выписан рукой: базовый список
# берётся из sampling.go, номера порции — из манифеста, который генерируется
# tools/rules-audit/nr-portions.py.
#
# Использование: w7-roleB-patch.py <порция> [<путь к конфигу>]
# Репозиторий — W7_REPO (по умолчанию /opt/ebpf-guard); без второго аргумента
# правится config-test.yaml В ДЕРЕВЕ, с ним — любая копия (сухой прогон на mac и
# фикстура, [[rule-fields-and-binary-ship-together]]: патчер не должен требовать стенда).
# Живёт в репозитории, а не в /root: пара воспроизводима только из git.
import io, os, re, sys
POR = sys.argv[1]
REPO = os.environ.get("W7_REPO", "/opt/ebpf-guard")
CFG = sys.argv[2] if len(sys.argv) > 2 else REPO + "/deploy/docker-test-setup/config-test.yaml"
MAN = REPO + "/deploy/docker-test-setup/attacks/wave7-nr-portions.txt"


def count_list(text, key):
    """Число элементов списка под ключом YAML. Список КОНЧАЕТСЯ на первой
    строке, не являющейся ни элементом, ни комментарием, ни пустой: счётчик без
    терминатора втягивал следующий список (path_denylist) и печатал 37 вместо 34
    (№513, [[yaml-list-counter-without-terminator-absorbs-next-list]])."""
    n, inside = 0, False
    for line in text.splitlines():
        if not inside:
            inside = re.match(r"^\s*" + re.escape(key) + r":\s*$", line) is not None
            continue
        if re.match(r"^\s*-\s", line):
            n += 1
        elif line.strip() == "" or line.lstrip().startswith("#"):
            continue
        else:
            break
    return n

src = io.open(REPO + "/internal/bpf/sampling.go", encoding="utf-8").read()
body = src.split("func DefaultMonitoredSyscalls() []int {", 1)[1].split("\n}", 1)[0]
base, names = [], {}
for m in re.finditer(r"^\t\t(\d+),\s*//\s*(\S+)", body, re.M):
    base.append(int(m.group(1))); names[int(m.group(1))] = m.group(2)
assert base, "базовый аллоулист не разобран"

por, pnames = [], {}
for line in io.open(MAN, encoding="utf-8"):
    f = line.split()
    if len(f) >= 3 and f[0] == "P" + POR and f[1] == "NR":
        por.append(int(f[2]))
    if len(f) >= 5 and f[0] == "P" + POR and f[1] == "PRICE":
        pnames[int(f[2].split("=")[0])] = (f[4], f[2].split("=")[1])
assert por, "в манифесте нет номеров порции " + POR

# Номер, помеченный в манифесте REJECTED, роль B НЕ открывает: отказ по цене
# (или по каталогу) — это решение, и пара не имеет права его отменять молча.
rej = set()
for line in io.open(MAN, encoding="utf-8"):
    f = line.split()
    if len(f) >= 3 and f[0] == "P" + POR and f[1] == "REJECTED":
        rej.add(int(f[2]))
if rej:
    print("порция %s: отвергнутые номера НЕ открываются: %s" % (POR, sorted(rej)))
por = [n for n in por if n not in rej]
assert por, "у порции %s все номера отвергнуты — пару ставить не на чем" % POR
overlap = sorted(set(base) & set(por))
assert not overlap, "порция %s уже открыта в дереве: %s" % (POR, overlap)

s = io.open(CFG, encoding="utf-8").read()
anchor = "  kernel_filter:\n    enabled: true\n"
assert anchor in s, "якорь kernel_filter не найден"
assert "monitored_syscalls" not in s, "ключ уже есть — роль A не чиста"
out = ["    # ── ВОЛНА 7, ITEM б3, РОЛЬ B ПАРЫ ПОРЦИИ %s. Ставится на ВРЕМЯ ПРОГОНА B" % POR,
       "    #    и снимается после него. Базовые %d номера ниже — ПОБУКВЕННО состояние" % len(base),
       "    #    дерева (DefaultMonitoredSyscalls()), поэтому пара отличается ровно",
       "    #    номерами порции, а не способом задания списка.",
       "    monitored_syscalls:"]
for n in base:
    out.append("      - %-4d # %s" % (n, names.get(n, "?")))
out.append("    # ── порция %s (цена/мин по замеру item б2):" % POR)
for n in por:
    nm, pr = pnames.get(n, ("?", "?"))
    out.append("      - %-4d # %s, %s вызовов/мин по замеру б2" % (n, nm, pr))
new = s.replace(anchor, anchor + "\n".join(out) + "\n", 1)
io.open(CFG, "w", encoding="utf-8").write(new)
got = count_list(new, "monitored_syscalls")
assert got == len(base) + len(por), "перечитанный список %d != записанному %d" % (got, len(base) + len(por))
print("роль B порции %s: базовых %d + порция %d = %d номеров" % (POR, len(base), len(por), got))
