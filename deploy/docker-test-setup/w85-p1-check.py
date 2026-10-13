#!/usr/bin/env python3
"""w85-p1-check.py — живые проверки таблицы процессов ядра (волна 8.5, P1) через GET /debug/lineage.

  compare  <api host:port> <token> [N=60] [--proc /proc]
      Сверка таблицы с /proc: N случайных живых процессов, у каждого цепочка предков из /proc (PPid до init)
      против `ancestors` ответа агента. Сравнивается: (1) цепочка pid/ppid, (2) comm звена, (3) образ звена
      (readlink exe против image). pid-цепочка — ЖЁСТКОЕ условие (≥ 98% сверенных); comm и образ печатаются
      как факт с долей (comm меняется prctl'ом после exec; образ предка, умершего между снимками, недоступен).
  mcchain  <api host:port> <token> <nginx-копия> <bash-копия> <curl-цель>
      Контроль мс-цепочки nginx→bash→curl с МГНОВЕННЫМ bash: bash порождает curl в фоне и выходит. Цепочка curl
      читается (а) пока curl жив, а bash мёртв, и (б) после выхода curl — обе обязаны дать [nginx, bash, curl].

Вердикт печатает инструмент: ДОСТИГНУТО / ПРОВАЛЕН / НЕИЗМЕРИМ с названным классом (нет таблицы, нет
ответа, мало процессов — «ноль без класса» не засчитывается).
"""
import json, os, random, subprocess, sys, time, urllib.request


def api_get(api, token, pid):
    req = urllib.request.Request("http://%s/debug/lineage?pid=%d" % (api, pid), headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def proc_chain(procroot, pid, depth=16):
    """Цепочка pid → предки до init из /proc, от листа к корню: [(pid, ppid, comm, exe)]; None — процесс исчез."""
    out, cur = [], pid
    while cur > 1 and len(out) < depth:
        try:
            with open("%s/%d/status" % (procroot, cur)) as f:
                st = f.read()
        except OSError:
            return None
        name = ppid = None
        for line in st.splitlines():
            if line.startswith("Name:"):
                name = line.split(None, 1)[1].strip()
            elif line.startswith("PPid:"):
                ppid = int(line.split()[1])
        if name is None or ppid is None:
            return None
        try:
            exe = os.readlink("%s/%d/exe" % (procroot, cur))
        except OSError:
            exe = ""
        out.append((cur, ppid, name, exe))
        if ppid == 0:
            break
        cur = ppid
    return out


def compare(api, token, n, procroot):
    pids = [int(d) for d in os.listdir(procroot) if d.isdigit() and int(d) > 1]
    random.shuffle(pids)
    seen = pid_ok = comm_ok = img_ok = hops = comm_hops = img_hops = 0
    skipped_exit = skipped_leaf = 0
    bad = []
    for pid in pids:
        if seen >= n:
            break
        exp = proc_chain(procroot, pid)
        if exp is None or len(exp) < 2:
            continue  # исчез или ребёнок init: сверять нечего
        try:
            got = api_get(api, token, pid)
        except Exception as e:  # агент не отвечает — это не «ноль», а класс
            print("НЕИЗМЕРИМ: P1-live НЕИЗМЕРИМ (класс НАЗВАН: /debug/lineage не отвечает: %s)" % e)
            return
        if not got.get("table"):
            print("НЕИЗМЕРИМ: P1-live НЕИЗМЕРИМ (класс НАЗВАН: агент отвечает table=false — таблица процессов не включена)")
            return
        exp_chain = exp[1:][::-1]  # предки от корня к родителю, лист не входит
        if proc_chain(procroot, pid) is None:  # процесс умер, пока спрашивали — не считать
            skipped_exit += 1
            continue
        seen += 1
        anc = got.get("ancestors") or []
        # агент мог обрезать корневую сторону (глубина) — сравнивается СУФФИКС ожидаемой цепочки
        k = min(len(anc), len(exp_chain))
        e_tail, a_tail = exp_chain[len(exp_chain) - k:], anc[len(anc) - k:]
        same = k > 0 and all(e[0] == a["pid"] and e[1] == a["ppid"] for e, a in zip(e_tail, a_tail))
        pid_ok += 1 if same and k == len(exp_chain) else 0
        if not (same and k == len(exp_chain)):
            bad.append("pid %d: /proc %s | агент %s | исход %s" % (pid, [e[0] for e in exp_chain], [a["pid"] for a in anc], got.get("outcome")))
        if same:
            for e, a in zip(e_tail, a_tail):
                hops += 1
                comm_hops += 1 if e[2] == a["comm"] else 0
                if e[3] and a.get("image"):
                    img_hops += 1
                    img_ok += 1 if e[3] == a["image"] else 0
                elif not e[3]:
                    pass
            comm_ok += 1 if all(e[2] == a["comm"] for e, a in zip(e_tail, a_tail)) else 0
    if seen < max(10, n // 3):
        print("НЕИЗМЕРИМ: P1-live НЕИЗМЕРИМ (класс НАЗВАН: сверено %d процессов из %d запрошенных — слишком мало живых цепочек)" % (seen, n))
        return
    print("  сверено процессов %d (исчезли во время опроса %d); звеньев %d" % (seen, skipped_exit, hops))
    print("  цепочка pid/ppid полностью совпала: %d/%d (%.1f%%)" % (pid_ok, seen, 100.0 * pid_ok / seen))
    print("  comm звена совпал: %d/%d звеньев (%.1f%%); у всей цепочки: %d/%d" % (comm_hops, hops, 100.0 * comm_hops / max(hops, 1), comm_ok, seen))
    print("  образ звена совпал с readlink exe: %d/%d сверимых (%.1f%%)" % (img_ok, img_hops, 100.0 * img_ok / max(img_hops, 1)))
    for b in bad[:8]:
        print("   расхождение:", b)
    # причины пустого образа у ЖИВЫХ звеньев (экспертиза: dev/ino, записанные ядром, против stat(/proc/<pid>/exe))
    shown = 0
    for pid in pids:
        if shown >= 6:
            break
        try:
            got = api_get(api, token, pid)
        except Exception:
            continue
        for a in got.get("ancestors") or []:
            if a.get("image") or a.get("exited"):
                continue
            try:
                st = os.stat("%s/%d/exe" % (procroot, a["pid"]))
                real = "stat dev=%#x ino=%d" % (st.st_dev, st.st_ino)
            except OSError as e:
                real = "stat exe: %s" % e.__class__.__name__
            print("   пустой образ у живого звена pid=%d comm=%s: агент exe_dev=%#x exe_ino=%d seeded=%s; %s" % (a["pid"], a["comm"], a.get("exe_dev", 0), a.get("exe_ino", 0), a.get("seeded"), real))
            shown += 1
            break
    if 100.0 * pid_ok / seen >= 98.0:
        print("ДОСТИГНУТО: P1-live ДОСТИГНУТО (цепочка pid/ppid таблицы ядра = /proc у %d/%d живых процессов; comm %.1f%%, образ %.1f%%)" % (pid_ok, seen, 100.0 * comm_hops / max(hops, 1), 100.0 * img_ok / max(img_hops, 1)))
    else:
        print("ПРОВАЛЕН: P1-live ПРОВАЛЕН (цепочка pid/ppid совпала у %d/%d = %.1f%% < 98%%)" % (pid_ok, seen, 100.0 * pid_ok / seen))


def pgrep_x(name, must_contain=""):
    """pid процессов с точным comm; must_contain — подстрока cmdline (чужие curl'ы харнесса не берутся)."""
    r = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    out = []
    for p in (int(x) for x in r.stdout.split()):
        try:
            cl = open("/proc/%d/cmdline" % p, "rb").read().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            continue
        if must_contain in cl:
            out.append(p)
    return out


def judge_mc(results, want=("nginx", "bash", "curl")):
    """results — [(метка, ответ /debug/lineage | None, ошибка)]. Возвращает строки вердикта."""
    want = list(want)
    lines, fail = [], []
    for label, d, err in results:
        if d is None:
            fail.append("%s: %s" % (label, err)); continue
        if not d.get("table"):
            return ["НЕИЗМЕРИМ: P1-mc НЕИЗМЕРИМ (класс НАЗВАН: table=false)"]
        tree = d.get("tree_comms") or []
        anc = [a["comm"] for a in d.get("ancestors") or []]
        lines.append("  %s: tree_comms=%s ancestors=%s исход=%s" % (label, tree, anc, d.get("outcome")))
        if tree != want:
            fail.append("%s: дерево %s, ждали %s" % (label, tree, want))
    if len(results) < 2:
        lines.append("НЕИЗМЕРИМ: P1-mc НЕИЗМЕРИМ (класс НАЗВАН: прочитано %d снимков цепочки из 2)" % len(results))
    elif fail:
        lines.append("ПРОВАЛЕН: P1-mc ПРОВАЛЕН (%s)" % "; ".join(fail))
    else:
        lines.append("ДОСТИГНУТО: P1-mc ДОСТИГНУТО (цепочка nginx→bash→curl полная и пока curl жив при мёртвом bash, и после выхода curl)")
    return lines


def mcchain(api, token, nginx, bash, target):
    unit = "w85p1-mc-%d" % int(time.time())
    script = '%s -c \'%s -c "/usr/bin/curl -s --max-time 25 -o /dev/null %s &"; sleep 40\'' % (nginx, bash, target)
    subprocess.run(["systemd-run", "--quiet", "--unit=" + unit, "/bin/sh", "-c", "exec " + script], check=False)
    curl = None
    for _ in range(100):
        time.sleep(0.2)
        cands = pgrep_x("curl", target)
        if cands:
            curl = max(cands)
            break
    if curl is None:
        subprocess.run(["systemctl", "stop", unit + ".service"], capture_output=True)
        print("НЕИЗМЕРИМ: P1-mc НЕИЗМЕРИМ (класс НАЗВАН: curl не запустился — контроль не исполнился)")
        return

    def read(label):
        try:
            return (label, api_get(api, token, curl), "")
        except Exception as e:
            return (label, None, "нет ответа: %s" % e)
    results = []
    time.sleep(1.0)  # bash успел выйти (он только форкает curl в фон)
    bash_alive = pgrep_x("bash", bash)
    results.append(read("пока curl жив, bash мёртв"))
    time.sleep(30)  # curl --max-time 25 вышел
    results.append(read("после выхода curl"))
    subprocess.run(["systemctl", "stop", unit + ".service"], capture_output=True)
    if bash_alive:
        print("НЕИЗМЕРИМ: P1-mc НЕИЗМЕРИМ (класс НАЗВАН: bash %s ещё жив через секунду — «мгновенного bash» нет, контроль не про мёртвого родителя)" % bash_alive)
        return
    for line in judge_mc(results):
        print(line)


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) >= 3 and a[0] == "compare":
        procroot = "/proc"
        if "--proc" in a:
            i = a.index("--proc"); procroot = a[i + 1]; del a[i:i + 2]
        compare(a[1], a[2], int(a[3]) if len(a) > 3 else 60, procroot)
    elif len(a) >= 6 and a[0] == "mcchain":
        mcchain(*a[1:6])
    else:
        print(__doc__); sys.exit(2)
