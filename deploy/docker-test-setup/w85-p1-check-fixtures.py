#!/usr/bin/env python3
"""Фикстуры w85-p1-check.py (сверка с /proc и вердикт мс-цепочки) и мутации: --mutate."""
import http.server, importlib.util, io, json, os, shutil, sys, tempfile, threading, contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.environ.get("CHECK", os.path.join(HERE, "w85-p1-check.py"))
spec = importlib.util.spec_from_file_location("chk", TARGET)
chk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chk)

fails = 0
def ok(n): print("ok   " + n)
def bad(n, extra=""):
    global fails; fails += 1; print("FAIL " + n + (" — " + extra if extra else ""))

def mkproc(root, procs):
    """procs: {pid: (ppid, comm, exe)}"""
    for pid, (ppid, comm, exe) in procs.items():
        d = os.path.join(root, str(pid)); os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "status"), "w").write("Name:\t%s\nState:\tS\nPPid:\t%d\n" % (comm, ppid))
        if exe:
            try: os.symlink(exe, os.path.join(d, "exe"))
            except FileExistsError: pass

def serve(handler_fn):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            code, body = handler_fn(self.path)
            self.send_response(code); self.end_headers(); self.wfile.write(json.dumps(body).encode())
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "127.0.0.1:%d" % srv.server_port

def run_compare(procs, agent, n=30):
    root = tempfile.mkdtemp()
    try:
        mkproc(root, procs)
        def h(path):
            pid = int(path.split("pid=")[1])
            return agent(pid, procs)
        srv, api = serve(h)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            chk.compare(api, "t", n, root)
        srv.shutdown()
        return buf.getvalue()
    finally:
        shutil.rmtree(root)

def truth(pid, procs, mutate=None):
    """что ответил бы честный агент: ancestors от корня к родителю, без init"""
    chain, cur = [], procs[pid][0]
    while cur > 1:
        ppid, comm, exe = procs[cur]
        chain.append({"pid": cur, "ppid": ppid, "comm": comm, "image": exe})
        cur = ppid
    chain.reverse()
    if mutate: mutate(chain)
    return 200, {"pid": pid, "table": True, "outcome": "resolved", "ancestors": chain}

# 40 процессов: цепочки глубины 2–4 под init
PROCS = {}
for i in range(10):
    b = 1000 + i * 10
    PROCS[b] = (1, "svc%d" % i, "/usr/sbin/svc%d" % i)
    PROCS[b + 1] = (b, "sh", "/usr/bin/dash")
    PROCS[b + 2] = (b + 1, "worker", "/usr/bin/python3")
    PROCS[b + 3] = (b + 2, "leaf", "/usr/bin/leaf")

def check(name, procs, agent, pat, n=30):
    out = run_compare(procs, agent, n)
    if pat in out: ok(name)
    else: bad(name, "нет «%s»\n%s" % (pat, out))

check("compare-good", PROCS, lambda pid, p: truth(pid, p), "ДОСТИГНУТО: P1-live")
def wrong_ppid(chain):
    if len(chain) > 1: chain[-1]["ppid"] = 99999
check("compare-wrong-ppid", PROCS, lambda pid, p: truth(pid, p, wrong_ppid), "ПРОВАЛЕН: P1-live")
def drop_hop(chain):
    if len(chain) > 1: chain.pop(0)   # агент потерял корневую сторону — это НЕ глубина: сверка должна заметить
check("compare-lost-root", PROCS, lambda pid, p: truth(pid, p, drop_hop), "ПРОВАЛЕН: P1-live")
def wrong_comm(chain):
    for c in chain: c["comm"] = "x"
check("compare-comm-is-fact-not-gate", PROCS, lambda pid, p: truth(pid, p, wrong_comm), "ДОСТИГНУТО: P1-live")
check("compare-comm-printed", PROCS, lambda pid, p: truth(pid, p, wrong_comm), "comm звена совпал: 0/")
check("compare-no-table", PROCS, lambda pid, p: (200, {"table": False, "ancestors": []}), "НЕИЗМЕРИМ: P1-live НЕИЗМЕРИМ (класс НАЗВАН: агент отвечает table=false")
check("compare-api-error", PROCS, lambda pid, p: (500, {}), "НЕИЗМЕРИМ: P1-live НЕИЗМЕРИМ (класс НАЗВАН: /debug/lineage не отвечает")
check("compare-too-few", {1000: (1, "a", ""), 1001: (1000, "b", "")}, lambda pid, p: truth(pid, p), "НЕИЗМЕРИМ: P1-live НЕИЗМЕРИМ (класс НАЗВАН: сверено")

# вердикт мс-цепочки
def mc(tree, anc, table=True, outcome="resolved"):
    return {"table": table, "tree_comms": tree, "ancestors": [{"comm": c} for c in anc], "outcome": outcome}
GOOD = [("пока curl жив", mc(["nginx", "bash", "curl"], ["nginx", "bash"]), ""), ("после выхода", mc(["nginx", "bash", "curl"], ["nginx", "bash"]), "")]
def judge(name, results, pat):
    out = "\n".join(chk.judge_mc(results))
    if pat in out: ok(name)
    else: bad(name, "нет «%s»\n%s" % (pat, out))
judge("mc-good", GOOD, "ДОСТИГНУТО: P1-mc")
judge("mc-bash-lost-after-death", [GOOD[0], ("после выхода", mc(["nginx", "curl"], ["nginx"]), "")], "ПРОВАЛЕН: P1-mc")
judge("mc-chain-cut-while-alive", [("жив", mc(["curl"], []), ""), GOOD[1]], "ПРОВАЛЕН: P1-mc")
judge("mc-no-table", [("жив", mc([], [], table=False), ""), GOOD[1]], "НЕИЗМЕРИМ: P1-mc")
judge("mc-no-answer", [("жив", None, "нет ответа: x"), GOOD[1]], "ПРОВАЛЕН: P1-mc")
judge("mc-one-snapshot", [GOOD[0]], "НЕИЗМЕРИМ: P1-mc")

if "--mutate" in sys.argv[1:]:
    print("== мутации")
    src = open(TARGET, encoding="utf-8").read()
    def mut(name, old, new):
        global fails
        if old not in src: bad("мутация %s устарела" % name); return
        d = tempfile.mkdtemp(); p = os.path.join(d, "w85-p1-check.py")
        open(p, "w", encoding="utf-8").write(src.replace(old, new, 1))
        import subprocess
        r = subprocess.run([sys.executable, __file__], env=dict(os.environ, CHECK=p), capture_output=True, text=True)
        shutil.rmtree(d)
        if r.returncode != 0: ok("мутация %s покраснила фикстуры" % name)
        else: bad("мутация %s ПРОШЛА" % name)
    mut("pid-gate-off", "if 100.0 * pid_ok / seen >= 98.0:", "if True:")
    mut("pid-chain-any-suffix", "pid_ok += 1 if same and k == len(exp_chain) else 0", "pid_ok += 1 if same else 0")
    mut("table-guard-off", 'if not got.get("table"):', "if False:")
    mut("tree-not-compared", "if tree != want:", "if False:")
    mut("one-snapshot-ok", "if len(results) < 2:", "if False:")
    mut("api-error-as-zero", "except Exception as e:  # агент не отвечает", "except KeyboardInterrupt as e:  # агент не отвечает")
    mut("too-few-ok", "if seen < max(10, n // 3):", "if False:")
print("-- fails=%d" % fails)
sys.exit(1 if fails else 0)
