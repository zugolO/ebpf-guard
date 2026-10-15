#!/usr/bin/env python3
"""Самопроверка w86-d1-report.py на синтетических окнах: плоское, наклон по P1, наклон у всех ячеек."""
import os, random, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CELLS = ["p1on_f1on", "p1on_f1off", "p1off_f1on", "p1off_f1off"]
HDR = "ts\tcg_anon\tproc_anonymous\theap_inuse\theap_idle\theap_released\tstack_inuse\tsys\theap_alloc\tby_nr_321\tcg_file\n"


def build(slopes, seed=1):
    random.seed(seed)
    d = tempfile.mkdtemp()
    for c in CELLS:
        os.makedirs(os.path.join(d, c))
        with open(os.path.join(d, c, "snap.tsv"), "w") as f:
            f.write(HDR)
            for i in range(30):  # 30 снимков по 5 мин = 2.5 ч
                t = 1_000_000 + i * 300
                hrs = i * 300 / 3600.0
                anon = 50e6 + slopes[c] * hrs + random.uniform(-100e3, 100e3)
                f.write("\t".join(str(int(x)) for x in (t, anon, anon, 30e6, 20e6, 5e6, 1e6, 80e6, 25e6, 1000, 10e6)) + "\n")
    return d


def run(slopes):
    out = subprocess.run([sys.executable, os.path.join(HERE, "w86-d1-report.py"), build(slopes)], capture_output=True, text=True)
    return out.stdout


flat = run({c: 0 for c in CELLS})
assert "наклона anon нет" in flat, flat
p1 = run({"p1on_f1on": 2e6, "p1on_f1off": 2e6, "p1off_f1on": 0, "p1off_f1off": 0})
assert "по оси P1" in p1 and "F1 (" not in p1.split("ВЕРДИКТ")[1], p1
allc = run({c: 2e6 for c in CELLS})
assert "не объяснено" in allc and "нужна ночь" in allc, allc
f1 = run({"p1on_f1on": 2e6, "p1on_f1off": 0, "p1off_f1on": 2e6, "p1off_f1off": 0})
assert "по оси F1" in f1, f1
print("w86-d1-report selftest: 4/4")
