#!/usr/bin/env python3
"""Волна 8.6 B, Д1: разбор w86-d1-anon.sh — наклоны anon и компонент по четырём ячейкам P1 x F1.

   w86-d1-report.py <OUT>

Для каждой ячейки — МНК-наклон (байт/ч) по снимкам с оценкой погрешности (стандартная ошибка наклона). Первые
WARMUP_MIN минут окна отбрасываются: рост из-за прогрева (кэши, page cache, профили) не накопление.
Вывод: таблица, разность P1 (on - off) и F1 (on - off) по наклону anon с погрешностью, и вердикт:
  - ячейка «даёт наклон», если её наклон anon > 3 стандартных ошибок и > ABS_MIN байт/ч И он больше наклона
    ячейки, где P1/F1 выключены, больше чем на сумму трёх ошибок;
  - иначе «не объяснено — нужна ночь > 12 ч», если наклон anon любой ячейки значим, но разность между ячейками нет;
  - «наклона нет» — если ни один наклон не значим.
"""
import os, sys, math

WARMUP_MIN = 20
ABS_MIN = 256 * 1024  # байт/ч: меньше — ниже шума страничной гранулярности
CELLS = ["p1on_f1on", "p1on_f1off", "p1off_f1on", "p1off_f1off"]
COLS = ["cg_anon", "proc_anonymous", "heap_inuse", "heap_idle_minus_released", "stack_inuse", "sys", "heap_alloc", "cg_file"]


def load(path):
    rows = []
    with open(path) as f:
        hdr = f.readline().split("\t")
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) != len(hdr) or any(x == "" for x in p):
                continue
            r = dict(zip([h.strip() for h in hdr], p))
            try:
                rows.append({k: float(v) for k, v in r.items()})
            except ValueError:
                continue
    return rows


def series(rows, col):
    t0 = rows[0]["ts"]
    out = []
    for r in rows:
        if (r["ts"] - t0) / 60.0 < WARMUP_MIN:
            continue
        if col == "heap_idle_minus_released":
            v = r["heap_idle"] - r["heap_released"]
        else:
            v = r[col]
        out.append(((r["ts"] - t0) / 3600.0, v))
    return out


def slope(xy):
    n = len(xy)
    if n < 4:
        return None, None, n
    mx = sum(x for x, _ in xy) / n
    my = sum(y for _, y in xy) / n
    sxx = sum((x - mx) ** 2 for x, _ in xy)
    if sxx == 0:
        return None, None, n
    b = sum((x - mx) * (y - my) for x, y in xy) / sxx
    res = sum((y - (my + b * (x - mx))) ** 2 for x, y in xy)
    se = math.sqrt(res / (n - 2) / sxx) if n > 2 else float("inf")
    return b, se, n


def main():
    out = sys.argv[1]
    data = {}
    for c in CELLS:
        p = os.path.join(out, c, "snap.tsv")
        if not os.path.exists(p):
            print("НЕИЗМЕРИМ: нет", p)
            return 2
        data[c] = load(p)
        if len(data[c]) < 8:
            print("НЕИЗМЕРИМ: мало снимков у", c, len(data[c]))
            return 2
    span = (data[CELLS[0]][-1]["ts"] - data[CELLS[0]][0]["ts"]) / 3600.0
    print("окно %.2f ч, снимков %d, прогрев %d мин отброшен" % (span, len(data[CELLS[0]]), WARMUP_MIN))
    print("%-14s %-24s %14s %14s %5s" % ("ячейка", "компонента", "наклон Б/ч", "± 1 SE", "n"))
    sl = {}
    for c in CELLS:
        for col in COLS:
            b, se, n = slope(series(data[c], col))
            sl[(c, col)] = (b, se)
            if b is None:
                print("%-14s %-24s %14s" % (c, col, "n/a"))
            else:
                print("%-14s %-24s %14.0f %14.0f %5d" % (c, col, b, se, n))
    # контроль симметрии: by_nr{321} по ячейкам на конец окна
    print("by_nr{321} на конце: " + ", ".join("%s=%d" % (c, data[c][-1]["by_nr_321"]) for c in CELLS))

    def eff(col, a, b):  # среднее по ячейкам, где ключ a, минус где b
        xs = [sl[(c, col)] for c in CELLS if a(c)]
        ys = [sl[(c, col)] for c in CELLS if b(c)]
        if any(v[0] is None for v in xs + ys):
            return None, None
        m = sum(v[0] for v in xs) / len(xs) - sum(v[0] for v in ys) / len(ys)
        se = math.sqrt(sum(v[1] ** 2 for v in xs + ys)) / 2
        return m, se

    print()
    for col in ("cg_anon", "proc_anonymous", "heap_inuse", "heap_idle_minus_released", "stack_inuse", "sys"):
        for name, a, b in (("P1 on-off", lambda c: "p1on" in c, lambda c: "p1off" in c),
                           ("F1 on-off", lambda c: "f1on" in c, lambda c: "f1off" in c)):
            m, se = eff(col, a, b)
            print("эффект %-9s %-24s %s" % (name, col, "n/a" if m is None else "%+.0f ± %.0f Б/ч" % (m, se)))
    # вердикт по cg_anon
    sig = [c for c in CELLS if sl[(c, "cg_anon")][0] is not None and sl[(c, "cg_anon")][0] > max(ABS_MIN, 3 * sl[(c, "cg_anon")][1])]
    p1, p1se = eff("cg_anon", lambda c: "p1on" in c, lambda c: "p1off" in c)
    f1, f1se = eff("cg_anon", lambda c: "f1on" in c, lambda c: "f1off" in c)
    print()
    if not sig:
        print("ВЕРДИКТ: наклона anon нет (ни одна ячейка > 3 SE и > %d Б/ч)" % ABS_MIN)
    else:
        named = []
        if p1 is not None and p1 > max(ABS_MIN, 3 * p1se):
            named.append("P1 (+%.0f Б/ч)" % p1)
        if f1 is not None and f1 > max(ABS_MIN, 3 * f1se):
            named.append("F1 (+%.0f Б/ч)" % f1)
        if named:
            print("ВЕРДИКТ: наклон даёт ячейка по оси " + " и ".join(named) + "; значимые ячейки: " + ", ".join(sig))
        else:
            print("ВЕРДИКТ: не объяснено — наклон есть (%s), разность P1/F1 не значима: нужна ночь > 12 ч" % ", ".join(sig))
    return 0


if __name__ == "__main__":
    sys.exit(main())
