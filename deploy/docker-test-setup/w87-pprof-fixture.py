#!/usr/bin/env python3
"""w87-pprof-fixture.py <out> <длительность_с> <спец>... — синтетический CPU-профиль pprof (profile.proto, без сжатия)
для фикстур эмиттеров волны 8.7. Спец: «фн1>фн2>…:секунды[:ключ=знач]» — стек от корня к листу, CPU-секунды,
необязательная метка (event_type=file). Нужен только фикстурам; боевые профили снимает агент.
Сэмплов («samples», 10 мс) = секунды × 100."""
import sys


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def fld(num, wt, payload):
    return varint((num << 3) | wt) + payload


def vi(num, n):
    return fld(num, 0, varint(n))


def ld(num, data):
    return fld(num, 2, varint(len(data)) + data)


def packed(num, vals):
    return ld(num, b"".join(varint(v) for v in vals))


def main():
    out, dur = sys.argv[1], float(sys.argv[2])
    strs = [""]

    def sid(s):
        if s not in strs:
            strs.append(s)
        return strs.index(s)

    sid("samples"); sid("count"); sid("cpu"); sid("nanoseconds"); sid("x.go")
    funcs = {}

    def fid(name):
        if name not in funcs:
            funcs[name] = len(funcs) + 1
            sid(name)
        return funcs[name]

    samples = b""
    for spec in sys.argv[3:]:
        parts = spec.split(":")
        stack = parts[0].split(">")
        secs = float(parts[1])
        ids = [fid(f) for f in reversed(stack)]  # лист первым
        s = packed(1, ids) + packed(2, [int(secs * 100), int(secs * 1e9)])
        if len(parts) > 2:
            k, v = parts[2].split("=", 1)
            s += ld(3, vi(1, sid(k)) + vi(2, sid(v)))
        samples += ld(2, s)
    body = ld(1, vi(1, 1) + vi(2, 2)) + ld(1, vi(1, 3) + vi(2, 4))
    body += samples
    for name, i in funcs.items():
        body += ld(4, vi(1, i) + ld(4, vi(1, i) + vi(2, 1)))
    for name, i in funcs.items():
        body += ld(5, vi(1, i) + vi(2, sid(name)) + vi(3, sid(name)) + vi(4, 5))
    for s in strs:
        body += ld(6, s.encode())
    body += vi(9, 1760000000000000000) + vi(10, int(dur * 1e9))
    body += ld(11, vi(1, 3) + vi(2, 4)) + vi(12, 10000000)
    open(out, "wb").write(body)


main()
