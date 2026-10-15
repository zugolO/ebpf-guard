#!/usr/bin/env python3
"""w86-pprof-fixture.py <out> <длительность_с> <cum_EvaluateInto_с> <прочее_с> — синтетический CPU-профиль pprof
(profile.proto, без сжатия) для фикстур эмиттера rule-eval: узел RuleEngine.EvaluateInto с заданным cum и
корневой узел «прочее». Нужен только фикстурам; боевые профили снимает агент."""
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
    out, dur, ev, other = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
    strs = ["", "samples", "count", "cpu", "nanoseconds",
            "github.com/zugolO/ebpf-guard/internal/correlator.(*RuleEngine).EvaluateInto",
            "github.com/zugolO/ebpf-guard/cmd/ebpf-guard.run", "x.go"]
    body = b""
    body += ld(1, vi(1, 1) + vi(2, 2)) + ld(1, vi(1, 3) + vi(2, 4))
    body += ld(2, packed(1, [1]) + packed(2, [int(ev * 100), int(ev * 1e9)]))
    body += ld(2, packed(1, [2]) + packed(2, [int(other * 100), int(other * 1e9)]))
    body += ld(4, vi(1, 1) + ld(4, vi(1, 1) + vi(2, 1)))
    body += ld(4, vi(1, 2) + ld(4, vi(1, 2) + vi(2, 1)))
    body += ld(5, vi(1, 1) + vi(2, 5) + vi(3, 5) + vi(4, 7))
    body += ld(5, vi(1, 2) + vi(2, 6) + vi(3, 6) + vi(4, 7))
    for s in strs:
        body += ld(6, s.encode())
    body += vi(9, 1760000000000000000) + vi(10, int(dur * 1e9))
    body += ld(11, vi(1, 3) + vi(2, 4)) + vi(12, 10000000)
    open(out, "wb").write(body)


main()
