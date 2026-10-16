#!/usr/bin/env python3
"""w87-ab-patch.py <config.yaml> <SRC> — роль «new» пары ABBA волны 8.7: окно слива читателя кольца (П2).
Роль «base» (SRC без w87-new) не трогается: старый бинарь ключа не знает. Окно — W87_DRAIN (по умолчанию 10ms)."""
import os, sys, yaml
cfg, src = sys.argv[1], sys.argv[2]
if "w87-new" not in src:
    sys.exit(0)
c = yaml.safe_load(open(cfg))
c.setdefault("bpf", {})["ringbuf_drain_window"] = os.environ.get("W87_DRAIN", "10ms")
yaml.safe_dump(c, open(cfg, "w"), allow_unicode=True, sort_keys=False)
print("ringbuf_drain_window =", c["bpf"]["ringbuf_drain_window"])
