#!/usr/bin/env python3
"""w82-pod-night-values.py <config-test.yaml> <image tag> <token> <out values.yaml>

Волна 8.2, ночь закрытия (пробел Г1 доводки): values чарта, с которыми под на
k3s стенда работает на БОЕВОМ конфиге хостового агента — тот же config-test.yaml
и тот же каталог rules/ (hostPath /opt/ebpf-guard только чтение), а не пробные
правила из rules.content, на которых мерились этап 4 и доводка.

Что меняется против хоста и почему (каждая замена — путь, которого в поде нет,
или место, которое делит с хостовым агентом):
  server.bind_address                → :19091 (на :9090 хоста Prometheus, :19090 — хостовый агент)
  auth.admin_token / viewer_token    → заданы (файл токена хоста — чужой)
  store.backend                      → memory: образ продукта собран CGO_ENABLED=0,
                                       sqlite в нём нет (internal/store/sqlite_nocgo.go);
                                       memory — то, что под продукта и держит
  profiler.state_persistence.path, correlator.observer_exclude.root_pid_file,
  enforcement.audit_log, notifications.unix_socket.path
                                     → /var/lib/ebpf-guard-pod/ (свой каталог, стор хоста не трогаем)
  kubernetes.kubeconfig_path         → "" (in-cluster, RBAC чарта)
  collectors.required                → как в чарте, если в конфиге нет (иначе kmod/lsm=0
                                       на ядре стенда держат под не-Ready, находка 2 этапа 4)

Волна 8.5 (D1): W85_ARG_PREDICATES=1 включает bpf.kernel_filter.arg_predicates
(F1 по умолчанию выключен до ночи закрытия, поэтому включается явно на прогон);
W85_REPO=<каталог> — hostPath репозитория вместо /opt/ebpf-guard (бинарь и правила
из КОММИТА, стендовое дерево и рабочий агент не трогаются; внутри пода путь прежний).

Любой оставшийся путь хоста (/var/lib/ebpf-guard/, /run/, /var/log/, /etc/rancher/)
— отказ: молча переехавший путь дал бы под, пишущий в стор хоста или падающий
на запись (память die-only-for-unmeasurable-run — это неизмеримый прогон).
"""
import os
import sys

import yaml

POD_DIR = "/var/lib/ebpf-guard-pod"
HOST_PREFIXES = ("/var/lib/ebpf-guard/", "/run/", "/var/log/", "/etc/rancher/")
CHART_REQUIRED = ["syscall", "network", "fileaccess"]


def die(msg):
    sys.stderr.write("w82-pod-night-values: %s\n" % msg)
    sys.exit(1)


def setp(cfg, dotted, value, must_exist=True):
    keys = dotted.split(".")
    node = cfg
    for k in keys[:-1]:
        if not isinstance(node.get(k), dict):
            die("в конфиге нет секции %s (ключ %s) — схема переехала, замена не применится" % (k, dotted))
        node = node[k]
    if must_exist and keys[-1] not in node:
        die("в конфиге нет ключа %s — схема переехала, замена не применится" % dotted)
    node[keys[-1]] = value


def host_paths(node, prefix=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from host_paths(v, prefix + "." + str(k) if prefix else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from host_paths(v, "%s[%d]" % (prefix, i))
    elif isinstance(node, str) and node.startswith(HOST_PREFIXES):
        yield prefix, node


def build(cfg, tag, token):
    setp(cfg, "server.bind_address", ":19091")
    setp(cfg, "auth.admin_token", token)
    setp(cfg, "auth.viewer_token", token + "-viewer")
    setp(cfg, "store.backend", "memory")
    cfg["store"].pop("sqlite", None)
    setp(cfg, "profiler.state_persistence.path", POD_DIR + "/profiler-state.json")
    setp(cfg, "correlator.observer_exclude.root_pid_file", POD_DIR + "/observer-root-pid")
    setp(cfg, "enforcement.audit_log", POD_DIR + "/audit.jsonl")
    setp(cfg, "notifications.unix_socket.path", POD_DIR + "/alerts.sock")
    setp(cfg, "kubernetes.kubeconfig_path", "")
    if os.environ.get("W85_ARG_PREDICATES") == "1":
        kf = cfg.get("bpf", {}).get("kernel_filter")
        if not isinstance(kf, dict):
            die("в конфиге нет bpf.kernel_filter — F1 включить некуда")
        kf["arg_predicates"] = {"enabled": True, "counters_interval": "5s"}
    col = cfg.setdefault("collectors", {})
    if not col.get("required"):
        col["required"] = list(CHART_REQUIRED)
    left = list(host_paths(cfg))
    if left:
        die("остались пути хоста: " + ", ".join("%s=%s" % kv for kv in left))
    return {
        "image": {"repository": "zugolo/ebpf-guard", "tag": tag, "pullPolicy": "Never"},
        "namespaceCreate": False,
        # containerPort и пробы берутся из config.server.bind_address даже при configRaw.
        "config": {"server": {"bind_address": ":19091", "enable_pprof": True}},
        "workingDir": "/opt/ebpf-guard",
        "extraVolumes": [
            {"name": "repo", "hostPath": {"path": os.environ.get("W85_REPO", "/opt/ebpf-guard"), "type": "Directory"}},
            {"name": "pod-state", "hostPath": {"path": POD_DIR, "type": "DirectoryOrCreate"}},
        ],
        "extraVolumeMounts": [
            {"name": "repo", "mountPath": "/opt/ebpf-guard", "readOnly": True},
            {"name": "pod-state", "mountPath": POD_DIR},
        ],
        "configRaw": yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False),
    }


class _Dumper(yaml.SafeDumper):
    pass


# configRaw — блоком «|», а не экранированной строкой: values читаются глазами.
_Dumper.add_representer(str, lambda d, v: d.represent_scalar(
    "tag:yaml.org,2002:str", v, style="|" if "\n" in v else None))


def main():
    if len(sys.argv) != 5:
        die("usage: <config-test.yaml> <image tag> <token> <out values.yaml>")
    src, tag, token, out = sys.argv[1:]
    with open(src) as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        die("%s — не YAML-словарь" % src)
    rules = (cfg.get("rules") or {}).get("path", "")
    if not rules.startswith("/opt/ebpf-guard/"):
        die("rules.path=%r вне /opt/ebpf-guard — каталог правил в под не смонтирован" % rules)
    values = build(cfg, tag, token)
    with open(out, "w") as f:
        yaml.dump(values, f, Dumper=_Dumper, allow_unicode=True, sort_keys=False)
    print("values: %s (тег %s, правила %s, стор memory, состояние %s)" % (out, tag, rules, POD_DIR))


if __name__ == "__main__":
    main()
