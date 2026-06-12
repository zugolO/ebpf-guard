# Comparative Benchmark: Tool Installation Guide

This document explains how to install the pinned competitor versions required for
full end-to-end comparison via `bench/comparative/run.sh`.

For the **automated path**, use the Vagrantfile:

```bash
vagrant up    # provisions Ubuntu 22.04 + all tools automatically
vagrant ssh -c "cd /vagrant && bench/comparative/run.sh"
```

---

## Pinned versions

| Tool     | Version | Reference machine                     |
|----------|---------|---------------------------------------|
| Falco    | 0.38.1  | Ubuntu 22.04, kernel 6.1 LTS, x86-64 |
| Tetragon | 1.1.0   | Ubuntu 22.04, kernel 6.1 LTS, x86-64 |
| Tracee   | 0.21.0  | Ubuntu 22.04, kernel 6.1 LTS, x86-64 |

---

## Falco 0.38.1

```bash
# Download the pre-built deb (requires kernel headers).
FALCO_VERSION=0.38.1
curl -fsSL -o /tmp/falco.deb \
  "https://github.com/falcosecurity/falco/releases/download/${FALCO_VERSION}/falco_${FALCO_VERSION}_amd64.deb"

sudo dpkg -i /tmp/falco.deb || sudo apt-get -f install -y
falco --version   # must print 0.38.1

# Verify the required kernel module or modern-bpf driver loads:
sudo falco --modern-bpf --version
```

Falco requires either the kernel module or the modern-bpf probe.
On kernel 5.8+, `--modern-bpf` is the recommended probe.

---

## Tetragon 1.1.0

```bash
TETRAGON_VERSION=1.1.0
curl -fsSL -o /tmp/tetragon.tar.gz \
  "https://github.com/cilium/tetragon/releases/download/v${TETRAGON_VERSION}/tetragon-linux-amd64.tar.gz"

sudo tar -C /usr/local/bin -xzf /tmp/tetragon.tar.gz --strip-components=1 tetragon
tetragon version   # must print 1.1.0
```

Tetragon requires kernel 5.4+ and BTF (`/sys/kernel/btf/vmlinux`).

---

## Tracee 0.21.0

```bash
TRACEE_VERSION=0.21.0
sudo curl -fsSL -o /usr/local/bin/tracee \
  "https://github.com/aquasecurity/tracee/releases/download/v${TRACEE_VERSION}/tracee-linux-amd64"
sudo chmod +x /usr/local/bin/tracee
tracee version   # must print 0.21.0
```

Tracee requires kernel 5.8+ and BTF. Run as root or with `CAP_BPF + CAP_PERFMON`.

---

## Verification

After installing all tools, verify they are at the correct versions:

```bash
falco --version | grep 0.38.1
tetragon version | grep 1.1.0
tracee version | grep 0.21.0
```

Then run the full benchmark:

```bash
sudo bench/comparative/run.sh
```

The script will print `SKIP: <tool> not installed` for any tool that is missing
rather than failing — allowing partial runs (e.g., ebpf-guard only).
