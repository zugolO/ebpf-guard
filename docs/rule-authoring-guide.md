# Rule Authoring Guide

This guide explains how to write, validate, and unit-test detection rules for
ebpf-guard.

## Rule File Format

Rules are YAML files in the `rules/` directory.  Each file contains a `rules:`
list.  A minimal rule looks like:

```yaml
rules:
  - id: my_rule_001
    name: "Suspicious execve from web process"
    description: "Web server executed a shell — possible command injection."
    event_type: syscall
    condition:
      field: nr
      op: in
      values: ["59"]   # execve
    severity: critical
    action: alert
    tags: [rce, web]
```

### Required fields

| Field        | Description                                                  |
|-------------|--------------------------------------------------------------|
| `id`         | Unique rule identifier (snake_case, no spaces)               |
| `name`       | Short human-readable label                                    |
| `event_type` | Event category: `syscall`, `network`, `file`, `dns`, `tls`, `privesc` |
| `condition`  | Single condition **or** `condition_group` for AND/OR logic   |
| `severity`   | `warning` or `critical`                                      |
| `action`     | `alert`, `drop`, `block`, `kill`, or `throttle`              |

### Condition operators

| Operator    | Description                                              |
|-------------|----------------------------------------------------------|
| `in`        | Field value is in the list                               |
| `not_in`    | Field value is NOT in the list                           |
| `equals`    | Field equals a single value                              |
| `not_equals`| Field does not equal a value                             |
| `prefix`    | Field starts with any listed prefix                      |
| `suffix`    | Field ends with any listed suffix                        |
| `contains`  | Field contains any listed substring                      |
| `regex`     | Field matches any listed RE2 regular expression          |
| `gt` / `lt` | Numeric greater-than / less-than                         |
| `gte` / `lte` | Numeric greater-or-equal / less-or-equal               |
| `in_cidr`   | IP address falls within any listed CIDR                  |
| `not_in_cidr` | IP address is NOT within any listed CIDR               |
| `caps_gained` | Capability name was newly acquired (privesc events)    |
| `caps_dropped`| Capability name was dropped (privesc events)           |

### Event fields by type

**syscall** — `nr`, `ret`, `uid`, `comm`, `arg0`–`arg5`, `fd.name`, `proc.args`

**network** — `dport`, `sport`, `daddr`, `saddr`, `proto`, `family`, `proc.args`

**file** — `filename`, `op`, `flags`, `mode`, `fd.name`, `proc.args`

**dns** — `qname`, `qtype`, `rcode`, `direction`, `qname_length`, `qname_entropy`,
`qname_dga_score`, `qname_digit_ratio`, `qname_subdomain_count`, `qname_is_dga`

**tls** — `data` (or `tls_data`), `data_len`, `direction`

**privesc** — `caps` (bitmask hex string), `uid`, `comm`

### Complex logic with `condition_group`

Use `condition_group` with `operator: and` or `operator: or` to combine multiple
conditions:

```yaml
condition_group:
  operator: and
  conditions:
    - field: filename
      op: prefix
      values: ["/tmp/"]
    - field: filename
      op: suffix
      values: [".ko"]
```

Nested `subgroups` are supported for deeper logic.

---

## Unit Testing Rules

ebpf-guard includes a declarative YAML fixture framework for testing rules
without a real kernel, BPF program, or running agent.

### Writing a fixture file

Create a `*_test.yaml` file (conventionally in `tests/rules/`) for each rule
file you want to test:

```yaml
suite: my_rule_suite
rules_path: ../../rules/my-rules.yaml
tests:
  - name: "ptrace syscall fires proc_inject_ptrace"
    rule_id: proc_inject_ptrace
    event:
      type: syscall
      syscall:
        nr: 101   # ptrace
    expect: alert
    expect_severity: critical

  - name: "read syscall does not fire any injection rule"
    event:
      type: syscall
      syscall:
        nr: 0    # read
    expect: no_alert
```

#### Fixture schema

| Field            | Description                                                     |
|------------------|-----------------------------------------------------------------|
| `suite`          | Human-readable suite name (used in test output)                 |
| `rules_path`     | Path to the rule file(s) to load, relative to the fixture file  |
| `tests`          | List of test cases                                              |

Each test case:

| Field              | Description                                                   |
|--------------------|---------------------------------------------------------------|
| `name`             | Short description of what the test exercises                  |
| `rule_id`          | (optional) Documents which rule is under test                 |
| `event`            | Synthetic event spec (see below)                              |
| `expect`           | `alert`, `no_alert`, or `drop`                                |
| `expect_severity`  | (optional) `warning` or `critical` — asserts severity level   |
| `expect_rule_id`   | (optional) Specific rule ID that must fire                    |

#### Event spec fields

```yaml
event:
  type: syscall | network | file | dns | tls | privesc
  pid: 1234          # optional, defaults to 1
  uid: 0
  comm: "nginx"
  syscall:           # for type: syscall
    nr: 59
    ret: 0
    args: [0, 1, 2]
  network:           # for type: network
    src_ip: "10.0.0.1"
    dst_ip: "185.220.101.45"
    sport: 54321
    dport: 4444
    family: ipv4     # or ipv6
  file:              # for type: file
    filename: "/etc/shadow"
    op: open         # open | read | write
    flags: 0
  dns:               # for type: dns
    qname: "pool.supportxmr.com"
    qtype: 1         # A record
    rcode: 0
  tls:               # for type: tls
    data: "Authorization: Basic dXNlcjpwYXNz"
    data_len: 0      # optional override; defaults to len(data)
    direction: write # write (default) or read
  privesc:           # for type: privesc
    caps_gained: ["CAP_SYS_ADMIN"]
    caps_lost: []
    old_caps: 0      # raw bitmask alternative
    new_caps: 0
```

### Running fixture tests

**Via CLI** (no Go toolchain needed):

```bash
# Run all fixtures in tests/rules/
./build/ebpf-guard rules check ./tests/rules/ --rules ./rules/

# Run a single fixture file
./build/ebpf-guard rules check ./tests/rules/cryptominer_test.yaml

# Watch mode — re-runs on any YAML file change
./build/ebpf-guard rules check ./tests/rules/ --watch

# Write JUnit XML (for CI artifact upload)
./build/ebpf-guard rules check ./tests/rules/ --junit rule-results.xml
```

**Via Go test** (integrated with `go test ./...`):

```bash
# Run all rule fixtures as Go sub-tests
go test -v -race ./tests/...

# Or via the Makefile shortcut
make rule-test
```

**Via `make test`** — the rule fixtures are included automatically in the
full test suite.

### CI integration

The `.github/workflows/ci.yml` pipeline includes a dedicated **Rule Tests**
job that runs on every pull request.  PRs that touch `rules/` or
`tests/rules/` will trigger the rule test job and block merge if any fixture
fails.

You can also add custom rule tests to the same CI check by placing
`*_test.yaml` files in `tests/rules/` and pointing `rules_path` at your new
rule file.

### Programmatic use from Go tests

The `internal/testing` package exposes a `testing.T`-integrated runner:

```go
import ruletesting "github.com/zugolO/ebpf-guard/internal/testing"

func TestMyRules(t *testing.T) {
    // Run all fixtures in a directory
    ruletesting.RunDir(t, "testdata/rules", "../../rules")

    // Or a single fixture file
    ruletesting.RunFile(t, "testdata/rules/my_rule_test.yaml", "../../rules")
}
```

Each fixture test case surfaces as a named Go sub-test, compatible with
`go test -run`, parallel execution, and `-v` output.

---

## Hot-reload

Rules are watched with `fsnotify`.  Any change to a file under the configured
`rules.path` directory is picked up within one second without restarting the
agent.  You can verify hot-reload by watching `ebpf_guard_rules_loaded` in
Prometheus metrics.

## Exceptions

A rule either fires or it doesn't — but production environments have
legitimate processes (systemd, ldconfig, package managers) that regularly
trip detection rules like `container_escape_proc_write` or
`fim_library_replaced`. Editing the rule's own `condition` to carve out that
process is one option, but it's lost the next time the rule set is updated.

`exceptions` let you attach named suppression conditions to a rule: if the
event matches the rule's condition **and** any one of its exceptions, the
alert is suppressed instead of raised.

```yaml
rules:
  - id: container_escape_proc_write
    event_type: file
    condition:
      field: filename
      op: regex
      values: ["/proc/sys/.*"]
    severity: warning
    action: alert
    exceptions:
      - name: systemd-sysctl
        condition:
          field: proc.comm
          op: in
          values: [systemd, systemd-sysctl]
      - name: ldconfig
        condition_group:
          operator: and
          conditions:
            - { field: proc.comm, op: eq, values: [ldconfig.real] }
            - { field: file.path, op: prefix, values: ["/etc/ld.so"] }
```

Exceptions use the exact same condition language as rule conditions —
`condition` or `condition_group`, the same operators, the same field names
for the rule's `event_type` — and are validated at load time the same way:
unknown field names or operators are rejected before the rule set is
activated.

Every suppressed alert increments
`ebpf_guard_rule_exceptions_total{rule_id, exception_name}`, so you can see
exactly how much noise each exception is removing.

### Local-tuning overlay

Editing `exceptions:` directly into a shipped rule file still means your
change is lost on the next rule-set update. For exceptions you want to keep
across updates, add them to a separate overlay file instead — by default
`rules/local-tuning.yaml` (configurable via `rules.local_tuning_path`), which
is **not** part of the shipped rule set and is never touched by a rules
refresh. See [`rules/local-tuning.yaml.example`](../rules/local-tuning.yaml.example)
for the full format:

```yaml
overlays:
  - rule_id: container_escape_proc_write
    exceptions:
      - name: systemd-sysctl
        condition:
          field: proc.comm
          op: in
          values: [systemd, systemd-sysctl]
```

Each entry adds its `exceptions` to the existing rule matching `rule_id`, so
the base rule file is never modified. The overlay is loaded and merged
every time rules are (re)loaded — including hot-reload — so editing it takes
effect without restarting the agent, the same as any other rules change. A
`rule_id` that doesn't match a currently loaded rule is logged as a warning
and skipped rather than treated as a startup error, since the overlay may
reference rules from a currently-disabled rule set.

## Best practices

- Give every rule a globally unique, descriptive `id` (e.g. `cryptominer_pool_ports`).
- Write at least **two fixture cases per rule**: one positive (should alert) and
  one negative (should not alert on a benign event).
- Use `expect_rule_id` in positive tests to assert the *correct* rule fires, not
  just any rule.
- Use `expect_severity` to lock in the intended severity so accidental downgrades
  are caught in CI.
- Run `make rule-test` locally before opening a PR that touches `rules/`.
