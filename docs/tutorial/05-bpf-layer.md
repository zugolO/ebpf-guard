# Глава 5. BPF-слой (`bpf/*.bpf.c`)

> Уровень: **средний**. Предполагает главы [2](02-ebpf-basics.md) и [4](04-architecture.md).

## Зачем это нужно

Глава 2 объяснила общие механизмы eBPF (verifier, JIT, точки прикрепления,
ring buffer, BTF/CO-RE). Глава 4 показала, где BPF-слой находится в общей
картине. Эта глава — конкретика: какие именно 14 BPF-программ лежат в
`bpf/`, за что каждая цепляется в ядре и что производит. Это справочник,
к которому удобно возвращаться при чтении кода коллекторов (глава 6) или
при написании нового правила, использующего поле из конкретного события.

## Программы и точки прикрепления

Все программы объявлены через макрос `SEC(...)` из libbpf — именно эта
строка сообщает ядру (или загрузчику), к какой точке прикрепить программу
при загрузке (см. главу 2 про типы точек).

| Файл | `SEC(...)` (строка) | Что цепляет | Зачем |
|---|---|---|---|
| `syscall.bpf.c` | `tp/raw_syscalls/sys_enter` (42), `tp/raw_syscalls/sys_exit` (93), `tp/sched/sched_process_exec` (156) | Вход/выход из **любого** системного вызова + событие `exec` | Базовая syscall-телеметрия и захват аргументов `execve` (командная строка процесса) |
| `network.bpf.c` | `kprobe/tcp_connect` (51), `kprobe/tcp_close` (175) | Функции ядра `tcp_connect`/`tcp_close` | Начало и завершение TCP-соединений, включая длительность |
| `fileaccess.bpf.c` | `sys_enter_openat` (108), `sys_exit_openat` (137), `sys_exit_openat2` (150), `sys_enter_close` (164), `sys_enter_read` (181), `sys_enter_write` (213) | Файловые syscalls | Открытие/чтение/запись файлов — основа для `container-escape.yaml` и подобных правил по `path` |
| `dns.bpf.c` | `sys_enter_connect` (221), `sys_enter_close` (246), `sys_enter_write` (261), `sys_enter_writev` (284), `sys_enter_read` (312), `sys_exit_read` (333), `sys_enter_recvfrom` (353), `sys_exit_recvfrom` (373), `sys_enter_sendmmsg` (402), `sys_enter_recvmsg` (436), `sys_exit_recvmsg` (471), `sys_enter_sendmsg` (490), `sys_enter_sendto` (530) | Сокетные syscalls на UDP/53 | Разбор DNS-пакетов прямо в BPF, до копирования в userspace (см. CLAUDE.md: «early BPF-side filter») |
| `tls_uprobe.bpf.c` | `uprobe/SSL_write` (102), `uprobe/SSL_read` (179), `uretprobe/SSL_read_full` (204) | Функции OpenSSL/BoringSSL внутри `libssl.so` | Захват TLS-payload **до** шифрования / **после** расшифровки (plaintext TLS inspection, глава 17) |
| `tls_clienthello.bpf.c` | `kprobe/__x64_sys_sendto` (105) | Первый пакет TLS-рукопожатия | Захват ClientHello для JA3/JA4-фингерпринтинга (глава 17) |
| `http_uprobe.bpf.c` | `uprobe/read` (187), `uprobe/recv` (194), `uretprobe/read` (267), `uretprobe/recv` (273) | libc `read`/`recv` | Захват незашифрованного HTTP-трафика |
| `lsm.bpf.c` | `lsm/bpf_file_open` (139), `lsm/bpf_socket_connect` (193), `lsm/bpf_task_kill` (298), `lsm/kernel_module_request` (334), `lsm/kernel_read_file` (388), `tp/sched/sched_process_exec` (444) | LSM hook-и (открытие файла, сетевое соединение, kill, загрузка модуля, чтение файла ядром) | Единственный слой, способный **заблокировать** действие синхронно (`-EPERM`), а не просто увидеть его постфактум — требует ядро 5.7+ |
| `xdp_block.bpf.c` | `xdp` (66) | Сетевая карта, максимально рано | Блокировка по IP/порту на скорости линии, до входа пакета в сетевой стек ядра |
| `cgroup.bpf.c` | `lsm/cgroup_attach_task` (53) | Присоединение процесса к cgroup | Детекция попытки сбежать из cgroup-неймспейса контейнера |
| `privesc.bpf.c` | `sys_enter_capset` (71), `kprobe/commit_creds` (101) | Изменение capabilities / credentials процесса | Детекция повышения привилегий |
| `hidden_process.bpf.c` | `iter/task` (31) | BPF task iterator (обход списка процессов ядра) | Сравнение списка процессов, видимого ядру, со списком из `/proc` — детекция скрытых процессов (руткиты) |
| `iouring.bpf.c` | `kprobe/__x64_sys_io_uring_setup` (44), `kprobe/__x64_sys_io_uring_enter` (94) | Syscalls `io_uring_setup`/`io_uring_enter` | Детекция злоупотребления io_uring как способом обхода классических syscall-хуков |
| `gpu_uprobe.bpf.c` | Uprobes/uretprobes на `cuMemAlloc_v2` (137/158), `cuMemFree_v2` (197), `cuMemcpyDtoH_v2` (225), `cuMemcpyDtoHAsync_v2` (258), `cuMemcpyHtoD_v2` (290), `cuMemcpyHtoDAsync_v2` (322), `cudaMalloc` (354/372), `cudaFree` (409), `cudaMemcpy` (438), `cuLaunchKernel` (484) | Функции CUDA-рантайма (`libcuda`/`libcudart`) | Мониторинг операций с GPU-памятью — детекция GPU-майнинга и утечки данных через видеопамять |
| `bpf_monitor.bpf.c` | `kprobe/__x64_sys_bpf` (117), `kretprobe/__x64_sys_bpf` (152) | Сам syscall `bpf()` | Наблюдение за загрузкой сторонних BPF-программ/maps — детекция BPF-руткитов, которые пытаются спрятаться от того же самого ebpf-guard |

`bpf/vmlinux.h` не входит в этот список — это не отдельная программа, а
сгенерированный заголовок с типами ядра для CO-RE (глава 2).

## `common.h`: общий контракт между C и Go

`bpf/common.h` определяет идентификаторы типов событий (`common.h:31-43`,
например `EVENT_TYPE_SYSCALL 1`, `EVENT_TYPE_TCP_CONNECT 2`, ...,
`EVENT_TYPE_BPF_PROGRAM 15`) и структуру `struct event` (`common.h:73`),
общую для всех программ, публикующих события в ring buffer. Комментарий
прямо над структурой (`common.h:74-75`) формулирует главное инвариант этого
файла:

> Layout must match exactly with Go struct Event in `pkg/types/event.go`.

То есть `struct event` в C и `types.Event` в Go — это **один и тот же**
двоичный макет данных, описанный дважды: один раз для компилятора C
(байткод eBPF), один раз для Go (парсинг байтов из ring buffer). Если поля
разъедутся по смещению или размеру — события будут читаться с мусором
вместо реальных данных, без ошибки компиляции. Как раз поэтому изменение
`common.h` требует пересборки через `make generate` (глава 2) — и
пересмотра парсера на Go-стороне (глава 6).

## От `.bpf.c` к `*_gen.go`

`make generate` (`Makefile:51-65`) выполняет два шага:

1. Если на машине доступен `/sys/kernel/btf/vmlinux`, перегенерирует
   `bpf/vmlinux.h` под текущее ядро через `bpftool btf dump`
   (`Makefile:54-57`); иначе использует уже закоммиченный файл
   (`Makefile:58-60`).
2. Запускает `GOPACKAGE=bpf go generate ./internal/bpf/...`
   (`Makefile:63`) — это раскручивает `//go:generate` директивы,
   встроенные в файлы `internal/bpf/*.go`, каждая из которых вызывает
   `bpf2go` для соответствующего `.bpf.c`-файла. `bpf2go`:
   - компилирует `.bpf.c` в eBPF-байткод (`clang -target bpf`);
   - встраивает скомпилированный байткод в Go-файл как `[]byte`;
   - генерирует типизированные Go-обёртки над maps и программами
     (например, `internal/bpf/xdp_bpf_gen.go` для `xdp_block.bpf.c`) —
     без них пришлось бы вручную работать с сырыми файловыми
     дескрипторами BPF-объектов через syscall `bpf()`.

После генерации `Makefile:65` удаляет два файла-заглушки
(`syscall_bpf_gen.go`, `xdp_bpf_gen.go`), которые в репозитории существуют
только как плейсхолдеры для случая, когда `make generate` ещё не
запускался — реальная сгенерированная версия их полностью заменяет.

## Как это связано с главой 6

Каждая строка из таблицы выше соответствует Go-файлу в
`internal/collector/`, который открывает эту BPF-программу, подписывается
на её ring buffer и превращает сырые байты `struct event` в
`pkg/types.Event`. Это — тема следующей главы.

## Дальше почитать

- [libbpf documentation](https://libbpf.readthedocs.io/) — библиотека, на API которой построена загрузка BPF-объектов.
- [cilium/ebpf: bpf2go](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) — генератор Go-биндингов.
- [Kernel docs: tracepoint format](https://www.kernel.org/doc/html/latest/trace/tracepoints.html) — формат `tp/...` точек, использованных в `syscall.bpf.c`/`dns.bpf.c`.
- [Kernel docs: LSM eBPF](https://docs.kernel.org/bpf/prog_lsm.html) — официальная документация по `lsm/*` hook-ам, использованным в `lsm.bpf.c`.

## Глоссарий

- **`SEC(...)`** — макрос libbpf, определяющий, к какой точке ядра прикрепляется eBPF-программа при загрузке.
- **Kprobe/uprobe/tracepoint/LSM/XDP** — типы точек прикрепления, разобраны подробно в [главе 2](02-ebpf-basics.md#где-ebpf-программа-может-зацепиться-за-ядро).
- **`bpf2go`** — генератор типизированных Go-обёрток вокруг скомпилированного eBPF-байткода.
- **`struct event`** — общая C/Go структура события, определённая в `bpf/common.h` и зеркально отражённая в `pkg/types/event.go`.

---

**Назад:** [Глава 4. Архитектура и поток событий](04-architecture.md) · **Далее:** [Глава 6. Коллекторы](06-collectors.md)
