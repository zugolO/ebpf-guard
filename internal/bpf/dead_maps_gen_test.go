//go:build bpfgen && (386 || amd64)

// Волна 8.2, B1 (№537): карта, на которую не ссылается ни одна программа
// объекта, всё равно создаётся ядром (она есть в поле *Maps объекта). Каждый
// объект, включающий common.h, получал свою копию каждой карты — по пять
// экземпляров одного имени, из них четыре мёртвых.
//
// Тест читает НАСТОЯЩИЕ объекты bpf2go (`make generate`), поэтому собирается
// только с тегом bpfgen — на mac, где BPF-бэкенда нет, он не участвует:
//
//	go test -tags bpfgen -run TestW82 ./internal/bpf/
//
// Печатает таблицу «объект: карты / мёртвые / кольца» — вход метки 8.2.4.
package bpf

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func w82Specs(t *testing.T) map[string]*ebpf.CollectionSpec {
	t.Helper()
	loaders := map[string]func() (*ebpf.CollectionSpec, error){
		"syscall": LoadSyscall, "network": LoadNetwork, "fileaccess": LoadFileaccess,
		"privesc": LoadPrivesc, "dns": LoadDNS, "iouring": LoadIouring,
		"bpfmonitor": LoadBpfMonitor, "kmod": LoadKmod, "cgroup": LoadCgroup,
		"hiddenprocess": LoadHiddenProcess, "tlsclienthello": LoadTlsClientHello,
		"tlsuprobe": LoadTlsUprobe, "httpuprobe": LoadHttpUprobe,
		"xdp": LoadXDP, "gpuuprobe": LoadGpuUprobe,
	}
	out := make(map[string]*ebpf.CollectionSpec, len(loaders))
	for name, load := range loaders {
		spec, err := load()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = spec
	}
	return out
}

// w82DeadMaps returns the maps of spec no program references. Ring buffers
// are never "referenced" by symbol alone when a program only calls
// bpf_ringbuf_reserve through the pointer, but the loader still emits a
// LoadMapPtr for it, so the same rule applies to them.
func w82DeadMaps(spec *ebpf.CollectionSpec) []string {
	used := map[string]bool{}
	for _, p := range spec.Programs {
		for _, ins := range p.Instructions {
			if ins.IsLoadFromMap() || ins.IsConstantLoad(0) {
				if ref := ins.Reference(); ref != "" {
					used[ref] = true
				}
			}
		}
	}
	var dead []string
	for name := range spec.Maps {
		if !used[name] {
			dead = append(dead, name)
		}
	}
	sort.Strings(dead)
	return dead
}

func TestW82_NoDeadMapsInObjects(t *testing.T) {
	specs := w82Specs(t)
	names := make([]string, 0, len(specs))
	for n := range specs {
		names = append(names, n)
	}
	sort.Strings(names)

	var report strings.Builder
	var failures []string
	var ringBytes, mapBytes uint64
	for _, n := range names {
		spec := specs[n]
		dead := w82DeadMaps(spec)
		for _, m := range spec.Maps {
			if m.Type == ebpf.RingBuf {
				ringBytes += uint64(m.MaxEntries)
			}
		}
		fmt.Fprintf(&report, "%-15s maps=%2d dead=%d %s\n", n, len(spec.Maps), len(dead), strings.Join(dead, ","))
		for _, d := range dead {
			failures = append(failures, n+"."+d)
		}
		_ = mapBytes
	}
	t.Logf("карты по объектам (8.2.4):\n%s", report.String())
	t.Logf("кольца суммарно: %.1f МиБ (размер объявления в C; во время работы задаётся из Go)", float64(ringBytes)/(1<<20))
	if len(failures) != 0 {
		t.Errorf("8.2.4 ПРОВАЛЕН: карт без программ %d: %s", len(failures), strings.Join(failures, " "))
	}
}
