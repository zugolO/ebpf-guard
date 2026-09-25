package collector

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// upRecorder keeps every SetUp call a collector makes, in order.
type upRecorder struct {
	mu    sync.Mutex
	calls []bool
}

func (r *upRecorder) SetUp(_ string, up bool) {
	r.mu.Lock()
	r.calls = append(r.calls, up)
	r.mu.Unlock()
}

func (r *upRecorder) snapshot() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.calls...)
}

// TestCollectorUp_NoLoadMeansNotUp — item 6 волны 6.5. После №457 «0» честно
// предъявлял только lsm, и то как свойство ядра стенда; у остальных «1» была
// безусловна по аналогии. Тест берёт КАЖДЫЙ коллектор, у которого есть хук
// репортёра, и судит его ПО ФАКТИЧЕСКОМУ ИСХОДУ ЗАГРУЗКИ, а не по платформе:
//
//   - загрузка НЕ удалась (хост без BPF — mac, или ядро без хука): ни одного
//     `SetUp(true)`. Репортёр, сказавший «up» без загруженного объекта, лжёт
//     единицей (№438);
//   - загрузка УДАЛАСЬ (способное ядро — стенд): «up» законен, и проверяется
//     то, что на способном хосте вообще проверяемо — репортёр ВЫЗВАН, то есть
//     серия перестала быть оптимистичной единицей, выставленной main до Start.
//
// №470 (25.09.2026). Первая версия требовала «ни одного true» БЕЗУСЛОВНО и
// была зелёной только потому, что писалась на mac, где BPF не грузится вовсе.
// На стенде она покраснела восемью подтестами на ЗДОРОВЫХ коллекторах. Это
// ровно дефект, уже записанный за `TestXDPManager_LoadBPF_StubDegradesToLogOnly`:
// тест, держащийся на неспособности окружения, а не на инъекции сбоя, падает
// на любом способном Linux-хосте. Отрицательную половину (ложь единицей)
// доказывает прогон на mac, положительную (проводка) — прогон на стенде;
// ни одна из них не выводится из другой, поэтому названы обе.
func TestCollectorUp_NoLoadMeansNotUp(t *testing.T) {
	log := slog.Default()
	type startable interface {
		Start(context.Context, chan<- types.Event) error
	}
	mk := func(t *testing.T, name string, rec *upRecorder) startable {
		t.Helper()
		var (
			c   startable
			err error
		)
		switch name {
		case "syscall":
			x, e := NewSyscallCollector(log)
			c, err = x.WithStatusReporter(rec), e
		case "network":
			x, e := NewNetworkCollector(log)
			c, err = x.WithStatusReporter(rec), e
		case "fileaccess":
			x, e := NewFileaccessCollector(log)
			c, err = x.WithStatusReporter(rec), e
		case "iouring":
			x, e := NewIOUringCollector(log)
			c, err = x.WithStatusReporter(rec), e
		case "privesc":
			x, e := NewPrivescCollector(log)
			c, err = x.WithStatusReporter(rec), e
		case "bpfmonitor":
			x, e := NewBPFMonitorCollector(log)
			c, err = x.WithStatusReporter(rec), e
		case "tlsfingerprint":
			x, e := NewTLSFingerprintCollector(log)
			c, err = x.WithStatusReporter(rec), e
		case "kmod":
			x, e := NewKmodCollector(log)
			c, err = x.WithStatusReporter(rec), e
		case "dns-disabled":
			// The one series that lied unconditionally in a run: dns is
			// constructed even when config disables it, and until item 6
			// волны 6.5 it had no reporter at all, so main's optimistic 1
			// stood for the whole run.
			x, e := NewDNSCollector(false)
			c, err = x.WithStatusReporter(rec), e
		case "dns":
			x, e := NewDNSCollector(true)
			if e != nil {
				// No BPF host (mac): the constructor fails before Start, so
				// there is no reporter path to judge. Named skip, not a pass.
				t.Skipf("dns: constructor needs a BPF host: %v", e)
			}
			c, err = x.WithStatusReporter(rec), e
		}
		require.NoError(t, err)
		return c
	}

	for _, name := range []string{"syscall", "network", "fileaccess", "iouring",
		"privesc", "bpfmonitor", "tlsfingerprint", "kmod", "dns", "dns-disabled"} {
		t.Run(name, func(t *testing.T) {
			rec := &upRecorder{}
			c := mk(t, name, rec)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			// Start НЕ вызывается синхронно: у dns на способном ядре он не
			// возвращается по ctx и держал подтест 363 с (№470). Ждём ровно
			// свой срок и судим по записанному, а не по возврату.
			errc := make(chan error, 1)
			go func() { errc <- c.Start(ctx, make(chan types.Event, 1)) }()
			var (
				err      error
				returned bool
			)
			select {
			case err = <-errc:
				returned = true
			case <-time.After(3 * time.Second):
			}
			cancel()
			calls := rec.snapshot()
			// СТОРОЖ ЛОЖНОГО PASS, общий для ОБЕИХ ветвей. «Ни одного true»
			// выполняется и у коллектора, который не позвал репортёра ВОВСЕ —
			// а тогда серия остаётся на оптимистичной единице, выставленной
			// main до Start, и тест зеленеет ровно на том дефекте, ради
			// которого заведён ([[false-pass-sentinel-must-share-the-axis]]).
			require.NotEmptyf(t, calls, "%s never called the reporter: collector_up keeps main's pre-Start 1", name)
			if returned && err != nil {
				// Загрузка не удалась — предъявляется отрицательная половина.
				for _, up := range calls {
					require.Falsef(t, up, "%s reported up without a loaded BPF object (err=%v, calls=%v)", name, err, calls)
				}
				t.Logf("%s: загрузка не удалась (%v) — проверено, что «up» не прозвучал: calls=%v", name, err, calls)
				return
			}
			// Start не сообщил об ошибке (или ещё идёт): судить «up» нулём
			// здесь значило бы требовать неспособного ЯДРА, а не годного кода
			// ([[gated-metric-cannot-carry-product-verdict]]). Проверяется то,
			// что на способном хосте проверяемо — репортёр вызван.
			t.Logf("%s: Start об ошибке не сообщил (returned=%v) — проверена ПРОВОДКА репортёра: calls=%v", name, returned, calls)
		})
	}
}
