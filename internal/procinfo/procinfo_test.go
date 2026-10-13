package procinfo

import "testing"

type tbl map[uint32]Record

func (t tbl) Lookup(pid uint32) (Record, Result) {
	r, ok := t[pid]
	if !ok {
		return Record{}, Absent
	}
	return r, Found
}

func TestWalk_RootConventionAndOrder(t *testing.T) {
	src := tbl{
		100: {PPID: 1, Comm: "cron", StartBoottimeNs: 10},
		101: {PPID: 100, Comm: "sh", StartBoottimeNs: 20},
	}
	chain, out := Walk(src, 101, 8)
	if out != OutcomeResolved || len(chain) != 2 || chain[0].PID != 101 || chain[1].PID != 100 {
		t.Fatalf("chain=%+v out=%s (лист первым, pid 1 не входит)", chain, out)
	}
	if chain, out = Walk(src, 1, 8); len(chain) != 0 || out != OutcomeResolved {
		t.Fatalf("pid 1: %+v %s", chain, out)
	}
	if chain, out = Walk(src, 999, 8); len(chain) != 0 || out != OutcomeEvicted {
		t.Fatalf("неизвестный лист: %+v %s", chain, out)
	}
}

func TestWalk_NonPositiveDepthDefaults(t *testing.T) {
	src := tbl{100: {PPID: 1, StartBoottimeNs: 1}}
	if chain, _ := Walk(src, 100, 0); len(chain) != 1 {
		t.Fatalf("depth 0 должен брать значение по умолчанию: %+v", chain)
	}
}

// Время старта неизвестно (0) — проверка непрерывности по нему пропускается, а не ломает цепочку.
func TestWalk_UnknownStartIsNotBroken(t *testing.T) {
	src := tbl{100: {PPID: 1, Comm: "a"}, 101: {PPID: 100, Comm: "b", StartBoottimeNs: 5}}
	if chain, out := Walk(src, 101, 8); out != OutcomeResolved || len(chain) != 2 {
		t.Fatalf("chain=%+v out=%s", chain, out)
	}
}
