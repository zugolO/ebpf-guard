package profiler

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zugolO/ebpf-guard/internal/procinfo"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, P1: LineageTracker как тонкое чтение таблицы процессов в ядре.
//
// Что ушло: Go-карты lineage/ancestry/procCache × 16 шардов, Track на каждом событии,
// /proc для предков дальше первого хопа, TTL-уборка и утечка ancestry (находка доводки
// 8.2). Вместе с ними ушла находка этапа 1 «Track не освежает цепочку для событий,
// отфильтрованных F1»: цепочку ведёт ядро на fork/exec/exit, а не поток событий.
//
// Что осталось прежним: контракт GetProcessTree (от корня к листу, pid 1 не входит,
// не более maxDepth звеньев с листовой стороны) и ParentOf (родитель и comm родителя).

// procSourceBox — обёртка для atomic.Pointer (интерфейс напрямую не кладётся).
type procSourceBox struct{ src procinfo.Source }

// Потребители чтения цепочки — значения label consumer метрики исходов.
const (
	chainConsumerTree   = "tree"   // GetProcessTree: дерево алерта/инцидента
	chainConsumerParent = "parent" // ParentOf: обход proc.ancestor_exe_path
	chainConsumerField  = "field"  // поля proc.lineage / proc.lineage_exe_paths
)

var lineageChainReads = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_proc_chain_reads_total",
		Help: "Reads of the ancestor chain from the in-kernel process table by consumer (tree, parent, field) and outcome: resolved (reached the root, every hop present and consistent), broken (a parent started after its child — pid reused), exhausted (depth limit before the root), evicted (a hop's record is absent: evicted by the LRU, past its TTL, or the process predates the agent).",
	},
	[]string{"consumer", "outcome"},
)

// lineageProcReads — чтения /proc/<pid>/status трекером (метка 8.5.5: ноль на горячем пути).
var lineageProcReads = promauto.NewCounter(prometheus.CounterOpts{
	Name: "ebpf_guard_lineage_proc_reads_total",
	Help: "Reads of /proc/<pid>/status by the lineage tracker. With the in-kernel process table active this stays flat; any growth is the /proc fallback at work.",
})

func init() {
	// Материализация с нуля: прогон без единого чтения обязан отличаться в /metrics от бинаря без прибора.
	for _, c := range []string{chainConsumerTree, chainConsumerParent, chainConsumerField} {
		for _, o := range procinfo.Outcomes {
			lineageChainReads.WithLabelValues(c, string(o))
		}
	}
}

func recordChain(consumer string, o procinfo.Outcome) {
	lineageChainReads.WithLabelValues(consumer, string(o)).Inc()
}

// SetProcSource переключает трекер на таблицу процессов в ядре; nil возвращает прежний путь.
func (lt *LineageTracker) SetProcSource(src procinfo.Source) {
	if src == nil {
		lt.table.Store(nil)
		return
	}
	lt.table.Store(&procSourceBox{src: src})
}

// HasProcSource — включена ли таблица ядра.
func (lt *LineageTracker) HasProcSource() bool { return lt.table.Load() != nil }

// tableTree — дерево предков pid: от корня к листу, не более maxDepth звеньев с листовой стороны.
func (lt *LineageTracker) tableTree(src procinfo.Source, pid uint32) types.ProcessTree {
	chain, outcome := procinfo.Walk(src, pid, lt.maxDepth)
	recordChain(chainConsumerTree, outcome)
	if len(chain) == 0 {
		return nil
	}
	tree := make(types.ProcessTree, len(chain))
	for i, r := range chain { // chain — от листа к корню
		tree[len(chain)-1-i] = types.ProcessNode{PID: r.PID, PPID: r.PPID, Comm: r.Comm}
	}
	return tree
}

// tableParentOf — родитель pid и comm родителя. ok=false: про pid ничего нет или родитель
// несогласован (pid переиспользован) — вызывающая сторона прекращает обход.
func (lt *LineageTracker) tableParentOf(src procinfo.Source, pid uint32) (uint32, string, bool) {
	rec, res := src.Lookup(pid)
	if res != procinfo.Found || rec.PPID == 0 {
		recordChain(chainConsumerParent, procinfo.OutcomeEvicted)
		return 0, "", false
	}
	prec, pres := src.Lookup(rec.PPID)
	switch {
	case pres != procinfo.Found:
		// родитель известен номером (ядро проставило ppid), но записи нет: обход дальше
		// невозможен, comm неизвестен — отдаём пустой, вызывающая сторона увидит расхождение comm
		recordChain(chainConsumerParent, procinfo.OutcomeEvicted)
		return rec.PPID, "", true
	case prec.StartBoottimeNs != 0 && rec.StartBoottimeNs != 0 &&
		prec.StartBoottimeNs > rec.StartBoottimeNs+procinfo.StartToleranceNs:
		recordChain(chainConsumerParent, procinfo.OutcomeBroken)
		return 0, "", false
	}
	recordChain(chainConsumerParent, procinfo.OutcomeResolved)
	return rec.PPID, prec.Comm, true
}

// tableParentInfo — родитель и его comm для события e (контракт getParentInfo без /proc):
// сперва то, что проставило ядро в самом событии, затем запись таблицы.
func (lt *LineageTracker) tableParentInfo(src procinfo.Source, e types.Event) (uint32, string) {
	ppid := e.PPID
	if ppid == 0 {
		rec, res := src.Lookup(e.PID)
		if res != procinfo.Found {
			return 0, ""
		}
		ppid = rec.PPID
		if ppid == 0 {
			return 0, ""
		}
	} else if comm := cleanComm(e.ParentComm[:]); comm != "" {
		return ppid, comm
	}
	if prec, res := src.Lookup(ppid); res == procinfo.Found {
		return ppid, prec.Comm
	}
	return ppid, ""
}

// AncestorChain отдаёт непрерывную цепочку ПРЕДКОВ pid (без самого pid) — от корня к родителю —
// вместе с исходом обхода. Для полей proc.lineage*: звенья за первым несогласованным/отсутствующим
// не возвращаются, поэтому «предок X по непрерывной цепочке» не может опереться на разрыв.
// ok=false — таблицы нет (прежний путь), обход не выполнялся.
func (lt *LineageTracker) AncestorChain(pid uint32) (anc []procinfo.Record, outcome procinfo.Outcome, ok bool) {
	box := lt.table.Load()
	if box == nil {
		return nil, "", false
	}
	chain, outcome := procinfo.Walk(box.src, pid, lt.maxDepth+1) // +1: лист в предки не входит
	recordChain(chainConsumerField, outcome)
	if len(chain) <= 1 {
		return nil, outcome, true
	}
	anc = make([]procinfo.Record, 0, len(chain)-1)
	for i := len(chain) - 1; i >= 1; i-- { // от корня к родителю
		anc = append(anc, chain[i])
	}
	return anc, outcome, true
}
