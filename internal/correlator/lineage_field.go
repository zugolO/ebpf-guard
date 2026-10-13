package correlator

import (
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zugolO/ebpf-guard/internal/procinfo"
)

// Волна 8.4.1 (на таблице процессов ядра, волна 8.5 P1): поля proc.lineage и
// proc.lineage_exe_paths.
//
// ЗАЧЕМ. proc.ancestor_exe_path — не родословная (хоп 1 + участок одного comm, память
// ancestor-exe-path-is-not-lineage): maintainer-скрипт под dpkg запускает sh/perl, comm
// предков расходятся, и обход встаёт на первом хопе. Здесь — НАСТОЯЩАЯ цепочка из ядра:
// ppid проставляет fork, образ и exec-filename — exec, время старта — ядро, поэтому
// подделка argv[0]/comm (exec -a dpkg) цепочку не меняет.
//
// ЧТО ЭТО ЗА ЗНАЧЕНИЕ. Строка из звеньев ПРЕДКОВ (сам процесс не входит) от корня к родителю,
// звенья разделены "\n":
//
//	proc.lineage            "<образ>\t<exec-filename>" на звено
//	proc.lineage_exe_paths  "<образ>" на звено
//
// «?» — не разрешилось (образ без проверяемого пути; нет exec-filename: засеянный из /proc
// процесс или прямой fork без exec). Образ — путь, сверенный по inode (procinfo.ImageCache);
// exec-filename — bprm->filename последнего exec: для шебанг-скрипта это путь САМОГО скрипта,
// а образ звена — интерпретатор.
//
// ПОЧЕМУ ТАКАЯ ФОРМА, А НЕ ОПЕРАТОР «ПРЕДОК С ОБРАЗОМ X». Условие 8.4.2 порядковое: «dpkg выше,
// между ним и systemctl — maintainer-скрипт». Оператор «предок X» порядка не выражает; два
// несвязанных поля тоже (нельзя связать звено в одном поле со звеном в другом). Строка с
// порядком звеньев и существующий оператор regex (RE2) порядок выражают, не меняя загрузчик
// правил: новое поле — единственное, что нужно загрузчику («неизвестное поле отвергается»,
// поле и бинарь едут вместе).
//
// НЕПРЕРЫВНОСТЬ. Звенья за первым отсутствующим/несогласованным (pid переиспользован, запись
// вытеснена, TTL) в значение не входят: «предок dpkg» нельзя вывести через разрыв. Предел
// глубины обрезает со стороны КОРНЯ — потеря корня не создаёт предка, которого нет.
//
// АНТИСПУФ-ИНЪЕКЦИЯ. exec-filename и путь образа — данные, которыми распоряжается
// атакующий (имя файла может содержать "\n" и "\t"): без нейтрализации такое имя подделало бы
// соседнее звено прямо в значении. Управляющие символы заменяются на «?».
//
// ПОРЯДОК УСЛОВИЙ. Как у exe_path: условие на это поле — ПОСЛЕДНЕЕ в группе "and" (чтение
// таблицы — syscall на каждое звено, чтение образа — stat/readlink на промахе кэша).
// Нет таблицы (ядро без поддержки, dry-run) — значение пусто, исключение не применяется,
// правило срабатывает: тот же отказ «в сторону шума», что у всех осей идентичности.

const (
	lineageFieldFull   = "lineage"
	lineageFieldImages = "lineage_exe_paths"
)

// LineageChainResolver отдаёт непрерывную цепочку предков pid (от корня к родителю).
// Реализуется profiler.LineageTracker. ok=false — таблицы процессов нет.
type LineageChainResolver interface {
	AncestorChain(pid uint32) (anc []procinfo.Record, outcome procinfo.Outcome, ok bool)
}

type lineageResolverHolder struct{ r LineageChainResolver }

var lineageResolver atomic.Value // lineageResolverHolder

// lineageImages — кэш «inode → путь образа» поля; общий на процесс.
var lineageImages = procinfo.NewImageCache(4096)

// LineageImages — кэш образов, который main наполняет при засеве из /proc.
func LineageImages() *procinfo.ImageCache { return lineageImages }

// SetLineageChainResolver подключает источник цепочки. nil отключает поле (значение пусто).
func SetLineageChainResolver(r LineageChainResolver) {
	lineageResolver.Store(lineageResolverHolder{r: r})
}

var lineageFieldResults = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_lineage_field_total",
		Help: "Evaluations of proc.lineage / proc.lineage_exe_paths by field and result: resolved (a chain of at least one ancestor), empty (the table has the process but no ancestors under init), no_table (no process table — the field is empty and exceptions on it do not apply).",
	},
	[]string{"field", "result"},
)

var lineageImageResults = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_lineage_image_total",
		Help: "Resolutions of an ancestor's image path for proc.lineage by result: cached, proc (readlink /proc/<pid>/exe of a live ancestor, verified by inode), filename (exec filename from the table, verified by inode), unresolved.",
	},
	[]string{"result"},
)

func init() {
	for _, f := range []string{lineageFieldFull, lineageFieldImages} {
		for _, r := range []string{"resolved", "empty", "no_table"} {
			lineageFieldResults.WithLabelValues(f, r)
		}
	}
	for _, r := range []string{procinfo.ImageCached, procinfo.ImageProc, procinfo.ImageFilename, procinfo.ImageUnresolved} {
		lineageImageResults.WithLabelValues(r)
	}
}

// sanitizeLineageToken нейтрализует управляющие символы: значение собирается из данных, которыми
// распоряжается атакующий, а разделители звеньев и полей — "\n" и "\t".
func sanitizeLineageToken(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] < 0x20 || b[i] == 0x7f {
			b[i] = '?'
		}
	}
	return string(b)
}

// resolveLineageField — значение поля для процесса pid.
func resolveLineageField(pid uint32, field string) string {
	h, _ := lineageResolver.Load().(lineageResolverHolder)
	if h.r == nil {
		lineageFieldResults.WithLabelValues(field, "no_table").Inc()
		return ""
	}
	anc, _, ok := h.r.AncestorChain(pid)
	if !ok {
		lineageFieldResults.WithLabelValues(field, "no_table").Inc()
		return ""
	}
	if len(anc) == 0 {
		lineageFieldResults.WithLabelValues(field, "empty").Inc()
		return ""
	}
	lineageFieldResults.WithLabelValues(field, "resolved").Inc()
	var sb strings.Builder
	for i, rec := range anc {
		if i > 0 {
			sb.WriteByte('\n')
		}
		image, how := lineageImages.Resolve(rec)
		lineageImageResults.WithLabelValues(how).Inc()
		if image == "" {
			image = "?"
		}
		sb.WriteString(sanitizeLineageToken(image))
		if field == lineageFieldFull {
			fname := rec.Filename
			if fname == "" {
				fname = "?"
			}
			sb.WriteByte('\t')
			sb.WriteString(sanitizeLineageToken(fname))
		}
	}
	return sb.String()
}

// LineageHopInfo — одно звено цепочки в отладочном ответе.
type LineageHopInfo struct {
	PID          uint32 `json:"pid"`
	PPID         uint32 `json:"ppid"`
	Comm         string `json:"comm"`
	Image        string `json:"image"`
	ImageHow     string `json:"image_how"`
	ExecFilename string `json:"exec_filename"`
	StartNs      uint64 `json:"start_boottime_ns"`
	Exited       bool   `json:"exited"`
	Seeded       bool   `json:"seeded"`
	ExeDev       uint32 `json:"exe_dev"` // что записало ядро: по ним образ сверяется с stat(путь)
	ExeIno       uint64 `json:"exe_ino"`
}

// LineageDescription — что агент видит про предков pid: то же, что читают дерево инцидента и поля
// proc.lineage*. Для живой сверки с /proc на стенде (GET /debug/lineage?pid=N).
type LineageDescription struct {
	PID             uint32           `json:"pid"`
	Table           bool             `json:"table"`
	Outcome         string           `json:"outcome"`
	Ancestors       []LineageHopInfo `json:"ancestors"` // от корня к родителю
	Tree            []string         `json:"tree_comms"`
	Lineage         string           `json:"lineage"`
	LineageExePaths string           `json:"lineage_exe_paths"`
}

// DescribeLineage собирает описание для pid; r — тот же резолвер цепочки, что у поля.
func DescribeLineage(pid uint32, r LineageChainResolver, tree func(uint32) []string) LineageDescription {
	d := LineageDescription{PID: pid, Ancestors: []LineageHopInfo{}}
	if r == nil {
		return d
	}
	anc, out, ok := r.AncestorChain(pid)
	d.Table, d.Outcome = ok, string(out)
	for _, rec := range anc {
		img, how := lineageImages.Resolve(rec)
		d.Ancestors = append(d.Ancestors, LineageHopInfo{
			PID: rec.PID, PPID: rec.PPID, Comm: rec.Comm, Image: img, ImageHow: how, ExecFilename: rec.Filename,
			StartNs: rec.StartBoottimeNs, Exited: rec.Exited(), Seeded: rec.Flags&procinfo.FlagSeeded != 0,
			ExeDev: rec.ExeDev, ExeIno: rec.ExeIno,
		})
	}
	if tree != nil {
		d.Tree = tree(pid)
	}
	d.Lineage = resolveLineageField(pid, lineageFieldFull)
	d.LineageExePaths = resolveLineageField(pid, lineageFieldImages)
	return d
}
