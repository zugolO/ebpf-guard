// Package procinfo — общий словарь таблицы процессов (волна 8.5, P1): запись, источник и
// проверка непрерывности цепочки предков. Пакет не знает ни про BPF, ни про профайлер:
// реализует Source internal/bpf.ProcTable (ядро) и тестовые подставные таблицы,
// читают LineageTracker (профайлер) и поле proc.lineage (коррелятор).
package procinfo

// Флаги записи; значения = PROC_FLAG_* в bpf/proctable.h (сверяет TestW85_P1_RecordLayoutMatchesHeader).
const (
	FlagExec       uint32 = 0x1 // execve наблюдался: Comm/Filename/exe — после exec
	FlagFnameTrunc uint32 = 0x2 // Filename обрезан
	FlagSeeded     uint32 = 0x4 // запись из /proc при старте агента, Filename пуст
)

// StartToleranceNs — допуск при сравнении времён старта родителя и потомка. Записи из /proc
// (FlagSeeded) имеют точность тика 10 мс (поле 22 /proc/<pid>/stat), записи ядра — наносекунды:
// родитель, засеянный округлением вниз, не должен выглядеть «моложе» потомка. Переиспользование
// pid отделяется от допуска на порядки: между смертью родителя и новым процессом с тем же pid
// проходит полный оборот pid_max.
const StartToleranceNs uint64 = 10_000_000

// Record — запись таблицы процессов.
type Record struct {
	PID             uint32
	PPID            uint32
	StartBoottimeNs uint64
	ExitTS          uint64 // монотонные нс (bpf_ktime_get_ns); 0 — процесс жив
	ExeIno          uint64
	ExeDev          uint32 // кодировка ядра: major<<20 | minor
	Flags           uint32
	Comm            string
	Filename        string // bprm->filename последнего exec; для шебанг-скрипта — путь самого скрипта
}

// Exited — процесс вышел.
func (r Record) Exited() bool { return r.ExitTS != 0 }

// Result — исход чтения одной записи.
type Result int

const (
	// Found — запись есть и годна.
	Found Result = iota
	// Absent — записи нет ни в живых, ни в вышедших: вытеснена LRU, процесс старше агента и не засеян,
	// или запись не вошла в полную карту.
	Absent
	// Expired — процесс вышел и exit_ts + TTL истёк.
	Expired
	// Error — сбой чтения карты (не «нет записи»).
	Error
)

// Source — источник записей. Реализация обязана быть безопасной для конкурентных вызовов.
type Source interface {
	Lookup(pid uint32) (Record, Result)
}

// Outcome — исход обхода цепочки предков.
type Outcome string

const (
	// OutcomeResolved — дошли до корня (pid ≤ 1 или родитель 0), все звенья на месте и согласованы.
	OutcomeResolved Outcome = "resolved"
	// OutcomeBroken — несогласованное звено: родитель «моложе» потомка (pid переиспользован) или цикл.
	OutcomeBroken Outcome = "broken"
	// OutcomeExhausted — упёрлись в предел глубины, не дойдя до корня.
	OutcomeExhausted Outcome = "exhausted"
	// OutcomeEvicted — записи звена нет (вытеснена, истёк TTL, процесс старше агента) или чтение упало.
	OutcomeEvicted Outcome = "evicted"
)

// Outcomes — полный перечень исходов (для материализации серий с нуля).
var Outcomes = []Outcome{OutcomeResolved, OutcomeBroken, OutcomeExhausted, OutcomeEvicted}

// Hop — звено цепочки.
type Hop struct {
	Rec Record
}

// Walk идёт от pid вверх по ppid до maxDepth звеньев и возвращает звенья от ЛИСТА к корню
// (leaf-first) вместе с исходом. Звенья после первого несогласованного/отсутствующего не
// возвращаются: цепочка непрерывна от листа до последнего возвращённого звена.
//
// Конвенция корня — как у прежнего трекера: pid 1 в цепочку не входит (цепочка кончается
// ребёнком init), pid > 1 с родителем 0 (kthreadd) входит как корень.
func Walk(src Source, pid uint32, maxDepth int) ([]Record, Outcome) {
	if maxDepth <= 0 {
		maxDepth = 16
	}
	var chain []Record
	cur := pid
	seen := make(map[uint32]struct{}, 4)
	for cur > 1 {
		if len(chain) >= maxDepth {
			return chain, OutcomeExhausted
		}
		if _, dup := seen[cur]; dup {
			return chain, OutcomeBroken
		}
		seen[cur] = struct{}{}
		rec, res := src.Lookup(cur)
		if res != Found {
			return chain, OutcomeEvicted
		}
		if n := len(chain); n > 0 {
			child := chain[n-1]
			// родитель запущен позже потомка — значит, под этим pid уже другой процесс
			if rec.StartBoottimeNs != 0 && child.StartBoottimeNs != 0 &&
				rec.StartBoottimeNs > child.StartBoottimeNs+StartToleranceNs {
				return chain, OutcomeBroken
			}
		}
		rec.PID = cur
		chain = append(chain, rec)
		if rec.PPID == 0 || rec.PPID == cur {
			return chain, OutcomeResolved
		}
		cur = rec.PPID
	}
	return chain, OutcomeResolved
}
