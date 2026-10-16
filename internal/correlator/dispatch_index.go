package correlator

import (
	"strconv"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.6, заход C, шаг C0 (G3): индекс правил по номеру syscall и операции
// файла + предвычисленные коды полей.
//
// До индекса каждое syscall-событие проходило ВСЕ syscall-правила, а каждое
// файловое — все файловые, хотя у большинства правило называет конкретный nr
// (op) условием, которое отсекает событие за одно сравнение строк после
// вычисления поля. Профиль захода B: 22% CPU агента — диспетчеризация условий
// (evaluateCondition, evaluateConditionGroup, getFieldValueCached,
// normaliseFieldName), в основном по syscall-правилам.
//
// Индекс строится из ЗАГРУЖЕННЫХ правил (ручных списков нет) при создании
// движка и на каждой горячей перезагрузке. Он не меняет поведение, а только
// пропускает правило, которое заведомо не совпадёт:
//
//   - правило ОГРАНИЧЕНО по nr (op), если in/eq по nr (op) — единственное условие
//     правила или прямое условие группы «and», а каждое значение — каноническая
//     запись числа (имя операции). Группа «or» и вложенные группы ничего не
//     ограничивают;
//   - правило с сэмплером (!skipSampler) НЕ ограничено: сэмплер считает счётчики
//     до условия, пропуск изменил бы их;
//   - пока у сэмплера есть адаптивные переопределения, индекс не применяется
//     вовсе (тот же довод);
//   - событие с nr вне таблицы, без Syscall или с неизвестной операцией видит
//     только неограниченные правила — ограниченные на нём всё равно не совпали бы.
//
// Порядок правил в списке кандидатов исходный: алерты выходят в том же порядке.

// nrIndexSize — размер таблицы номеров (как syscallNrStrings).
const nrIndexSize = 512

// dispatchEnabled — выключатель G3 (бенч «до/после», мутационный тест);
// читается при построении движка.
var dispatchEnabled = true

// fieldByIDEnabled — выключатель П4 (значение поля по коду): бенч «до/после» и тест
// тождества алерт-в-алерт на дампе (волна 8.7).
var fieldByIDEnabled = true

// condFieldID — код поля условия для быстрого пути evaluateCondition.
type condFieldID uint8

const (
	fidOther condFieldID = iota
	fidNr
	fidOp
	// Волна 8.7, П4: полный код поля для горячих типов (file, syscall, network) и
	// осей идентичности. Незнакомое поле — fidOther: значение берёт строковая
	// версия getFieldValueNorm (редкие типы: dns-обогащения, tls, gpu, cloud, …).
	fidContainerID
	fidPodName
	fidNamespace
	fidExePath
	fidParentExePath
	fidAncestorExePath
	fidLineage
	fidLineageExePaths
	fidSystemdUnit
	fidFilename
	fidFDName
	fidFDNameTrunc
	fidFlags
	fidMode
	fidDirectory
	fidExtension
	fidProcArgs
	fidProcArgsTrunc
	fidComm
	fidUID
	fidPID
	fidPPID
	fidParentComm
	fidRet
	fidArg0
	fidArg1
	fidArg2
	fidArg3
	fidArg4
	fidArg5
	fidDport
	fidSport
	fidDaddr
	fidSaddr
	fidProto
	fidFamily
	fidConnRate
	fidConnPeriodicCount
	fidConnPeriodicCV
)

var fieldIDByName = map[string]condFieldID{
	"nr": fidNr, "op": fidOp,
	"container_id": fidContainerID, "pod_name": fidPodName, "namespace": fidNamespace,
	"exe_path": fidExePath, "parent_exe_path": fidParentExePath, "ancestor_exe_path": fidAncestorExePath,
	"lineage": fidLineage, "lineage_exe_paths": fidLineageExePaths, "systemd_unit": fidSystemdUnit,
	"filename": fidFilename, "fd.name": fidFDName, "fd.name_truncated": fidFDNameTrunc,
	"flags": fidFlags, "mode": fidMode, "directory": fidDirectory, "extension": fidExtension,
	"proc.args": fidProcArgs, "proc.args_truncated": fidProcArgsTrunc,
	"comm": fidComm, "uid": fidUID, "pid": fidPID, "ppid": fidPPID, "parent_comm": fidParentComm,
	"ret": fidRet, "arg0": fidArg0, "arg1": fidArg1, "arg2": fidArg2, "arg3": fidArg3, "arg4": fidArg4, "arg5": fidArg5,
	"dport": fidDport, "sport": fidSport, "daddr": fidDaddr, "saddr": fidSaddr, "proto": fidProto, "family": fidFamily,
	"conn_rate_1m": fidConnRate, "conn_periodic_count_5m": fidConnPeriodicCount, "conn_periodic_cv_5m": fidConnPeriodicCV,
}

func fieldIDOf(norm string) condFieldID { return fieldIDByName[norm] }

// condValue — значение поля условия. Быстрый путь для nr (syscall) и op (file):
// те же строки, что отдаёт getFieldValueNorm, без разбора имени поля.
func (re *RuleEngine) condValue(e *types.Event, cond *RuleCondition, dnsAnalysis *DomainAnalysis, cache *eventFieldCache) string {
	switch cond.fieldID {
	case fidNr:
		if e.Type == types.EventSyscall && e.Syscall != nil {
			if nr := e.Syscall.Nr; nr >= 0 && nr < nrIndexSize {
				return syscallNrStrings[nr]
			}
		}
	case fidOp:
		if e.Type == types.EventFileAccess && e.File != nil && int(e.File.Op) < len(fileOpNames) {
			return fileOpNames[e.File.Op]
		}
	}
	field := cond.fieldNorm
	if field == "" {
		field = normaliseFieldName(cond.Field)
		return re.getFieldValueNorm(e, field, dnsAnalysis, cache)
	}
	if !fieldByIDEnabled {
		return re.getFieldValueNorm(e, field, dnsAnalysis, cache)
	}
	return re.getFieldValueByID(e, cond.fieldID, field, dnsAnalysis, cache)
}

// dispatchIndex — кандидаты по ключу события; значения — позиции в re.byType[t].
type dispatchIndex struct {
	sysSlot   [nrIndexSize]uint16           // nr → номер списка; 0 — «только неограниченные»
	sysLists  [][]int32                     // [0] — неограниченные
	// П3 (волна 8.7): то же без правил, обязательно требующих непустой proc.args
	// (эвристика пуста у 99,5% syscall-событий idle). Применяется к событию с ProcArgs == "".
	sysEmpty [][]int32
	fileLists [len(fileOpNames) + 1][]int32 // [i] — op i; [len] — «только неограниченные»
	// счётчики для тестов и отчёта
	sysConstrained, sysTotal   int
	fileConstrained, fileTotal int
	sysArgsGated               int
}

// argsGateEnabled — выключатель П3 (мутация, бенч «до/после»); читается при построении индекса.
var argsGateEnabled = true

// requiresNonEmptyArgs — правило обязательно (прямым условием группы «and» или единственным
// условием) читает proc.args оператором, который на пустой строке даёт false ДО сравнения
// (evaluateCondition: пусто и код не equals/not_equals/not_in → false). Сэмплер правила
// выключен (иначе пропуск правила изменил бы его счётчики).
func requiresNonEmptyArgs(r *Rule) bool {
	if !r.skipSampler {
		return false
	}
	gate := func(c *RuleCondition) bool {
		if c.fieldID != fidProcArgs {
			return false
		}
		switch c.opCode {
		case condOpEquals, condOpNotEquals, condOpNotIn, condOpUnknown, condOpCapsGained, condOpCapsDropped:
			return false
		}
		return true
	}
	if g := r.ConditionGroup; g != nil {
		if g.Operator == "or" {
			return false
		}
		for i := range g.Conditions {
			if gate(&g.Conditions[i]) {
				return true
			}
		}
		return false
	}
	return gate(&r.Condition)
}

// requiredKey возвращает значения обязательного условия по полю want у
// правила, или ok=false, если правило по нему не ограничено.
func requiredKey(r *Rule, want condFieldID) (values []string, ok bool) {
	if !r.skipSampler {
		return nil, false
	}
	pick := func(c *RuleCondition) ([]string, bool) {
		if c.fieldID != want {
			return nil, false
		}
		switch c.opCode {
		case condOpIn:
			return c.Values, true
		case condOpEquals:
			if len(c.Values) == 0 {
				return nil, false
			}
			return c.Values[:1], true
		}
		return nil, false
	}
	if g := r.ConditionGroup; g != nil {
		if g.Operator == "or" {
			return nil, false
		}
		for i := range g.Conditions {
			if v, ok := pick(&g.Conditions[i]); ok {
				return v, true
			}
		}
		return nil, false
	}
	return pick(&r.Condition)
}

// buildDispatchIndex строит индекс из re.byType. Вызывается после buildTypeIndex.
func (re *RuleEngine) buildDispatchIndex() {
	re.dispatch = nil
	if !dispatchEnabled {
		return
	}
	d := &dispatchIndex{sysLists: [][]int32{nil}}
	sys := re.byType[types.EventSyscall]
	file := re.byType[types.EventFileAccess]

	// syscall: сначала ключи, затем списки в исходном порядке правил
	nrsOf := make([][]int, len(sys)) // nil — неограничено
	slotOf := map[int]uint16{}
	for i := range sys {
		vals, ok := requiredKey(&sys[i], fidNr)
		if !ok {
			continue
		}
		nrs := make([]int, 0, len(vals))
		for _, v := range vals {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n >= nrIndexSize || strconv.Itoa(n) != v {
				nrs = nil
				break
			}
			nrs = append(nrs, n)
		}
		if nrs == nil {
			continue
		}
		nrsOf[i] = nrs
		for _, n := range nrs {
			if _, seen := slotOf[n]; !seen {
				slotOf[n] = uint16(len(d.sysLists))
				d.sysLists = append(d.sysLists, nil)
				d.sysSlot[n] = slotOf[n]
			}
		}
	}
	for i := range sys {
		d.sysTotal++
		if nrsOf[i] == nil {
			for s := range d.sysLists {
				d.sysLists[s] = append(d.sysLists[s], int32(i))
			}
			continue
		}
		d.sysConstrained++
		done := map[uint16]bool{}
		for _, n := range nrsOf[i] {
			if s := slotOf[n]; !done[s] {
				done[s] = true
				d.sysLists[s] = append(d.sysLists[s], int32(i))
			}
		}
	}

	// П3: списки для событий с пустым proc.args — без правил, требующих непустой.
	d.sysEmpty = make([][]int32, len(d.sysLists))
	gated := make([]bool, len(sys))
	for i := range sys {
		gated[i] = argsGateEnabled && requiresNonEmptyArgs(&sys[i])
		if gated[i] {
			d.sysArgsGated++
		}
	}
	for s, l := range d.sysLists {
		for _, i := range l {
			if !gated[i] {
				d.sysEmpty[s] = append(d.sysEmpty[s], i)
			}
		}
	}

	// file
	for i := range file {
		d.fileTotal++
		vals, ok := requiredKey(&file[i], fidOp)
		var ops []int
		if ok {
			for _, v := range vals {
				op := -1
				for j, name := range fileOpNames {
					if name == v {
						op = j
					}
				}
				if op < 0 {
					ok = false
					break
				}
				ops = append(ops, op)
			}
		}
		if !ok {
			for j := range d.fileLists {
				d.fileLists[j] = append(d.fileLists[j], int32(i))
			}
			continue
		}
		d.fileConstrained++
		var done [len(fileOpNames)]bool
		for _, op := range ops {
			if !done[op] {
				done[op] = true
				d.fileLists[op] = append(d.fileLists[op], int32(i))
			}
		}
	}
	re.dispatch = d
}

// candidateRules возвращает позиции правил типа события, которые могут
// совпасть; indexed=false — индекса нет, перебирать все.
func (re *RuleEngine) candidateRules(e *types.Event) (cand []int32, indexed bool) {
	d := re.dispatch
	if d == nil {
		return nil, false
	}
	switch e.Type {
	case types.EventSyscall:
		if re.sampler.entryCount.Load() > 0 {
			return nil, false
		}
		slot := uint16(0)
		if s := e.Syscall; s != nil && s.Nr >= 0 && s.Nr < nrIndexSize {
			slot = d.sysSlot[s.Nr]
		}
		if e.ProcArgs == "" {
			return d.sysEmpty[slot], true
		}
		return d.sysLists[slot], true
	case types.EventFileAccess:
		if re.sampler.entryCount.Load() > 0 {
			return nil, false
		}
		op := len(fileOpNames)
		if f := e.File; f != nil && int(f.Op) < len(fileOpNames) {
			op = int(f.Op)
		}
		return d.fileLists[op], true
	}
	return nil, false
}
