package correlator

import (
	"strconv"
	"strings"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.7, П4: значение поля условия по ЧИСЛОВОМУ коду (condFieldID), а не по
// строке. getFieldValueNorm остаётся эталоном: каждая ветка здесь возвращает то же,
// что строковая, а любая комбинация «тип события × поле», которую эта функция не
// разбирает, уходит в строковую версию (редкие типы: dns-обогащения, tls, gpu,
// cloud, kmod, io_uring, bpf — их поток мал). Тождество — корпусный тест
// TestFieldValueByIDMatchesNorm: все поля × все типы событий × варианты структур.
func (re *RuleEngine) getFieldValueByID(e *types.Event, id condFieldID, name string, dnsAnalysis *DomainAnalysis, cache *eventFieldCache) string {
	// Идентичность нагрузки доступна на любом типе события (см. getFieldValueNorm).
	switch id {
	case fidContainerID:
		if e.Enrichment != nil {
			return e.Enrichment.ContainerID
		}
		return ""
	case fidPodName:
		if e.Enrichment != nil {
			return e.Enrichment.PodName
		}
		return ""
	case fidNamespace:
		if e.Enrichment != nil {
			return e.Enrichment.Namespace
		}
		return ""
	case fidExePath:
		return resolveExePath(e.PID, exePathFieldSelf)
	case fidParentExePath:
		return resolveExePath(e.PPID, exePathFieldParent)
	case fidAncestorExePath:
		return resolveAncestorExePath(e.PID, e.PPID, eventComm(e, cache), eventParentComm(e, cache))
	case fidLineage, fidLineageExePaths:
		return resolveLineageField(e.PID, name)
	case fidSystemdUnit:
		return resolveSystemdUnit(e.CgroupID, e.UnitCgroupID)
	}

	switch e.Type {
	case types.EventFileAccess:
		if e.File == nil {
			return ""
		}
		switch id {
		case fidFilename:
			return eventFilename(e, cache)
		case fidFDName:
			return e.File.Path()
		case fidFDNameTrunc:
			if e.File.FDPathTruncated {
				return "true"
			}
			return "false"
		case fidFlags:
			return strconv.FormatInt(int64(e.File.Flags), 10)
		case fidMode:
			return strconv.FormatUint(uint64(e.File.Mode), 10)
		case fidOp:
			if int(e.File.Op) < len(fileOpNames) {
				return fileOpNames[e.File.Op]
			}
			return strconv.FormatUint(uint64(e.File.Op), 10)
		case fidDirectory:
			p := eventFilename(e, cache)
			if idx := strings.LastIndexByte(p, '/'); idx >= 0 {
				return p[:idx]
			}
			return "/"
		case fidExtension:
			p := eventFilename(e, cache)
			if idx := strings.LastIndexByte(p, '.'); idx >= 0 {
				return p[idx:]
			}
			return ""
		case fidProcArgs:
			return e.ProcArgs
		case fidProcArgsTrunc:
			if e.ProcArgsTruncated {
				return "true"
			}
			return "false"
		case fidComm:
			return eventComm(e, cache)
		case fidUID:
			return strconv.FormatUint(uint64(e.UID), 10)
		case fidPID:
			return strconv.FormatUint(uint64(e.PID), 10)
		case fidPPID:
			return strconv.FormatUint(uint64(e.PPID), 10)
		case fidParentComm:
			return eventParentComm(e, cache)
		}
	case types.EventSyscall:
		if e.Syscall == nil {
			return ""
		}
		switch id {
		case fidNr:
			if nr := e.Syscall.Nr; nr >= 0 && nr < 512 {
				return syscallNrStrings[nr]
			}
			return strconv.FormatInt(e.Syscall.Nr, 10)
		case fidRet:
			return strconv.FormatInt(e.Syscall.Ret, 10)
		case fidUID:
			return strconv.FormatUint(uint64(e.UID), 10)
		case fidComm:
			return eventComm(e, cache)
		case fidArg0:
			return strconv.FormatUint(e.Syscall.Args[0], 10)
		case fidArg1:
			return strconv.FormatUint(e.Syscall.Args[1], 10)
		case fidArg2:
			return strconv.FormatUint(e.Syscall.Args[2], 10)
		case fidArg3:
			return strconv.FormatUint(e.Syscall.Args[3], 10)
		case fidArg4:
			return strconv.FormatUint(e.Syscall.Args[4], 10)
		case fidArg5:
			return strconv.FormatUint(e.Syscall.Args[5], 10)
		case fidFDName:
			if e.File != nil {
				return e.File.FDPath
			}
			return ""
		case fidProcArgs:
			return e.ProcArgs
		case fidProcArgsTrunc:
			if e.ProcArgsTruncated {
				return "true"
			}
			return "false"
		case fidPID:
			return strconv.FormatUint(uint64(e.PID), 10)
		case fidPPID:
			return strconv.FormatUint(uint64(e.PPID), 10)
		case fidParentComm:
			return eventParentComm(e, cache)
		}
	case types.EventTCPConnect:
		if e.Network == nil {
			return ""
		}
		switch id {
		case fidDport:
			return strconv.FormatUint(uint64(e.Network.Dport), 10)
		case fidSport:
			return strconv.FormatUint(uint64(e.Network.Sport), 10)
		case fidDaddr:
			return util.FormatIP(e.Network.Daddr[:], e.Network.Family)
		case fidSaddr:
			return util.FormatIP(e.Network.Saddr[:], e.Network.Family)
		case fidProto:
			return strconv.FormatUint(uint64(e.Network.Proto), 10)
		case fidFamily:
			if e.Network.Family == types.AFInet6 {
				return "ipv6"
			}
			return "ipv4"
		case fidProcArgs:
			return e.ProcArgs
		case fidProcArgsTrunc:
			if e.ProcArgsTruncated {
				return "true"
			}
			return "false"
		case fidComm:
			return eventComm(e, cache)
		case fidUID:
			return strconv.FormatUint(uint64(e.UID), 10)
		case fidPPID:
			return strconv.FormatUint(uint64(e.PPID), 10)
		case fidParentComm:
			return eventParentComm(e, cache)
		}
		// conn_rate_1m и conn_periodic_*: побочные счётчики — строковая версия.
	}
	return re.getFieldValueNorm(e, name, dnsAnalysis, cache)
}
