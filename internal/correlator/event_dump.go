package correlator

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.6, заход B, шаг 0: дамп событий движка. Выборка «каждое N-е событие,
// дошедшее до RuleEngine.EvaluateInto» пишется JSONL-ом в файл — настоящий вход
// для офлайн-бенча G0 вместо замены из распределений (заход A: абсолют бенча
// был в 3,1× ниже ночи).
//
// Режим измерения, по умолчанию выключен (server.event_dump_path пуст). Цена
// выключенного: одна атомарная загрузка указателя на событие. Цена включённого:
// счётчик на событие и сериализация каждого N-го под мьютексом.
//
// Файл содержит comm, пути и аргументы процессов хоста — создаётся с правами
// 0600; наружу его не отдавать.
var eventDump atomic.Pointer[eventDumper]

type eventDumper struct {
	every uint64
	n     atomic.Uint64
	mu    sync.Mutex
	w     *bufio.Writer
	c     io.Closer
	wrote uint64
	errs  uint64
}

// dumpFile / dumpSys / dumpNet — плоские формы вложенных событий: строки вместо
// массивов байт (прежняя JSON-форма FileEvent — 256 чисел на путь).
type dumpFile struct {
	Op      uint8  `json:"op"`
	Flags   int32  `json:"flags,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
	Name    string `json:"name,omitempty"`
	FDPath  string `json:"fdpath,omitempty"`
	FDTrunc bool   `json:"fdtrunc,omitempty"`
}

type dumpNet struct {
	Saddr  string `json:"saddr"`
	Daddr  string `json:"daddr"`
	Sport  uint16 `json:"sport"`
	Dport  uint16 `json:"dport"`
	Proto  uint8  `json:"proto"`
	Family uint8  `json:"family"`
}

// dumpRecord — строка дампа. Редкие типы (TLS, Privesc, Kmod, …) идут в Ext
// штатной JSON-формой своих структур.
type dumpRecord struct {
	Type      uint8                 `json:"t"`
	TS        uint64                `json:"ts"`
	PID       uint32                `json:"pid"`
	TGID      uint32                `json:"tgid,omitempty"`
	PPID      uint32                `json:"ppid,omitempty"`
	UID       uint32                `json:"uid,omitempty"`
	Comm      string                `json:"comm"`
	PComm     string                `json:"pcomm,omitempty"`
	CgroupID  uint64                `json:"cg,omitempty"`
	UnitCg    uint64                `json:"ucg,omitempty"`
	Args      string                `json:"args,omitempty"`
	ArgsTrunc bool                  `json:"args_trunc,omitempty"`
	File      *dumpFile             `json:"file,omitempty"`
	Syscall   *types.SyscallEvent   `json:"sys,omitempty"`
	Net       *dumpNet              `json:"net,omitempty"`
	DNS       *types.DNSEvent       `json:"dns,omitempty"`
	Enrich    *types.EnrichmentInfo `json:"enrich,omitempty"`
	Ext       *dumpExt              `json:"ext,omitempty"`
}

type dumpExt struct {
	TLS        *types.TLSEvent          `json:"tls,omitempty"`
	Privesc    *types.PrivescEvent      `json:"privesc,omitempty"`
	NetClose   *types.NetworkCloseEvent `json:"net_close,omitempty"`
	Kmod       *types.KmodEvent         `json:"kmod,omitempty"`
	CgroupEsc  *types.CgroupEscapeEvent `json:"cgroup_esc,omitempty"`
	GPU        *types.GPUEvent          `json:"gpu,omitempty"`
	CloudAudit *types.CloudAuditEvent   `json:"cloud_audit,omitempty"`
	IOUring    *types.IOUringEvent      `json:"io_uring,omitempty"`
	BPFProgram *types.BPFProgramEvent   `json:"bpf_program,omitempty"`
	HTTP       *types.HTTPEvent         `json:"http,omitempty"`
}

func commString(c [16]byte) string {
	n := 0
	for n < len(c) && c[n] != 0 {
		n++
	}
	return string(c[:n])
}

func toDumpRecord(e *types.Event) dumpRecord {
	r := dumpRecord{
		Type: uint8(e.Type), TS: e.Timestamp, PID: e.PID, TGID: e.TGID, PPID: e.PPID, UID: e.UID,
		Comm: commString(e.Comm), PComm: commString(e.ParentComm),
		CgroupID: e.CgroupID, UnitCg: e.UnitCgroupID,
		Args: e.ProcArgs, ArgsTrunc: e.ProcArgsTruncated,
		Syscall: e.Syscall, DNS: e.DNS, Enrich: e.Enrichment,
	}
	if f := e.File; f != nil {
		r.File = &dumpFile{Op: f.Op, Flags: f.Flags, Mode: f.Mode, Name: f.Filename, FDPath: f.FDPath, FDTrunc: f.FDPathTruncated}
	}
	if n := e.Network; n != nil {
		r.Net = &dumpNet{Saddr: fmt.Sprintf("%x", n.Saddr[:]), Daddr: fmt.Sprintf("%x", n.Daddr[:]),
			Sport: n.Sport, Dport: n.Dport, Proto: n.Proto, Family: uint8(n.Family)}
	}
	if e.TLS != nil || e.Privesc != nil || e.NetClose != nil || e.Kmod != nil || e.CgroupEsc != nil ||
		e.GPU != nil || e.CloudAudit != nil || e.IOUring != nil || e.BPFProgram != nil || e.HTTPPlaintext != nil {
		r.Ext = &dumpExt{TLS: e.TLS, Privesc: e.Privesc, NetClose: e.NetClose, Kmod: e.Kmod, CgroupEsc: e.CgroupEsc,
			GPU: e.GPU, CloudAudit: e.CloudAudit, IOUring: e.IOUring, BPFProgram: e.BPFProgram, HTTP: e.HTTPPlaintext}
	}
	return r
}

func (r *dumpRecord) toEvent() (types.Event, error) {
	e := types.Event{
		Type: types.EventType(r.Type), Timestamp: r.TS, PID: r.PID, TGID: r.TGID, PPID: r.PPID, UID: r.UID,
		CgroupID: r.CgroupID, UnitCgroupID: r.UnitCg, ProcArgs: r.Args, ProcArgsTruncated: r.ArgsTrunc,
		Syscall: r.Syscall, DNS: r.DNS, Enrichment: r.Enrich,
	}
	copy(e.Comm[:], r.Comm)
	copy(e.ParentComm[:], r.PComm)
	if f := r.File; f != nil {
		e.File = &types.FileEvent{Op: f.Op, Flags: f.Flags, Mode: f.Mode, Filename: f.Name, FDPath: f.FDPath, FDPathTruncated: f.FDTrunc}
	}
	if n := r.Net; n != nil {
		ne := &types.NetworkEvent{Sport: n.Sport, Dport: n.Dport, Proto: n.Proto, Family: types.AddressFamily(n.Family)}
		hexInto(ne.Saddr[:], n.Saddr)
		hexInto(ne.Daddr[:], n.Daddr)
		e.Network = ne
	}
	if x := r.Ext; x != nil {
		e.TLS, e.Privesc, e.NetClose, e.Kmod, e.CgroupEsc = x.TLS, x.Privesc, x.NetClose, x.Kmod, x.CgroupEsc
		e.GPU, e.CloudAudit, e.IOUring, e.BPFProgram, e.HTTPPlaintext = x.GPU, x.CloudAudit, x.IOUring, x.BPFProgram, x.HTTP
	}
	return e, nil
}

func hexInto(dst []byte, s string) {
	for i := 0; i < len(dst) && 2*i+1 < len(s); i++ {
		var b byte
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &b)
		dst[i] = b
	}
}

// EnableEventDump включает дамп: каждое every-е событие движка — строка JSONL в
// path (0600, дозапись). every < 1 считается за 1. Возвращает функцию остановки
// (сбрасывает буфер, закрывает файл, выключает дамп).
func EnableEventDump(path string, every int) (stop func() error, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return enableEventDumpWriter(f, f, every), nil
}

func enableEventDumpWriter(w io.Writer, c io.Closer, every int) (stop func() error) {
	if every < 1 {
		every = 1
	}
	d := &eventDumper{every: uint64(every), w: bufio.NewWriterSize(w, 256<<10), c: c}
	eventDump.Store(d)
	return func() error {
		eventDump.CompareAndSwap(d, nil)
		d.mu.Lock()
		defer d.mu.Unlock()
		err := d.w.Flush()
		if d.c != nil {
			if cerr := d.c.Close(); err == nil {
				err = cerr
			}
		}
		return err
	}
}

// EventDumpStats — сколько строк записано и сколько записей не удалось (для лога
// остановки и тестов). Без включённого дампа — нули.
func EventDumpStats() (written, errs uint64) {
	d := eventDump.Load()
	if d == nil {
		return 0, 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.wrote, d.errs
}

func (d *eventDumper) sample(e *types.Event) {
	if d.n.Add(1)%d.every != 0 {
		return
	}
	rec := toDumpRecord(e)
	b, err := json.Marshal(&rec)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.errs++
		return
	}
	if _, err := d.w.Write(append(b, '\n')); err != nil {
		d.errs++
		return
	}
	d.wrote++
}

// LoadEventDump читает дамп обратно в события (вход офлайн-бенча и реплеев).
func LoadEventDump(path string) ([]types.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []types.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	line := 0
	for sc.Scan() {
		line++
		var r dumpRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		e, err := r.toEvent()
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
