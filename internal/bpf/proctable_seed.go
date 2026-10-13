package bpf

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// SeedRecord — процесс, существовавший до привязки хуков таблицы (демоны, старше агента).
type SeedRecord struct {
	PID             uint32
	PPID            uint32
	StartBoottimeNs uint64
	Comm            string
	ExeDev          uint32 // кодировка ядра: major<<20 | minor
	ExeIno          uint64
	ExePath         string // readlink /proc/<pid>/exe — для кэша «inode → путь»; в запись таблицы не идёт
}

// procClockTick — USER_HZ: поле 22 /proc/<pid>/stat — в тиках 1/100 с (на Linux для пространства
// пользователя неизменно 100).
const procClockTickNs = 10_000_000

// kernelDevFromStat переводит st_dev (кодировка userspace: new_encode_dev —
// (minor & 0xff) | major<<8 | (minor & ^0xff)<<12) в кодировку ядра s_dev (major<<20 | minor),
// которую пишет ядро в запись таблицы.
func kernelDevFromStat(dev uint64) uint32 {
	major := (dev >> 8) & 0xfff
	minor := (dev & 0xff) | ((dev >> 12) & 0xfff00)
	return uint32(major<<20 | minor)
}

// parseProcStat разбирает /proc/<pid>/stat: comm в скобках может содержать пробелы и скобки,
// поэтому поля считаются после ПОСЛЕДНЕЙ «)». Поле 4 — ppid, поле 22 — starttime (тики от старта системы).
func parseProcStat(data string) (comm string, ppid uint32, startTicks uint64, ok bool) {
	l := strings.IndexByte(data, '(')
	r := strings.LastIndexByte(data, ')')
	if l < 0 || r < l {
		return "", 0, 0, false
	}
	comm = data[l+1 : r]
	f := strings.Fields(data[r+1:])
	// f[0] — state (поле 3), f[1] — ppid (поле 4), f[19] — starttime (поле 22)
	if len(f) < 20 {
		return "", 0, 0, false
	}
	pp, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return "", 0, 0, false
	}
	st, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return "", 0, 0, false
	}
	return comm, uint32(pp), st, true
}

// ReadProcSeed перечисляет процессы procRoot (обычно "/proc"; лидеры групп — нити в корне /proc
// не видны). Один раз при старте, не на горячем пути. Процесс, исчезнувший посреди чтения, пропускается.
func ReadProcSeed(procRoot string) ([]SeedRecord, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	out := make([]SeedRecord, 0, len(entries))
	for _, e := range entries {
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		data, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue
		}
		comm, ppid, ticks, ok := parseProcStat(string(data))
		if !ok {
			continue
		}
		rec := SeedRecord{PID: uint32(pid64), PPID: ppid, StartBoottimeNs: ticks * procClockTickNs, Comm: comm}
		if st, err := os.Stat(filepath.Join(dir, "exe")); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				rec.ExeDev = kernelDevFromStat(uint64(sys.Dev))
				rec.ExeIno = uint64(sys.Ino)
			}
			if p, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
				rec.ExePath = p
			}
		}
		out = append(out, rec)
	}
	return out, nil
}
