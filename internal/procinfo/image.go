package procinfo

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
)

// KernelDevFromStat переводит st_dev (кодировка userspace: new_encode_dev —
// (minor & 0xff) | major<<8 | (minor & ^0xff)<<12) в кодировку ядра s_dev (major<<20 | minor),
// которую пишет ядро в запись таблицы процессов.
func KernelDevFromStat(dev uint64) uint32 {
	major := (dev >> 8) & 0xfff
	minor := (dev & 0xff) | ((dev >> 12) & 0xfff00)
	return uint32(major<<20 | minor)
}

// imageKey — идентичность образа: файловая система + inode (то, что ядро записало в Record).
type imageKey struct {
	dev uint32
	ino uint64
}

// ImageCache — минимальный кэш «inode → путь образа» (волна 8.4.1; E1 части 2 его расширит).
// Образов на узле сотни, поэтому размер ограничен жёстко и без политик: переполнение —
// очистка (повторное разрешение дёшево и редко).
//
// Путь образа разрешается только если его можно ПРОВЕРИТЬ: stat(путь) обязан дать тот же
// dev/ino, что ядро записало в процесс. Так подделка argv[0]/comm (exec -a dpkg) образ не
// меняет, а имя файла, под которым образ не лежит, в кэш не попадает.
type ImageCache struct {
	mu   sync.RWMutex
	m    map[imageKey]string
	max  int
	root string // префикс корня ХОСТА для stat (под с hostPID: /proc/1/root); "" — тот же корень
	stat func(path string) (dev uint32, ino uint64, ok bool)
	link func(path string) (string, error)
}

// HostRootPath — путь к корню хоста из mount-namespace агента: «/proc/1/root», когда агент в поде с hostPID (pid 1 — init
// хоста, его корень — корень хоста), иначе пусто. Пути образов, которые отдаёт ядро (readlink /proc/<pid>/exe, exec-filename),
// — пути ХОСТА, а stat из namespace пода видит свою файловую систему: без префикса сверка по dev/ino в поде не сходится никогда.
const HostRootPath = "/proc/1/root"

// DetectHostRoot возвращает HostRootPath, если корень pid 1 — другая файловая система, чем «/» агента (под с hostPID), и «»,
// если это один корень (агент на хосте, либо под без hostPID: pid 1 — сам под) или корень pid 1 не читается.
func DetectHostRoot() string { return DetectHostRootWith(statIDs) }

// DetectHostRootWith — DetectHostRoot с подставным stat (шов для тестов).
func DetectHostRootWith(stat func(string) (uint32, uint64, bool)) string {
	rd, ri, ok := stat("/")
	if !ok {
		return ""
	}
	hd, hi, ok := stat(HostRootPath + "/")
	if !ok || (hd == rd && hi == ri) {
		return ""
	}
	return HostRootPath
}

// SetHostRoot задаёт префикс корня хоста для сверки stat (см. HostRootPath).
func (c *ImageCache) SetHostRoot(prefix string) {
	c.mu.Lock()
	c.root = strings.TrimRight(prefix, "/")
	c.mu.Unlock()
}

func (c *ImageCache) hostStat(path string) (uint32, uint64, bool) {
	c.mu.RLock()
	root := c.root
	c.mu.RUnlock()
	return c.stat(root + path)
}

// NewImageCache создаёт кэш на maxEntries (≤ 0 — 4096) с реальными stat/readlink.
func NewImageCache(maxEntries int) *ImageCache {
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &ImageCache{m: make(map[imageKey]string, 256), max: maxEntries, stat: statIDs, link: os.Readlink}
}

// NewImageCacheWith — тот же кэш с подставными stat/readlink (шов для тестов: настоящая ФС и /proc
// в юнит-тестах недоступны).
func NewImageCacheWith(maxEntries int, stat func(string) (uint32, uint64, bool), link func(string) (string, error)) *ImageCache {
	c := NewImageCache(maxEntries)
	c.stat, c.link = stat, link
	return c
}

func statIDs(path string) (uint32, uint64, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return KernelDevFromStat(uint64(sys.Dev)), uint64(sys.Ino), true
}

// Put заносит известную пару (при засеве из /proc: readlink /proc/<pid>/exe уже сделан).
func (c *ImageCache) Put(dev uint32, ino uint64, path string) {
	if ino == 0 || path == "" {
		return
	}
	c.mu.Lock()
	if len(c.m) >= c.max {
		c.m = make(map[imageKey]string, 256)
	}
	c.m[imageKey{dev, ino}] = path
	c.mu.Unlock()
}

// Len — число образов в кэше.
func (c *ImageCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

// Outcomes разрешения образа — значения label result серии ebpf_guard_lineage_image_total.
const (
	ImageCached     = "cached"     // образ взят из кэша
	ImageProc       = "proc"       // живой процесс: readlink /proc/<pid>/exe, сверен по inode
	ImageFilename   = "filename"   // путь exec-filename из таблицы, сверен по inode
	ImageUnresolved = "unresolved" // проверяемого пути нет
	ImageStale      = "stale"      // кэш знал путь, но файл по нему теперь другой/удалён (ResolveChecked)
)

// Resolve отдаёт путь образа процесса rec и способ, которым он получен. Пусто — не разрешился
// (вызывающая сторона ставит «?»: исключение не применяется, правило срабатывает).
//
// Порядок: кэш → живой процесс (readlink /proc/<pid>/exe — КАНОНИЧЕСКИЙ путь, а не тот, под которым
// запустили) → exec-filename из таблицы, если он абсолютный и stat даёт тот же inode. Для шебанг-скрипта
// exec-filename — путь скрипта, у которого inode не совпадает с образом (интерпретатором), и в качестве
// образа он не принимается — ровно то, что нужно: образом скрипта считается интерпретатор.
func (c *ImageCache) Resolve(rec Record) (path, how string) {
	if rec.ExeIno == 0 {
		return "", ImageUnresolved
	}
	k := imageKey{rec.ExeDev, rec.ExeIno}
	c.mu.RLock()
	p, ok := c.m[k]
	c.mu.RUnlock()
	if ok {
		return p, ImageCached
	}
	if !rec.Exited() && rec.PID != 0 {
		if target, err := c.link(fmt.Sprintf("/proc/%d/exe", rec.PID)); err == nil && !strings.HasSuffix(target, " (deleted)") {
			if dev, ino, ok := c.hostStat(target); ok && dev == rec.ExeDev && ino == rec.ExeIno {
				c.Put(rec.ExeDev, rec.ExeIno, target)
				return target, ImageProc
			}
		}
	}
	if strings.HasPrefix(rec.Filename, "/") && rec.Flags&FlagFnameTrunc == 0 {
		if dev, ino, ok := c.hostStat(rec.Filename); ok && dev == rec.ExeDev && ino == rec.ExeIno {
			c.Put(rec.ExeDev, rec.ExeIno, rec.Filename)
			return rec.Filename, ImageFilename
		}
	}
	return "", ImageUnresolved
}

// forget удаляет запись образа, если она всё ещё указывает на path.
func (c *ImageCache) forget(k imageKey, path string) {
	c.mu.Lock()
	if c.m[k] == path {
		delete(c.m, k)
	}
	c.mu.Unlock()
}

// ResolveChecked — Resolve для оси exe_path (волна 8.5, E1): попадание в кэш сверяется stat по
// dev/ino записи. Файл, удалённый или заменённый по тому же пути (новый inode), даёт ImageStale и
// пустой путь, а запись выбрасывается: ядро для такого образа показывает «<путь> (deleted)», и
// исключение по образу к нему не применяется (самоудаляющийся дроппер не получает исключение
// демона, см. correlator/exepath.go). Вызывающая сторона при пустом пути идёт прежним readlink,
// который вернёт ровно то, что видит ядро. Кэш для lineage (Resolve) остаётся без сверки: ему
// нужен образ звена на момент exec, а не нынешнее состояние файла.
func (c *ImageCache) ResolveChecked(rec Record) (path, how string) {
	if rec.ExeIno == 0 {
		return "", ImageUnresolved
	}
	k := imageKey{rec.ExeDev, rec.ExeIno}
	c.mu.RLock()
	p, ok := c.m[k]
	c.mu.RUnlock()
	if ok {
		if dev, ino, sok := c.hostStat(p); sok && dev == rec.ExeDev && ino == rec.ExeIno {
			return p, ImageCached
		}
		c.forget(k, p)
		return "", ImageStale
	}
	return c.Resolve(rec)
}
