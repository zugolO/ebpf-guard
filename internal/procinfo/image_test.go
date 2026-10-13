package procinfo

import (
	"errors"
	"testing"
)

type fsFake struct {
	stat  map[string][2]uint64 // путь → {dev, ino}
	links map[string]string    // /proc/<pid>/exe → путь
	calls int
}

func (f *fsFake) Stat(p string) (uint32, uint64, bool) {
	f.calls++
	v, ok := f.stat[p]
	return uint32(v[0]), v[1], ok
}
func (f *fsFake) Link(p string) (string, error) {
	f.calls++
	t, ok := f.links[p]
	if !ok {
		return "", errors.New("ENOENT")
	}
	return t, nil
}

func newFS() (*fsFake, *ImageCache) {
	f := &fsFake{stat: map[string][2]uint64{}, links: map[string]string{}}
	return f, NewImageCacheWith(64, f.Stat, f.Link)
}

func TestImage_LiveProcessUsesCanonicalReadlinkVerifiedByInode(t *testing.T) {
	f, c := newFS()
	f.links["/proc/300/exe"] = "/usr/bin/dpkg"
	f.stat["/usr/bin/dpkg"] = [2]uint64{7, 555}
	f.stat["/bin/dpkg"] = [2]uint64{7, 555} // тот же образ под другим именем
	rec := Record{PID: 300, ExeDev: 7, ExeIno: 555, Filename: "/bin/dpkg"}
	p, how := c.Resolve(rec)
	if p != "/usr/bin/dpkg" || how != ImageProc {
		t.Fatalf("%q %q: канонический путь живого процесса должен победить exec-filename", p, how)
	}
	if p, how = c.Resolve(rec); p != "/usr/bin/dpkg" || how != ImageCached {
		t.Fatalf("второй раз из кэша: %q %q", p, how)
	}
}

func TestImage_ReadlinkOfSomeOtherFileIsRejected(t *testing.T) {
	// pid переиспользован/подмена: ссылка ведёт на файл с ДРУГИМ inode — в образ не принимается
	f, c := newFS()
	f.links["/proc/300/exe"] = "/tmp/evil"
	f.stat["/tmp/evil"] = [2]uint64{7, 999}
	rec := Record{PID: 300, ExeDev: 7, ExeIno: 555}
	if p, how := c.Resolve(rec); p != "" || how != ImageUnresolved {
		t.Fatalf("%q %q", p, how)
	}
	if c.Len() != 0 {
		t.Fatal("в кэш попал непроверенный путь")
	}
}

func TestImage_ExitedProcessFallsBackToExecFilenameWithInodeCheck(t *testing.T) {
	f, c := newFS()
	f.stat["/usr/bin/curl"] = [2]uint64{7, 42}
	rec := Record{PID: 9, ExitTS: 5, ExeDev: 7, ExeIno: 42, Filename: "/usr/bin/curl"}
	if p, how := c.Resolve(rec); p != "/usr/bin/curl" || how != ImageFilename {
		t.Fatalf("%q %q", p, how)
	}
	for _, link := range f.links {
		_ = link
	}
}

// Шебанг-скрипт: exec-filename — путь скрипта, inode другой (образ — интерпретатор) → в образ НЕ принимается.
func TestImage_ShebangScriptFilenameIsNotTheImage(t *testing.T) {
	f, c := newFS()
	f.stat["/var/lib/dpkg/info/pkg.prerm"] = [2]uint64{7, 1000}                                        // скрипт
	rec := Record{PID: 9, ExitTS: 5, ExeDev: 7, ExeIno: 200, Filename: "/var/lib/dpkg/info/pkg.prerm"} // exe = /bin/dash, ino 200
	if p, how := c.Resolve(rec); p != "" || how != ImageUnresolved {
		t.Fatalf("скрипт принят за образ: %q %q", p, how)
	}
}

func TestImage_RejectsRelativeTruncatedDeletedAndNoInode(t *testing.T) {
	f, c := newFS()
	f.stat["./x"] = [2]uint64{7, 1}
	f.stat["/a/b"] = [2]uint64{7, 1}
	f.links["/proc/5/exe"] = "/a/b (deleted)"
	f.stat["/a/b (deleted)"] = [2]uint64{7, 1} // даже если «путь» статится: суффикс ядра — признак удалённого образа
	if p, _ := c.Resolve(Record{PID: 5, ExitTS: 1, ExeDev: 7, ExeIno: 1, Filename: "./x"}); p != "" {
		t.Fatalf("относительный путь принят: %q", p)
	}
	if p, _ := c.Resolve(Record{PID: 6, ExitTS: 1, ExeDev: 7, ExeIno: 1, Filename: "/a/b", Flags: FlagFnameTrunc}); p != "" {
		t.Fatalf("обрезанный путь принят: %q", p)
	}
	if p, _ := c.Resolve(Record{PID: 5, ExeDev: 7, ExeIno: 1}); p != "" {
		t.Fatalf("удалённый образ принят: %q", p)
	}
	if p, how := c.Resolve(Record{PID: 5, Filename: "/a/b"}); p != "" || how != ImageUnresolved {
		t.Fatalf("без inode: %q %q", p, how)
	}
}

func TestImage_CacheIsBoundedAndPutIgnoresEmpty(t *testing.T) {
	c := NewImageCacheWith(3, func(string) (uint32, uint64, bool) { return 0, 0, false }, func(string) (string, error) { return "", errors.New("x") })
	for i := uint64(1); i <= 10; i++ {
		c.Put(1, i, "/p")
	}
	if c.Len() > 3 {
		t.Fatalf("кэш вышел за предел: %d", c.Len())
	}
	c.Put(1, 0, "/p")
	c.Put(1, 5, "")
	if c.Len() > 3 {
		t.Fatal("пустые записи приняты")
	}
}

func TestKernelDevFromStat(t *testing.T) {
	if got, want := KernelDevFromStat(0xFE01), uint32(254<<20|1); got != want {
		t.Errorf("%#x want %#x", got, want)
	}
	major, minor := uint64(259), uint64(0x1ab)
	enc := (minor & 0xff) | (major << 8) | ((minor &^ 0xff) << 12)
	if got, want := KernelDevFromStat(enc), uint32(259<<20|0x1ab); got != want {
		t.Errorf("%#x want %#x", got, want)
	}
}
