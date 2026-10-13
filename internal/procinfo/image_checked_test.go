package procinfo

import (
	"fmt"
	"runtime"
	"testing"
)

// E1: попадание в кэш сверяется stat'ом — файл, заменённый или удалённый по тому же пути, не образ.
func TestImage_ResolveChecked_CachedHitIsVerified(t *testing.T) {
	f, c := newFS()
	f.stat["/usr/bin/x"] = [2]uint64{7, 100}
	rec := Record{PID: 1, ExeDev: 7, ExeIno: 100}
	rec.ExitTS = 5 // вышел: живого readlink нет, путь только из exec-filename
	rec.Filename = "/usr/bin/x"
	if p, how := c.ResolveChecked(rec); p != "/usr/bin/x" || how != ImageFilename {
		t.Fatalf("%q %q", p, how)
	}
	if p, how := c.ResolveChecked(rec); p != "/usr/bin/x" || how != ImageCached {
		t.Fatalf("второй раз из кэша: %q %q", p, how)
	}
	// файл заменили по тому же пути: inode 100 больше не по этому пути
	f.stat["/usr/bin/x"] = [2]uint64{7, 200}
	if p, how := c.ResolveChecked(rec); p != "" || how != ImageStale {
		t.Fatalf("замена файла: %q %q (старый inode не должен получать новый путь)", p, how)
	}
	if c.Len() != 0 {
		t.Fatal("устаревшая запись не выброшена")
	}
	// новый процесс с новым inode — новый путь
	rec2 := Record{PID: 2, ExitTS: 6, ExeDev: 7, ExeIno: 200, Filename: "/usr/bin/x"}
	if p, how := c.ResolveChecked(rec2); p != "/usr/bin/x" || how != ImageFilename {
		t.Fatalf("новый inode: %q %q", p, how)
	}
	// файл удалён: stat не находит — устаревшая запись
	delete(f.stat, "/usr/bin/x")
	if p, how := c.ResolveChecked(rec2); p != "" || how != ImageStale {
		t.Fatalf("удалённый файл: %q %q", p, how)
	}
}

func TestImage_ResolveChecked_NoInode(t *testing.T) {
	_, c := newFS()
	if p, how := c.ResolveChecked(Record{PID: 1}); p != "" || how != ImageUnresolved {
		t.Fatalf("%q %q", p, how)
	}
}

// A1 (инвентарь памяти, E1): кэш «inode → путь» на полной ёмкости — числом, не оценкой. Путь средней
// длины 48 Б; потолок 1 МиБ — запас на порядок над ожидаемыми сотнями образов.
func TestImage_CacheBytesAtCapacity(t *testing.T) {
	_, c := newFS()
	c = NewImageCacheWith(4096, c.stat, c.link)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < 4096; i++ {
		c.Put(7, uint64(1000+i), fmt.Sprintf("/usr/lib/x86_64-linux-gnu/some/dir/image-%06d.bin", i))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	b := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("кэш образов: %d записей, %d Б кучи (%d Б/запись)", c.Len(), b, b/int64(c.Len()))
	if c.Len() != 4096 || b > 1<<20 {
		t.Fatalf("%d записей, %d Б", c.Len(), b)
	}
	runtime.KeepAlive(c)
}
