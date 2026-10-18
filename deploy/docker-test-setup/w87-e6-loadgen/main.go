//go:build linux

// Волна 8.7, заход Е6: генератор нагрузки для ступенчатого смока насыщения агента.
//
// Даёт заданный темп операций (ops/s) со смесью, повторяющей поток ноды (file ≈ 78%,
// syscall ≈ 21%, network ≈ 2% по events_total рабочего агента 17.10): чтение по
// открытому fd (хук sys_enter_read), open+read+close (openat), prctl(PR_GET_DUMPABLE)
// (raw_syscalls), connect на свой слушатель 127.0.0.1 (tcp_connect/tcp_close) и
// fork+exec /bin/true (sched_process_exec и файловый хвост загрузчика).
// Вызовы — сырые syscall, чтобы число поданных операций было известно точно.
// Сколько СОБЫТИЙ агента даёт одна операция, генератор не знает: это калибруется на
// нижней ступени по events_total (w87-e6-table.sh).
//
//	e6load -rate 5000 -dur 60 -workers 2 -mix read=60,open=20,prctl=15,connect=4,exec=1 -dir /var/tmp/e6
//
// -rate 0 — без ограничения темпа (ступень «max»). Итог — одна строка JSON на stdout.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	opRead = iota
	opOpen
	opPrctl
	opConnect
	opExec
	nOps
)

var opNames = [nOps]string{"read", "open", "prctl", "connect", "exec"}

const nFiles = 64

func parseMix(s string) ([nOps]int, error) {
	var w [nOps]int
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			return w, fmt.Errorf("mix: %q без «=»", kv)
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return w, fmt.Errorf("mix: %q", kv)
		}
		found := false
		for i, name := range opNames {
			if name == k {
				w[i] = n
				found = true
			}
		}
		if !found {
			return w, fmt.Errorf("mix: неизвестная операция %q", k)
		}
	}
	return w, nil
}

// sequence раскладывает веса в равномерную последовательность (сглаженный взвешенный
// round-robin), чтобы смесь держалась на любом отрезке, а не пачками по типу.
func sequence(w [nOps]int) []int {
	total := 0
	for _, x := range w {
		total += x
	}
	cur := [nOps]int{}
	seq := make([]int, 0, total)
	for len(seq) < total {
		best := -1
		for i := range w {
			cur[i] += w[i]
			if w[i] > 0 && (best < 0 || cur[i] > cur[best]) {
				best = i
			}
		}
		cur[best] -= total
		seq = append(seq, best)
	}
	return seq
}

type worker struct {
	fds    []int
	fi     int
	buf    []byte
	paths  []string
	port   int
	counts [nOps]uint64
	errs   [nOps]uint64
	// connectErrno — разбивка ошибок connect по errno (волна 8.8, Р0(а)): чем именно
	// генератор упёрся (EADDRNOTAVAIL — порты, EAGAIN/ETIMEDOUT — backlog).
	connectErrno map[string]uint64
}

func (w *worker) do(op int) {
	var err error
	switch op {
	case opRead:
		fd := w.fds[w.fi%len(w.fds)]
		w.fi++
		var n int
		n, err = syscall.Read(fd, w.buf)
		if err == nil && n < len(w.buf) {
			_, err = syscall.Seek(fd, 0, 0)
		}
	case opOpen:
		p := w.paths[w.fi%len(w.paths)]
		w.fi++
		var fd int
		fd, err = syscall.Open(p, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err == nil {
			_, err = syscall.Read(fd, w.buf)
			syscall.Close(fd)
		}
	case opPrctl:
		_, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
		if e != 0 {
			err = e
		}
	case opConnect:
		var fd int
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err == nil {
			// Волна 8.8, Р0(а): блокирующий connect на переполненный backlog слушателя
			// ждал повтора SYN (ступень 60 000 шла 79,5 с вместо 60 в Е6) — это артефакт
			// генератора, не агента. SO_SNDTIMEO обрывает ожидание, ошибка считается.
			tv := syscall.NsecToTimeval(int64(200 * time.Millisecond))
			_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)
			// EINTR — сигнал планировщика Go (SIGURG) прервал блокирующий connect: это не отказ
			// сервера, а артефакт рантайма генератора (стенд, 22:39: 51 ошибка «interrupted system call»).
			sa := &syscall.SockaddrInet4{Port: w.port, Addr: [4]byte{127, 0, 0, 1}}
			for try := 0; try < 4; try++ {
				err = syscall.Connect(fd, sa)
				if err != syscall.EINTR {
					break
				}
			}
			syscall.Close(fd)
		}
	case opExec:
		err = exec.Command("/bin/true").Run()
	}
	if err != nil {
		w.errs[op]++
		if op == opConnect {
			if w.connectErrno == nil {
				w.connectErrno = map[string]uint64{}
			}
			w.connectErrno[err.Error()]++
		}
		return
	}
	w.counts[op]++
}

// listenBig слушает 127.0.0.1:0 с backlog 65535 (ядро урежет до somaxconn).
func listenBig() (net.Listener, int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		syscall.Close(fd)
		return nil, 0, err
	}
	if err := syscall.Listen(fd, 65535); err != nil {
		syscall.Close(fd)
		return nil, 0, err
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, 0, err
	}
	f := os.NewFile(uintptr(fd), "listener")
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return nil, 0, err
	}
	return ln, sa.(*syscall.SockaddrInet4).Port, nil
}

func main() {
	rate := flag.Float64("rate", 1000, "операций в секунду на все воркеры; 0 — без ограничения")
	dur := flag.Duration("dur", 60*time.Second, "длительность")
	workers := flag.Int("workers", 2, "воркеров")
	mixS := flag.String("mix", "read=60,open=20,prctl=15,connect=4,exec=1", "веса операций")
	execCap := flag.Float64("exec-cap", 300, "потолок exec/s на все воркеры (fork дорог и перекосил бы ступень)")
	dir := flag.String("dir", "/var/tmp/e6", "каталог файлов нагрузки")
	// Волна 8.8, п.1б: «горячий атакующий» — процесс, который сам разгоняет темп выше порога сброса и,
	// пока идёт поток, периодически открывает и читает /etc/shadow (правило cred_shadow_read).
	shadowEvery := flag.Duration("shadow-every", 0, "если > 0 — раз в этот интервал open+read /etc/shadow (контроль горячего атакующего)")
	flag.Parse()

	mix, err := parseMix(*mixS)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	seq := sequence(mix)
	if len(seq) == 0 {
		fmt.Fprintln(os.Stderr, "mix: все веса нулевые")
		os.Exit(2)
	}

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	paths := make([]string, nFiles)
	data := make([]byte, 64<<10)
	for i := range paths {
		paths[i] = filepath.Join(*dir, fmt.Sprintf("data-%02d.bin", i))
		if err := os.WriteFile(paths[i], data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	// Волна 8.8, Р0(а): слушатель с большим backlog и несколькими accept-горутинами —
	// на ступенях 45 000+ оп/с очередь Go-слушателя (somaxconn) переполнялась.
	ln, port, err := listenBig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer ln.Close()
	for a := 0; a < 8; a++ {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}

	ws := make([]*worker, *workers)
	for i := range ws {
		w := &worker{buf: make([]byte, 4096), paths: paths, port: port}
		for j := 0; j < 8; j++ {
			fd, err := syscall.Open(paths[(i*8+j)%nFiles], syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			w.fds = append(w.fds, fd)
		}
		ws[i] = w
	}

	// SIGINT/SIGTERM — штатный конец (режим attack держит генератор, пока идёт пакет): итог всё равно печатается.
	var stop atomic.Bool
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; stop.Store(true) }()

	var shadowReads atomic.Uint64
	if *shadowEvery > 0 {
		go func() {
			buf := make([]byte, 256)
			for !stop.Load() {
				if fd, err := syscall.Open("/etc/shadow", syscall.O_RDONLY|syscall.O_CLOEXEC, 0); err == nil {
					if _, err := syscall.Read(fd, buf); err == nil {
						shadowReads.Add(1)
					}
					syscall.Close(fd)
				}
				time.Sleep(*shadowEvery)
			}
		}()
	}

	var execBudget atomic.Int64 // exec, разрешённые сверх уже сделанных (пополняется по exec-cap)
	start := time.Now()
	deadline := start.Add(*dur)
	stopCap := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		per := *execCap / 100
		acc := 0.0
		for {
			select {
			case <-stopCap:
				return
			case <-t.C:
				acc += per
				if n := int64(acc); n > 0 {
					acc -= float64(n)
					if execBudget.Load() < int64(*execCap) {
						execBudget.Add(n)
					}
				}
			}
		}
	}()

	var wg sync.WaitGroup
	perWorker := *rate / float64(*workers)
	for i, w := range ws {
		wg.Add(1)
		go func(i int, w *worker) {
			defer wg.Done()
			si := i * 7
			var done float64
			for {
				now := time.Now()
				if now.After(deadline) || stop.Load() {
					return
				}
				due := 256.0
				if perWorker > 0 {
					due = now.Sub(start).Seconds()*perWorker - done
					if due < 1 {
						time.Sleep(200 * time.Microsecond)
						continue
					}
					if due > 4096 {
						due = 4096 // отставание не догоняется лавиной
					}
				}
				for k := 0; k < int(due); k++ {
					op := seq[si%len(seq)]
					si++
					if op == opExec {
						if execBudget.Add(-1) < 0 {
							execBudget.Add(1)
							op = opPrctl // exec сверх потолка заменяется дешёвой операцией, темп сохраняется
						}
					}
					w.do(op)
				}
				done += float64(int(due))
			}
		}(i, w)
	}
	wg.Wait()
	close(stopCap)
	elapsed := time.Since(start).Seconds()

	out := map[string]any{"rate_target": *rate, "workers": *workers, "mix": *mixS, "elapsed_s": elapsed, "pid": os.Getpid()}
	ops := map[string]uint64{}
	errsM := map[string]uint64{}
	var total uint64
	for _, w := range ws {
		for op := 0; op < nOps; op++ {
			ops[opNames[op]] += w.counts[op]
			errsM[opNames[op]] += w.errs[op]
			total += w.counts[op]
		}
	}
	out["shadow_reads"] = shadowReads.Load()
	out["ops"] = ops
	out["errors"] = errsM
	out["connect_errors"] = errsM["connect"]
	cerr := map[string]uint64{}
	for _, w := range ws {
		for k, v := range w.connectErrno {
			cerr[k] += v
		}
	}
	out["connect_errno"] = cerr
	out["ops_total"] = total
	out["ops_per_s"] = float64(total) / elapsed
	// CPU самого генератора (и детей exec отдельно): на 4 ядрах стенда он делит машину с агентом.
	var ru, rc syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	syscall.Getrusage(syscall.RUSAGE_CHILDREN, &rc)
	tv := func(t syscall.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }
	out["cpu_self_s"] = tv(ru.Utime) + tv(ru.Stime)
	out["cpu_children_s"] = tv(rc.Utime) + tv(rc.Stime)
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
