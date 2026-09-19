package collector

import (
	"os"
	"strings"
	"testing"
)

// №390 (волна 6.3-up). Зонд контролей, писавший в ПРИСОЕДИНЁННЫЙ DNS-сокет
// тремя способами, дал на одном и том же сокете: send(2) Δ=0 событий,
// write(2) Δ=1, sendto(2) с адресом Δ=1. Причина — `trace_sendto` брал адрес
// из args[4] и выходил на `if (!addr) return 0;`, не заглянув в
// dns_socket_map, а send(2) на Linux и ЕСТЬ sendto(2) с NULL-адресом
// (отдельного номера syscall'а у него нет). Резолвер, пишущий через send(),
// был невидим целиком — как coredns до №328. Ровно та же дыра была во второй
// половине: sendmsg() на присоединённом сокете несёт msg_name=NULL.
//
// Проверяется ИСХОДНИК, а не поведение, и это осознанно: BPF-часть на
// машинах разработки не компилируется вовсе (*_bpf_gen.go в дереве —
// заглушки), поэтому регрессия «кто-то вернул ранний выход по NULL-адресу»
// иначе ловится только прогоном на стенде — то есть на цену целого замера.
func TestDNSBPFSendPathsFallBackToSocketMap(t *testing.T) {
	src, err := os.ReadFile("../../bpf/dns.bpf.c")
	if err != nil {
		t.Fatalf("read bpf/dns.bpf.c: %v", err)
	}
	text := string(src)

	for _, fn := range []string{"trace_sendto", "trace_sendmsg", "trace_write"} {
		body := bpfFunctionBody(t, text, fn)
		if !strings.Contains(body, "is_dns_socket_fd") {
			t.Errorf("%s: не сверяется с dns_socket_map — запись в присоединённый сокет "+
				"(send(2), sendmsg() с msg_name=NULL) снова невидима, находка №390", fn)
		}
	}

	// Ранний выход по NULL-адресу — именно та форма, что была дефектом:
	// `if (!addr)\n\t\treturn 0;` без альтернативы по fd.
	for _, fn := range []string{"trace_sendto", "trace_sendmsg"} {
		body := bpfFunctionBody(t, text, fn)
		if strings.Contains(body, "if (!addr)\n\t\treturn 0;") {
			t.Errorf("%s: безусловный ранний выход `if (!addr) return 0;` вернулся — "+
				"адрес не единственная идентичность вызова, fd несёт её всегда (№390)", fn)
		}
	}
}

// bpfFunctionBody возвращает текст от строки `int <fn>(` до следующей строки,
// начинающейся с `}` в нулевой колонке. Разбор грубый и этого достаточно: в
// этом файле каждая программа — функция верхнего уровня.
func bpfFunctionBody(t *testing.T, text, fn string) string {
	t.Helper()
	idx := strings.Index(text, "int "+fn+"(")
	if idx < 0 {
		t.Fatalf("функция %s не найдена в bpf/dns.bpf.c", fn)
	}
	rest := text[idx:]
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}
