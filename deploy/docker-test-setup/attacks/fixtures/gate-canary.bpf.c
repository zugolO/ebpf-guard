/*
 * 5.9.5j (долг 5.9.4e): минимальный источник для позитивного контроля
 * rootkit_bpf_prog_load_suspicious. Правило матчит bpf(2) с arg0=BPF_PROG_LOAD
 * (rules/rootkit-detection.yaml) — единственный реальный способ его вызвать
 * без спуфинга comm — это дать bpftool загрузить настоящий скомпилированный
 * BPF-объект (bpftool prog load сам не доходит до syscall на невалидном
 * файле, см. run-all-attacks.sh:run_bpf_attack).
 *
 * Ничего не делает: SEC("socket") без карт и без хелперов — самый простой
 * тип программы, не требующий привязки к интерфейсу или какого-либо
 * состояния ядра сверх самой загрузки. Не собран в бинарник и не хранится
 * в репозитории как .bpf.o (нет линуксового clang/BPF-таргета в песочнице,
 * где писался этот файл, и бинарный артефакт не был бы проверяем/переносим
 * между версиями ядра) — компилируется на стенде во время атаки, см.
 * run_bpf_attack() в run-all-attacks.sh.
 */

#define SEC(name) __attribute__((section(name), used))

SEC("socket")
int gate_canary(void *ctx)
{
	return 0;
}

SEC("license")
char _license[] = "GPL";
