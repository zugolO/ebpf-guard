package bpf

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Волна 8.2, C3 (№541): ОДИН набор типов ядра на все загрузки BPF-объектов.
//
// Без него cilium/ebpf v0.16 на КАЖДУЮ программу с CO-RE-релокациями зовёт
// btf.LoadKernelSpec(), а та отдаёт spec.Copy() — свежую копию с пустым кэшем
// копий типов. Релокация трогает task_struct и прочее, а mutableTypes.add копирует
// тип вместе со ВСЕМИ достижимыми потомками, то есть кусок графа vmlinux копируется
// заново для каждой программы (68 программ при старте, коллекторы грузятся
// параллельно). Профиль у пика старта (A3, 10.10.2026): живая куча 124 МБ, из них
// ≈55 МБ — BTF, из них copyType 29 МБ — копии, живые в момент пика.
//
// Один общий *btf.Spec в Programs.KernelTypes даёт одну копию графа с общим кэшем
// (mutableTypes защищён RWMutex — безопасен при параллельных загрузках) и ни одной
// LoadKernelSpec() на релокацию. Освобождается вместе с кэшем cilium в
// FlushKernelBTF — после последнего загрузчика.
var sharedKernelTypes struct {
	sync.Mutex
	spec     *btf.Spec
	released bool // после FlushKernelBTF новые загрузки идут штатным путём cilium
}

// loadKernelSpec — точка подмены для тестов; на не-Linux возвращает ошибку.
var loadKernelSpec = btf.LoadKernelSpec

// SharedKernelTypes возвращает общий *btf.Spec типов ядра для CO-RE-релокаций
// или nil, если его нет (нет BTF, либо кэш уже освобождён): nil значит «штатный
// путь cilium», то есть поведение до C3.
func SharedKernelTypes() *btf.Spec {
	sharedKernelTypes.Lock()
	defer sharedKernelTypes.Unlock()
	if sharedKernelTypes.released {
		return nil
	}
	if sharedKernelTypes.spec == nil {
		spec, err := loadKernelSpec()
		if err != nil {
			// Не запоминаем отказ как release: следующий загрузчик попробует снова,
			// а до тех пор cilium сам решит, что делать без BTF.
			return nil
		}
		sharedKernelTypes.spec = spec
	}
	return sharedKernelTypes.spec
}

// WithSharedKernelTypes подставляет общие типы ядра в opts (создаёт opts, если
// nil) и возвращает его. Явно заданные вызывающим KernelTypes не трогает.
func WithSharedKernelTypes(opts *ebpf.CollectionOptions) *ebpf.CollectionOptions {
	if opts == nil {
		opts = &ebpf.CollectionOptions{}
	}
	if opts.Programs.KernelTypes == nil {
		opts.Programs.KernelTypes = SharedKernelTypes()
	}
	return opts
}

// releaseSharedKernelTypes отпускает общий spec; дальше SharedKernelTypes — nil.
func releaseSharedKernelTypes() {
	sharedKernelTypes.Lock()
	sharedKernelTypes.spec = nil
	sharedKernelTypes.released = true
	sharedKernelTypes.Unlock()
}
