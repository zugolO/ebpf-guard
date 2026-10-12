package bpf

// Волна 8.5, F3: какие bpf(2)-команды агент не показывает себе в потоке.
//
// SelfExcludedBPFServiceCmds зеркалит bpf_cmd_is_service() в bpf/syscall.bpf.c
// (сверка по исходнику — TestW85_F3_ServiceCmdsMirrorTheKernelSwitch). Это
// ПОЗИТИВНЫЙ список служебных команд чтения/записи собственных карт:
//
//	1 MAP_LOOKUP_ELEM, 2 MAP_UPDATE_ELEM, 4 MAP_GET_NEXT_KEY,
//	21 MAP_LOOKUP_AND_DELETE_ELEM, 24 MAP_LOOKUP_BATCH,
//	25 MAP_LOOKUP_AND_DELETE_BATCH, 26 MAP_UPDATE_BATCH, 27 MAP_DELETE_BATCH.
//
// Всё вне списка — в том числе BPFDestructiveCmds — от агента идёт как раньше.
var SelfExcludedBPFServiceCmds = []uint32{1, 2, 4, 21, 24, 25, 26, 27}

// BPFDestructiveCmds — команды, которые читают правила eBPF-subversion и
// rootkit_bpf_* (решение владельца 12.10): 0 MAP_CREATE, 3 MAP_DELETE_ELEM,
// 5 PROG_LOAD, 6 OBJ_PIN, 9 PROG_DETACH, 33 LINK_DETACH-класс. Самоисключение
// их не касается ни при каких обстоятельствах.
var BPFDestructiveCmds = []uint32{0, 3, 5, 6, 9, 33}
