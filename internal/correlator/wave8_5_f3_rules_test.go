package correlator

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"
)

// Контроль F3 на уровне правил: служебные cmd, которые агент больше не
// показывает себе, не читает НИ ОДНО правило боевого набора по nr=321 — ни
// арг-условием, ни исключением. Правило без условия на arg0 (читает любой cmd)
// допустимо только из явного списка: новое такое правило — красный тест, его
// автор решает, нужен ли ему служебный вход от агента.
func TestW85_F3_NoRuleReadsAServiceCmdOnBPF(t *testing.T) {
	rules, err := LoadRulesFromDir("../../rules")
	require.NoError(t, err)
	svc := map[string]bool{}
	for _, c := range internalbpf.SelfExcludedBPFServiceCmds {
		svc[strconv.Itoa(int(c))] = true
	}
	// Правила, читающие любой cmd bpf(): их вход от СВОЕГО tgid агента исчезает намеренно
	// (решение владельца 12.10); вход от чужих процессов не меняется.
	anyCmdAllowed := map[string]string{
		"drift_dangerous_syscall": "класс drift: смотрит все cmd; от агента служебные не нужны",
	}
	for i := range rules {
		r := &rules[i]
		conds := getAllConditions(r)
		var hasNR321, hasArg0 bool
		for _, c := range conds {
			if c.Field == "nr" {
				for _, v := range c.Values {
					if v == "321" {
						hasNR321 = true
					}
				}
			}
		}
		if !hasNR321 {
			continue
		}
		for _, c := range conds {
			if c.Field != "arg0" {
				continue
			}
			hasArg0 = true
			for _, v := range c.Values {
				assert.Falsef(t, svc[v], "правило %s читает служебный cmd %s на nr=321: F3 спрячет его от агента, но правило перестанет видеть вход агента", r.ID, v)
			}
		}
		if !hasArg0 {
			_, ok := anyCmdAllowed[r.ID]
			assert.Truef(t, ok, "правило %s читает nr=321 без условия на arg0 — вход служебных cmd от агента F3 снимет; внести в список осознанно", r.ID)
		}
	}
}
