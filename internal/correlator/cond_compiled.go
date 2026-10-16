package correlator

import (
	"net/netip"
	"strconv"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.7, П4: числовые пороги и CIDR разбираются при компиляции условия, а не на
// каждое событие. Семантика прежняя до байта: тождество проверяют p4_cond_test.go
// (прежние compareNumeric / matchesCIDR остаются эталоном) и дамп idle.

// compileNumericAndCIDR заполняет numThr/cidrPfx. Вызывается из compileCondPtr после
// opCode; пустое поле = «разобрать нельзя, работает прежний путь».
// condPrecompile — выключатель П4 для бенча «до/после» и теста тождества на дампе.
var condPrecompile = true

func (c *RuleCondition) compileNumericAndCIDR() {
	if !condPrecompile {
		c.numParsed, c.numOK, c.numThr, c.cidrPfx = false, false, 0, nil
		return
	}
	c.numParsed, c.numOK, c.numThr, c.cidrPfx = true, false, 0, nil
	switch c.opCode {
	case condOpGT, condOpLT, condOpGTE, condOpLTE:
		if len(c.Values) > 0 {
			if v, err := strconv.ParseFloat(c.Values[0], 64); err == nil {
				c.numThr, c.numOK = v, true
			}
		}
	case condOpInCIDR, condOpNotInCIDR:
		pfx := make([]netip.Prefix, 0, len(c.Values))
		for _, v := range c.Values {
			p, err := netip.ParsePrefix(v)
			// 4in6-префикс и всё, что netip понимает иначе, чем net.ParseCIDR, —
			// остаются на прежнем пути целиком.
			if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
				pfx = nil
				break
			}
			pfx = append(pfx, p)
		}
		if len(pfx) == len(c.Values) && len(pfx) > 0 {
			c.cidrPfx = pfx
		}
	}
}

// numericCmp — gt(0)/lt(1)/gte(2)/lte(3); эквивалент compareNumeric.
func (c *RuleCondition) numericCmp(re *RuleEngine, value string, kind int) bool {
	if !c.numParsed {
		var f func(a, b float64) bool
		switch kind {
		case 0:
			f = func(a, b float64) bool { return a > b }
		case 1:
			f = func(a, b float64) bool { return a < b }
		case 2:
			f = func(a, b float64) bool { return a >= b }
		default:
			f = func(a, b float64) bool { return a <= b }
		}
		return re.compareNumeric(value, c.Values, f)
	}
	if !c.numOK {
		return false
	}
	val, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}
	switch kind {
	case 0:
		return val > c.numThr
	case 1:
		return val < c.numThr
	case 2:
		return val >= c.numThr
	default:
		return val <= c.numThr
	}
}

// netipFromEvent — адрес события как netip.Addr: то, что дало бы util.FormatIP и
// net.ParseIP (семейство inet6 — 16 байт, иначе первые 4; v4-mapped сворачивается).
func netipFromEvent(b *[16]byte, family types.AddressFamily) netip.Addr {
	if family == types.AFInet6 {
		return netip.AddrFrom16(*b).Unmap()
	}
	return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
}

// cidrMatchAddr — первый префикс, содержащий адрес, возвращает expect; иначе !expect.
func cidrMatchAddr(pfx []netip.Prefix, a netip.Addr, expect bool) bool {
	for i := range pfx {
		if pfx[i].Contains(a) {
			return expect
		}
	}
	return !expect
}

// cidrMatchString — то же по строке адреса; непарсящийся адрес не совпадает ни с in, ни с not_in.
func cidrMatchString(pfx []netip.Prefix, s string, expect bool) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return false
	}
	return cidrMatchAddr(pfx, a.Unmap(), expect)
}

