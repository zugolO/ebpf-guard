package correlator

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// П4: разобранные при компиляции CIDR и пороги дают то же, что прежние matchesCIDR/compareNumeric.
func TestP4_CIDRPrecompiledMatchesLegacy(t *testing.T) {
	re := NewRuleEngine(nil)
	sets := [][]string{
		{"10.0.0.0/8"}, {"169.254.169.254/32", "100.64.0.0/10"}, {"0.0.0.0/0"}, {"2001:db8::/32"},
		{"10.0.0.0/8", "fe80::/10", "192.168.0.0/16"}, {"172.16.0.0/12", "127.0.0.0/8"}, {"::/0"}, {"10.1.2.3/8"},
	}
	rng := rand.New(rand.NewSource(8705))
	addrs := []string{"", "x", "1.2.3", "10.1.2.3", "10.255.255.255", "169.254.169.254", "100.100.1.1", "::", "::1", "2001:db8::1",
		"2001:db9::1", "fe80::1", "fe80::1%eth0", "::ffff:10.1.2.3", "::ffff:8.8.8.8", "192.168.5.5", "1.1.1.1", "255.255.255.255", "0.0.0.0", "01.2.3.4"}
	for i := 0; i < 400; i++ {
		addrs = append(addrs, fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256)))
		addrs = append(addrs, fmt.Sprintf("%x:%x::%x", 0x2001+rng.Intn(3), 0xdb8+rng.Intn(3), rng.Intn(1000)))
	}
	for _, set := range sets {
		for _, op := range []RuleConditionOperator{OpInCIDR, OpNotInCIDR} {
			c := &RuleCondition{Field: "daddr", Op: op, Values: set}
			require.NoError(t, re.compileCondPtr(c))
			require.NotNil(t, c.cidrPfx, "набор %v должен разбираться при компиляции", set)
			for _, a := range addrs {
				want := re.matchesCIDR(a, set, op == OpInCIDR)
				got := cidrMatchString(c.cidrPfx, a, op == OpInCIDR)
				require.Equal(t, want, got, "набор %v op %s адрес %q", set, op, a)
			}
		}
	}
	// 4in6-префикс остаётся на прежнем пути целиком
	c := &RuleCondition{Field: "daddr", Op: OpInCIDR, Values: []string{"::ffff:10.0.0.0/104"}}
	require.NoError(t, re.compileCondPtr(c))
	require.Nil(t, c.cidrPfx)
}

// Адрес из байт события совпадает с адресом, который дал бы FormatIP → ParseIP.
func TestP4_CIDRFromBytesMatchesString(t *testing.T) {
	re := NewRuleEngine(nil)
	set := []string{"10.0.0.0/8", "169.254.0.0/16", "2001:db8::/32", "192.168.0.0/16"}
	c := &RuleCondition{Field: "daddr", Op: OpInCIDR, Values: set}
	require.NoError(t, re.compileCondPtr(c))
	rng := rand.New(rand.NewSource(8706))
	for i := 0; i < 5000; i++ {
		var b [16]byte
		rng.Read(b[:])
		if rng.Intn(2) == 0 {
			b[0], b[1] = []byte{10, 169, 192, 8}[rng.Intn(4)], byte(rng.Intn(256))
			if b[0] == 169 {
				b[1] = 254
			}
			if b[0] == 192 {
				b[1] = 168
			}
		}
		if rng.Intn(6) == 0 {
			b = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(rng.Intn(9))}
		}
		if rng.Intn(9) == 0 { // v4-mapped в семействе inet6
			b = [16]byte{10: 0xff, 11: 0xff, 12: 10, 13: byte(rng.Intn(256)), 14: 1, 15: 2}
		}
		for _, fam := range []types.AddressFamily{types.AFInet, types.AFInet6} {
			e := types.Event{Type: types.EventTCPConnect, Network: &types.NetworkEvent{Family: fam, Daddr: b}}
			str := fmt.Sprint(re.getFieldValueNorm(&e, "daddr", nil, nil))
			want := re.matchesCIDR(str, set, true)
			got := cidrMatchAddr(c.cidrPfx, netipFromEvent(&e.Network.Daddr, fam), true)
			require.Equal(t, want, got, "fam=%v addr=%x str=%s", fam, b, str)
		}
	}
}

func TestP4_NumericThresholdMatchesLegacy(t *testing.T) {
	re := NewRuleEngine(nil)
	thr := []string{"0", "10", "-3", "1.5", "1e3", "abc", "", "0x10", "99999999999999999999"}
	vals := []string{"", "0", "10", "11", "9", "-3", "-4", "1.5", "1.6", "1000", "999.9", "x", "NaN", "Inf", "0x10", "1e400"}
	kinds := []struct {
		op   RuleConditionOperator
		kind int
		f    func(a, b float64) bool
	}{{OpGreaterThan, 0, func(a, b float64) bool { return a > b }}, {OpLessThan, 1, func(a, b float64) bool { return a < b }},
		{OpGreaterOrEqual, 2, func(a, b float64) bool { return a >= b }}, {OpLessOrEqual, 3, func(a, b float64) bool { return a <= b }}}
	for _, k := range kinds {
		for _, th := range thr {
			c := &RuleCondition{Field: "arg0", Op: k.op, Values: []string{th}}
			require.NoError(t, re.compileCondPtr(c))
			for _, v := range vals {
				require.Equal(t, re.compareNumeric(v, c.Values, k.f), c.numericCmp(re, v, k.kind), "op %s thr %q val %q", k.op, th, v)
			}
		}
		// без значений и без компиляции
		c := &RuleCondition{Field: "arg0", Op: k.op}
		require.NoError(t, re.compileCondPtr(c))
		require.False(t, c.numericCmp(re, "5", k.kind))
		raw := &RuleCondition{Field: "arg0", Op: k.op, Values: []string{"3"}}
		for _, v := range vals {
			require.Equal(t, re.compareNumeric(v, raw.Values, k.f), raw.numericCmp(re, v, k.kind))
		}
	}
	_ = strconv.Itoa
}

// П4: IsMiningPoolIP по набору префиксов ≡ прежний перебор IPNet.
func TestP4_MiningPoolPrefixSetMatchesLegacy(t *testing.T) {
	f := t.TempDir() + "/pools.txt"
	require.NoError(t, os.WriteFile(f, []byte("45.9.148.0/24 # a\n185.0.0.0/8\n2a01:4f8::/32\nevil.pool.example\n10.0.0.0/8\n"), 0o600))
	d, err := NewMiningPoolDetector(f)
	require.NoError(t, err)
	require.True(t, d.pfxOK)
	rng := rand.New(rand.NewSource(8707))
	addrs := []string{"45.9.148.7", "45.9.149.7", "185.1.2.3", "10.1.1.1", "2a01:4f8::1", "2a01:4f9::1", "::ffff:185.1.2.3", "x", "", "fe80::1%eth0"}
	for i := 0; i < 2000; i++ {
		addrs = append(addrs, fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256)))
	}
	for _, a := range addrs {
		got := d.IsMiningPoolIP(a)
		d.mu.Lock()
		d.pfxOK = false
		d.mu.Unlock()
		want := d.IsMiningPoolIP(a)
		d.mu.Lock()
		d.pfxOK = true
		d.mu.Unlock()
		require.Equal(t, want, got, a)
	}
}
