// Package exporter tests UTF-8 sanitization of kernel-supplied label values.
package exporter

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetAnomalyScoreInvalidUTF8 reproduces the crash from the 2026-08-04 idle
// run: a process whose comm contained the bytes \xfe\xff reached
// WithLabelValues, and the Prometheus client panicked with
//
//	panic: label value "\xfe\xff" is not valid UTF-8
//
// taking the whole agent down mid-run. comm is attacker-controlled, so this is
// reachable on purpose during an attack, not just by accident.
func TestSetAnomalyScoreInvalidUTF8(t *testing.T) {
	guard := NewAnomalyScoreGuard()

	// The exact byte sequence from the production panic.
	require.NotPanics(t, func() {
		guard.SetAnomalyScore("676182", "\xfe\xff", 0.5)
	}, "invalid UTF-8 comm must not panic")

	// Other shapes of hostile input.
	hostile := []string{
		"\xff",               // lone invalid byte
		"nginx\xfe\xff",      // valid prefix, invalid tail
		"a\x00b",             // embedded NUL
		"\x1b[31mred\x1b[0m", // ANSI escapes
		"tab\there",          // control character
		string([]byte{0x80}), // stray continuation byte
	}
	for _, comm := range hostile {
		require.NotPanics(t, func() {
			guard.SetAnomalyScore("1234", comm, 0.9)
		}, "comm %q must not panic", comm)
	}
}

// TestSanitizeLabelValue checks that output is always valid UTF-8 and that
// legitimate values survive untouched.
func TestSanitizeLabelValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain ascii unchanged", "nginx", "nginx"},
		{"empty unchanged", "", ""},
		{"path-like unchanged", "/usr/bin/curl", "/usr/bin/curl"},
		{"invalid bytes escaped", "\xfe\xff", `\xfe\xff`},
		{"valid prefix kept", "nginx\xff", `nginx\xff`},
		{"NUL escaped", "a\x00b", `a\x00b`},
		{"DEL escaped", "a\x7fb", `a\x7fb`},
		{"newline escaped", "a\nb", `a\x0ab`},
		{"valid multibyte kept", "café", "café"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLabelValue(tt.in)
			assert.Equal(t, tt.want, got)
			assert.True(t, utf8.ValidString(got),
				"sanitized output must be valid UTF-8, got %q", got)
		})
	}
}

// TestSanitizeLabelValueAlwaysValidUTF8 fuzzes arbitrary byte sequences to
// guarantee the invariant the Prometheus client depends on.
func TestSanitizeLabelValueAlwaysValidUTF8(t *testing.T) {
	for b := 0; b < 256; b++ {
		in := string([]byte{byte(b)})
		got := SanitizeLabelValue(in)
		assert.True(t, utf8.ValidString(got),
			"byte 0x%02x produced invalid UTF-8: %q", b, got)
	}
}

// TestEvictionUsesSanitizedLabels guards the ordering bug: sanitization happens
// before the map key is built, so eviction deletes the same series that was
// created. If comm were sanitized only at the WithLabelValues call, eviction
// would call DeleteLabelValues with the raw bytes and leak the series forever.
func TestEvictionUsesSanitizedLabels(t *testing.T) {
	guard := NewAnomalyScoreGuard()
	guard.SetAnomalyScore("999", "\xfe\xff", 0.5)

	entry, ok := guard.entries["999/"+SanitizeLabelValue("\xfe\xff")]
	require.True(t, ok, "entry must be keyed by the sanitized comm")
	assert.Equal(t, SanitizeLabelValue("\xfe\xff"), entry.Comm,
		"stored Comm must be sanitized so DeleteLabelValues matches")
	assert.True(t, utf8.ValidString(entry.Comm))

	// Updating the same process must hit the existing entry, not create a second.
	guard.SetAnomalyScore("999", "\xfe\xff", 0.7)
	assert.Len(t, guard.entries, 1, "same comm must not create a duplicate series")
}
