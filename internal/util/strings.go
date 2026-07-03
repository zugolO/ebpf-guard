package util

import "strings"

// Truncate shortens s to at most n runes, appending a single-rune ellipsis
// ("…") when it has to cut. It counts and slices by rune, not byte, so it never
// splits a multi-byte UTF-8 character mid-sequence. n <= 0 yields "".
func Truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n == 1 {
		return string(runes[:1])
	}
	return string(runes[:n-1]) + "…"
}

// SplitAndTrim splits s on sep, trims surrounding whitespace from each element,
// and drops empty/whitespace-only elements.
func SplitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
