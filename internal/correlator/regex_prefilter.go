// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Wave 6.2.2, finding №244 / open question 19. The first pprof profile ever
// taken of the agent put 44.88% of its CPU (cum) in matchesRegex →
// regexp.MatchString → backtrack/tryBacktrack, with tryBacktrack alone at
// 36.02% flat — more than every enrichment path put together and second only
// to the kernel syscalls themselves. Per-rule attribution (offline, see
// TestWave6_2_2_RegexPrefilterAttribution) traced that to a handful of
// `filename` rules whose patterns share one shape:
//
//	".*(c99|r57|…|backdoor)\\.php$"                webshell_common_filename
//	".*/package-lock\\.json$"                      supply_chain_lockfile_recon
//	"(nginx|apache|…|webrick).*?(\\.\\.|%2e|…)"    web_path_traversal_process
//
// Two properties make those pathological on an idle node, where 98.7% of all
// events are file events and essentially none of the paths can ever match:
//
//  1. The leading ".*" is redundant — MatchString already searches every start
//     position — but it makes the backtracker walk the whole path from every
//     one of those positions before failing.
//  2. Failure is decided only after that walk, even though the pattern cannot
//     match without some fixed text (".php", "/package-lock.json") or without
//     one of a fixed set of alternatives ("nginx", "apache", …), and
//     strings.Contains settles that in nanoseconds.
//
// normalizeRegexPattern addresses (1) and requiredLiterals addresses (2). Both
// run at rule-load time; the hot path only gains a short strings.Contains
// loop per pattern. Measured over the shipped ruleset against a realistic
// idle-node file-event mix, the total per-event cost of all 246 file rules
// falls from ~49 µs to ~2 µs.

// normalizeRegexPattern strips a redundant leading ".*" / ".*?" from an
// unanchored pattern.
//
// Soundness: MatchString reports whether the pattern matches ANY substring, so
// for a pattern P without a leading "^", ".*P" matches s exactly when P
// matches s — if ".*P" matches some substring then P matches that substring's
// suffix, and conversely a match of P is a match of ".*P" with ".*" empty.
// Patterns starting with "^" (anchored) or "(" (a group or an inline flag
// such as "(?i)") are left untouched: for those the prefix is not a free
// wildcard and removing it would change the language.
func normalizeRegexPattern(pattern string) string {
	for strings.HasPrefix(pattern, ".*") {
		rest := strings.TrimPrefix(pattern[2:], "?")
		// ".*" followed by another quantifier ("*", "+", "{n,m}") is not a
		// plain wildcard prefix — leave the pattern alone rather than guess.
		if strings.HasPrefix(rest, "*") || strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, "{") {
			return pattern
		}
		pattern = rest
	}
	return pattern
}

const (
	// prefilterMinLiteral is the shortest literal worth checking. Shorter ones
	// ("/", ".", "..") occur in every path the agent sees, so the Contains
	// would cost without ever filtering.
	prefilterMinLiteral = 2
	// prefilterMaxAlternatives bounds the Contains loop the hot path runs. An
	// alternation wider than this is cheaper to hand to the regex engine,
	// which scans the input once for all branches, than to check branch by
	// branch.
	prefilterMaxAlternatives = 24
)

// requiredLiterals returns a set of literals such that every string matching
// pattern contains at least one of them, or nil when no such set can be
// derived. A caller may skip the regex entirely when none of the returned
// literals occurs in the value.
//
// Only constructs that must be traversed on every match contribute: literals,
// captures, concatenations (any one child's requirement is the whole
// concatenation's requirement), repetitions with min >= 1, and alternations
// all of whose branches have a requirement (their union). Stars, optional
// constructs and character classes contribute nothing, since a match may
// avoid them or vary freely inside them.
//
// Case-folded literals are expanded into their case variants rather than
// dropped, since Contains is byte-exact (see literalAlternatives).
func requiredLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	set := requiredLiteralsOf(re.Simplify())
	if !usableLiteralSet(set) {
		return nil
	}
	return set
}

func requiredLiteralsOf(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return literalAlternatives(re)
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiteralsOf(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiteralsOf(re.Sub[0])
		}
		return nil
	case syntax.OpConcat:
		// Every child must be matched, so any child's requirement is the whole
		// concatenation's requirement — keep the most selective one.
		//
		// Adjacent children that each match a bounded set of fixed strings
		// (a literal, a small character class, an alternation of those) are
		// additionally combined into their cross product, which is required
		// contiguous text: "[Oo][Rr]" yields {OR, Or, oR, or}. Without this,
		// case-spelled-out patterns like "[Oo][Rr]\\s+\\d+=\\d+" have no
		// literal anywhere and fall back to full backtracking. The parser
		// also factors common prefixes on its own ("python|php" becomes
		// "p(?:ython|hp)"), which produces exactly this shape.
		//
		// The run and each child on its own are both offered as candidates:
		// a wide run of long strings ({/tmp/sshd, /tmp/nginx, …}) is a worse
		// filter than the short single literal it was built from ("/tmp/"),
		// because every member costs a scan of the value — see literalSetScore.
		var best []string
		var run []string // cross product of the fixed-string run so far
		flushRun := func() {
			best = betterLiteralSet(best, run)
			run = nil
		}
		for _, sub := range re.Sub {
			best = betterLiteralSet(best, requiredLiteralsOf(sub))
			alts := fixedAlternativesOf(sub)
			if len(alts) == 0 {
				flushRun()
				continue
			}
			extended := crossProduct(run, alts)
			if len(extended) == 0 {
				// Extending would exceed the width bound: keep the run built
				// so far (a prefix of required contiguous text is itself
				// required) and start a new one from this node.
				flushRun()
				extended = alts
			}
			run = extended
		}
		flushRun()
		return best
	case syntax.OpAlternate:
		// A match takes exactly one branch, so the requirement holds only if
		// every branch has one; the union is then required.
		var union []string
		for _, sub := range re.Sub {
			branch := requiredLiteralsOf(sub)
			if !usableLiteralSet(branch) {
				return nil
			}
			union = append(union, branch...)
			if len(union) > prefilterMaxAlternatives {
				return nil
			}
		}
		return union
	default:
		return nil
	}
}

// fixedAlternativesOf returns the complete set of strings a node can match,
// when that set is small and fixed — a plain literal, a narrow character
// class, or an alternation of those. Returns nil when the node can match text
// outside any bounded set (a star, a wide class, an anchor). Unlike
// requiredLiteralsOf this is an EXACT enumeration, which is what makes the
// cross product with a neighbouring node sound.
func fixedAlternativesOf(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return literalAlternatives(re)
	case syntax.OpCharClass:
		var out []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi > 0x7f {
				return nil
			}
			for r := lo; r <= hi; r++ {
				out = append(out, string(r))
				if len(out) > prefilterMaxAlternatives {
					return nil
				}
			}
		}
		return out
	case syntax.OpCapture:
		return fixedAlternativesOf(re.Sub[0])
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			alts := fixedAlternativesOf(sub)
			if len(alts) == 0 {
				return nil
			}
			out = append(out, alts...)
			if len(out) > prefilterMaxAlternatives {
				return nil
			}
		}
		return out
	default:
		return nil
	}
}

// literalAlternatives enumerates the strings a literal node can match. A
// plain literal is itself; a case-folded one ("[Dd][Rr][Oo][Pp]", which the
// parser turns into a single fold-case literal) is every case variant of it.
//
// Folding is taken from unicode.SimpleFold, the same relation the regexp
// engine itself uses — spelling the variants out by ASCII case alone would be
// wrong for "k" and "s", which also fold to U+212A KELVIN SIGN and U+017F
// LATIN SMALL LETTER LONG S. When the variants would exceed the width bound,
// the longest prefix of the literal that fits is used instead: a prefix of
// required contiguous text is itself required.
func literalAlternatives(re *syntax.Regexp) []string {
	if re.Flags&syntax.FoldCase == 0 {
		return []string{string(re.Rune)}
	}
	out := []string{""}
	for _, r := range re.Rune {
		variants := foldVariants(r)
		next := crossProduct(out, variants)
		if len(next) == 0 {
			break // width bound reached — keep the prefix built so far
		}
		out = next
	}
	if len(out) == 1 && out[0] == "" {
		return nil
	}
	return out
}

// foldVariants returns every rune equivalent to r under simple case folding,
// as single-rune strings.
func foldVariants(r rune) []string {
	out := []string{string(r)}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		out = append(out, string(f))
	}
	return out
}

// crossProduct concatenates every element of prefixes with every element of
// suffixes, or returns nil when the result would exceed the width bound. An
// empty prefix set means the run starts here, so suffixes pass through.
func crossProduct(prefixes, suffixes []string) []string {
	if len(prefixes) == 0 {
		return suffixes
	}
	if len(prefixes)*len(suffixes) > prefilterMaxAlternatives {
		return nil
	}
	out := make([]string, 0, len(prefixes)*len(suffixes))
	for _, p := range prefixes {
		for _, s := range suffixes {
			out = append(out, p+s)
		}
	}
	return out
}

// usableLiteralSet reports whether a set is worth checking on the hot path:
// non-empty, not too wide, and with every member long enough. A member
// carrying U+FFFD is rejected: the engine substitutes that rune for invalid
// input bytes, so a byte-exact strings.Contains could disagree with it.
func usableLiteralSet(set []string) bool {
	if len(set) == 0 || len(set) > prefilterMaxAlternatives {
		return false
	}
	for _, lit := range set {
		if len(lit) < prefilterMinLiteral || strings.ContainsRune(lit, utf8.RuneError) {
			return false
		}
	}
	return true
}

// betterLiteralSet returns whichever of two candidate sets makes the better
// prefilter, ignoring unusable ones.
func betterLiteralSet(current, candidate []string) []string {
	if !usableLiteralSet(candidate) {
		return current
	}
	if !usableLiteralSet(current) {
		return candidate
	}
	if literalSetScore(candidate) > literalSetScore(current) {
		return candidate
	}
	return current
}

// literalSetScore ranks a candidate prefilter. A longer shortest member
// filters more; every extra member costs another scan of the value on every
// event, which is why a narrow short literal ("/tmp/") beats a wide set of
// long ones ({"/tmp/sshd", "/tmp/nginx", …}) built from it.
func literalSetScore(set []string) int {
	return minLen(set) - 2*(len(set)-1)
}

func minLen(set []string) int {
	m := len(set[0])
	for _, s := range set[1:] {
		if len(s) < m {
			m = len(s)
		}
	}
	return m
}

// containsAny reports whether value contains at least one of the literals.
// An empty set means "no prefilter available" and always passes.
func containsAny(value string, literals []string) bool {
	if len(literals) == 0 {
		return true
	}
	for _, lit := range literals {
		if strings.Contains(value, lit) {
			return true
		}
	}
	return false
}

