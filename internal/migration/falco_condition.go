package migration

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zugolO/ebpf-guard/internal/autolearn"
)

// falcoNode is the internal union of a single condition or a group, produced
// while walking a Falco boolean condition expression.
type falcoNode struct {
	single *FalcoCondition
	group  *FalcoConditionGroup
}

// fileOpenSyscalls / fileReadSyscalls / fileWriteSyscalls / networkSyscallTokens
// classify Falco evt.type / syscall.type values so evt.type-based selection
// can be translated into the "op" field (file events) or dropped as an
// implicit precondition of the event type (network events).
var (
	fileOpenSyscalls = map[string]bool{
		"open": true, "openat": true, "openat2": true, "creat": true, "open_by_handle_at": true,
	}
	fileReadSyscalls = map[string]bool{
		"read": true, "pread64": true, "readv": true, "preadv": true, "preadv2": true,
	}
	fileWriteSyscalls = map[string]bool{
		"write": true, "pwrite64": true, "writev": true, "pwritev": true, "pwritev2": true,
	}
	networkSyscallTokens = map[string]bool{
		"connect": true, "accept": true, "accept4": true, "bind": true, "listen": true, "socket": true,
	}
)

// ── Macro expansion ──────────────────────────────────────────────────────

// maxExpandedConditionLen bounds the size a condition string may grow to
// during macro expansion, guarding against pathological or cyclic macro
// definitions in untrusted rule files.
const maxExpandedConditionLen = 64 * 1024

// expandMacros repeatedly substitutes bare-word macro references in cond
// with their (parenthesized) macro body, until a fixed point is reached,
// a macro cycle is detected, or the expression grows unreasonably large.
func expandMacros(cond string, macros map[string]string) string {
	if len(macros) == 0 {
		return cond
	}
	for i := 0; i < 25; i++ {
		if len(cond) > maxExpandedConditionLen {
			break
		}
		changedAny := false
		for name, body := range macros {
			newCond, changed := substituteWord(cond, name, "("+body+")")
			if changed {
				cond = newCond
				changedAny = true
			}
		}
		if !changedAny {
			break
		}
	}
	return cond
}

// substituteWord replaces every standalone (word-boundary, quote-aware)
// occurrence of word in s with replacement.
func substituteWord(s, word, replacement string) (string, bool) {
	var sb strings.Builder
	changed := false
	var inQuote byte
	i := 0
	for i < len(s) {
		c := s[i]
		if inQuote != 0 {
			sb.WriteByte(c)
			if c == inQuote {
				inQuote = 0
			}
			i++
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = c
			sb.WriteByte(c)
			i++
			continue
		}
		if i+len(word) <= len(s) && s[i:i+len(word)] == word {
			prevOK := i == 0 || !isIdentByte(s[i-1])
			nextOK := i+len(word) == len(s) || !isIdentByte(s[i+len(word)])
			if prevOK && nextOK {
				sb.WriteString(replacement)
				i += len(word)
				changed = true
				continue
			}
		}
		sb.WriteByte(c)
		i++
	}
	return sb.String(), changed
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '.' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// resolveListTokens expands any token that names a known `list:` block into
// its (recursively resolved) items; tokens that are not list names are kept
// as literal values. seen guards against cyclic list references.
func resolveListTokens(tokens []string, lists map[string][]string, seen map[string]bool) []string {
	var out []string
	for _, t := range tokens {
		items, ok := lists[t]
		if !ok || seen[t] {
			out = append(out, t)
			continue
		}
		seen[t] = true
		out = append(out, resolveListTokens(items, lists, seen)...)
	}
	return out
}

// ── Boolean expression parsing (AND / OR / NOT / parentheses) ───────────

// splitTopLevelKeyword splits s on every standalone (word-boundary,
// paren-depth-0, quote-aware) occurrence of the case-insensitive keyword.
// Returns a single-element slice (the trimmed input) if keyword never
// appears at the top level.
func splitTopLevelKeyword(s, keyword string) []string {
	lower := strings.ToLower(s)
	klen := len(keyword)

	var parts []string
	depth := 0
	var inQuote byte
	start := 0
	i := 0
	for i < len(s) {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			i++
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
			i++
			continue
		case '(':
			depth++
			i++
			continue
		case ')':
			depth--
			i++
			continue
		}
		if depth == 0 && i+klen <= len(lower) && lower[i:i+klen] == keyword {
			prevOK := i == 0 || !isIdentByte(s[i-1])
			nextOK := i+klen == len(s) || !isIdentByte(s[i+klen])
			if prevOK && nextOK {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + klen
				i += klen
				continue
			}
		}
		i++
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts
}

// stripNotPrefix removes a leading standalone "not" keyword, if present.
func stripNotPrefix(expr string) (string, bool) {
	if len(expr) < 3 || !strings.EqualFold(expr[:3], "not") {
		return "", false
	}
	if len(expr) > 3 && isIdentByte(expr[3]) {
		return "", false
	}
	return strings.TrimSpace(expr[3:]), true
}

// stripOuterParens removes a matching pair of outer parentheses that wraps
// the entire expression, e.g. "(a and b)" -> "a and b". Returns ok=false if
// the outermost '(' closes before the end of the string (e.g. "(a) and (b)").
func stripOuterParens(expr string) (string, bool) {
	if len(expr) < 2 || expr[0] != '(' || expr[len(expr)-1] != ')' {
		return "", false
	}
	depth := 0
	var inQuote byte
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(expr)-1 {
				return "", false
			}
		}
	}
	return strings.TrimSpace(expr[1 : len(expr)-1]), true
}

// flattenLeaves walks the same and/or/not/paren grammar as parseExpr but
// only returns the leaf atom strings, ignoring polarity and grouping. It is
// used for a lightweight pre-pass over the condition to infer the event
// type before atoms are actually mapped to ebpf-guard fields.
func flattenLeaves(expr string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	if parts := splitTopLevelKeyword(expr, "or"); len(parts) > 1 {
		var out []string
		for _, p := range parts {
			out = append(out, flattenLeaves(p)...)
		}
		return out
	}
	if parts := splitTopLevelKeyword(expr, "and"); len(parts) > 1 {
		var out []string
		for _, p := range parts {
			out = append(out, flattenLeaves(p)...)
		}
		return out
	}
	if rest, ok := stripNotPrefix(expr); ok {
		return flattenLeaves(rest)
	}
	if inner, ok := stripOuterParens(expr); ok {
		return flattenLeaves(inner)
	}
	return []string{expr}
}

// detectEventType infers the ebpf-guard event_type for an (already
// macro-expanded) Falco condition. It prefers explicit evt.type/syscall.type
// selectors — classifying the referenced syscall names into "file" (all
// open/read/write variants), "network" (all connect/accept/bind/... variants)
// or "syscall" (anything else, resolved by number) — and falls back to
// fd.*-field prefix heuristics when no evt.type selector is present.
func detectEventType(expandedCond string) string {
	leaves := flattenLeaves(expandedCond)

	var tokens []string
	for _, leaf := range leaves {
		if hasFieldPrefix(leaf, "evt.type") || hasFieldPrefix(leaf, "syscall.type") {
			tokens = append(tokens, extractEvtTypeTokens(leaf)...)
		}
	}

	if len(tokens) > 0 {
		allFile, allNetwork := true, true
		for _, t := range tokens {
			if !(fileOpenSyscalls[t] || fileReadSyscalls[t] || fileWriteSyscalls[t]) {
				allFile = false
			}
			if !networkSyscallTokens[t] {
				allNetwork = false
			}
		}
		switch {
		case allFile:
			return "file"
		case allNetwork:
			return "network"
		default:
			return "syscall"
		}
	}

	for _, leaf := range leaves {
		if hasFieldPrefix(leaf, "fd.sip") || hasFieldPrefix(leaf, "fd.dip") ||
			hasFieldPrefix(leaf, "fd.sport") || hasFieldPrefix(leaf, "fd.dport") ||
			hasFieldPrefix(leaf, "fd.proto") {
			return "network"
		}
	}
	for _, leaf := range leaves {
		if hasFieldPrefix(leaf, "fd.name") || hasFieldPrefix(leaf, "fd.filename") ||
			hasFieldPrefix(leaf, "fd.directory") {
			return "file"
		}
	}
	return "syscall"
}

// extractEvtTypeTokens extracts the syscall name(s) referenced by a leaf
// evt.type/syscall.type atom (equality or "in (...)" form). Inequality
// atoms ("!=") are not usable for event-type inference and are skipped.
func extractEvtTypeTokens(leaf string) []string {
	if strings.Contains(leaf, "!=") {
		return nil
	}
	if strings.Contains(leaf, " in ") {
		return extractInList(leaf)
	}
	if idx := strings.Index(leaf, "="); idx >= 0 {
		val := strings.Trim(strings.TrimSpace(leaf[idx+1:]), `"' `)
		if val != "" {
			return []string{val}
		}
	}
	return nil
}

// parseExpr recursively parses a (macro-expanded) Falco boolean condition
// expression into a falcoNode tree, honoring and/or/not/paren precedence
// (or binds loosest, then and, then not). Unmappable clauses are dropped
// with a reason appended to the returned slice rather than failing the
// whole expression — the caller decides whether a rule with some dropped
// clauses is still usable (yes, as long as at least one clause survived).
func parseExpr(expr string, eventType string, lists map[string][]string) (*falcoNode, []string) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, []string{"empty expression"}
	}

	if parts := splitTopLevelKeyword(expr, "or"); len(parts) > 1 {
		return combineParts(parts, eventType, lists, "or")
	}
	if parts := splitTopLevelKeyword(expr, "and"); len(parts) > 1 {
		return combineParts(parts, eventType, lists, "and")
	}
	if rest, ok := stripNotPrefix(expr); ok {
		return parseNot(rest, eventType, lists)
	}
	if inner, ok := stripOuterParens(expr); ok {
		return parseExpr(inner, eventType, lists)
	}

	cond, reason := mapAtom(expr, eventType, lists)
	var reasons []string
	if reason != "" {
		reasons = append(reasons, reason)
	}
	if cond == nil {
		return nil, reasons
	}
	return &falcoNode{single: cond}, reasons
}

func combineParts(parts []string, eventType string, lists map[string][]string, op string) (*falcoNode, []string) {
	var nodes []*falcoNode
	var reasons []string
	for _, p := range parts {
		n, r := parseExpr(p, eventType, lists)
		reasons = append(reasons, r...)
		if n != nil {
			nodes = append(nodes, n)
		}
	}
	return mergeFalcoNodes(nodes, op), reasons
}

// mergeNodes flattens/combines multiple condition nodes into a single group
// node. A single surviving node is returned unwrapped (dropping siblings
// that failed to convert narrows an "or" and broadens an "and" — both are
// treated as acceptable best-effort degradation, consistent with the
// sigma/ecs importers).
func mergeFalcoNodes(nodes []*falcoNode, op string) *falcoNode {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	var conds []FalcoCondition
	var subs []FalcoConditionGroup
	for _, n := range nodes {
		if n.single != nil {
			conds = append(conds, *n.single)
		} else if n.group != nil {
			subs = append(subs, *n.group)
		}
	}
	return &falcoNode{
		group: &FalcoConditionGroup{Operator: op, Conditions: conds, SubGroups: subs},
	}
}

// parseNot parses "not <expr>". A NOT of a single leaf condition is
// translated by inverting its operator (eq<->neq, in<->not_in, ...); NOT of
// a compound (and/or) expression, or of an operator with no negated form
// (e.g. contains, regex), cannot be represented and is dropped.
func parseNot(expr string, eventType string, lists map[string][]string) (*falcoNode, []string) {
	inner, reasons := parseExpr(expr, eventType, lists)
	if inner == nil {
		return nil, reasons
	}
	if inner.group != nil {
		reasons = append(reasons, fmt.Sprintf("NOT of a compound expression is not supported and was dropped: %q", expr))
		return nil, reasons
	}
	negated, ok := negateCondition(inner.single)
	if !ok {
		reasons = append(reasons, fmt.Sprintf("operator %q cannot be negated; dropped: %q", inner.single.Op, expr))
		return nil, reasons
	}
	return &falcoNode{single: negated}, reasons
}

func negateCondition(c *FalcoCondition) (*FalcoCondition, bool) {
	var op string
	switch c.Op {
	case "eq":
		op = "neq"
	case "neq":
		op = "eq"
	case "in":
		op = "not_in"
	case "not_in":
		op = "in"
	case "prefix":
		op = "not_prefix"
	case "not_prefix":
		op = "prefix"
	case "suffix":
		op = "not_suffix"
	case "not_suffix":
		op = "suffix"
	case "in_cidr":
		op = "not_in_cidr"
	case "not_in_cidr":
		op = "in_cidr"
	default:
		return nil, false
	}
	return &FalcoCondition{Field: c.Field, Op: op, Values: c.Values}, true
}

// ── Leaf atom mapping ─────────────────────────────────────────────────────

// hasFieldPrefix reports whether atom starts with prefix at a word boundary
// (the next byte, if any, is not an identifier-continuation byte).
func hasFieldPrefix(atom, prefix string) bool {
	if !strings.HasPrefix(atom, prefix) {
		return false
	}
	return len(atom) == len(prefix) || !isIdentByte(atom[len(prefix)])
}

// containsOperator reports whether atom looks like a field comparison
// (as opposed to a bare, unresolved macro/identifier reference).
func containsOperator(atom string) bool {
	return strings.Contains(atom, "=") ||
		strings.Contains(atom, " in ") ||
		strings.Contains(atom, " contains ") ||
		strings.Contains(atom, " startswith ") ||
		strings.Contains(atom, " glob ") ||
		strings.ContainsAny(atom, "<>")
}

// mapAtom converts a single Falco filter atom to an ebpf-guard condition,
// reconciled against the exact field names accepted by
// internal/correlator/rule_loader.go for the given (already-detected)
// event type. Returns (nil, "") only for evt.type atoms that are fully
// implied by the event type itself (e.g. evt.type=connect on a network
// event) — a legitimate no-op, not a failure.
func mapAtom(atom string, eventType string, lists map[string][]string) (*FalcoCondition, string) {
	atom = strings.TrimSpace(atom)
	if atom == "" {
		return nil, "empty atom"
	}
	if !containsOperator(atom) {
		return nil, fmt.Sprintf("unresolved macro or bare identifier (no operator): %q", atom)
	}

	switch {
	case hasFieldPrefix(atom, "evt.type"):
		return mapEvtType(atom, eventType)
	case hasFieldPrefix(atom, "syscall.type"):
		return mapEvtType("evt.type"+atom[len("syscall.type"):], eventType)

	case hasFieldPrefix(atom, "fd.name"):
		if eventType != "file" && eventType != "syscall" {
			return nil, fmt.Sprintf("fd.name is only valid for file/syscall events, not %q: %q", eventType, atom)
		}
		return buildCondition(atom, "fd.name", lists)
	case hasFieldPrefix(atom, "fd.filename"):
		return mapSimpleField(atom, "filename", eventType, lists, "file")
	case hasFieldPrefix(atom, "fd.directory"):
		return mapSimpleField(atom, "directory", eventType, lists, "file")
	case hasFieldPrefix(atom, "fd.typechar"):
		return nil, fmt.Sprintf("fd.typechar has no ebpf-guard equivalent: %q", atom)
	case hasFieldPrefix(atom, "fd.type"):
		return nil, fmt.Sprintf("fd.type has no ebpf-guard equivalent: %q", atom)
	case hasFieldPrefix(atom, "fd.sport"):
		return mapSimpleField(atom, "sport", eventType, lists, "network")
	case hasFieldPrefix(atom, "fd.dport"):
		return mapSimpleField(atom, "dport", eventType, lists, "network")
	case hasFieldPrefix(atom, "fd.sip"):
		return mapIPField(atom, "saddr", eventType)
	case hasFieldPrefix(atom, "fd.dip"):
		return mapIPField(atom, "daddr", eventType)
	case hasFieldPrefix(atom, "fd.proto"):
		return mapSimpleField(atom, "proto", eventType, lists, "network")
	case hasFieldPrefix(atom, "fd.net"), hasFieldPrefix(atom, "fd.cnet"),
		hasFieldPrefix(atom, "fd.snet"), hasFieldPrefix(atom, "fd.rnet"):
		return nil, fmt.Sprintf("ambiguous-direction subnet field has no unambiguous ebpf-guard equivalent (use fd.sip/fd.dip): %q", atom)
	case hasFieldPrefix(atom, "fd."):
		return nil, fmt.Sprintf("no ebpf-guard field mapping for this fd.* attribute: %q", atom)

	case hasFieldPrefix(atom, "container."):
		return nil, fmt.Sprintf("container metadata is not exposed to rule conditions: %q", atom)
	case hasFieldPrefix(atom, "k8s."):
		return nil, fmt.Sprintf("kubernetes metadata is not exposed to rule conditions: %q", atom)

	case hasFieldPrefix(atom, "proc.args"):
		return mapSimpleField(atom, "proc.args", eventType, lists, "syscall", "file", "network")
	case hasFieldPrefix(atom, "proc.name"):
		return mapSimpleField(atom, "proc.comm", eventType, lists, "syscall", "file", "network")
	case hasFieldPrefix(atom, "proc."):
		return nil, fmt.Sprintf("only proc.name and proc.args are supported; no ebpf-guard field for this proc.* attribute: %q", atom)

	case hasFieldPrefix(atom, "user.uid"):
		return mapSimpleField(atom, "uid", eventType, lists, "syscall", "file", "network")
	case hasFieldPrefix(atom, "user."):
		return nil, fmt.Sprintf("only user.uid is supported; no ebpf-guard field for this user.* attribute: %q", atom)
	case hasFieldPrefix(atom, "group."):
		return nil, fmt.Sprintf("group.* fields have no ebpf-guard equivalent: %q", atom)

	default:
		return nil, fmt.Sprintf("unsupported Falco filter expression (no ebpf-guard field mapping): %q", atom)
	}
}

// mapSimpleField checks that ebpfField is a valid rule_loader field for
// eventType before delegating to the generic operator parser.
func mapSimpleField(atom, ebpfField, eventType string, lists map[string][]string, validTypes ...string) (*FalcoCondition, string) {
	for _, t := range validTypes {
		if t == eventType {
			return buildCondition(atom, ebpfField, lists)
		}
	}
	return nil, fmt.Sprintf("field maps to %q which is not a valid field for event_type %q: %q", ebpfField, eventType, atom)
}

// mapIPField handles fd.sip/fd.dip -> saddr/daddr, choosing "in_cidr" when
// the value looks like a CIDR range (contains '/') and "eq"/"in" otherwise.
// in_cidr is only accepted by the loader for daddr/saddr, so both fields map
// cleanly.
func mapIPField(atom, ebpfField, eventType string) (*FalcoCondition, string) {
	if eventType != "network" {
		return nil, fmt.Sprintf("field maps to %q which is only valid for network events, not %q: %q", ebpfField, eventType, atom)
	}
	switch {
	case strings.Contains(atom, " in "):
		vals := extractInList(atom)
		if len(vals) == 0 {
			return nil, fmt.Sprintf("could not extract list from: %q", atom)
		}
		if anyContainsSlash(vals) {
			return &FalcoCondition{Field: ebpfField, Op: "in_cidr", Values: vals}, ""
		}
		return &FalcoCondition{Field: ebpfField, Op: "in", Values: vals}, ""
	case strings.Contains(atom, "!="):
		val := extractQuotedOrTrailing(atom, "!=")
		if val == "" {
			return nil, fmt.Sprintf("could not extract value from: %q", atom)
		}
		return &FalcoCondition{Field: ebpfField, Op: "neq", Values: []string{val}}, ""
	case strings.Contains(atom, "="):
		val := extractQuotedOrTrailing(atom, "=")
		if val == "" {
			return nil, fmt.Sprintf("could not extract value from: %q", atom)
		}
		op := "eq"
		if strings.Contains(val, "/") {
			op = "in_cidr"
		}
		return &FalcoCondition{Field: ebpfField, Op: op, Values: []string{val}}, ""
	}
	return nil, fmt.Sprintf("unsupported IP expression: %q", atom)
}

func anyContainsSlash(vals []string) bool {
	for _, v := range vals {
		if strings.Contains(v, "/") {
			return true
		}
	}
	return false
}

// mapEvtType translates a Falco evt.type/syscall.type selector into a
// concrete ebpf-guard condition for the given (already-detected) event
// type: "op" for file events, a dropped no-op for network events (the
// event type itself already implies the syscall category), and "nr"
// (via the x86_64 syscall-number table) for the generic syscall event type.
func mapEvtType(atom string, eventType string) (*FalcoCondition, string) {
	var tokens []string
	switch {
	case strings.Contains(atom, "!="):
		return nil, fmt.Sprintf("evt.type != is not supported: %q", atom)
	case strings.Contains(atom, " in "):
		tokens = extractInList(atom)
	case strings.Contains(atom, "="):
		val := strings.Trim(strings.TrimSpace(atom[strings.Index(atom, "=")+1:]), `"' `)
		if val != "" {
			tokens = []string{val}
		}
	}
	if len(tokens) == 0 {
		return nil, fmt.Sprintf("could not extract evt.type value(s) from: %q", atom)
	}

	switch eventType {
	case "file":
		ops := classifyFileOp(tokens)
		if len(ops) == 0 {
			return nil, fmt.Sprintf("evt.type value(s) %v have no file \"op\" equivalent", tokens)
		}
		op := "eq"
		if len(ops) > 1 {
			op = "in"
		}
		return &FalcoCondition{Field: "op", Op: op, Values: ops}, ""
	case "network":
		for _, t := range tokens {
			if !networkSyscallTokens[t] {
				return nil, fmt.Sprintf("evt.type value %q has no network-event equivalent", t)
			}
		}
		// Fully implied by the event type itself: not a failure, just a no-op.
		return nil, ""
	default: // "syscall"
		var nrs []string
		for _, t := range tokens {
			nr, ok := autolearn.SyscallNr(t)
			if !ok {
				return nil, fmt.Sprintf("unknown syscall name %q (no x86_64 syscall number mapping)", t)
			}
			nrs = append(nrs, strconv.FormatInt(nr, 10))
		}
		op := "eq"
		if len(nrs) > 1 {
			op = "in"
		}
		return &FalcoCondition{Field: "nr", Op: op, Values: nrs}, ""
	}
}

// classifyFileOp maps a set of Falco syscall-name tokens to the ebpf-guard
// file event "op" values ("open"/"read"/"write") they correspond to.
// Returns nil if any token doesn't belong to one of those three categories.
func classifyFileOp(tokens []string) []string {
	set := map[string]bool{}
	for _, t := range tokens {
		switch {
		case fileOpenSyscalls[t]:
			set["open"] = true
		case fileReadSyscalls[t]:
			set["read"] = true
		case fileWriteSyscalls[t]:
			set["write"] = true
		default:
			return nil
		}
	}
	var out []string
	for _, op := range []string{"open", "read", "write"} {
		if set[op] {
			out = append(out, op)
		}
	}
	return out
}

// buildCondition is the generic operator parser used for fields that map
// directly onto an ebpf-guard field name: equality/inequality, in/not-in
// (with list resolution), contains, startswith, glob, and the >/>=/</<=
// numeric comparisons.
func buildCondition(atom, ebpfField string, lists map[string][]string) (*FalcoCondition, string) {
	switch {
	case strings.Contains(atom, " not in "):
		vals := resolveListTokens(extractInList(atom), lists, map[string]bool{})
		if len(vals) == 0 {
			return nil, fmt.Sprintf("could not extract list from: %q", atom)
		}
		return &FalcoCondition{Field: ebpfField, Op: "not_in", Values: vals}, ""
	case strings.Contains(atom, " in "):
		vals := resolveListTokens(extractInList(atom), lists, map[string]bool{})
		if len(vals) == 0 {
			return nil, fmt.Sprintf("could not extract list from: %q", atom)
		}
		return &FalcoCondition{Field: ebpfField, Op: "in", Values: vals}, ""
	case strings.Contains(atom, " contains "):
		val := extractQuotedOrTrailing(atom, " contains ")
		if val == "" {
			return nil, fmt.Sprintf("could not extract value from: %q", atom)
		}
		return &FalcoCondition{Field: ebpfField, Op: "contains", Values: []string{val}}, ""
	case strings.Contains(atom, " startswith "):
		val := extractQuotedOrTrailing(atom, " startswith ")
		if val == "" {
			return nil, fmt.Sprintf("could not extract value from: %q", atom)
		}
		return &FalcoCondition{Field: ebpfField, Op: "prefix", Values: []string{val}}, ""
	case strings.Contains(atom, " glob "):
		return mapGlob(atom, ebpfField)
	case strings.Contains(atom, ">="):
		return buildComparison(atom, ebpfField, ">=", "gte")
	case strings.Contains(atom, "<="):
		return buildComparison(atom, ebpfField, "<=", "lte")
	case strings.Contains(atom, "!="):
		return buildComparison(atom, ebpfField, "!=", "neq")
	case strings.Contains(atom, ">"):
		return buildComparison(atom, ebpfField, ">", "gt")
	case strings.Contains(atom, "<"):
		return buildComparison(atom, ebpfField, "<", "lt")
	case strings.Contains(atom, "="):
		return buildComparison(atom, ebpfField, "=", "eq")
	}
	return nil, fmt.Sprintf("unsupported expression for field %q: %q", ebpfField, atom)
}

func buildComparison(atom, ebpfField, opToken, op string) (*FalcoCondition, string) {
	idx := strings.Index(atom, opToken)
	if idx < 0 {
		return nil, fmt.Sprintf("could not find operator %q in: %q", opToken, atom)
	}
	val := strings.Trim(strings.TrimSpace(atom[idx+len(opToken):]), `"'`)
	if val == "" {
		return nil, fmt.Sprintf("could not extract value from: %q", atom)
	}
	return &FalcoCondition{Field: ebpfField, Op: op, Values: []string{val}}, ""
}

// mapGlob converts a simple Falco glob pattern (leading/trailing "*" only)
// into the closest matching ebpf-guard operator.
func mapGlob(atom, ebpfField string) (*FalcoCondition, string) {
	val := extractQuotedOrTrailing(atom, " glob ")
	if val == "" {
		return nil, fmt.Sprintf("could not extract glob pattern from: %q", atom)
	}
	starCount := strings.Count(val, "*")
	switch {
	case starCount == 0:
		return &FalcoCondition{Field: ebpfField, Op: "eq", Values: []string{val}}, ""
	case starCount == 1 && strings.HasSuffix(val, "*"):
		return &FalcoCondition{Field: ebpfField, Op: "prefix", Values: []string{strings.TrimSuffix(val, "*")}}, ""
	case starCount == 1 && strings.HasPrefix(val, "*"):
		return &FalcoCondition{Field: ebpfField, Op: "suffix", Values: []string{strings.TrimPrefix(val, "*")}}, ""
	case starCount == 2 && strings.HasPrefix(val, "*") && strings.HasSuffix(val, "*"):
		inner := strings.Trim(val, "*")
		if inner == "" {
			return nil, fmt.Sprintf("unsupported glob pattern: %q", val)
		}
		return &FalcoCondition{Field: ebpfField, Op: "contains", Values: []string{inner}}, ""
	default:
		return nil, fmt.Sprintf("unsupported glob pattern (multiple/inner wildcards): %q", val)
	}
}

// extractQuoted extracts the first quoted string value from an expression.
func extractQuoted(s string) string {
	for _, q := range []byte{'"', '\''} {
		start := strings.IndexByte(s, q)
		if start == -1 {
			continue
		}
		end := strings.IndexByte(s[start+1:], q)
		if end == -1 {
			continue
		}
		return s[start+1 : start+1+end]
	}
	return ""
}

// extractQuotedOrTrailing extracts a quoted value if present, else
// everything after sep, trimmed of whitespace and surrounding quotes.
func extractQuotedOrTrailing(atom, sep string) string {
	if v := extractQuoted(atom); v != "" {
		return v
	}
	parts := strings.SplitN(atom, sep, 2)
	if len(parts) == 2 {
		return strings.Trim(strings.TrimSpace(parts[1]), `"'`)
	}
	return ""
}

// extractInList extracts values from a Falco "in (a, b, c)" expression.
func extractInList(s string) []string {
	start := strings.Index(s, "(")
	end := strings.LastIndex(s, ")")
	if start == -1 || end == -1 || end <= start {
		return nil
	}
	inner := s[start+1 : end]
	var vals []string
	for _, v := range strings.Split(inner, ",") {
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if v != "" {
			vals = append(vals, v)
		}
	}
	return vals
}
