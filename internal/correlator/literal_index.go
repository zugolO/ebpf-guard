package correlator

import (
	"sort"
	"unsafe"
)

// Волна 8.6, заход B, G1: один проход литералов на событие.
//
// До этого префильтр regex-условия был линейным ПО ПРАВИЛАМ: каждое файловое
// событие прогоняло containsAny (strings.Contains по каждому литералу каждого
// шаблона каждого правила — 350 различных литералов, 325 шаблонов) заново.
// Здесь все литералы всех regex-условий по filename файловых правил собраны в
// один автомат Ахо—Корасик; одно сканирование строки пути даёт битовое множество
// найденных литералов, и шаблон «литерал прошёл» ⇔ в множестве есть любой его id.
// Ответ тот же, что у containsAny (литерал найден в строке ⇔ найден автоматом),
// поэтому детект тот же — тождество проверяется тестами на корпусе и дампе.
//
// Источник истины — правила: литералы берутся из regexLiterals уже
// скомпилированных условий; автомат строится при создании движка и при каждой
// горячей перезагрузке, ручных списков нет.

type literalIndex struct {
	class  [256]uint8 // класс байта; 0 — байт не встречается ни в одном литерале
	nClass int
	next   []int32 // состояние*nClass + класс → состояние (полный ДКА)
	outOff []int32 // состояние → начало в outIDs, длина states+1
	outIDs []int32 // id литералов, оканчивающихся в состоянии (с суффиксными)
	nWords int
}

func buildLiteralIndex(lits []string) *literalIndex {
	x := &literalIndex{nWords: (len(lits) + 63) / 64}
	// алфавит: байты, встречающиеся в литералах
	var seen [256]bool
	for _, l := range lits {
		for i := 0; i < len(l); i++ {
			seen[l[i]] = true
		}
	}
	x.nClass = 1
	for b := 0; b < 256; b++ {
		if seen[b] {
			x.class[b] = uint8(x.nClass)
			x.nClass++
		}
	}
	if x.nClass > 255 {
		return nil // не помещается в uint8-классы; вызывающий остаётся на containsAny
	}
	// trie
	type node struct {
		child map[byte]int32
		out   []int32
	}
	nodes := []node{{}}
	for id, l := range lits {
		cur := int32(0)
		for i := 0; i < len(l); i++ {
			c := l[i]
			if nodes[cur].child == nil {
				nodes[cur].child = map[byte]int32{}
			}
			nx, ok := nodes[cur].child[c]
			if !ok {
				nx = int32(len(nodes))
				nodes = append(nodes, node{})
				nodes[cur].child[c] = nx
			}
			cur = nx
		}
		nodes[cur].out = append(nodes[cur].out, int32(id))
	}
	n := len(nodes)
	fail := make([]int32, n)
	x.next = make([]int32, n*x.nClass)
	// BFS: корень, затем по уровням
	queue := make([]int32, 0, n)
	for b := 0; b < 256; b++ {
		if x.class[b] == 0 {
			continue
		}
		if ch, ok := nodes[0].child[byte(b)]; ok {
			x.next[int(x.class[b])] = ch
			queue = append(queue, ch)
		}
	}
	for qi := 0; qi < len(queue); qi++ {
		s := queue[qi]
		// выходы суффиксной ссылки добавляются к выходам состояния
		nodes[s].out = mergeIDs(nodes[s].out, nodes[fail[s]].out)
		for b := 0; b < 256; b++ {
			c := x.class[b]
			if c == 0 {
				continue
			}
			if ch, ok := nodes[s].child[byte(b)]; ok {
				fail[ch] = x.next[int(fail[s])*x.nClass+int(c)]
				x.next[int(s)*x.nClass+int(c)] = ch
				queue = append(queue, ch)
			} else {
				x.next[int(s)*x.nClass+int(c)] = x.next[int(fail[s])*x.nClass+int(c)]
			}
		}
	}
	x.outOff = make([]int32, n+1)
	for s := 0; s < n; s++ {
		x.outOff[s+1] = x.outOff[s] + int32(len(nodes[s].out))
		x.outIDs = append(x.outIDs, nodes[s].out...)
	}
	return x
}

func mergeIDs(a, b []int32) []int32 {
	if len(b) == 0 {
		return a
	}
	m := make(map[int32]struct{}, len(a)+len(b))
	for _, v := range a {
		m[v] = struct{}{}
	}
	for _, v := range b {
		m[v] = struct{}{}
	}
	out := make([]int32, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// scan проставляет в hits бит каждого литерала, найденного в s. hits — x.nWords
// слов, обнулённых вызывающим.
func (x *literalIndex) scan(s string, hits []uint64) {
	var st int32
	nc := int32(x.nClass)
	for i := 0; i < len(s); i++ {
		c := x.class[s[i]]
		if c == 0 {
			st = 0
			continue
		}
		st = x.next[st*nc+int32(c)]
		if lo, hi := x.outOff[st], x.outOff[st+1]; lo != hi {
			for _, id := range x.outIDs[lo:hi] {
				hits[id>>6] |= 1 << (uint(id) & 63)
			}
		}
	}
}

func anyBit(hits []uint64, ids []int32) bool {
	for _, id := range ids {
		if hits[id>>6]&(1<<(uint(id)&63)) != 0 {
			return true
		}
	}
	return false
}

// litHitsSmallWords — слов в массиве внутри eventFieldCache (1024 литерала; на боевом
// наборе ≈640); больше —
// кучей.
const litHitsSmallWords = 16

// fileLitHits возвращает множество литералов, найденных в имени файла события;
// сканирует один раз на событие. value — то самое строковое значение поля filename.
func (c *eventFieldCache) fileLitHits(x *literalIndex, value string) []uint64 {
	small := x.nWords <= litHitsSmallWords
	if c.litDone && c.litIdx == x && len(c.litSrc) == len(value) && unsafe.StringData(c.litSrc) == unsafe.StringData(value) {
		if small {
			return c.litBuf[:x.nWords]
		}
		return c.litBig
	}
	var hits []uint64
	if small {
		c.litBuf = [litHitsSmallWords]uint64{}
		hits = c.litBuf[:x.nWords]
	} else {
		c.litBig = make([]uint64, x.nWords)
		hits = c.litBig
	}
	x.scan(value, hits)
	c.litDone, c.litIdx, c.litSrc = true, x, value
	return hits
}

// ruleLitGate — условие применимости правила: любой из id должен быть найден в
// имени файла, иначе правило не может совпасть (его обязательное regex-условие
// по filename не пройдёт префильтр ни одним шаблоном).
type ruleLitGate struct {
	idx  *literalIndex
	pats [][][]int32 // шаблон → набор → id литералов (КНФ)
}

// patternPasses — шаблон может совпасть: в каждом его наборе найден литерал.
// Шаблон без наборов проходит всегда.
func patternPasses(hits []uint64, sets [][]int32) bool {
	for _, ids := range sets {
		if !anyBit(hits, ids) {
			return false
		}
	}
	return true
}

func (g *ruleLitGate) passes(hits []uint64) bool {
	for _, sets := range g.pats {
		if patternPasses(hits, sets) {
			return true
		}
	}
	return false
}

// isFilenameRegexCond — условие, чьи литералы идут в автомат.
func isFilenameRegexCond(c *RuleCondition) bool {
	return c.Op == OpRegex && normaliseFieldName(c.Field) == "filename" && len(c.regexes) == len(c.Values) && len(c.Values) > 0
}

// buildLiteralIndexes собирает автомат по условиям файловых правил и расставляет
// id литералов в условиях и ворота правил. Вызывается между compilePatterns и
// buildTypeIndex. Выключатель literalIndexEnabled — для сравнения «до/после».
func (re *RuleEngine) buildLiteralIndexes() {
	re.fileLits = nil
	if !literalIndexEnabled {
		return
	}
	idOf := map[string]int32{}
	var lits []string
	intern := func(l string) int32 {
		if id, ok := idOf[l]; ok {
			return id
		}
		id := int32(len(lits))
		idOf[l] = id
		lits = append(lits, l)
		return id
	}
	var conds []*RuleCondition
	var collect func(g *RuleConditionGroup)
	collect = func(g *RuleConditionGroup) {
		for i := range g.Conditions {
			conds = append(conds, &g.Conditions[i])
		}
		for i := range g.SubGroups {
			collect(&g.SubGroups[i])
		}
	}
	for i := range re.rules {
		r := &re.rules[i]
		if r.EventType.String() != "file" || r.Synthetic {
			continue
		}
		conds = append(conds, &r.Condition)
		if r.ConditionGroup != nil {
			collect(r.ConditionGroup)
		}
	}
	setsOf := map[*RuleCondition][][][]string{} // условие → шаблон → КНФ-наборы
	for _, c := range conds {
		if !isFilenameRegexCond(c) {
			continue
		}
		per := make([][][]string, len(c.Values))
		for i, pat := range c.Values {
			per[i] = requiredLiteralSets(pat)
			for _, set := range per[i] {
				for _, l := range set {
					intern(l)
				}
			}
		}
		setsOf[c] = per
	}
	if len(lits) == 0 {
		return
	}
	idx := buildLiteralIndex(lits)
	if idx == nil {
		return
	}
	re.fileLits = idx
	for _, c := range conds {
		if !isFilenameRegexCond(c) {
			continue
		}
		ids := make([][][]int32, len(c.Values))
		for i, sets := range setsOf[c] {
			for _, set := range sets {
				var one []int32
				for _, l := range set {
					one = append(one, idOf[l])
				}
				ids[i] = append(ids[i], one)
			}
		}
		c.litIdx, c.litIDs = idx, ids
	}
	// ворота правила: обязательное (top-level) regex-условие по filename,
	// все шаблоны которого имеют набор литералов
	for i := range re.rules {
		r := &re.rules[i]
		r.litGate = nil
		if r.EventType.String() != "file" || r.Synthetic {
			continue
		}
		var req *RuleCondition
		if r.ConditionGroup != nil {
			if g := r.ConditionGroup; g.Operator != "or" {
				for j := range g.Conditions {
					if isFilenameRegexCond(&g.Conditions[j]) && c0AllHaveLiterals(&g.Conditions[j]) {
						req = &g.Conditions[j]
						break
					}
				}
			}
		} else if isFilenameRegexCond(&r.Condition) && c0AllHaveLiterals(&r.Condition) {
			req = &r.Condition
		}
		if req == nil {
			continue
		}
		r.litGate = &ruleLitGate{idx: idx, pats: req.litIDs}
	}
}

func c0AllHaveLiterals(c *RuleCondition) bool {
	if len(c.litIDs) != len(c.regexes) {
		return false
	}
	for _, s := range c.litIDs {
		if len(s) == 0 {
			return false // шаблон без обязательных литералов проходит всегда — ворота невозможны
		}
	}
	return true
}

// literalIndexEnabled — выключатель G1 (бенч, мутационный тест); читается при
// создании движка.
var literalIndexEnabled = true
