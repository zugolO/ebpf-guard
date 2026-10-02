package correlator

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Каждое семейство немоты без продюсера несёт ПРИЧИНУ и ЦЕНУ с источником замера.
// Цена без числа и без источника — это слово «дорого», которое задача Т запрещает.
func TestMuteFamilyCostsAreMeasuredAndSourced(t *testing.T) {
	digit := regexp.MustCompile(`[0-9]`)
	for _, fam := range []string{MuteFamilyFileOp, MuteFamilyProto, MuteFamilyEventType} {
		c, ok := MuteFamilyCostFor(fam)
		require.True(t, ok, "семейство %s без записи цены", fam)
		assert.NotEmpty(t, c.Reason, fam)
		assert.True(t, digit.MatchString(c.Price), "%s: цена без числа", fam)
		assert.True(t, strings.Contains(c.Price, "alert"), "%s: цена не называет АЛЕРТЫ — вторую половину цены", fam)
		assert.True(t, strings.HasPrefix(c.Source, "server-logs/"), "%s: источник не назван архивом замера", fam)
	}
	_, ok := MuteFamilyCostFor("nr")
	assert.False(t, ok, "ось nr открывается порциями и записи цены семейства не имеет")
}
