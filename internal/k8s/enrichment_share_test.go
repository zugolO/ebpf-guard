package k8s

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Волна 8.7, П7: события пода делят одну неизменяемую копию меток (карты не
// копируются на каждое событие), а сама копия отвязана от карты наблюдателя.
func TestToTypesEnrichmentSharesPodLabels(t *testing.T) {
	ei := &EnrichmentInfo{PodName: "p", Labels: map[string]string{"app": "x"}, Annotations: map[string]string{"a": "b"}}
	a, b := ei.ToTypesEnrichment(), ei.ToTypesEnrichment()
	require.NotSame(t, a, b, "структура своя на событие: ContainerID дописывает рантайм-обогатитель")
	a.ContainerID = "c1"
	require.Empty(t, b.ContainerID)
	require.Equal(t, map[string]string{"app": "x"}, a.Labels)
	// одна копия на под: адрес карты тот же
	require.Equal(t, mapPtr(a.Labels), mapPtr(b.Labels))
	require.Equal(t, mapPtr(a.Annotations), mapPtr(b.Annotations))
}

func TestAttributionLabelsDetachedFromWatcherMap(t *testing.T) {
	src := map[string]string{"app": "x"}
	cp := copyMap(src)
	src["app"] = "changed"
	require.Equal(t, "x", cp["app"], "копия при разрешении не следует за картой наблюдателя")
}

func mapPtr(m map[string]string) uintptr {
	return reflectPointer(m)
}
