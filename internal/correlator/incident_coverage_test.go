package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestNewIncidentTracker_DefaultsWindowWhenZeroOrNegative(t *testing.T) {
	tr := newIncidentTracker(0)
	assert.Equal(t, 60*time.Second, tr.window)

	tr = newIncidentTracker(-time.Second)
	assert.Equal(t, 60*time.Second, tr.window)
}

func TestIncidentTracker_Add_ZeroTimestampUsesNow(t *testing.T) {
	tr := newIncidentTracker(60 * time.Second)
	before := time.Now()

	tr.Add(types.Alert{PID: 1, RuleID: "r1"}) // Timestamp left zero-valued

	incidents := tr.GetAll("", "", 10)
	require := assert.New(t)
	require.Len(incidents, 1)
	require.False(incidents[0].FirstSeen.Before(before.Add(-time.Second)))
}
