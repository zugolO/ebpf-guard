package k8s

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestMissReason_ProcGoneVsNoContainer(t *testing.T) {
	_, err := (&Watcher{}).getContainerIDFromPID(4294967290) // never a live pid
	assert.Equal(t, MissProcGone, missReason(err), "vanished /proc entry is the pid→pod race")
	assert.Equal(t, MissNoContainer, missReason(errors.New("container ID not found in cgroup")))
	// A task that exits mid-read answers ESRCH, not ENOENT — the fastest
	// processes must not be filed as ordinary host traffic.
	assert.Equal(t, MissProcGone, missReason(fmt.Errorf("read cgroup: %w", syscall.ESRCH)))
	assert.Equal(t, 3, testutil.CollectAndCount(enrichMissByReason), "reasons materialized at init")
}
