package k8s

import (
	"sync"
	"testing"
	"time"
)

type fakeRegistrar struct {
	mu         sync.Mutex
	registered map[uint64]string
	unregCount int
}

func newFakeRegistrar() *fakeRegistrar {
	return &fakeRegistrar{registered: map[uint64]string{}}
}

func (f *fakeRegistrar) RegisterCgroup(id uint64, profile string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registered[id] = profile
	return nil
}

func (f *fakeRegistrar) UnregisterCgroup(id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.registered, id)
	f.unregCount++
	return nil
}

func staticResolver(m map[string][]uint64) CgroupResolver {
	return func(cid string) ([]uint64, error) {
		return m[cid], nil
	}
}

func TestSandboxController_LabelledPodRegistered(t *testing.T) {
	reg := newFakeRegistrar()
	res := staticResolver(map[string][]uint64{"cid-1": {100, 101}})
	c := NewSandboxController("ebpf-guard.io/sandbox-profile", reg, res, nil)

	c.OnPodEvent(PodAdded, &PodInfo{
		UID:          "pod-uid-1",
		Name:         "agent",
		Labels:       map[string]string{"ebpf-guard.io/sandbox-profile": "ai-agent"},
		ContainerIDs: []string{"cid-1"},
	})

	if reg.registered[100] != "ai-agent" || reg.registered[101] != "ai-agent" {
		t.Fatalf("expected both cgroups registered under ai-agent, got %v", reg.registered)
	}
}

func TestSandboxController_UnlabelledPodIgnored(t *testing.T) {
	reg := newFakeRegistrar()
	res := staticResolver(map[string][]uint64{"cid-1": {100}})
	c := NewSandboxController("ebpf-guard.io/sandbox-profile", reg, res, nil)

	c.OnPodEvent(PodAdded, &PodInfo{
		UID:          "pod-uid-2",
		ContainerIDs: []string{"cid-1"},
		Labels:       map[string]string{"other": "x"},
	})
	if len(reg.registered) != 0 {
		t.Fatalf("unlabelled pod should not register cgroups, got %v", reg.registered)
	}
}

func TestSandboxController_DeleteUnregisters(t *testing.T) {
	reg := newFakeRegistrar()
	res := staticResolver(map[string][]uint64{"cid-1": {100, 101}})
	c := NewSandboxController("ebpf-guard.io/sandbox-profile", reg, res, nil)

	pod := &PodInfo{
		UID:          "pod-uid-3",
		Labels:       map[string]string{"ebpf-guard.io/sandbox-profile": "ai-agent"},
		ContainerIDs: []string{"cid-1"},
	}
	c.OnPodEvent(PodAdded, pod)
	if len(reg.registered) != 2 {
		t.Fatalf("expected 2 registered, got %d", len(reg.registered))
	}
	c.OnPodEvent(PodDeleted, pod)
	if len(reg.registered) != 0 {
		t.Fatalf("expected all unregistered after delete, got %v", reg.registered)
	}
}

func TestSandboxController_LabelRemovalUnregisters(t *testing.T) {
	reg := newFakeRegistrar()
	res := staticResolver(map[string][]uint64{"cid-1": {100}})
	c := NewSandboxController("ebpf-guard.io/sandbox-profile", reg, res, nil)

	c.OnPodEvent(PodAdded, &PodInfo{
		UID:          "pod-uid-4",
		Labels:       map[string]string{"ebpf-guard.io/sandbox-profile": "ai-agent"},
		ContainerIDs: []string{"cid-1"},
	})
	// Update with the label removed → should unregister.
	c.OnPodEvent(PodUpdated, &PodInfo{
		UID:          "pod-uid-4",
		Labels:       map[string]string{},
		ContainerIDs: []string{"cid-1"},
	})
	if len(reg.registered) != 0 {
		t.Fatalf("label removal should unregister, got %v", reg.registered)
	}
}

func TestSandboxController_UnenforcedWindowRecorded(t *testing.T) {
	reg := newFakeRegistrar()
	res := staticResolver(map[string][]uint64{"cid-1": {100}})
	c := NewSandboxController("ebpf-guard.io/sandbox-profile", reg, res, nil)
	// Pin the clock 3s after the pod started so the window is deterministic.
	start := time.Unix(1000, 0)
	c.now = func() time.Time { return start.Add(3 * time.Second) }

	c.OnPodEvent(PodAdded, &PodInfo{
		UID:          "pod-uid-win",
		Name:         "agent",
		Labels:       map[string]string{"ebpf-guard.io/sandbox-profile": "ai-agent"},
		ContainerIDs: []string{"cid-1"},
		StartTime:    start,
	})

	late, max := c.UnenforcedWindowStats()
	if late != 1 {
		t.Fatalf("expected 1 late registration, got %d", late)
	}
	if max != 3*time.Second {
		t.Fatalf("expected max window 3s, got %s", max)
	}
}

func TestSandboxController_NoWindowWhenStartTimeUnset(t *testing.T) {
	reg := newFakeRegistrar()
	res := staticResolver(map[string][]uint64{"cid-1": {100}})
	c := NewSandboxController("ebpf-guard.io/sandbox-profile", reg, res, nil)

	// No StartTime → nothing to measure, so no late registration is recorded
	// even though the pod is placed under the profile.
	c.OnPodEvent(PodAdded, &PodInfo{
		UID:          "pod-uid-nowin",
		Name:         "agent",
		Labels:       map[string]string{"ebpf-guard.io/sandbox-profile": "ai-agent"},
		ContainerIDs: []string{"cid-1"},
	})

	if reg.registered[100] != "ai-agent" {
		t.Fatalf("pod should still be registered, got %v", reg.registered)
	}
	if late, max := c.UnenforcedWindowStats(); late != 0 || max != 0 {
		t.Fatalf("expected no window recorded, got late=%d max=%s", late, max)
	}
}

func TestSandboxController_IdempotentAdd(t *testing.T) {
	reg := newFakeRegistrar()
	calls := 0
	res := func(cid string) ([]uint64, error) {
		calls++
		return []uint64{100}, nil
	}
	c := NewSandboxController("ebpf-guard.io/sandbox-profile", reg, res, nil)
	pod := &PodInfo{
		UID:          "pod-uid-5",
		Labels:       map[string]string{"ebpf-guard.io/sandbox-profile": "ai-agent"},
		ContainerIDs: []string{"cid-1"},
	}
	c.OnPodEvent(PodAdded, pod)
	c.OnPodEvent(PodUpdated, pod)
	if calls != 1 {
		t.Fatalf("resolver should run once for a stable pod, ran %d times", calls)
	}
}
