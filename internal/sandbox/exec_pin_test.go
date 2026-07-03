package sandbox

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/config"
)

// digest is a test helper returning the SHA-256 of s as a [32]byte and its hex.
func digest(s string) ([32]byte, string) {
	sum := sha256.Sum256([]byte(s))
	var hexs strings.Builder
	const hexdigits = "0123456789abcdef"
	for _, b := range sum {
		hexs.WriteByte(hexdigits[b>>4])
		hexs.WriteByte(hexdigits[b&0xf])
	}
	return sum, hexs.String()
}

func TestExecAllowed_PinnedIdentity(t *testing.T) {
	goodDigest, goodHex := digest("the real python3")
	badDigest, _ := digest("a swapped-in payload")

	pol, err := Compile(aiCfg("enforce", config.AISandboxProfile{
		Name:        "agent",
		AllowedExec: []string{"/usr/bin"},
		AllowedExecPins: []config.AISandboxExecPin{
			{Path: "/usr/bin/python3", Sha256: goodHex},
		},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	if !pol.ExecPathPinned("agent", "/usr/bin/python3") {
		t.Fatal("python3 should be reported as pinned")
	}
	if pol.ExecPathPinned("agent", "/usr/bin/ls") {
		t.Fatal("ls should not be reported as pinned")
	}

	// Matching digest at the pinned path -> allowed.
	if !pol.ExecAllowed("agent", "/usr/bin/python3", goodDigest) {
		t.Error("pinned path with matching digest must be allowed")
	}
	// Wrong digest at the pinned path -> denied (identity beats location).
	if pol.ExecAllowed("agent", "/usr/bin/python3", badDigest) {
		t.Error("pinned path with mismatched digest must be denied (dropped-binary)")
	}
	// An unpinned but allowed path is permitted regardless of digest.
	if !pol.ExecAllowed("agent", "/usr/bin/ls", badDigest) {
		t.Error("unpinned allowed path must be permitted by prefix trust")
	}
	// A path outside allowed_exec is denied.
	if pol.ExecAllowed("agent", "/tmp/dropped", goodDigest) {
		t.Error("path outside allowed_exec must be denied")
	}
	// Unknown profile -> denied.
	if pol.ExecAllowed("nope", "/usr/bin/python3", goodDigest) {
		t.Error("unknown profile must be denied")
	}
}

func TestWritePolicy_PopulatesExecPins(t *testing.T) {
	_, hexA := digest("bin-a")
	_, hexB := digest("bin-b")

	pol, err := Compile(aiCfg("enforce", config.AISandboxProfile{
		Name:        "agent",
		AllowedExec: []string{"/usr/bin"},
		AllowedExecPins: []config.AISandboxExecPin{
			{Path: "/usr/bin/a", Sha256: hexA},
			{Path: "/usr/bin/b", Sha256: hexB},
		},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	execPins := newFakeMap()
	maps := Maps{
		State:      newFakeMap(),
		Cgroups:    newFakeMap(),
		PathPolicy: newFakeMap(),
		NetV4:      newFakeMap(),
		NetV6:      newFakeMap(),
		Ports:      newFakeMap(),
		ExecPins:   execPins,
	}
	if err := writePolicy(maps, pol); err != nil {
		t.Fatalf("writePolicy: %v", err)
	}
	if n := len(execPins.data); n != 2 {
		t.Errorf("exec pin rows = %d, want 2", n)
	}
}

// A missing ExecPins map (older generated object) must not fail writePolicy.
func TestWritePolicy_NilExecPinsMapTolerated(t *testing.T) {
	_, hexA := digest("bin-a")
	pol, err := Compile(aiCfg("enforce", config.AISandboxProfile{
		Name:            "agent",
		AllowedExec:     []string{"/usr/bin"},
		AllowedExecPins: []config.AISandboxExecPin{{Path: "/usr/bin/a", Sha256: hexA}},
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	maps := Maps{
		State:      newFakeMap(),
		Cgroups:    newFakeMap(),
		PathPolicy: newFakeMap(),
		NetV4:      newFakeMap(),
		NetV6:      newFakeMap(),
		Ports:      newFakeMap(),
		ExecPins:   nil, // absent
	}
	if err := writePolicy(maps, pol); err != nil {
		t.Fatalf("writePolicy with nil ExecPins must be tolerated, got: %v", err)
	}
}
