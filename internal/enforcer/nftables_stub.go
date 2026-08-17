//go:build !linux

// Package enforcer — non-Linux stub for the nftables block backend.
//
// nftables is a Linux netfilter facility reached over netlink; the
// github.com/google/nftables expression types it needs reference Linux-only
// constants (unix.NFPROTO_*) and do not compile elsewhere. This file provides
// the same exported API so internal/enforcer — and everything importing it —
// builds and tests on macOS, with the backend reporting itself as unavailable.
//
// The real implementation lives in nftables.go behind `//go:build linux`.
package enforcer

import (
	"context"
	"errors"
	"log/slog"
)

// ErrNFTablesUnsupported is returned by every nftables operation on platforms
// without netfilter. Callers that treat block-backend init failure as fatal
// (see NewEnforcer) will surface this rather than silently degrading.
var ErrNFTablesUnsupported = errors.New("nftables: unsupported on this platform (Linux only)")

// NFTablesConfig configures the nftables manager.
// Mirrors the Linux definition so configuration parses identically everywhere.
type NFTablesConfig struct {
	// DryRun logs actions without applying rules
	DryRun bool
	// TableName is the nftables table name (default: "ebpf-guard")
	TableName string
}

// NFTablesManager is the non-Linux placeholder for the netlink-backed manager.
// It holds no state: every operation fails with ErrNFTablesUnsupported.
type NFTablesManager struct {
	logger *slog.Logger
}

// NewNFTablesManager always fails on non-Linux platforms.
func NewNFTablesManager(_ *slog.Logger, _ NFTablesConfig) (*NFTablesManager, error) {
	return nil, ErrNFTablesUnsupported
}

// IsNFTablesAvailable reports whether nftables can be used. Always false here.
func IsNFTablesAvailable() bool { return false }

// GetBackendName returns the name of this enforcement backend.
func (m *NFTablesManager) GetBackendName() string { return "nftables" }

// BlockUID is unsupported on this platform.
func (m *NFTablesManager) BlockUID(_ context.Context, _ uint32) error {
	return ErrNFTablesUnsupported
}

// UnblockUID is unsupported on this platform.
func (m *NFTablesManager) UnblockUID(_ context.Context, _ uint32) error {
	return ErrNFTablesUnsupported
}

// BlockCgroup is unsupported on this platform.
func (m *NFTablesManager) BlockCgroup(_ context.Context, _ uint64) error {
	return ErrNFTablesUnsupported
}

// UnblockCgroup is unsupported on this platform.
func (m *NFTablesManager) UnblockCgroup(_ context.Context, _ uint64) error {
	return ErrNFTablesUnsupported
}

// BlockIP is unsupported on this platform.
func (m *NFTablesManager) BlockIP(_ context.Context, _ string) error {
	return ErrNFTablesUnsupported
}

// UnblockIP is unsupported on this platform.
func (m *NFTablesManager) UnblockIP(_ context.Context, _ string) error {
	return ErrNFTablesUnsupported
}

// GetBlockedUIDs returns no UIDs — nothing can be blocked on this platform.
func (m *NFTablesManager) GetBlockedUIDs() []uint32 { return nil }

// GetBlockedCgroups returns no cgroups — nothing can be blocked on this platform.
func (m *NFTablesManager) GetBlockedCgroups() []uint64 { return nil }

// GetBlockedIPs returns no IPs — nothing can be blocked on this platform.
func (m *NFTablesManager) GetBlockedIPs() []string { return nil }

// Cleanup is a no-op: no rules were ever installed.
func (m *NFTablesManager) Cleanup() error { return nil }

// Close is a no-op: no netlink connection was ever opened.
func (m *NFTablesManager) Close() error { return nil }
