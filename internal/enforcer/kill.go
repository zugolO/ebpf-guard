// Package enforcer provides pidfd-based process termination with race-free PID handling.
package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// pidfdSupported indicates whether pidfd_open(2) is available (Linux 5.1+).
var pidfdSupported bool

func init() {
	pidfdSupported = checkPidfdSupport()
}

// checkPidfdSupport probes the kernel for pidfd_open availability by attempting
// to open a pidfd for PID 1 (init). On kernels < 5.1 this returns ENOSYS.
func checkPidfdSupport() bool {
	fd, err := unix.PidfdOpen(1, 0)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// killViaPidfd sends SIGKILL using pidfd_open(2) + pidfd_send_signal(2).
// This provides an atomic handle to a specific process instance, making
// PID-reuse races technically impossible.
func killViaPidfd(pid uint32) error {
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return fmt.Errorf("pidfd_open(%d): %w", pid, err)
	}
	defer syscall.Close(fd)

	if err := unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0); err != nil {
		return fmt.Errorf("pidfd_send_signal(%d): %w", pid, err)
	}
	return nil
}

// killViaProc sends SIGKILL via the traditional /proc-based method with a comm
// recheck to mitigate PID-reuse races on kernels that lack pidfd support.
func killViaProc(pid uint32, comm string) error {
	if comm != "" {
		if err := verifyPIDComm(pid, comm); err != nil {
			return fmt.Errorf("pid reuse detected: %w", err)
		}
	}
	return syscall.Kill(int(pid), syscall.SIGKILL)
}

// executeKill sends SIGKILL to the offending process.
//
// PID-reuse race prevention:
//   - Linux 5.1+: Uses pidfd_open(2) + pidfd_send_signal(2) which provides
//     an atomic handle to a specific process instance. PID-reuse is
//     impossible with this mechanism.
//   - Older kernels: Re-reads /proc/<pid>/comm after ValidatePID and
//     compares with the BPF-captured comm. A mismatch means the PID was
//     reused — abort. This reduces the race window from "unbounded"
//     to "single kernel round-trip".
func (e *Enforcer) executeKill(ctx context.Context, alert types.Alert) error {
	if err := validateEvent(alert.Event); err != nil {
		e.logger.Warn("kill rejected: invalid event", "error", err)
		return err
	}

	comm := sanitizeComm(string(bytesToString(alert.Event.Comm[:])))
	entry := AuditEntry{
		Timestamp:   time.Now(),
		Action:      ActionKill,
		RuleID:      alert.RuleID,
		PID:         alert.Event.PID,
		TGID:        alert.Event.TGID,
		Comm:        comm,
		UID:         alert.Event.UID,
		Description: fmt.Sprintf("SIGKILL sent to PID %d", alert.Event.PID),
		EventType:   alert.Event.Type,
	}

	if err := ValidatePID(alert.Event.PID); err != nil {
		entry.Success = false
		entry.Error = err.Error()
		e.logAudit(entry)
		return fmt.Errorf("enforcer/kill: %w", err)
	}

	pid := alert.Event.PID

	if pidfdSupported {
		if err := killViaPidfd(pid); err != nil {
			entry.Success = false
			entry.Error = fmt.Sprintf("pidfd kill: %v", err)
			e.logAudit(entry)
			return fmt.Errorf("enforcer/kill: %w", err)
		}
		if e.pidfdUsed != nil {
			e.pidfdUsed.Inc()
		}
	} else {
		if err := killViaProc(pid, comm); err != nil {
			entry.Success = false
			entry.Error = fmt.Sprintf("proc kill: %v", err)
			e.logAudit(entry)
			e.logger.Warn("kill aborted",
				slog.String("rule_id", alert.RuleID),
				slog.Uint64("pid", uint64(pid)),
				slog.String("expected_comm", comm),
				slog.String("error", err.Error()))
			return fmt.Errorf("enforcer/kill: %w", err)
		}
	}

	e.logger.Warn("KILL action executed",
		slog.String("rule_id", alert.RuleID),
		slog.Uint64("pid", uint64(pid)),
		slog.String("comm", comm),
	)

	entry.Success = true
	e.logAudit(entry)
	if e.actionsTotal != nil {
		e.actionsTotal.WithLabelValues("kill").Inc()
	}
	return nil
}
