//go:build !linux

package bpf

// newRingWaiter has no implementation off Linux: there is no BPF ring buffer to
// poll. A reader asked for the netpoll path here reports the fallback and keeps
// reading through the blocking path, which is what the --dry-run and unit-test
// builds on macOS use.
func newRingWaiter(fd int) (ringWaiter, error) {
	return nil, errRingWaitUnsupported
}
