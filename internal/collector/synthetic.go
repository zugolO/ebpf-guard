// Package collector provides a synthetic event generator for dry-run mode.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// SyntheticCollector generates synthetic events for testing and dry-run mode.
type SyntheticCollector struct {
	logger   *slog.Logger
	interval time.Duration
	stopped  chan struct{}
}

// NewSyntheticCollector creates a new synthetic event generator.
func NewSyntheticCollector(logger *slog.Logger, interval time.Duration) *SyntheticCollector {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &SyntheticCollector{
		logger:   logger.With("component", "synthetic_collector"),
		interval: interval,
		stopped:  make(chan struct{}),
	}
}

// Name returns the collector name.
func (s *SyntheticCollector) Name() string {
	return "synthetic"
}

// Start begins generating synthetic events.
func (s *SyntheticCollector) Start(ctx context.Context, out chan<- types.Event) error {
	s.logger.Info("starting synthetic event generator", slog.Duration("interval", s.interval))
	defer close(s.stopped)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Generate some initial events
	s.generateBurst(out, 10)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("stopping synthetic event generator")
			return nil
		case <-ticker.C:
			event := s.generateEvent()
			select {
			case out <- event:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// Close stops the synthetic collector.
func (s *SyntheticCollector) Close() error {
	<-s.stopped
	return nil
}

// IsHealthy always returns true for synthetic collector.
func (s *SyntheticCollector) IsHealthy() bool {
	return true
}

// LoadError always returns nil for synthetic collector.
func (s *SyntheticCollector) LoadError() error {
	return nil
}

// generateBurst generates a burst of events.
func (s *SyntheticCollector) generateBurst(out chan<- types.Event, count int) {
	for i := 0; i < count; i++ {
		select {
		case out <- s.generateEvent():
		default:
			// Channel full, skip
		}
	}
}

// generateEvent creates a single synthetic event.
func (s *SyntheticCollector) generateEvent() types.Event {
	eventTypes := []types.EventType{
		types.EventSyscall,
		types.EventTCPConnect,
		types.EventFileAccess,
		types.EventCloudAudit,
		types.EventIOUring,
	}
	eventType := eventTypes[rand.Intn(len(eventTypes))]

	baseEvent := types.Event{
		Type:      eventType,
		Timestamp: uint64(time.Now().UnixNano()),
		PID:       uint32(rand.Intn(65535) + 1),
		TGID:      uint32(rand.Intn(65535) + 1),
		UID:       uint32(rand.Intn(1000)),
	}
	copy(baseEvent.Comm[:], s.randomComm())

	switch eventType {
	case types.EventSyscall:
		baseEvent.Syscall = s.generateSyscallEvent()
	case types.EventTCPConnect:
		baseEvent.Network = s.generateNetworkEvent()
	case types.EventFileAccess:
		baseEvent.File = s.generateFileEvent()
	case types.EventCloudAudit:
		baseEvent.CloudAudit = s.generateCloudAuditEvent()
	case types.EventIOUring:
		baseEvent.IOUring = s.generateIOUringEvent()
	}

	return baseEvent
}

// generateCloudAuditEvent creates a synthetic cloud audit event.
func (s *SyntheticCollector) generateCloudAuditEvent() *types.CloudAuditEvent {
	providers := []string{"aws", "gcp"}
	provider := providers[rand.Intn(len(providers))]

	type cloudAction struct {
		service string
		action  string
	}
	awsActions := []cloudAction{
		{service: "iam", action: "AssumeRole"},
		{service: "iam", action: "CreateAccessKey"},
		{service: "secretsmanager", action: "GetSecretValue"},
		{service: "sts", action: "AssumeRoleWithWebIdentity"},
		{service: "ec2", action: "DescribeInstances"},
		{service: "s3", action: "GetObject"},
	}
	gcpActions := []cloudAction{
		{service: "iam.googleapis.com", action: "google.iam.admin.v1.CreateServiceAccountKey"},
		{service: "container.googleapis.com", action: "v1.projects.locations.clusters.get"},
		{service: "compute.googleapis.com", action: "v1.compute.instances.list"},
		{service: "secretmanager.googleapis.com", action: "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"},
		{service: "k8s.io", action: "pods/exec"},
	}

	var act cloudAction
	switch provider {
	case "aws":
		act = awsActions[rand.Intn(len(awsActions))]
	case "gcp":
		act = gcpActions[rand.Intn(len(gcpActions))]
	}

	principals := []string{
		"arn:aws:iam::123456789:user/admin",
		"arn:aws:sts::123456789:assumed-role/dev-role/session",
		"sa@my-project.iam.gserviceaccount.com",
		"user@example.com",
	}
	sourceIPs := []string{
		"203.0.113.42",
		"198.51.100.7",
		"10.0.1.50",
		"169.254.169.254",
	}
	regions := []string{"us-east-1", "eu-west-1", "us-central1", "europe-west1"}

	errorCodes := []string{"", "", "", "AccessDenied", ""}

	return &types.CloudAuditEvent{
		Provider:    provider,
		Service:     act.service,
		Action:      act.action,
		Principal:   principals[rand.Intn(len(principals))],
		ResourceARN: "arn:aws:iam::123456789:role/example-role",
		SourceIP:    sourceIPs[rand.Intn(len(sourceIPs))],
		UserAgent:   "aws-cli/2.0 Python/3.9",
		ErrorCode:   errorCodes[rand.Intn(len(errorCodes))],
		Region:      regions[rand.Intn(len(regions))],
		EventID:     fmt.Sprintf("synth-%d", rand.Intn(999999)),
	}
}

// generateSyscallEvent creates a synthetic syscall event.
func (s *SyntheticCollector) generateSyscallEvent() *types.SyscallEvent {
	syscalls := []int64{0, 1, 2, 59, 60, 61} // read, write, open, execve, exit, wait4
	return &types.SyscallEvent{
		Nr:  syscalls[rand.Intn(len(syscalls))],
		Ret: 0,
		Args: [6]uint64{
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
		},
	}
}

// generateNetworkEvent creates a synthetic network event.
func (s *SyntheticCollector) generateNetworkEvent() *types.NetworkEvent {
	ports := []uint16{80, 443, 53, 8080, 22, 3306}
	return &types.NetworkEvent{
		Saddr:  [16]byte{10, byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))},
		Daddr:  [16]byte{10, byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))},
		Sport:  uint16(rand.Intn(65535)),
		Dport:  ports[rand.Intn(len(ports))],
		Proto:  6, // TCP
		Family: types.AFInet,
	}
}

// generateFileEvent creates a synthetic file event.
func (s *SyntheticCollector) generateFileEvent() *types.FileEvent {
	paths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/proc/self/status",
		"/tmp/test.txt",
		"/var/log/syslog",
	}
	path := paths[rand.Intn(len(paths))]
	var filename [256]byte
	copy(filename[:], path)

	return &types.FileEvent{
		Filename: filename,
		Flags:    0,
		Mode:     0644,
		Op:       uint8(rand.Intn(3)), // 0=open, 1=read, 2=write
	}
}

// randomComm generates a random process name.
func (s *SyntheticCollector) randomComm() string {
	comms := []string{
		"nginx", "apache2", "mysql", "postgres", "redis",
		"python", "java", "node", "go", "curl", "wget",
		"bash", "sh", "ssh", "systemd",
	}
	return comms[rand.Intn(len(comms))]
}

// generateIOUringEvent creates a synthetic io_uring event.
func (s *SyntheticCollector) generateIOUringEvent() *types.IOUringEvent {
	return &types.IOUringEvent{
		Op:       uint8(rand.Intn(2)),          // 0=setup, 1=enter
		Flags:    uint32(rand.Intn(1000)),
		Fd:       int32(rand.Intn(1000) + 3),   // fd >= 3
		ToSubmit: uint32(rand.Intn(64) + 1),
	}
}
