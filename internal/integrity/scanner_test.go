package integrity

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestNewScanner(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	s := NewScanner(logger, DefaultConfig())
	if s == nil {
		t.Fatal("expected scanner to be created")
	}

	if s.checkWindow != 24*time.Hour {
		t.Errorf("expected check window 24h, got %v", s.checkWindow)
	}
}

func TestNewScannerWithCustomConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg := Config{
		CheckWindow: 1 * time.Hour,
	}

	s := NewScanner(logger, cfg)
	if s.checkWindow != 1*time.Hour {
		t.Errorf("expected check window 1h, got %v", s.checkWindow)
	}
}

func TestCheckLDPreload(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	s := NewScanner(logger, DefaultConfig())

	// Create a temporary file to simulate ld.so.preload
	tmpDir := t.TempDir()
	preloadFile := filepath.Join(tmpDir, "ld.so.preload")

	// Test with empty file
	os.WriteFile(preloadFile, []byte(""), 0644)

	// Manually test the logic
	data, err := os.ReadFile(preloadFile)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	content := string(data)
	if content != "" {
		t.Error("expected empty content")
	}

	// Test with malicious content
	os.WriteFile(preloadFile, []byte("/tmp/evil.so\n"), 0644)
	data, err = os.ReadFile(preloadFile)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	content = string(data)
	if content == "" {
		t.Error("expected non-empty content")
	}

	// The actual checkLDPreload function reads from /etc/ld.so.preload
	// which we can't modify in tests, so we just verify the scanner
	// was created correctly
	s.checkLDPreload()
}

func TestCheckCronDirs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temporary cron directory
	tmpDir := t.TempDir()
	cronDir := filepath.Join(tmpDir, "cron.d")
	os.MkdirAll(cronDir, 0755)

	// Create a recent file
	recentFile := filepath.Join(cronDir, "test-cron")
	os.WriteFile(recentFile, []byte("* * * * * root /bin/true"), 0644)

	// Create scanner with our temp directory
	s := NewScanner(logger, Config{
		CheckWindow: 24 * time.Hour,
	})

	// We can't easily redirect the cron check to our temp dir,
	// but we can verify the scanner runs without panic
	s.checkCronDirs()
}

func TestCheckRootShellConfigs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	s := NewScanner(logger, DefaultConfig())

	// This test will likely skip since we can't access /root in tests
	s.checkRootShellConfigs()

	// Just verify no panic occurred
}

func TestCheckAnonymousExecRegions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	s := NewScanner(logger, DefaultConfig())

	// This test reads from /proc which should work in most environments
	s.checkAnonymousExecRegions()

	// Just verify no panic occurred and we can read /proc
}

func TestScanIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	var alerts []types.Alert
	alertFunc := func(a types.Alert) {
		alerts = append(alerts, a)
	}

	s := NewScanner(logger, Config{
		CheckWindow: 24 * time.Hour,
		AlertFunc:   alertFunc,
	})

	findings := s.Scan()

	// We should get findings (at least from /proc check on Linux)
	// or an empty slice if running on non-Linux or in restricted environment
	t.Logf("Scan found %d findings", len(findings))

	// Verify findings is not nil
	if findings == nil {
		t.Error("expected findings to be non-nil")
	}
}

func TestGetFindingsByCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	s := NewScanner(logger, DefaultConfig())

	// Manually add some test findings
	s.findings = []Finding{
		{Check: "ld_preload", Path: "/etc/ld.so.preload", Details: "test"},
		{Check: "ld_preload", Path: "/etc/ld.so.preload", Details: "test2"},
		{Check: "cron", Path: "/etc/cron.d/test", Details: "test"},
	}

	ldPreloadFindings := s.GetFindingsByCheck("ld_preload")
	if len(ldPreloadFindings) != 2 {
		t.Errorf("expected 2 ld_preload findings, got %d", len(ldPreloadFindings))
	}

	cronFindings := s.GetFindingsByCheck("cron")
	if len(cronFindings) != 1 {
		t.Errorf("expected 1 cron finding, got %d", len(cronFindings))
	}

	emptyFindings := s.GetFindingsByCheck("nonexistent")
	if len(emptyFindings) != 0 {
		t.Errorf("expected 0 findings for nonexistent check, got %d", len(emptyFindings))
	}
}

func TestExportMetrics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	s := NewScanner(logger, DefaultConfig())

	// Add test findings
	s.findings = []Finding{
		{Check: "ld_preload", Path: "/etc/ld.so.preload", Details: "test"},
		{Check: "ld_preload", Path: "/etc/ld.so.preload", Details: "test2"},
		{Check: "cron", Path: "/etc/cron.d/test", Details: "test"},
	}

	// Should not panic
	s.exportMetrics()
}

func TestSendAlerts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	var alerts []types.Alert
	alertFunc := func(a types.Alert) {
		alerts = append(alerts, a)
	}

	s := NewScanner(logger, Config{
		AlertFunc: alertFunc,
	})

	// Add test findings
	s.findings = []Finding{
		{Check: "ld_preload", Path: "/etc/ld.so.preload", Details: "test"},
		{Check: "ld_preload", Path: "/etc/ld.so.preload", Details: "test2"},
		{Check: "cron", Path: "/etc/cron.d/test", Details: "test"},
	}

	s.sendAlerts()

	// Should have sent 2 alerts (one per check type)
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts))
	}

	// Verify alert structure
	for _, alert := range alerts {
		if alert.Severity != types.SeverityWarning {
			t.Errorf("expected warning severity, got %s", alert.Severity)
		}
		if alert.RuleID == "" {
			t.Error("expected non-empty rule_id")
		}
	}
}

func TestSendAlertsWithManyFindings(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	var alerts []types.Alert
	alertFunc := func(a types.Alert) {
		alerts = append(alerts, a)
	}

	s := NewScanner(logger, Config{
		AlertFunc: alertFunc,
	})

	// Add many test findings (more than 5 to test truncation)
	for i := 0; i < 10; i++ {
		s.findings = append(s.findings, Finding{
			Check:   "ld_preload",
			Path:    "/etc/ld.so.preload",
			Details: "test",
		})
	}

	s.sendAlerts()

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// Check that message mentions "and 5 more"
	if !contains(alerts[0].Message, "and 5 more") {
		t.Error("expected message to contain truncation notice")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestLogFindings(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	s := NewScanner(logger, DefaultConfig())

	// Test with no findings
	s.logFindings()

	// Test with findings
	s.findings = []Finding{
		{Check: "ld_preload", Path: "/etc/ld.so.preload", Details: "test"},
	}
	s.logFindings()
}
