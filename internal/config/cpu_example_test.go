package config

import "testing"

func TestExampleConfigLoadsCPUPressure(t *testing.T) {
	m, err := NewManagerSkipPermCheck("../../config/config.yaml")
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	cfg := m.Get()
	cp := cfg.Watchdog.CPUPressure
	if !cp.Enabled {
		t.Fatal("expected cpu_pressure.enabled=true from example config")
	}
	if cp.FileShedThreshold != 40.0 || cp.AllShedThreshold != 70.0 || cp.RecoveryThreshold != 20.0 {
		t.Fatalf("unexpected cpu_pressure thresholds: %+v", cp)
	}
	if cp.WindowSize != 6 {
		t.Fatalf("unexpected window_size: %d", cp.WindowSize)
	}
	// P1-18a: the dwell floor must be minutes, not seconds. This is the value
	// that actually reaches the watcher — watchdog.DefaultCPUConfig() only
	// applies when MinDwell is zero, so raising the floor there alone left the
	// flapping loop (813 reduce/recover cycles in 9h) fully intact in
	// production.
	if cp.MinDwell != 180 {
		t.Fatalf("unexpected min_dwell: %d", cp.MinDwell)
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("example config failed validation: %v", err)
	}
}
