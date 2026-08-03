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
	if cp.MinDwell != 30 {
		t.Fatalf("unexpected min_dwell: %d", cp.MinDwell)
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("example config failed validation: %v", err)
	}
}
