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
	if cp.FileShedThreshold != 15.0 || cp.AllShedThreshold != 25.0 || cp.RecoveryThreshold != 9.0 {
		t.Fatalf("unexpected cpu_pressure thresholds: %+v", cp)
	}
	if cp.WindowSize != 3 {
		t.Fatalf("unexpected window_size: %d", cp.WindowSize)
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("example config failed validation: %v", err)
	}
}
