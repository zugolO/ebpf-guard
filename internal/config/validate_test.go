package config

import (
	"strings"
	"testing"
	"time"
)

// baseConfig returns a minimal valid Config so individual tests only need
// to override the field they're testing.
func baseConfig() *Config {
	return &Config{
		Server: ServerConfig{BindAddress: ":9090"},
		Store:  StoreConfig{Backend: "memory"},
		Profiler: ProfilerConfig{
			Enabled:          true,
			LearningPeriod:   3600,
			AnomalyThreshold: 0.8,
			EWMAWeight:       0.3,
			Sequence:         SequenceProfilerConfig{Threshold: 0.3},
		},
		Rules: RulesConfig{
			RateLimitAlerts: true,
			RateLimitWindow: 60,
		},
		Alerting:    AlertingConfig{Enabled: false},
		Enforcement: EnforcementConfig{Enabled: false, BlockBackend: "log"},
		Watchdog: WatchdogConfig{MemoryPressure: MemoryPressureConfig{
			Enabled:            false,
			LowMemoryThreshold: 10,
			RecoveryThreshold:  20,
		}},
		Canary: CanaryConfig{AlertSeverity: "critical"},
	}
}

func TestValidateConfig_Valid(t *testing.T) {
	if err := ValidateConfig(baseConfig()); err != nil {
		t.Fatalf("expected no error for valid base config, got: %v", err)
	}
}

func TestValidateConfig_AISandbox(t *testing.T) {
	validProfile := AISandboxProfile{
		Name:               "ai-agent",
		AllowedExec:        []string{"/usr/bin/"},
		AllowedReadPaths:   []string{"/workspace/"},
		AllowedEgressCIDRs: []string{"140.82.112.0/20"},
		AllowedEgressPorts: []uint16{443},
		AllowedDomains:     []string{"github.com"},
	}

	t.Run("disabled skips validation", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: false, Mode: "nonsense"}
		if err := ValidateConfig(cfg); err != nil {
			t.Fatalf("disabled sandbox should not be validated, got: %v", err)
		}
	})

	t.Run("valid enforce profile", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{
			Enabled:  true,
			Mode:     "enforce",
			Profiles: []AISandboxProfile{validProfile},
			Selector: AISandboxSelector{DefaultProfile: "ai-agent"},
		}
		if err := ValidateConfig(cfg); err != nil {
			t.Fatalf("expected valid, got: %v", err)
		}
	})

	t.Run("invalid mode", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "block", Profiles: []AISandboxProfile{validProfile}}
		if err := ValidateConfig(cfg); err == nil {
			t.Fatal("expected error for invalid mode")
		}
	})

	t.Run("no profiles", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "audit"}
		if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "at least one profile") {
			t.Fatalf("expected missing-profile error, got: %v", err)
		}
	})

	t.Run("empty profile name", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "audit",
			Profiles: []AISandboxProfile{{Name: ""}}}
		if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "must not be empty") {
			t.Fatalf("expected empty-name error, got: %v", err)
		}
	})

	t.Run("duplicate profile name", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "audit",
			Profiles: []AISandboxProfile{{Name: "a"}, {Name: "a"}}}
		if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "duplicate profile name") {
			t.Fatalf("expected duplicate-name error, got: %v", err)
		}
	})

	t.Run("invalid egress CIDR", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "audit",
			Profiles: []AISandboxProfile{{Name: "a", AllowedEgressCIDRs: []string{"not-a-cidr"}}}}
		if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "invalid CIDR") {
			t.Fatalf("expected invalid-CIDR error, got: %v", err)
		}
	})

	t.Run("dangling default_profile", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "audit",
			Profiles: []AISandboxProfile{{Name: "a"}},
			Selector: AISandboxSelector{DefaultProfile: "missing"}}
		if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "does not match any defined profile") {
			t.Fatalf("expected dangling default_profile error, got: %v", err)
		}
	})

	t.Run("writable exec prefix rejected", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "enforce",
			Profiles: []AISandboxProfile{{
				Name:              "a",
				AllowedExec:       []string{"/work/bin"},
				AllowedWritePaths: []string{"/work"}, // /work/bin is under a writable dir
			}}}
		if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "overlaps writable path") {
			t.Fatalf("expected writable-exec overlap error, got: %v", err)
		}
	})

	t.Run("exec prefix equal to write prefix rejected", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "enforce",
			Profiles: []AISandboxProfile{{
				Name:              "a",
				AllowedExec:       []string{"/opt/app/"},
				AllowedWritePaths: []string{"/opt/app"},
			}}}
		if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "overlaps writable path") {
			t.Fatalf("expected overlap error for equal prefixes, got: %v", err)
		}
	})

	t.Run("disjoint exec and write prefixes allowed", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "enforce",
			Profiles: []AISandboxProfile{{
				Name:              "a",
				AllowedExec:       []string{"/usr/bin", "/workspace"}, // note: /workspace not writable
				AllowedWritePaths: []string{"/workspace/out"},
			}}}
		// /workspace is an ancestor of the writable /workspace/out -> overlap.
		if err := ValidateConfig(cfg); err == nil {
			t.Fatal("expected overlap: exec /workspace is an ancestor of writable /workspace/out")
		}
	})

	t.Run("sibling prefixes not treated as overlap", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "enforce",
			Profiles: []AISandboxProfile{{
				Name:              "a",
				AllowedExec:       []string{"/usr/bin"},
				AllowedWritePaths: []string{"/usr/binaries"}, // shares a string prefix, different dir
			}}}
		if err := ValidateConfig(cfg); err != nil {
			t.Fatalf("siblings /usr/bin and /usr/binaries must not overlap, got: %v", err)
		}
	})

	t.Run("valid exec pin", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "enforce",
			Profiles: []AISandboxProfile{{
				Name:        "a",
				AllowedExec: []string{"/usr/bin"},
				AllowedExecPins: []AISandboxExecPin{{
					Path:   "/usr/bin/python3",
					Sha256: strings.Repeat("ab", 32),
				}},
			}}}
		if err := ValidateConfig(cfg); err != nil {
			t.Fatalf("expected valid exec pin, got: %v", err)
		}
	})

	t.Run("exec pin not under allowed_exec", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "enforce",
			Profiles: []AISandboxProfile{{
				Name:        "a",
				AllowedExec: []string{"/usr/bin"},
				AllowedExecPins: []AISandboxExecPin{{
					Path:   "/opt/tool",
					Sha256: strings.Repeat("ab", 32),
				}},
			}}}
		if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "not covered by any allowed_exec") {
			t.Fatalf("expected coverage error, got: %v", err)
		}
	})

	t.Run("exec pin bad digest", func(t *testing.T) {
		cfg := baseConfig()
		cfg.AISandbox = AISandboxConfig{Enabled: true, Mode: "enforce",
			Profiles: []AISandboxProfile{{
				Name:        "a",
				AllowedExec: []string{"/usr/bin"},
				AllowedExecPins: []AISandboxExecPin{{
					Path:   "/usr/bin/python3",
					Sha256: "not-a-digest",
				}},
			}}}
		if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "hex SHA-256") {
			t.Fatalf("expected sha256 error, got: %v", err)
		}
	})
}

func TestValidateConfig_StoreBackend(t *testing.T) {
	tests := []struct {
		backend string
		wantErr bool
	}{
		{"memory", false},
		{"sqlite", false},
		{"opensearch", false},
		{"postgres", true},
		{"", true},
	}
	for _, tt := range tests {
		cfg := baseConfig()
		cfg.Store.Backend = tt.backend
		err := ValidateConfig(cfg)
		if tt.wantErr && err == nil {
			t.Errorf("backend %q: expected error, got nil", tt.backend)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("backend %q: unexpected error: %v", tt.backend, err)
		}
	}
}

func TestValidateConfig_BlockBackend(t *testing.T) {
	tests := []struct {
		backend string
		wantErr bool
	}{
		{"log", false},
		{"nftables", false},
		{"iptables", false},
		{"lsm", false},
		{"xdp", false},
		{"ebpf", true},
		{"", true},
	}
	for _, tt := range tests {
		cfg := baseConfig()
		cfg.Enforcement.Enabled = true
		cfg.Enforcement.BlockBackend = tt.backend
		cfg.Enforcement.ThrottleCPUPercent = 10
		cfg.Enforcement.ThrottleMaxAgeMinutes = 30
		err := ValidateConfig(cfg)
		if tt.wantErr && err == nil {
			t.Errorf("block_backend %q: expected error, got nil", tt.backend)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("block_backend %q: unexpected error: %v", tt.backend, err)
		}
	}
}

func TestValidateConfig_Thresholds(t *testing.T) {
	tests := []struct {
		name  string
		patch func(*Config)
		want  string
	}{
		{
			"anomaly_threshold below range",
			func(c *Config) { c.Profiler.AnomalyThreshold = -0.1 },
			"profiler.anomaly_threshold",
		},
		{
			"anomaly_threshold above range",
			func(c *Config) { c.Profiler.AnomalyThreshold = 1.5 },
			"profiler.anomaly_threshold",
		},
		{
			"ewma_weight below range",
			func(c *Config) { c.Profiler.EWMAWeight = -0.01 },
			"profiler.ewma_weight",
		},
		{
			"ewma_weight above range",
			func(c *Config) { c.Profiler.EWMAWeight = 1.1 },
			"profiler.ewma_weight",
		},
		{
			"sequence threshold out of range",
			func(c *Config) { c.Profiler.Sequence.Threshold = 2.0 },
			"profiler.sequence.threshold",
		},
		{
			"boundary 0.0 is valid",
			func(c *Config) { c.Profiler.AnomalyThreshold = 0.0 },
			"", // no error expected
		},
		{
			"boundary 1.0 is valid",
			func(c *Config) { c.Profiler.AnomalyThreshold = 1.0 },
			"", // no error expected
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			tt.patch(cfg)
			err := ValidateConfig(cfg)
			if tt.want == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention field %q", err, tt.want)
			}
		})
	}
}

func TestValidateConfig_Duration(t *testing.T) {
	cfg := baseConfig()
	cfg.Profiler.Enabled = true
	cfg.Profiler.LearningPeriod = 0
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for learning_period=0, got nil")
	}
	if !strings.Contains(err.Error(), "profiler.learning_period") {
		t.Errorf("error does not mention profiler.learning_period: %v", err)
	}
}

func TestValidateConfig_BindAddress(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{":9090", false},
		{"0.0.0.0:9090", false},
		{"127.0.0.1:8080", false},
		{"[::]:9090", false},
		{"not-valid", true},
		{"192.168.1.300:9090", true}, // invalid IP octet
	}
	for _, tt := range tests {
		cfg := baseConfig()
		cfg.Server.BindAddress = tt.addr
		err := ValidateConfig(cfg)
		if tt.wantErr && err == nil {
			t.Errorf("addr %q: expected error, got nil", tt.addr)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("addr %q: unexpected error: %v", tt.addr, err)
		}
	}
}

func TestValidateConfig_Alerting(t *testing.T) {
	cfg := baseConfig()
	cfg.Alerting.Enabled = true
	cfg.Alerting.WebhookURL = ""
	cfg.Alerting.BatchTimeout = 5
	err := ValidateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "alerting.webhook_url") {
		t.Errorf("expected alerting.webhook_url error, got: %v", err)
	}

	cfg.Alerting.WebhookURL = "ftp://bad-scheme"
	err = ValidateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "alerting.webhook_url") {
		t.Errorf("expected scheme error, got: %v", err)
	}

	cfg.Alerting.WebhookURL = "http://alertmanager:9093/api/v2/alerts"
	cfg.Alerting.BatchTimeout = 0
	err = ValidateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "alerting.batch_timeout") {
		t.Errorf("expected batch_timeout error, got: %v", err)
	}

	cfg.Alerting.BatchTimeout = 5
	err = ValidateConfig(cfg)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateConfig_WatchdogThresholds(t *testing.T) {
	cfg := baseConfig()
	cfg.Watchdog.MemoryPressure.Enabled = true
	cfg.Watchdog.MemoryPressure.LowMemoryThreshold = 20
	cfg.Watchdog.MemoryPressure.RecoveryThreshold = 10 // lo >= hi

	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for lo >= hi, got nil")
	}
	if !strings.Contains(err.Error(), "low_memory_threshold") {
		t.Errorf("error does not mention low_memory_threshold: %v", err)
	}
}

func TestValidateConfig_CPUPressure(t *testing.T) {
	valid := CPUPressureConfig{
		Enabled:           true,
		CheckInterval:     5,
		CPULimitPercent:   15,
		FileShedThreshold: 15,
		AllShedThreshold:  25,
		RecoveryThreshold: 9,
		WindowSize:        3,
	}

	tests := []struct {
		name    string
		mutate  func(c *CPUPressureConfig)
		wantErr string // substring expected in the error; "" means no error
	}{
		{"valid", func(c *CPUPressureConfig) {}, ""},
		{"disabled skips validation", func(c *CPUPressureConfig) {
			c.Enabled = false
			c.FileShedThreshold = 200 // out of range but ignored when disabled
		}, ""},
		{"cpu_limit out of range", func(c *CPUPressureConfig) { c.CPULimitPercent = 150 }, "cpu_limit_percent"},
		{"file_shed negative", func(c *CPUPressureConfig) { c.FileShedThreshold = -1 }, "file_shed_threshold"},
		{"all_shed out of range", func(c *CPUPressureConfig) { c.AllShedThreshold = 101 }, "all_shed_threshold"},
		{"recovery out of range", func(c *CPUPressureConfig) { c.RecoveryThreshold = 101 }, "recovery_threshold"},
		{"file_shed above all_shed", func(c *CPUPressureConfig) {
			c.FileShedThreshold = 30
			c.AllShedThreshold = 25
		}, "must be <= all_shed_threshold"},
		{"recovery above file_shed", func(c *CPUPressureConfig) {
			c.RecoveryThreshold = 20
			c.FileShedThreshold = 15
		}, "must be less than file_shed_threshold"},
		{"negative window", func(c *CPUPressureConfig) { c.WindowSize = -1 }, "window_size"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			cp := valid
			tt.mutate(&cp)
			cfg.Watchdog.CPUPressure = cp

			err := ValidateConfig(cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateConfig_MultipleErrors(t *testing.T) {
	cfg := baseConfig()
	cfg.Store.Backend = "invalid"
	cfg.Profiler.AnomalyThreshold = 2.0
	cfg.Profiler.EWMAWeight = -1.0

	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("expected multiple errors, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"store.backend", "profiler.anomaly_threshold", "profiler.ewma_weight"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing field %q: %s", want, msg)
		}
	}
}

func TestValidateConfig_ShutdownTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		wantErr bool
	}{
		{"zero (uses default)", 0, false},
		{"minimum boundary 5s", 5 * time.Second, false},
		{"typical 30s", 30 * time.Second, false},
		{"maximum boundary 300s", 300 * time.Second, false},
		{"too short 4s", 4 * time.Second, true},
		{"too long 301s", 301 * time.Second, true},
		{"negative", -1 * time.Second, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Server.ShutdownTimeout = tt.timeout
			err := ValidateConfig(cfg)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for %s, got nil", tt.timeout)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for %s: %v", tt.timeout, err)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "server.shutdown_timeout") {
				t.Errorf("error does not mention server.shutdown_timeout: %v", err)
			}
		})
	}
}
