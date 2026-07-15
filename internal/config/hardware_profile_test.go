package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectProfile(t *testing.T) {
	tests := []struct {
		name string
		hw   HardwareInfo
		want string
	}{
		{"single_cpu_small_ram", HardwareInfo{CPUs: 1, MemTotalMB: 1024}, ProfileLite},
		{"single_cpu_large_ram", HardwareInfo{CPUs: 1, MemTotalMB: 16000}, ProfileLite},
		{"multi_cpu_small_ram", HardwareInfo{CPUs: 4, MemTotalMB: 2000}, ProfileLite},
		{"multi_cpu_large_ram", HardwareInfo{CPUs: 4, MemTotalMB: 8192}, ProfileBalanced},
		{"unknown_ram_multi_cpu", HardwareInfo{CPUs: 2, MemTotalMB: 0}, ProfileBalanced},
		{"boundary_2200mb", HardwareInfo{CPUs: 2, MemTotalMB: 2200}, ProfileLite},
		{"boundary_2201mb", HardwareInfo{CPUs: 2, MemTotalMB: 2201}, ProfileBalanced},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := DetectProfile(tt.hw)
			assert.Equal(t, tt.want, got)
			assert.NotEmpty(t, reason)
		})
	}
}

func TestProfilePresets_UnknownProfile(t *testing.T) {
	_, err := ProfilePresets("nonsense")
	require.Error(t, err)
}

func TestProfilePresets_LiteIsSmallerThanProduction(t *testing.T) {
	lite, err := ProfilePresets(ProfileLite)
	require.NoError(t, err)
	prod, err := ProfilePresets(ProfileProduction)
	require.NoError(t, err)

	assert.Less(t, lite.EventsMap, prod.EventsMap)
	assert.Less(t, lite.ProcessesMap, prod.ProcessesMap)
	assert.Less(t, lite.ConnectionsMap, prod.ConnectionsMap)
	assert.Less(t, lite.MaxTrackedPIDs, prod.MaxTrackedPIDs)
	assert.False(t, lite.SequenceEnabled)
	assert.False(t, lite.LineageEnabled)
	assert.True(t, prod.SequenceEnabled)
	assert.True(t, prod.LineageEnabled)
}

func TestValidProfileName(t *testing.T) {
	assert.True(t, ValidProfileName(ProfileLite))
	assert.True(t, ValidProfileName(ProfileBalanced))
	assert.True(t, ValidProfileName(ProfileProduction))
	assert.False(t, ValidProfileName("extreme"))
	assert.False(t, ValidProfileName(""))
}

// TestNewManagerWithProfile_LiteAppliesReducedDefaults verifies the lite
// preset is applied when no config file overrides the relevant keys.
func TestNewManagerWithProfile_LiteAppliesReducedDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(""), 0644))

	mgr, err := NewManagerSkipPermCheckWithProfile(configPath, ProfileLite)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	assert.Equal(t, 8192, cfg.BPF.MapSizes.Events)
	assert.Equal(t, 2048, cfg.BPF.MapSizes.Processes)
	assert.Equal(t, 4096, cfg.BPF.MapSizes.Connections)
	assert.Equal(t, 256, cfg.Profiler.MaxTrackedPIDs)
	assert.False(t, cfg.Profiler.Sequence.Enabled)
	assert.False(t, cfg.Profiler.Lineage.Enabled)
	assert.Equal(t, ProfileLite, cfg.Profile)

	hw := mgr.HardwareProfile()
	assert.Equal(t, ProfileLite, hw.Profile)
	assert.Equal(t, "flag", hw.Source)
}

// TestNewManagerWithProfile_ConfigFileOverridesProfile verifies that a value
// explicitly set in the config file wins over the profile preset, per the
// issue's "named default set, overridden by config" requirement.
func TestNewManagerWithProfile_ConfigFileOverridesProfile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	yaml := `
bpf:
  map_sizes:
    events: 99999
profiler:
  max_tracked_pids: 777
`
	require.NoError(t, os.WriteFile(configPath, []byte(yaml), 0644))

	mgr, err := NewManagerSkipPermCheckWithProfile(configPath, ProfileLite)
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	// Explicitly set in the file: must win over the lite preset.
	assert.Equal(t, 99999, cfg.BPF.MapSizes.Events)
	assert.Equal(t, 777, cfg.Profiler.MaxTrackedPIDs)
	// Not set in the file: lite preset still applies.
	assert.Equal(t, 2048, cfg.BPF.MapSizes.Processes)
	assert.False(t, cfg.Profiler.Sequence.Enabled)
}

// TestNewManagerWithProfile_ConfigFileProfileKey verifies the "profile:"
// config key is honored when no --profile flag is passed.
func TestNewManagerWithProfile_ConfigFileProfileKey(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("profile: production\n"), 0644))

	mgr, err := NewManagerSkipPermCheckWithProfile(configPath, "")
	require.NoError(t, err)
	defer mgr.Stop()

	cfg := mgr.Get()
	assert.Equal(t, ProfileProduction, cfg.Profile)
	assert.Equal(t, 131072, cfg.BPF.MapSizes.Events)

	hw := mgr.HardwareProfile()
	assert.Equal(t, "config", hw.Source)
}

// TestNewManagerWithProfile_InvalidFlagRejected verifies an unrecognized
// --profile value fails fast instead of silently falling back.
func TestNewManagerWithProfile_InvalidFlagRejected(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(""), 0644))

	_, err := NewManagerSkipPermCheckWithProfile(configPath, "extreme")
	require.Error(t, err)
}

// TestNewZeroConfigManagerWithProfile_Balanced verifies the zero-config path
// (used by --zero-config / one-command install) also applies the profile.
func TestNewZeroConfigManagerWithProfile_Balanced(t *testing.T) {
	mgr := NewZeroConfigManagerWithProfile(ProfileBalanced)
	cfg := mgr.Get()
	assert.Equal(t, ProfileBalanced, cfg.Profile)
	assert.Equal(t, 65536, cfg.BPF.MapSizes.Events)

	hw := mgr.HardwareProfile()
	assert.Equal(t, ProfileBalanced, hw.Profile)
	assert.Equal(t, "flag", hw.Source)
}

func TestNewZeroConfigManager_AutodetectsProfile(t *testing.T) {
	mgr := NewZeroConfigManager()
	hw := mgr.HardwareProfile()
	assert.Equal(t, "autodetect", hw.Source)
	assert.True(t, ValidProfileName(hw.Profile))
}
