package config

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// Hardware-aware profiles (issue #287): three built-in presets — lite,
// balanced, production — that set BPF map sizes, tracked-PID limits,
// sequence/lineage profiler enablement, and Go runtime memory tuning
// appropriate for the host. They are applied as viper defaults, so any value
// explicitly present in the config file still wins.
const (
	ProfileLite       = "lite"
	ProfileBalanced   = "balanced"
	ProfileProduction = "production"
)

// liteThresholdCPUs and liteThresholdMemMB define the autodetect boundary
// for the "lite" profile: a host at or below either threshold is assumed to
// be a small VPS (the target audience for one-command install) and gets the
// reduced-footprint preset without the operator having to think about it.
const (
	liteThresholdCPUs  = 1
	liteThresholdMemMB = 2200 // ~2GB, with headroom for /proc/meminfo rounding
)

// HardwareInfo captures the host resources used to pick a profile.
type HardwareInfo struct {
	CPUs       int
	MemTotalMB int
}

// DetectHardware reads nproc (runtime.NumCPU) and /proc/meminfo to describe
// the host the agent is running on. MemTotalMB is 0 if it could not be
// determined (e.g. /proc/meminfo unavailable), in which case profile
// autodetection falls back to CPU count alone.
func DetectHardware() HardwareInfo {
	info := HardwareInfo{CPUs: runtime.NumCPU()}
	if mb, err := readMemTotalMB("/proc/meminfo"); err == nil {
		info.MemTotalMB = mb
	}
	return info
}

func readMemTotalMB(path string) (int, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is an internal constant (/proc/meminfo), never user input
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("hardware_profile: malformed MemTotal line %q", line)
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, fmt.Errorf("hardware_profile: parse MemTotal: %w", err)
		}
		return kb / 1024, nil
	}
	return 0, fmt.Errorf("hardware_profile: MemTotal not found in %s", path)
}

// DetectProfile picks lite or balanced from host resources, plus a
// human-readable reason suitable for a startup log line. production is
// never autodetected — it implies a deliberate, explicitly-configured
// deployment, so it must be requested via --profile or the config file.
func DetectProfile(hw HardwareInfo) (profile string, reason string) {
	if hw.CPUs <= liteThresholdCPUs || (hw.MemTotalMB > 0 && hw.MemTotalMB <= liteThresholdMemMB) {
		return ProfileLite, fmt.Sprintf(
			"detected %d CPU(s) / %dMB RAM (lite threshold: <=%d CPU(s) or <=%dMB RAM)",
			hw.CPUs, hw.MemTotalMB, liteThresholdCPUs, liteThresholdMemMB)
	}
	return ProfileBalanced, fmt.Sprintf("detected %d CPU(s) / %dMB RAM", hw.CPUs, hw.MemTotalMB)
}

// ProfileDefaults holds the tuning values a hardware profile applies.
type ProfileDefaults struct {
	EventsMap       int
	ProcessesMap    int
	ConnectionsMap  int
	MaxTrackedPIDs  int
	SequenceEnabled bool
	LineageEnabled  bool
	// GOMEMLIMITRatio is the fraction of detected total RAM to pass to
	// debug.SetMemoryLimit; 0 disables the soft memory limit.
	GOMEMLIMITRatio float64
	// GOGCPercent is passed to debug.SetGCPercent; 0 leaves the Go default (100).
	GOGCPercent int
}

// ProfilePresets returns the built-in tuning values for a named profile.
func ProfilePresets(profile string) (ProfileDefaults, error) {
	switch profile {
	case ProfileLite:
		return ProfileDefaults{
			EventsMap:       8192,
			ProcessesMap:    2048,
			ConnectionsMap:  4096,
			MaxTrackedPIDs:  256,
			SequenceEnabled: false,
			LineageEnabled:  false,
			GOMEMLIMITRatio: 0.4,
			GOGCPercent:     50,
		}, nil
	case ProfileBalanced:
		// Matches the pre-existing global defaults (setDefaults in config.go) —
		// balanced is the "everything on, moderate limits" starting point.
		return ProfileDefaults{
			EventsMap:       65536,
			ProcessesMap:    16384,
			ConnectionsMap:  32768,
			MaxTrackedPIDs:  4096,
			SequenceEnabled: true,
			LineageEnabled:  true,
		}, nil
	case ProfileProduction:
		return ProfileDefaults{
			EventsMap:       131072,
			ProcessesMap:    32768,
			ConnectionsMap:  65536,
			MaxTrackedPIDs:  8192,
			SequenceEnabled: true,
			LineageEnabled:  true,
		}, nil
	default:
		return ProfileDefaults{}, fmt.Errorf(
			"hardware_profile: unknown profile %q (valid: %s, %s, %s)",
			profile, ProfileLite, ProfileBalanced, ProfileProduction)
	}
}

// ApplyHardwareProfile registers the named profile's preset values as viper
// defaults (SetDefault, not Set) for any key not explicitly present in the
// config file. Because viper's precedence is config-file > default,
// this must be called after setDefaults(v) but before v.ReadInConfig() —
// the file's own values always win regardless of call order, so callers must
// use isSetInFile to skip keys the file explicitly sets (a plain v.IsSet
// would incorrectly report "set" for the base defaults applied earlier).
// Returns the resolved ProfileDefaults for logging.
func ApplyHardwareProfile(v *viper.Viper, isSetInFile func(key string) bool, profile string) (ProfileDefaults, error) {
	defaults, err := ProfilePresets(profile)
	if err != nil {
		return ProfileDefaults{}, err
	}
	if isSetInFile == nil {
		isSetInFile = func(string) bool { return false }
	}

	setIfUnset := func(key string, value interface{}) {
		if !isSetInFile(key) {
			v.SetDefault(key, value)
		}
	}

	setIfUnset("bpf.map_sizes.events", defaults.EventsMap)
	setIfUnset("bpf.map_sizes.processes", defaults.ProcessesMap)
	setIfUnset("bpf.map_sizes.connections", defaults.ConnectionsMap)
	setIfUnset("profiler.max_tracked_pids", defaults.MaxTrackedPIDs)
	setIfUnset("profiler.sequence.enabled", defaults.SequenceEnabled)
	setIfUnset("profiler.lineage.enabled", defaults.LineageEnabled)

	return defaults, nil
}

// ValidProfileName reports whether name is a recognized profile identifier.
func ValidProfileName(name string) bool {
	switch name {
	case ProfileLite, ProfileBalanced, ProfileProduction:
		return true
	default:
		return false
	}
}

// resolveHardwareProfile decides which profile to use, in order of
// precedence: explicit override (--profile), the config file's "profile:"
// key, then autodetection from host resources.
func resolveHardwareProfile(override string, fileV *viper.Viper) HardwareProfileInfo {
	hw := DetectHardware()

	if override != "" {
		return HardwareProfileInfo{
			Profile:  override,
			Source:   "flag",
			Reason:   "explicit --profile override",
			Hardware: hw,
		}
	}
	if fileV != nil && fileV.IsSet("profile") {
		if p := fileV.GetString("profile"); p != "" {
			return HardwareProfileInfo{
				Profile:  p,
				Source:   "config",
				Reason:   `explicit "profile:" key in config file`,
				Hardware: hw,
			}
		}
	}

	profile, reason := DetectProfile(hw)
	return HardwareProfileInfo{
		Profile:  profile,
		Source:   "autodetect",
		Reason:   reason,
		Hardware: hw,
	}
}
