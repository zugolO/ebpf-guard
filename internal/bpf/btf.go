//go:build linux

package bpf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// BTFSource identifies how BTF type information was obtained.
type BTFSource string

const (
	// BTFSourceLocal means /sys/kernel/btf/vmlinux or an explicit btf_path was used.
	BTFSourceLocal BTFSource = "local"
	// BTFSourceBTFHub means a pre-built BTF file was fetched from the BTF hub archive.
	BTFSourceBTFHub BTFSource = "btf_hub"
	// BTFSourceHeaders means kernel headers at /usr/src/linux-headers-<release> were used.
	BTFSourceHeaders BTFSource = "headers"
	// BTFSourceNone means no BTF is available; reduced feature set applies.
	BTFSourceNone BTFSource = "none"
)

// btfSourceGauge is the ebpf_guard_btf_source gauge family.
// Exactly one label value is set to 1.0; the rest are 0.0.
var btfSourceGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "ebpf_guard_btf_source",
	Help: "BTF source used by ebpf-guard (1 = active). Labels: local, btf_hub, headers, none.",
}, []string{"source"})

func init() {
	// Pre-create all label combinations so the metric appears at /metrics
	// even before ResolveBTF is called.
	for _, src := range []BTFSource{BTFSourceLocal, BTFSourceBTFHub, BTFSourceHeaders, BTFSourceNone} {
		btfSourceGauge.WithLabelValues(string(src)).Set(0)
	}
}

// RegisterBTFMetrics registers the BTF source gauge with the given Prometheus registerer.
func RegisterBTFMetrics(reg prometheus.Registerer) {
	_ = reg.Register(btfSourceGauge)
}

// BTFResolutionConfig holds parameters for the BTF source resolution.
// These are mapped from config.BPFConfig.
type BTFResolutionConfig struct {
	// BTFPath is an explicit path to a .btf file. Empty = auto-detect.
	BTFPath string
	// BTFHubEnabled controls whether the BTF hub is queried as a fallback.
	BTFHubEnabled bool
	// BTFHubCache is the local directory for cached BTF hub files.
	// Default: /var/lib/ebpf-guard/btf
	BTFHubCache string
	// FallbackReducedFeatures allows starting with a reduced collector set
	// when no BTF source is found, instead of failing hard.
	FallbackReducedFeatures bool
}

// BTFResult holds the outcome of BTF source resolution.
type BTFResult struct {
	// Source is the strategy that succeeded (or BTFSourceNone).
	Source BTFSource
	// Path is the path to the resolved external BTF file.
	// Empty when Source == BTFSourceLocal (kernel-embedded) or BTFSourceNone.
	Path string
	// DisabledCollectors lists the collector names that must be skipped
	// because they require BTF struct offsets unavailable at runtime.
	DisabledCollectors []string
}

// ResolveBTF determines which BTF source is available and updates the
// Prometheus gauge. Resolution order:
//  1. Explicit btf_path override (treated as local)
//  2. /sys/kernel/btf/vmlinux (kernel-embedded BTF, requires 5.8+)
//  3. BTF hub archive cache / download (if btf_hub_enabled = true)
//  4. Kernel headers at /usr/src/linux-headers-<release>
//  5. None — start with reduced feature set if fallback_reduced_features = true
func ResolveBTF(cfg BTFResolutionConfig) (*BTFResult, error) {
	// Reset all label values before setting the winner.
	for _, src := range []BTFSource{BTFSourceLocal, BTFSourceBTFHub, BTFSourceHeaders, BTFSourceNone} {
		btfSourceGauge.WithLabelValues(string(src)).Set(0)
	}

	// Strategy 0: explicit btf_path override.
	if cfg.BTFPath != "" {
		if _, err := os.Stat(cfg.BTFPath); err == nil {
			btfSourceGauge.WithLabelValues(string(BTFSourceLocal)).Set(1)
			slog.Info("btf: using explicit BTF file", slog.String("path", cfg.BTFPath))
			return &BTFResult{Source: BTFSourceLocal, Path: cfg.BTFPath}, nil
		}
		slog.Warn("btf: explicit btf_path not found, continuing with auto-detect",
			slog.String("path", cfg.BTFPath))
	}

	// Strategy 1: local kernel-embedded BTF.
	if detectLocalBTF() {
		btfSourceGauge.WithLabelValues(string(BTFSourceLocal)).Set(1)
		slog.Info("btf: using kernel-embedded BTF (/sys/kernel/btf/vmlinux)")
		return &BTFResult{Source: BTFSourceLocal}, nil
	}

	// Strategy 2: BTF hub fallback.
	if cfg.BTFHubEnabled {
		path, err := resolveBTFHub(cfg.BTFHubCache)
		if err == nil {
			btfSourceGauge.WithLabelValues(string(BTFSourceBTFHub)).Set(1)
			slog.Info("btf: using BTF hub file", slog.String("path", path))
			return &BTFResult{Source: BTFSourceBTFHub, Path: path}, nil
		}
		slog.Warn("btf: BTF hub lookup failed, trying kernel headers",
			slog.Any("error", err))
	}

	// Strategy 3: kernel headers.
	if path, err := resolveKernelHeaders(); err == nil {
		btfSourceGauge.WithLabelValues(string(BTFSourceHeaders)).Set(1)
		slog.Info("btf: using kernel headers", slog.String("path", path))
		return &BTFResult{Source: BTFSourceHeaders, Path: path}, nil
	}

	// No BTF available.
	btfSourceGauge.WithLabelValues(string(BTFSourceNone)).Set(1)

	if !cfg.FallbackReducedFeatures {
		return nil, fmt.Errorf(
			"no BTF source available: install kernel headers or enable btf_hub_enabled=true " +
				"(set fallback_reduced_features=true to start with reduced collectors)",
		)
	}

	// LSM hooks and TLS uprobes require BTF for struct offset resolution.
	disabled := []string{"lsm", "tls"}
	slog.Warn("btf: no BTF source found — starting with reduced feature set",
		slog.Any("disabled_collectors", disabled))
	return &BTFResult{Source: BTFSourceNone, DisabledCollectors: disabled}, nil
}

// detectLocalBTF returns true when /sys/kernel/btf/vmlinux is present and accessible.
func detectLocalBTF() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

// resolveKernelHeaders checks whether kernel development headers are installed
// for the running kernel. Returns the include path on success.
func resolveKernelHeaders() (string, error) {
	release, err := kernelRelease()
	if err != nil {
		return "", fmt.Errorf("read kernel release: %w", err)
	}
	hdrPath := filepath.Join("/usr/src", "linux-headers-"+release, "include")
	if _, err := os.Stat(hdrPath); err != nil {
		return "", fmt.Errorf("kernel headers not found at %s", hdrPath)
	}
	return hdrPath, nil
}

// resolveBTFHub looks up the matching BTF file from the BTF hub archive.
// It checks the local cache first; if missing and download succeeds, caches it.
// BTF hub archive: https://github.com/aquasecurity/btfhub-archive
func resolveBTFHub(cacheDir string) (string, error) {
	if cacheDir == "" {
		cacheDir = "/var/lib/ebpf-guard/btf"
	}

	release, err := kernelRelease()
	if err != nil {
		return "", fmt.Errorf("read kernel release: %w", err)
	}

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	distro, version, err := detectDistro()
	if err != nil {
		return "", fmt.Errorf("detect distro: %w", err)
	}

	// Cache path: <cacheDir>/<distro>/<version>/<arch>/vmlinux-<release>.btf
	cacheFile := filepath.Join(cacheDir, distro, version, arch, "vmlinux-"+release+".btf")
	if _, err := os.Stat(cacheFile); err == nil {
		return cacheFile, nil
	}

	// Not cached — attempt download from BTF hub archive.
	url := fmt.Sprintf(
		"https://github.com/aquasecurity/btfhub-archive/raw/main/%s/%s/%s/vmlinux-%s.btf.tar.xz",
		distro, version, arch, release,
	)
	if err := downloadAndExtractBTF(url, cacheFile); err != nil {
		return "", fmt.Errorf("btf hub download for %s/%s/%s kernel %s: %w",
			distro, version, arch, release, err)
	}
	return cacheFile, nil
}

// downloadAndExtractBTF downloads a .btf.tar.xz from the BTF hub and extracts
// the inner .btf file to destPath. Uses system tar(1) for XZ decompression.
func downloadAndExtractBTF(url, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	// Write tarball to a temp file.
	tmpTar := destPath + ".tar.xz.tmp"
	f, err := os.Create(tmpTar)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpTar)
		return fmt.Errorf("write tarball: %w", err)
	}
	f.Close()
	defer os.Remove(tmpTar)

	// Extract the single .btf file from the archive.
	// tar -xJf archive.tar.xz -C destdir --strip-components=0
	tmpDest := destPath + ".tmp"
	cmd := exec.CommandContext(ctx, "tar",
		"-xJf", tmpTar,
		"-C", filepath.Dir(destPath),
		"--wildcards", "*.btf",
		"--transform", "s|.*/||",
		"--no-anchored",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tmpDest)
		return fmt.Errorf("tar extract: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// The extracted file will be named by the archive's internal name.
	// Rename to the canonical cache path.
	extracted := filepath.Join(filepath.Dir(destPath), filepath.Base(destPath))
	if extracted != destPath {
		if err := os.Rename(extracted, destPath); err != nil {
			os.Remove(tmpDest)
			return fmt.Errorf("rename extracted btf: %w", err)
		}
	}

	return nil
}

// detectDistro reads /etc/os-release to extract the distro ID and version ID.
func detectDistro() (id, version string, err error) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "", "", fmt.Errorf("open /etc/os-release: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		case strings.HasPrefix(line, "VERSION_ID="):
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	if id == "" {
		return "", "", fmt.Errorf("ID not found in /etc/os-release")
	}
	return id, version, nil
}

// kernelRelease reads the running kernel's release string from
// /proc/sys/kernel/osrelease (e.g. "5.4.0-182-generic").
func kernelRelease() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
