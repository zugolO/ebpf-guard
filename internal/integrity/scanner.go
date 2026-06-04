// Package integrity provides startup integrity scanning for persistence techniques.
package integrity

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

var (
	// IntegrityFindingsTotal counts integrity check findings by type.
	IntegrityFindingsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_integrity_findings_total",
			Help: "Number of integrity findings detected at startup by check type",
		},
		[]string{"check"},
	)
)

// Finding represents a single integrity check finding.
type Finding struct {
	Check   string
	Path    string
	Details string
}

// Scanner performs startup integrity checks.
type Scanner struct {
	logger      *slog.Logger
	alertFunc   func(types.Alert)
	findings    []Finding
	checkWindow time.Duration
}

// Config holds scanner configuration.
type Config struct {
	// CheckWindow is the time window for "recent" modifications (default: 24h).
	CheckWindow time.Duration
	// AlertFunc is called when findings are detected.
	AlertFunc func(types.Alert)
}

// DefaultConfig returns default scanner configuration.
func DefaultConfig() Config {
	return Config{
		CheckWindow: 24 * time.Hour,
		AlertFunc:   nil,
	}
}

// NewScanner creates a new integrity scanner.
func NewScanner(logger *slog.Logger, cfg Config) *Scanner {
	if cfg.CheckWindow == 0 {
		cfg.CheckWindow = DefaultConfig().CheckWindow
	}

	return &Scanner{
		logger:      logger,
		alertFunc:   cfg.AlertFunc,
		findings:    make([]Finding, 0),
		checkWindow: cfg.CheckWindow,
	}
}

// Scan performs all integrity checks and returns findings.
func (s *Scanner) Scan() []Finding {
	s.logger.Info("starting integrity scan",
		slog.Duration("check_window", s.checkWindow),
	)

	// Check LD_PRELOAD hijack
	s.checkLDPreload()

	// Check cron directories for recent files
	s.checkCronDirs()

	// Check root user shell config files
	s.checkRootShellConfigs()

	// Check for anonymous executable memory regions
	s.checkAnonymousExecRegions()

	// Export metrics
	s.exportMetrics()

	// Log findings
	s.logFindings()

	// Send alerts if findings detected
	if len(s.findings) > 0 && s.alertFunc != nil {
		s.sendAlerts()
	}

	s.logger.Info("integrity scan complete",
		slog.Int("findings", len(s.findings)),
	)

	return s.findings
}

// checkLDPreload checks /etc/ld.so.preload for entries (LD_PRELOAD hijack technique).
func (s *Scanner) checkLDPreload() {
	const path = "/etc/ld.so.preload"

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logger.Warn("failed to read ld.so.preload",
				slog.String("path", path),
				slog.Any("error", err),
			)
		}
		return
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return
	}

	// File has content - potential LD_PRELOAD hijack
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		s.findings = append(s.findings, Finding{
			Check:   "ld_preload",
			Path:    path,
			Details: fmt.Sprintf("LD_PRELOAD entry: %s", line),
		})
	}
}

// checkCronDirs checks cron directories for recently modified files.
func (s *Scanner) checkCronDirs() {
	cronDirs := []string{
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron",
		"/var/spool/cron/crontabs",
	}

	cutoff := time.Now().Add(-s.checkWindow)

	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Directory might not exist, skip silently
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Skip system files that are typically present
			name := entry.Name()
			if name == "." || name == ".." {
				continue
			}

			if info.ModTime().After(cutoff) {
				s.findings = append(s.findings, Finding{
					Check:   "cron",
					Path:    filepath.Join(dir, name),
					Details: fmt.Sprintf("Modified: %s", info.ModTime().Format(time.RFC3339)),
				})
			}
		}
	}
}

// checkRootShellConfigs checks root's shell config files for recent modifications.
func (s *Scanner) checkRootShellConfigs() {
	rootHome := "/root"

	// Check if we're running as root or can access /root
	if _, err := os.Stat(rootHome); err != nil {
		// Can't access /root, skip
		return
	}

	configFiles := []string{
		".bashrc",
		".profile",
		".bash_profile",
		".bash_login",
		".zshrc",
		".zprofile",
	}

	cutoff := time.Now().Add(-s.checkWindow)

	for _, filename := range configFiles {
		path := filepath.Join(rootHome, filename)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.ModTime().After(cutoff) {
			// Read file to check for suspicious additions
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			details := fmt.Sprintf("Modified: %s", info.ModTime().Format(time.RFC3339))

			// Check for common persistence patterns
			contentStr := string(content)
			if strings.Contains(contentStr, "nc ") || strings.Contains(contentStr, "netcat") {
				details += "; contains netcat reference"
			}
			if strings.Contains(contentStr, "curl") && strings.Contains(contentStr, "| sh") {
				details += "; contains curl | sh pattern"
			}
			if strings.Contains(contentStr, "wget") && strings.Contains(contentStr, "| sh") {
				details += "; contains wget | sh pattern"
			}

			s.findings = append(s.findings, Finding{
				Check:   "bashrc",
				Path:    path,
				Details: details,
			})
		}
	}
}

// checkAnonymousExecRegions checks /proc/*/maps for anonymous executable regions.
// These can indicate shellcode injection or memory-resident malware.
func (s *Scanner) checkAnonymousExecRegions() {
	procDir := "/proc"

	entries, err := os.ReadDir(procDir)
	if err != nil {
		s.logger.Warn("failed to read /proc", slog.Any("error", err))
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID (numeric)
		pid := entry.Name()
		if _, err := fmt.Sscanf(pid, "%d", new(int)); err != nil {
			continue
		}

		if finding, ok := s.checkPIDAnonymousRegions(procDir, pid); ok {
			s.findings = append(s.findings, finding)
		}
	}
}

// checkPIDAnonymousRegions scans /proc/<pid>/maps for a single process and
// returns the first anonymous executable region found. Extracted into a
// dedicated function so defer file.Close() fires before the next iteration
// rather than accumulating open handles until checkAnonymousExecRegions returns.
func (s *Scanner) checkPIDAnonymousRegions(procDir, pid string) (Finding, bool) {
	mapsPath := filepath.Join(procDir, pid, "maps")
	file, err := os.Open(mapsPath)
	if err != nil {
		// Process might have exited, skip
		return Finding{}, false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Parse maps line format:
		// address perms offset dev inode pathname
		// Example: 7f8b4c000000-7f8b4c021000 rw-p 00000000 00:00 0
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Check permissions: rwxp means read-write-execute-private
		// Anonymous regions have inode 0 and no pathname
		perms := fields[1]
		if len(perms) < 4 {
			continue
		}

		// Check for executable permission (x) and anonymous (no pathname)
		isExecutable := perms[2] == 'x'
		isAnonymous := len(fields) == 5 || (len(fields) >= 6 && fields[5] == "0")

		if isExecutable && isAnonymous {
			commPath := filepath.Join(procDir, pid, "comm")
			comm, _ := os.ReadFile(commPath)
			commStr := strings.TrimSpace(string(comm))
			if commStr == "" {
				commStr = "unknown"
			}

			return Finding{
				Check:   "anon_exec",
				Path:    mapsPath,
				Details: fmt.Sprintf("PID %s (%s): anonymous executable region: %s", pid, commStr, fields[0]),
			}, true
		}
	}
	return Finding{}, false
}

// exportMetrics exports findings as Prometheus metrics.
func (s *Scanner) exportMetrics() {
	counts := make(map[string]int)
	for _, finding := range s.findings {
		counts[finding.Check]++
	}

	// Set metrics for all check types (zero for no findings)
	checkTypes := []string{"ld_preload", "cron", "bashrc", "anon_exec"}
	for _, checkType := range checkTypes {
		count := counts[checkType]
		IntegrityFindingsTotal.WithLabelValues(checkType).Set(float64(count))
	}
}

// logFindings logs all findings at appropriate log levels.
func (s *Scanner) logFindings() {
	if len(s.findings) == 0 {
		s.logger.Info("integrity scan: no findings")
		return
	}

	for _, finding := range s.findings {
		s.logger.Warn("integrity finding detected",
			slog.String("check", finding.Check),
			slog.String("path", finding.Path),
			slog.String("details", finding.Details),
		)
	}
}

// sendAlerts sends alerts for detected findings.
func (s *Scanner) sendAlerts() {
	// Group findings by check type for consolidated alerts
	grouped := make(map[string][]Finding)
	for _, finding := range s.findings {
		grouped[finding.Check] = append(grouped[finding.Check], finding)
	}

	for checkType, findings := range grouped {
		var details strings.Builder
		details.WriteString(fmt.Sprintf("Detected %d %s finding(s):\n", len(findings), checkType))
		for i, finding := range findings {
			if i >= 5 {
				details.WriteString(fmt.Sprintf("... and %d more\n", len(findings)-5))
				break
			}
			details.WriteString(fmt.Sprintf("- %s: %s\n", finding.Path, finding.Details))
		}

		alert := types.Alert{
			RuleID:    fmt.Sprintf("integrity_%s", checkType),
			RuleName:  fmt.Sprintf("Integrity Check: %s", checkType),
			Severity:  types.SeverityWarning,
			Message:   details.String(),
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"check_type":  checkType,
				"description": fmt.Sprintf("Startup integrity scan detected %s persistence technique", checkType),
				"findings":    findings,
			},
		}

		s.alertFunc(alert)
	}
}

// GetFindings returns all findings from the last scan.
func (s *Scanner) GetFindings() []Finding {
	return s.findings
}

// GetFindingsByCheck returns findings filtered by check type.
func (s *Scanner) GetFindingsByCheck(checkType string) []Finding {
	var result []Finding
	for _, finding := range s.findings {
		if finding.Check == checkType {
			result = append(result, finding)
		}
	}
	return result
}
