package correlator

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// VerifyRuleChecksums reads a sha256sum-format checksum file and verifies each
// listed rule file. It returns an error if any file is missing, tampered, or
// if the checksum file itself cannot be read.
//
// The checksum file format is identical to sha256sum(1) output:
//
//	<hex-sha256>  <filename>
//
// Filenames in the checksum file are treated as relative to rulesDir.
func VerifyRuleChecksums(rulesDir, checksumFile string) error {
	if checksumFile == "" {
		checksumFile = filepath.Join(rulesDir, "checksums.sha256")
	}

	expected, err := readChecksumFile(checksumFile)
	if err != nil {
		return fmt.Errorf("correlator: read checksum file %s: %w", checksumFile, err)
	}

	if len(expected) == 0 {
		return fmt.Errorf("correlator: checksum file %s is empty", checksumFile)
	}

	var errs []string
	for name, wantHex := range expected {
		path := filepath.Join(rulesDir, name)
		gotHex, err := sha256File(path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if gotHex != wantHex {
			errs = append(errs, fmt.Sprintf("%s: checksum mismatch (got %s, want %s)", name, gotHex, wantHex))
		}
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("correlator: rule integrity check failed (%d error(s)): %s",
			len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// ComputeRuleFileChecksums computes SHA-256 digests for all .yaml/.yml files
// in rulesDir. Returns a map from filename (basename only) to hex digest.
func ComputeRuleFileChecksums(rulesDir string) (map[string]string, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("correlator: read rules dir: %w", err)
	}

	checksums := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		digest, err := sha256File(filepath.Join(rulesDir, e.Name()))
		if err != nil {
			return nil, err
		}
		checksums[e.Name()] = digest
	}
	return checksums, nil
}

// WriteChecksumFile writes checksums to path in sha256sum(1) format.
// Files are written in sorted order for reproducibility.
func WriteChecksumFile(path string, checksums map[string]string) error {
	names := make([]string, 0, len(checksums))
	for n := range checksums {
		names = append(names, n)
	}
	sort.Strings(names)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("correlator: create checksum file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, name := range names {
		fmt.Fprintf(w, "%s  %s\n", checksums[name], name)
	}
	return w.Flush()
}

// sha256File computes the SHA-256 hex digest of a file.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readChecksumFile parses a sha256sum(1)-format file into a name→hex map.
func readChecksumFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// sha256sum output: "<64-char-hex>  <filename>" (two spaces, BSD variant uses one space + *)
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("line %d: malformed entry %q", lineNum, line)
		}
		digest := parts[0]
		if len(digest) != 64 {
			return nil, fmt.Errorf("line %d: invalid SHA-256 digest length %d", lineNum, len(digest))
		}
		// parts[1] may be "" (GNU two-space) and parts[2] the filename, or
		// parts[1] may start with " " or "*" and be trimmed filename.
		name := strings.TrimLeft(strings.Join(parts[1:], " "), " *")
		name = filepath.Base(name) // strip any directory component
		result[name] = digest
	}
	return result, scanner.Err()
}
