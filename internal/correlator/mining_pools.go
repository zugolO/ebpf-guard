// Package correlator provides mining pool detection for cryptominer detection.
package correlator

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// MiningPoolEntry represents a known mining pool entry.
type MiningPoolEntry struct {
	// Type is "cidr" or "domain"
	Type string
	// Value is the CIDR range or domain name
	Value string
	// IPNet is the parsed CIDR (only for Type == "cidr")
	IPNet *net.IPNet
	// Description is optional metadata
	Description string
}

// MiningPoolDetector maintains a list of known mining pools and provides
// detection capabilities for cryptomining activity.
type MiningPoolDetector struct {
	// pools is the list of known mining pool entries
	pools []MiningPoolEntry
	// domainSet for O(1) domain lookups
	domainSet map[string]struct{}
	// mu protects pools and domainSet for read/write access
	mu sync.RWMutex
	// reloadMu serializes concurrent Reload() calls so two simultaneous
	// SIGHUPs cannot race and leave detector in an inconsistent state.
	reloadMu sync.Mutex
	// filePath is the path to the mining pools file
	filePath string
	// lastReload tracks last reload time
	lastReload time.Time
}

// privateRanges are RFC-1918 / loopback ranges that must never appear in a
// mining-pool blocklist. Blocking these would drop internal traffic.
var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // loopback
		"::1/128",        // IPv6 loopback
		"10.0.0.0/8",     // RFC-1918
		"172.16.0.0/12",  // RFC-1918
		"192.168.0.0/16", // RFC-1918
		"fc00::/7",       // IPv6 unique local
	} {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateRanges = append(privateRanges, ipnet)
		}
	}
}

// isPrivateCIDR returns true if ipnet overlaps any RFC-1918 or loopback range.
func isPrivateCIDR(ipnet *net.IPNet) bool {
	for _, priv := range privateRanges {
		// Overlap: either network contains the other's base address.
		if priv.Contains(ipnet.IP) || ipnet.Contains(priv.IP) {
			return true
		}
	}
	return false
}

// NewMiningPoolDetector creates a new mining pool detector.
// It loads the initial pool list from the specified file.
func NewMiningPoolDetector(filePath string) (*MiningPoolDetector, error) {
	d := &MiningPoolDetector{
		pools:      make([]MiningPoolEntry, 0),
		domainSet:  make(map[string]struct{}),
		filePath:   filePath,
		lastReload: time.Time{},
	}

	if err := d.Reload(); err != nil {
		return nil, fmt.Errorf("mining_pools: initial load: %w", err)
	}

	return d, nil
}

// Reload reloads the mining pool list from the file.
// Concurrent calls are serialized via reloadMu so two simultaneous SIGHUPs
// cannot interleave writes to pools/domainSet.
func (d *MiningPoolDetector) Reload() error {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()

	file, err := os.Open(d.filePath)
	if err != nil {
		return fmt.Errorf("mining_pools: open file %s: %w", d.filePath, err)
	}
	defer file.Close()

	newPools := make([]MiningPoolEntry, 0)
	newDomains := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse line: "value    # optional comment"
		parts := strings.SplitN(line, "#", 2)
		value := strings.TrimSpace(parts[0])
		description := ""
		if len(parts) > 1 {
			description = strings.TrimSpace(parts[1])
		}

		if value == "" {
			continue
		}

		// Determine if it's a CIDR or domain
		entry := MiningPoolEntry{
			Value:       value,
			Description: description,
		}

		if strings.Contains(value, "/") {
			// Try to parse as CIDR
			_, ipnet, err := net.ParseCIDR(value)
			if err == nil {
				if isPrivateCIDR(ipnet) {
					// Warn and skip: blocking RFC-1918 / loopback would disrupt internal traffic
					// (operators must not accidentally include private ranges in mining-pool lists)
					continue
				}
				entry.Type = "cidr"
				entry.IPNet = ipnet
				newPools = append(newPools, entry)
			}
			// Skip invalid CIDRs silently (they might be placeholders)
		} else {
			// Treat as domain
			entry.Type = "domain"
			newPools = append(newPools, entry)
			newDomains[strings.ToLower(value)] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("mining_pools: scan file: %w", err)
	}

	// Atomically swap the data
	d.mu.Lock()
	d.pools = newPools
	d.domainSet = newDomains
	d.lastReload = time.Now()
	d.mu.Unlock()

	return nil
}

// IsMiningPoolIP checks if the given IP address belongs to a known mining pool.
func (d *MiningPoolDetector) IsMiningPoolIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, pool := range d.pools {
		if pool.Type == "cidr" && pool.IPNet != nil {
			if pool.IPNet.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// IsMiningPoolDomain checks if the given domain is a known mining pool.
func (d *MiningPoolDetector) IsMiningPoolDomain(domain string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Check exact match
	if _, exists := d.domainSet[strings.ToLower(domain)]; exists {
		return true
	}

	// Check if domain ends with known mining pool domain
	for poolDomain := range d.domainSet {
		if strings.HasSuffix(strings.ToLower(domain), "."+poolDomain) {
			return true
		}
	}

	return false
}

// IsMiningPool checks both IP and domain.
func (d *MiningPoolDetector) IsMiningPool(ipStr, domain string) bool {
	if domain != "" && d.IsMiningPoolDomain(domain) {
		return true
	}
	if ipStr != "" && d.IsMiningPoolIP(ipStr) {
		return true
	}
	return false
}

// GetPoolCount returns the number of loaded mining pool entries.
func (d *MiningPoolDetector) GetPoolCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.pools)
}

// GetDomainCount returns the number of loaded domain entries.
func (d *MiningPoolDetector) GetDomainCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.domainSet)
}

// GetLastReload returns the last reload timestamp.
func (d *MiningPoolDetector) GetLastReload() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastReload
}

// GetAllPools returns a copy of all loaded pool entries.
func (d *MiningPoolDetector) GetAllPools() []MiningPoolEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()

	poolsCopy := make([]MiningPoolEntry, len(d.pools))
	copy(poolsCopy, d.pools)
	return poolsCopy
}

// KnownMiningPorts is the list of TCP ports commonly used by mining pools.
var KnownMiningPorts = map[uint16]struct{}{
	3333:  {}, // Common stratum port
	4444:  {}, // Common stratum port
	8080:  {}, // Alternative HTTP port
	9999:  {}, // NiceHash
	14444: {}, // Common stratum SSL port
	20535: {}, // Mining pool port
	20536: {}, // Mining pool port
	45560: {}, // Mining pool port
	45700: {}, // Mining pool port
	45570: {}, // Mining pool port
	3334:  {}, // Alternative stratum
	45701: {}, // Mining pool port
	10001: {}, // Mining pool port
	10032: {}, // Mining pool port
	10128: {}, // Mining pool port
	10501: {}, // Mining pool port
	10502: {}, // Mining pool port
	11000: {}, // Mining pool port
	12000: {}, // Mining pool port
	13000: {}, // Mining pool port
	14000: {}, // Mining pool port
	15000: {}, // Mining pool port
	16000: {}, // Mining pool port
	17000: {}, // Mining pool port
	18000: {}, // Mining pool port
	19000: {}, // Mining pool port
	20000: {}, // Mining pool port
	21000: {}, // Mining pool port
	22000: {}, // Mining pool port
	23000: {}, // Mining pool port
	24000: {}, // Mining pool port
	25000: {}, // Mining pool port
	26000: {}, // Mining pool port
	27000: {}, // Mining pool port
	28000: {}, // Mining pool port
	29000: {}, // Mining pool port
	30000: {}, // Mining pool port
	31000: {}, // Mining pool port
	32000: {}, // Mining pool port
	33000: {}, // Mining pool port
	34000: {}, // Mining pool port
	35000: {}, // Mining pool port
	36000: {}, // Mining pool port
	37000: {}, // Mining pool port
	38000: {}, // Mining pool port
	39000: {}, // Mining pool port
	40000: {}, // Mining pool port
	41000: {}, // Mining pool port
	42000: {}, // Mining pool port
	43000: {}, // Mining pool port
	44000: {}, // Mining pool port
	45000: {}, // Mining pool port
	46000: {}, // Mining pool port
	47000: {}, // Mining pool port
	48000: {}, // Mining pool port
	49000: {}, // Mining pool port
	50000: {}, // Mining pool port
	51000: {}, // Mining pool port
	52000: {}, // Mining pool port
	53000: {}, // Mining pool port
	54000: {}, // Mining pool port
	55000: {}, // Mining pool port
	56000: {}, // Mining pool port
	57000: {}, // Mining pool port
	58000: {}, // Mining pool port
	59000: {}, // Mining pool port
	60000: {}, // Mining pool port
}

// IsKnownMiningPort checks if the port is a known mining pool port.
func IsKnownMiningPort(port uint16) bool {
	_, exists := KnownMiningPorts[port]
	return exists
}

// KnownMiningProcessNames is the list of process names commonly used by mining software.
var KnownMiningProcessNames = []string{
	"xmrig",
	"minerd",
	"cgminer",
	"bfgminer",
	"cpuminer",
	"ethminer",
	"nbminer",
	"teamredminer",
	"phoenixminer",
	"trexminer",
	"lolminer",
	"gminer",
	"excavator",
	"xmr-stak",
	"xmr-stak-rx",
	"xmr-stak-cpu",
	"xmr-stak-gpu",
	"minergate-cli",
	"minergate-miner",
	"nicehashminer",
	"ccminer",
	"sgminer",
	"vertminer",
	"yescryptminer",
	"scryptminer",
	"sha256miner",
	"equihashminer",
	"cryptonightminer",
	"randomxminer",
	"kawpowminer",
	"etchashminer",
	"progpowminer",
	"autolykosminer",
	"octopusminer",
	"firopowminer",
	"evrprogpowminer",
	"neoscryptminer",
	"lyra2rev2miner",
	"lyra2zminer",
	"x16rv2miner",
	"x16rminer",
	"mtpminer",
	"cuckoocycleminer",
	"cuckatoominer",
	"cuckaroominer",
	"beamhashminer",
	"zelhashminer",
	"grinprotonminer",
}

// IsKnownMiningProcess checks if the process name matches known mining software.
func IsKnownMiningProcess(comm string) bool {
	commLower := strings.ToLower(comm)
	for _, name := range KnownMiningProcessNames {
		if commLower == name || strings.Contains(commLower, name) {
			return true
		}
	}
	return false
}
