package main

import (
	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/config"
)

// lsmNetworkPolicy переводит enforcement.network_blocklist в форму менеджера карт
// net_block_* (Д14а, волна 8.6).
func lsmNetworkPolicy(cfg *config.Config) internalbpf.NetworkBlocklistConfig {
	return internalbpf.NetworkBlocklistConfig{
		Subnets: cfg.Enforcement.NetworkBlocklist.Subnets,
		Ports:   cfg.Enforcement.NetworkBlocklist.Ports,
	}
}
