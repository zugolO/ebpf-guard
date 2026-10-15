package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zugolO/ebpf-guard/internal/config"
)

func TestLSMNetworkPolicyCarriesConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Enforcement.NetworkBlocklist = config.NetworkBlocklistConfig{Subnets: []string{"10.0.0.0/8"}, Ports: []uint16{19777}}
	p := lsmNetworkPolicy(cfg)
	assert.Equal(t, []string{"10.0.0.0/8"}, p.Subnets)
	assert.Equal(t, []uint16{19777}, p.Ports)
}
