//go:build !linux

package bpf

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// BTFSource identifies how BTF type information was obtained.
type BTFSource string

const (
	BTFSourceLocal   BTFSource = "local"
	BTFSourceBTFHub  BTFSource = "btf_hub"
	BTFSourceHeaders BTFSource = "headers"
	BTFSourceNone    BTFSource = "none"
)

var btfSourceGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "ebpf_guard_btf_source",
	Help: "BTF source used by ebpf-guard (1 = active). Labels: local, btf_hub, headers, none.",
}, []string{"source"})

// RegisterBTFMetrics registers the BTF source gauge (no-op stub on non-Linux).
func RegisterBTFMetrics(reg prometheus.Registerer) {
	_ = reg.Register(btfSourceGauge)
}

// BTFResolutionConfig holds parameters for the BTF source resolution.
type BTFResolutionConfig struct {
	BTFPath                 string
	BTFHubEnabled           bool
	BTFHubCache             string
	FallbackReducedFeatures bool
}

// BTFResult holds the outcome of BTF source resolution.
type BTFResult struct {
	Source             BTFSource
	Path               string
	DisabledCollectors []string
}

// ResolveBTF is not supported on non-Linux platforms.
func ResolveBTF(_ BTFResolutionConfig) (*BTFResult, error) {
	return nil, fmt.Errorf("BTF resolution is only supported on Linux")
}
