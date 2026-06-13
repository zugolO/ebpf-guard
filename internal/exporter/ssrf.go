// Package exporter provides shared SSRF URL validation for all HTTP-based notifiers.
package exporter

import (
	"fmt"
	"net"
	"net/url"
)

// privateRanges lists RFC-1918 and other private IPv4/IPv6 ranges that are
// blocked when strict SSRF prevention is enabled.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",  // RFC 6598 shared address space
		"169.254.0.0/16", // link-local (IPv4)
		"fc00::/7",       // unique local (IPv6)
		"fe80::/10",      // link-local (IPv6)
	}
	for _, c := range cidrs {
		_, ipNet, _ := net.ParseCIDR(c)
		privateRanges = append(privateRanges, ipNet)
	}
}

// ValidateWebhookURL rejects URLs that could be used for SSRF.
// It enforces http/https scheme and blocks loopback and link-local addresses.
//
// When strictSSRF is true it also blocks RFC-1918 private IP ranges.
// Set strictSSRF=false for in-cluster deployments where the target is a
// cluster-internal service (e.g. http://alertmanager:9093).
func ValidateWebhookURL(rawURL string, strictSSRF bool) error {
	if rawURL == "" {
		return fmt.Errorf("webhook URL must not be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("webhook URL scheme %q is not allowed; use http or https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook URL must have a host")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("webhook URL must not point to a loopback address")
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("webhook URL must not point to a link-local address")
		}
		if strictSSRF {
			for _, cidr := range privateRanges {
				if cidr.Contains(ip) {
					return fmt.Errorf("webhook URL points to a private IP %s (blocked by strict SSRF prevention)", ip)
				}
			}
		}
	}
	return nil
}
