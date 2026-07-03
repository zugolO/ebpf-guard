package tui

import "time"

// FleetConfig configures client-side fan-out polling of multiple agent REST
// APIs, merging their alert streams into a single Feed. This is the "client-
// side fan-out" design for fleet-wide observability: no central aggregation
// service is required, each agent is queried directly over its existing
// /api/v1 HTTP API.
//
// It lives in an untagged file so the type has a single definition shared by
// both the real fleet dashboard (fleet.go, built with -tags tui) and the stub
// (tui_disabled.go); only the RunFleet behavior differs by build tag.
type FleetConfig struct {
	// Endpoints are agent base URLs, e.g. "http://node-a:9090".
	Endpoints []string
	// Token is the bearer token sent to every endpoint (agents are expected
	// to share credentials in fleet mode; per-agent tokens are not supported).
	Token string
	// PollInterval controls how often each agent is polled for new alerts
	// and health. Defaults to 3s when zero.
	PollInterval time.Duration
}
