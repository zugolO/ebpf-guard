// Package api provides the embedded OpenAPI 3.0 specification for ebpf-guard.
package api

import _ "embed"

// OpenAPISpec is the OpenAPI 3.0 YAML specification, embedded at build time.
//
//go:embed openapi.yaml
var OpenAPISpec []byte
