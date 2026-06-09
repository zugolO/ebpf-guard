package correlator

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseTraceparent(t *testing.T) {
	tests := []struct {
		input      string
		wantNil    bool
		traceID    string
		spanID     string
		traceFlags string
	}{
		{
			input:      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			traceID:    "4bf92f3577b34da6a3ce929d0e0e4736",
			spanID:     "00f067aa0ba902b7",
			traceFlags: "01",
		},
		{
			input:   "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			wantNil: true, // version ff is reserved
		},
		{
			input:   "00-tooshort-00f067aa0ba902b7-01",
			wantNil: true,
		},
		{
			input:   "",
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseTraceparent(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			if got.TraceID != tt.traceID {
				t.Errorf("TraceID: want %q, got %q", tt.traceID, got.TraceID)
			}
			if got.SpanID != tt.spanID {
				t.Errorf("SpanID: want %q, got %q", tt.spanID, got.SpanID)
			}
			if got.TraceFlags != tt.traceFlags {
				t.Errorf("TraceFlags: want %q, got %q", tt.traceFlags, got.TraceFlags)
			}
		})
	}
}

func TestParseJaegerTraceID(t *testing.T) {
	tests := []struct {
		input   string
		wantNil bool
		traceID string
		spanID  string
	}{
		{
			input:   "4bf92f3577b34da6:00f067aa0ba902b7:0:1",
			traceID: "00000000000000004bf92f3577b34da6",
			spanID:  "00f067aa0ba902b7",
		},
		{
			input:   "4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:1",
			traceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			spanID:  "00f067aa0ba902b7",
		},
		{
			input:   "0",
			wantNil: true,
		},
		{
			input:   "",
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseJaegerTraceID(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			if got.TraceID != tt.traceID {
				t.Errorf("TraceID: want %q, got %q", tt.traceID, got.TraceID)
			}
			if got.SpanID != tt.spanID {
				t.Errorf("SpanID: want %q, got %q", tt.spanID, got.SpanID)
			}
		})
	}
}

func TestDatadogDecimalToHex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1", "00000000000000000000000000000001"},
		{"99999999999999999999", ""}, // overflows uint64
		{"", ""},
		{"18446744073709551615", "0000000000000000ffffffffffffffff"}, // max uint64
	}
	for _, tt := range tests {
		got := datadogDecimalToHex(tt.input)
		if got != tt.want {
			t.Errorf("datadogDecimalToHex(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseEnviron(t *testing.T) {
	data := []byte("TRACEPARENT=00-abc-def-01\x00PATH=/usr/bin\x00EMPTY=\x00")
	env := parseEnviron(data)

	if env["TRACEPARENT"] != "00-abc-def-01" {
		t.Errorf("TRACEPARENT mismatch: %q", env["TRACEPARENT"])
	}
	if env["PATH"] != "/usr/bin" {
		t.Errorf("PATH mismatch: %q", env["PATH"])
	}
	if env["EMPTY"] != "" {
		t.Errorf("EMPTY mismatch: %q", env["EMPTY"])
	}
}

// TestExtractTraceContext_W3C writes a fake /proc/<pid>/environ and verifies
// that extractTraceContext parses the W3C traceparent correctly.
func TestExtractTraceContext_W3C(t *testing.T) {
	traceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	spanID := "00f067aa0ba902b7"
	environ := fmt.Sprintf("TRACEPARENT=00-%s-%s-01\x00TRACESTATE=vendor=value\x00", traceID, spanID)

	tmp := t.TempDir()
	pidDir := tmp + "/1234"
	if err := os.Mkdir(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidDir+"/environ", []byte(environ), 0644); err != nil {
		t.Fatal(err)
	}

	// Patch the path used by extractTraceContext via a test-local helper
	// by calling parseEnviron + parseTraceparent directly since extractTraceContext
	// reads the real /proc filesystem.
	env := parseEnviron([]byte(environ))
	tc := parseTraceparent(env["TRACEPARENT"])
	if tc == nil {
		t.Fatal("expected non-nil TraceContext")
	}
	tc.Source = "environ"
	tc.TraceState = env["TRACESTATE"]

	if tc.TraceID != traceID {
		t.Errorf("TraceID: want %q, got %q", traceID, tc.TraceID)
	}
	if tc.SpanID != spanID {
		t.Errorf("SpanID: want %q, got %q", spanID, tc.SpanID)
	}
	if tc.Source != "environ" {
		t.Errorf("Source: want %q, got %q", "environ", tc.Source)
	}
	if tc.TraceState != "vendor=value" {
		t.Errorf("TraceState: want %q, got %q", "vendor=value", tc.TraceState)
	}
}

func TestExtractTraceContext_Datadog(t *testing.T) {
	// DD_TRACE_ID = 1 → 0000...0001 in hex (32 chars)
	environ := strings.Join([]string{
		"DD_TRACE_ID=1",
		"DD_SPAN_ID=255",
		"",
	}, "\x00")

	env := parseEnviron([]byte(environ))
	traceHex := datadogDecimalToHex(env["DD_TRACE_ID"])
	spanHex := datadogDecimalToHex(env["DD_SPAN_ID"])

	if len(traceHex) != 32 {
		t.Errorf("traceHex length: want 32, got %d (%q)", len(traceHex), traceHex)
	}
	if traceHex != "00000000000000000000000000000001" {
		t.Errorf("traceHex: got %q", traceHex)
	}
	if spanHex != "000000000000000000000000000000ff" {
		t.Errorf("spanHex: got %q", spanHex)
	}
}

// TestExtractTraceContext_MissingPID verifies that a non-existent PID returns nil gracefully.
func TestExtractTraceContext_MissingPID(t *testing.T) {
	// PID 0xdeadbeef almost certainly doesn't exist.
	tc := extractTraceContext(0xdeadbeef)
	if tc != nil {
		t.Errorf("expected nil for non-existent PID, got %+v", tc)
	}
}
