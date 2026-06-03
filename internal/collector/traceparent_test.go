package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractTraceContext_ValidTraceparent(t *testing.T) {
	payload := "GET /api/v1/users HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n" +
		"Content-Type: application/json\r\n\r\n"

	tc := ExtractTraceContext([]byte(payload))
	require.NotNil(t, tc)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", tc.TraceID)
	assert.Equal(t, "00f067aa0ba902b7", tc.SpanID)
	assert.Equal(t, "01", tc.TraceFlags)
	assert.Empty(t, tc.TraceState)
}

func TestExtractTraceContext_WithTracestate(t *testing.T) {
	payload := "POST /checkout HTTP/1.1\r\n" +
		"Host: shop.example.com\r\n" +
		"traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\r\n" +
		"tracestate: vendor1=value1,vendor2=value2\r\n\r\n"

	tc := ExtractTraceContext([]byte(payload))
	require.NotNil(t, tc)
	assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", tc.TraceID)
	assert.Equal(t, "b7ad6b7169203331", tc.SpanID)
	assert.Equal(t, "01", tc.TraceFlags)
	assert.Equal(t, "vendor1=value1,vendor2=value2", tc.TraceState)
}

func TestExtractTraceContext_CaseInsensitiveHeader(t *testing.T) {
	payload := "GET / HTTP/1.1\r\n" +
		"Traceparent: 00-aabbccddeeff00112233445566778899-1122334455667788-00\r\n\r\n"

	tc := ExtractTraceContext([]byte(payload))
	require.NotNil(t, tc)
	assert.Equal(t, "aabbccddeeff00112233445566778899", tc.TraceID)
	assert.Equal(t, "1122334455667788", tc.SpanID)
	assert.Equal(t, "00", tc.TraceFlags)
}

func TestExtractTraceContext_NoTraceparent(t *testing.T) {
	payload := "GET /health HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: */*\r\n\r\n"

	tc := ExtractTraceContext([]byte(payload))
	assert.Nil(t, tc)
}

func TestExtractTraceContext_EmptyPayload(t *testing.T) {
	tc := ExtractTraceContext([]byte{})
	assert.Nil(t, tc)
}

func TestExtractTraceContext_BinaryPayload(t *testing.T) {
	// TLS handshake bytes or other binary data — should not panic or match
	binary := []byte{0x16, 0x03, 0x03, 0x00, 0xf1, 0x01, 0x00, 0x00}
	tc := ExtractTraceContext(binary)
	assert.Nil(t, tc)
}

func TestExtractTraceContext_MalformedTraceparent(t *testing.T) {
	// Wrong length trace ID
	payload := "GET / HTTP/1.1\r\ntraceparent: 00-tooshort-00f067aa0ba902b7-01\r\n\r\n"
	tc := ExtractTraceContext([]byte(payload))
	assert.Nil(t, tc)
}

func TestExtractTraceContext_gRPC(t *testing.T) {
	// gRPC metadata format (HTTP/2 headers in plaintext for testing)
	payload := "traceparent: 00-d4cda95b652f4a1592b449dd92ffda3b-6e0c63257de34c92-01\r\n" +
		"tracestate: rojo=00f067aa0ba902b7\r\n"

	tc := ExtractTraceContext([]byte(payload))
	require.NotNil(t, tc)
	assert.Equal(t, "d4cda95b652f4a1592b449dd92ffda3b", tc.TraceID)
	assert.Equal(t, "6e0c63257de34c92", tc.SpanID)
	assert.Equal(t, "rojo=00f067aa0ba902b7", tc.TraceState)
}

func TestExtractTraceContext_WhitespaceTolerance(t *testing.T) {
	// Extra spaces around colon and value (valid per HTTP spec)
	payload := "traceparent :  00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n"
	tc := ExtractTraceContext([]byte(payload))
	require.NotNil(t, tc)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", tc.TraceID)
}
