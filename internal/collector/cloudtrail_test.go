package collector

import (
	"compress/gzip"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ── parseCloudTrailJSON ───────────────────────────────────────────────────────

func TestParseCloudTrailJSON_Valid(t *testing.T) {
	payload := `{
		"Records": [
			{
				"eventVersion": "1.08",
				"eventID": "abc-123",
				"eventTime": "2024-01-15T10:00:00Z",
				"eventSource": "iam.amazonaws.com",
				"eventName": "AssumeRole",
				"awsRegion": "us-east-1",
				"sourceIPAddress": "203.0.113.1",
				"userAgent": "aws-cli/2.0",
				"userIdentity": {
					"type": "IAMUser",
					"principalId": "AIDA123",
					"arn": "arn:aws:iam::123456789:user/alice",
					"userName": "alice"
				},
				"resources": [
					{"ARN": "arn:aws:iam::123456789:role/admin", "type": "AWS::IAM::Role"}
				]
			}
		]
	}`

	events, err := parseCloudTrailJSON([]byte(payload))
	require.NoError(t, err)
	require.Len(t, events, 1)

	e := events[0]
	assert.Equal(t, types.EventCloudAudit, e.Type)
	require.NotNil(t, e.CloudAudit)
	assert.Equal(t, "aws", e.CloudAudit.Provider)
	assert.Equal(t, "iam", e.CloudAudit.Service) // ".amazonaws.com" stripped
	assert.Equal(t, "AssumeRole", e.CloudAudit.Action)
	assert.Equal(t, "arn:aws:iam::123456789:user/alice", e.CloudAudit.Principal)
	assert.Equal(t, "arn:aws:iam::123456789:role/admin", e.CloudAudit.ResourceARN)
	assert.Equal(t, "203.0.113.1", e.CloudAudit.SourceIP)
	assert.Equal(t, "aws-cli/2.0", e.CloudAudit.UserAgent)
	assert.Equal(t, "us-east-1", e.CloudAudit.Region)
	assert.Equal(t, "abc-123", e.CloudAudit.EventID)
}

func TestParseCloudTrailJSON_MultipleRecords(t *testing.T) {
	payload := `{"Records": [
		{"eventID":"1","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-west-2",
		 "sourceIPAddress":"1.2.3.4","userAgent":"s3cmd","userIdentity":{"arn":"arn:aws:iam::1:user/a"}},
		{"eventID":"2","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","awsRegion":"eu-west-1",
		 "sourceIPAddress":"5.6.7.8","userAgent":"boto3","userIdentity":{"principalId":"AIDA456"}}
	]}`

	events, err := parseCloudTrailJSON([]byte(payload))
	require.NoError(t, err)
	assert.Len(t, events, 2)
}

func TestParseCloudTrailJSON_EmptyRecords(t *testing.T) {
	events, err := parseCloudTrailJSON([]byte(`{"Records": []}`))
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestParseCloudTrailJSON_InvalidJSON(t *testing.T) {
	_, err := parseCloudTrailJSON([]byte(`{invalid`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloudtrail")
}

func TestParseCloudTrailJSON_WithErrorCode(t *testing.T) {
	payload := `{"Records": [{
		"eventID":"err-1","eventSource":"iam.amazonaws.com","eventName":"CreateUser",
		"awsRegion":"us-east-1","sourceIPAddress":"1.2.3.4","userAgent":"cli",
		"errorCode":"AccessDenied",
		"userIdentity":{"arn":"arn:aws:iam::1:user/hacker"}
	}]}`

	events, err := parseCloudTrailJSON([]byte(payload))
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "AccessDenied", events[0].CloudAudit.ErrorCode)
}

func TestParseCloudTrailJSON_PrincipalFallback(t *testing.T) {
	// When ARN is empty, fall back to PrincipalID, then UserName
	payload := `{"Records": [{
		"eventID":"p1","eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity",
		"awsRegion":"us-east-1","sourceIPAddress":"1.1.1.1","userAgent":"cli",
		"userIdentity":{"type":"IAMUser","principalId":"AIDA789","arn":"","userName":"bob"}
	}]}`

	events, err := parseCloudTrailJSON([]byte(payload))
	require.NoError(t, err)
	require.Len(t, events, 1)
	// ARN is empty → should fall back to principalId "AIDA789"
	assert.Equal(t, "AIDA789", events[0].CloudAudit.Principal)
}

// ── parseSQSMessageBody ───────────────────────────────────────────────────────

func TestParseSQSMessageBody_DirectNotification(t *testing.T) {
	body := `{"s3Bucket":"my-trail-bucket","s3ObjectKey":["AWSLogs/123/CloudTrail/us-east-1/2024/01/01/log.json.gz"]}`

	bucket, keys, err := parseSQSMessageBody(body)
	require.NoError(t, err)
	assert.Equal(t, "my-trail-bucket", bucket)
	require.Len(t, keys, 1)
	assert.Contains(t, keys[0], "CloudTrail")
}

func TestParseSQSMessageBody_SNSWrapped(t *testing.T) {
	inner := `{"s3Bucket":"wrapped-bucket","s3ObjectKey":["path/to/file.json.gz"]}`
	outer, _ := json.Marshal(map[string]string{"Type": "Notification", "Message": inner})

	bucket, keys, err := parseSQSMessageBody(string(outer))
	require.NoError(t, err)
	assert.Equal(t, "wrapped-bucket", bucket)
	require.Len(t, keys, 1)
}

func TestParseSQSMessageBody_InvalidJSON(t *testing.T) {
	_, _, err := parseSQSMessageBody(`{not valid json`)
	require.Error(t, err)
}

func TestParseSQSMessageBody_MultipleKeys(t *testing.T) {
	body := `{"s3Bucket":"logs","s3ObjectKey":["file1.json.gz","file2.json.gz","file3.json.gz"]}`

	_, keys, err := parseSQSMessageBody(body)
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

// ── inferAWSRegion ────────────────────────────────────────────────────────────

func TestInferAWSRegion_Standard(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://sqs.us-east-1.amazonaws.com/123456789/my-queue", "us-east-1"},
		{"https://sqs.eu-west-1.amazonaws.com/123456789/my-queue", "eu-west-1"},
		{"https://sqs.ap-southeast-2.amazonaws.com/123456789/my-queue", "ap-southeast-2"},
		{"https://sqs.us-gov-east-1.amazonaws.com/123456789/my-queue", "us-gov-east-1"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := inferAWSRegion(tt.url)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestInferAWSRegion_Fallback(t *testing.T) {
	// Invalid URLs fall back to us-east-1
	assert.Equal(t, "us-east-1", inferAWSRegion("not-a-url"))
	assert.Equal(t, "us-east-1", inferAWSRegion(""))
	assert.Equal(t, "us-east-1", inferAWSRegion("https://example.com/queue"))
}

// ── NewCloudTrailCollector ────────────────────────────────────────────────────

func TestNewCloudTrailCollector_Defaults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.CloudTrailCollectorConfig{
		SQSQueueURL: "https://sqs.us-east-1.amazonaws.com/123456789/queue",
		Region:      "us-east-1",
	}
	c := NewCloudTrailCollector(logger, cfg, StrategyDrop)
	require.NotNil(t, c)
	assert.Equal(t, "cloudtrail", c.Name())
}

func TestNewCloudTrailCollector_MaxMessagesClamp(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.CloudTrailCollectorConfig{
		SQSQueueURL: "https://sqs.us-east-1.amazonaws.com/123456789/queue",
		MaxMessages: 100, // exceeds SQS maximum of 10
	}
	c := NewCloudTrailCollector(logger, cfg, StrategyDrop)
	// MaxMessages should be clamped to 10
	assert.Equal(t, 10, c.cfg.MaxMessages)
}

func TestNewCloudTrailCollector_InvalidPollInterval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.CloudTrailCollectorConfig{
		SQSQueueURL:  "https://sqs.us-east-1.amazonaws.com/123456789/queue",
		PollInterval: "invalid-duration",
	}
	c := NewCloudTrailCollector(logger, cfg, StrategyDrop)
	// Should use default 10s
	assert.Equal(t, 10*time.Second, c.pollInterval)
}

// ── S3 HTTP mock test ─────────────────────────────────────────────────────────

// TestCloudTrailCollector_FetchAndParseS3 verifies that fetchAndParseS3 correctly
// downloads and decompresses a gzipped CloudTrail JSON file from a mock S3 server.
func TestCloudTrailCollector_FetchAndParseS3(t *testing.T) {
	// Build a mock CloudTrail JSON payload
	payload := `{"Records":[{
		"eventID":"test-fetch-1",
		"eventSource":"s3.amazonaws.com",
		"eventName":"PutObject",
		"awsRegion":"us-east-1",
		"sourceIPAddress":"10.0.0.1",
		"userAgent":"test-agent",
		"userIdentity":{"arn":"arn:aws:iam::123:user/test"}
	}]}`

	// Gzip-compress the payload
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte(payload))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	gzipData := buf.Bytes()

	// Mock S3 server — fetchAndParseS3 constructs the URL itself, so we use the
	// redirect RoundTripper to intercept the call regardless of the URL.
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusOK)
		w.Write(gzipData)
	}))
	defer s3Server.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.CloudTrailCollectorConfig{
		SQSQueueURL: s3Server.URL,
		Region:      "us-east-1",
	}
	c := NewCloudTrailCollector(logger, cfg, StrategyDrop)
	c.client = newRedirectClient(s3Server)

	creds := awsCreds{
		AccessKeyID:     "AKIATEST",
		SecretAccessKey: "test-secret",
	}

	ctx := context.Background()
	events, err := c.fetchAndParseS3(ctx, creds, "test-bucket", "test-key.json.gz")
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "test-fetch-1", events[0].CloudAudit.EventID)
	assert.Equal(t, "PutObject", events[0].CloudAudit.Action)
}

// TestCloudTrailCollector_FetchAndParseS3_Non200 verifies that HTTP errors from
// S3 are correctly returned as errors.
func TestCloudTrailCollector_FetchAndParseS3_Non200(t *testing.T) {
	s3Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, "Access Denied")
	}))
	defer s3Server.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.CloudTrailCollectorConfig{Region: "us-east-1"}
	c := NewCloudTrailCollector(logger, cfg, StrategyDrop)
	c.client = newRedirectClient(s3Server)

	creds := awsCreds{AccessKeyID: "AKIATEST", SecretAccessKey: "secret"}
	ctx := context.Background()
	_, err := c.fetchAndParseS3(ctx, creds, "bucket", "key.json.gz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// ── SQS HTTP mock test ────────────────────────────────────────────────────────

// TestCloudTrailCollector_SQSReceive verifies that sqsReceive correctly parses
// the SQS XML response from a mock server.
func TestCloudTrailCollector_SQSReceive(t *testing.T) {
	sqsResponse := `<?xml version="1.0"?>
<ReceiveMessageResponse>
  <ReceiveMessageResult>
    <Message>
      <MessageId>msg-001</MessageId>
      <ReceiptHandle>handle-001</ReceiptHandle>
      <Body>{"s3Bucket":"trail-bucket","s3ObjectKey":["file.json.gz"]}</Body>
    </Message>
  </ReceiveMessageResult>
</ReceiveMessageResponse>`

	sqsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, sqsResponse)
	}))
	defer sqsServer.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.CloudTrailCollectorConfig{
		SQSQueueURL: sqsServer.URL, // already points to the test server
		Region:      "us-east-1",
		MaxMessages: 1,
	}
	c := NewCloudTrailCollector(logger, cfg, StrategyDrop)
	// No redirect needed — SQSQueueURL already points to sqsServer.URL directly.

	creds := awsCreds{AccessKeyID: "AKIATEST", SecretAccessKey: "secret"}
	ctx := context.Background()
	msgs, err := c.sqsReceive(ctx, creds)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, "msg-001", msgs[0].MessageID)
	assert.Equal(t, "handle-001", msgs[0].ReceiptHandle)
}

// TestCloudTrailCollector_SQSReceive_Non200 verifies error handling on non-200 response.
func TestCloudTrailCollector_SQSReceive_Non200(t *testing.T) {
	sqsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Service Unavailable")
	}))
	defer sqsServer.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.CloudTrailCollectorConfig{SQSQueueURL: sqsServer.URL, Region: "us-east-1"}
	c := NewCloudTrailCollector(logger, cfg, StrategyDrop)

	creds := awsCreds{AccessKeyID: "AKIATEST", SecretAccessKey: "secret"}
	_, err := c.sqsReceive(context.Background(), creds)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// Ensure sqsReceiveResponse can be parsed correctly (smoke test for XML struct).
func TestSQSReceiveResponse_XMLParsing(t *testing.T) {
	raw := `<?xml version="1.0"?>
<ReceiveMessageResponse>
  <ReceiveMessageResult>
    <Message>
      <MessageId>id-1</MessageId>
      <ReceiptHandle>rh-1</ReceiptHandle>
      <Body>body text</Body>
    </Message>
    <Message>
      <MessageId>id-2</MessageId>
      <ReceiptHandle>rh-2</ReceiptHandle>
      <Body>body 2</Body>
    </Message>
  </ReceiveMessageResult>
</ReceiveMessageResponse>`

	var result sqsReceiveResponse
	err := xml.NewDecoder(bytes.NewReader([]byte(raw))).Decode(&result)
	require.NoError(t, err)
	assert.Len(t, result.Result.Messages, 2)
	assert.Equal(t, "id-1", result.Result.Messages[0].MessageID)
}

// ── awsDeriveSigningKey ───────────────────────────────────────────────────────

func TestAWSDeriveSigningKey_Deterministic(t *testing.T) {
	key1 := awsDeriveSigningKey("secret", "20240101", "us-east-1", "s3")
	key2 := awsDeriveSigningKey("secret", "20240101", "us-east-1", "s3")
	assert.Equal(t, key1, key2)
}

func TestAWSDeriveSigningKey_DifferentSecrets(t *testing.T) {
	key1 := awsDeriveSigningKey("secret1", "20240101", "us-east-1", "s3")
	key2 := awsDeriveSigningKey("secret2", "20240101", "us-east-1", "s3")
	assert.NotEqual(t, key1, key2)
}

func TestAWSDeriveSigningKey_DifferentRegions(t *testing.T) {
	key1 := awsDeriveSigningKey("secret", "20240101", "us-east-1", "s3")
	key2 := awsDeriveSigningKey("secret", "20240101", "eu-west-1", "s3")
	assert.NotEqual(t, key1, key2)
}

// ── awsSHA256Hex ──────────────────────────────────────────────────────────────

func TestAWSSHA256Hex_Empty(t *testing.T) {
	// SHA-256 of empty string is well-known
	result := awsSHA256Hex("")
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result)
	assert.Len(t, result, 64)
}

func TestAWSSHA256Hex_KnownInput(t *testing.T) {
	result := awsSHA256Hex("hello world")
	assert.Len(t, result, 64)
	// Just verify it's hex
	for _, c := range result {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
	}
}

// ── Start/Stop lifecycle ──────────────────────────────────────────────────────

// TestCloudTrailCollector_StartStop verifies the lifecycle: the collector starts,
// the context is cancelled, and it shuts down without hanging.
func TestCloudTrailCollector_StartStop(t *testing.T) {
	// Mock SQS server that returns empty results — the collector polls SQSQueueURL
	// which already resolves to this server, so no redirect needed.
	sqsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0"?><ReceiveMessageResponse><ReceiveMessageResult/></ReceiveMessageResponse>`)
	}))
	defer sqsServer.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.CloudTrailCollectorConfig{
		SQSQueueURL:  sqsServer.URL,
		Region:       "us-east-1",
		PollInterval: "50ms",
		MaxMessages:  1,
	}
	// Inject static credentials to bypass the real IMDS credential resolution.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")

	c := NewCloudTrailCollector(logger, cfg, StrategyDrop)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	out := make(chan types.Event, 64)
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx, out)
	}()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("CloudTrailCollector.Start did not return after ctx cancel")
	}
}
