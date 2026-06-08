// Package collector provides eBPF-based and cloud event collection.
package collector

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// CloudTrailCollector polls an SQS queue for AWS CloudTrail events.
// CloudTrail delivers log files to S3 and sends SNS notifications to SQS.
// This collector polls SQS, fetches the S3 log objects, and converts events to types.Event.
type CloudTrailCollector struct {
	logger       *slog.Logger
	cfg          config.CloudTrailCollectorConfig
	client       *http.Client
	dropLogger   *dropLogger
	strategy     BackpressureStrategy
	pollInterval time.Duration
	region       string
	creds        *awsCredCache
	stopped      chan struct{}
}

// NewCloudTrailCollector creates a new AWS CloudTrail collector.
func NewCloudTrailCollector(logger *slog.Logger, cfg config.CloudTrailCollectorConfig, strategy BackpressureStrategy) *CloudTrailCollector {
	d, err := time.ParseDuration(cfg.PollInterval)
	if err != nil || d <= 0 {
		d = 10 * time.Second
	}
	if cfg.MaxMessages <= 0 || cfg.MaxMessages > 10 {
		cfg.MaxMessages = 10
	}
	region := cfg.Region
	if region == "" {
		region = inferAWSRegion(cfg.SQSQueueURL)
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	return &CloudTrailCollector{
		logger:       logger.With("component", "cloudtrail_collector"),
		cfg:          cfg,
		client:       httpClient,
		dropLogger:   newDropLogger(5 * time.Second),
		strategy:     strategy,
		pollInterval: d,
		region:       region,
		creds:        newAWSCredCache(httpClient),
		stopped:      make(chan struct{}),
	}
}

// Name returns the collector name.
func (c *CloudTrailCollector) Name() string { return "cloudtrail" }

// Close waits for the collector to stop.
func (c *CloudTrailCollector) Close() error {
	<-c.stopped
	return nil
}

// Start begins polling SQS for CloudTrail events. Blocks until ctx is cancelled.
func (c *CloudTrailCollector) Start(ctx context.Context, out chan<- types.Event) error {
	defer close(c.stopped)
	c.logger.Info("starting AWS CloudTrail collector",
		slog.String("queue", c.cfg.SQSQueueURL),
		slog.String("region", c.region),
	)

	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("stopping AWS CloudTrail collector")
			return nil
		case <-ticker.C:
			if err := c.poll(ctx, out); err != nil {
				c.logger.Warn("cloudtrail: poll error", slog.Any("error", err))
			}
		}
	}
}

// poll fetches SQS messages, downloads referenced S3 objects, and emits events.
func (c *CloudTrailCollector) poll(ctx context.Context, out chan<- types.Event) error {
	creds, err := c.creds.get(ctx)
	if err != nil {
		return fmt.Errorf("resolve credentials: %w", err)
	}

	msgs, err := c.sqsReceive(ctx, creds)
	if err != nil {
		return fmt.Errorf("sqs receive: %w", err)
	}

	for _, msg := range msgs {
		events, deleteErr := c.processMessage(ctx, creds, msg)
		if deleteErr != nil {
			c.logger.Warn("cloudtrail: failed to process message",
				slog.String("message_id", msg.MessageID),
				slog.Any("error", deleteErr))
			continue
		}
		for _, e := range events {
			sendEvent(ctx, out, e, c.strategy, func() {
				c.dropLogger.record(c.logger, c.Name())
			})
		}
		// Acknowledge and delete processed message.
		if err := c.sqsDelete(ctx, creds, msg.ReceiptHandle); err != nil {
			c.logger.Warn("cloudtrail: failed to delete SQS message",
				slog.String("receipt_handle", msg.ReceiptHandle),
				slog.Any("error", err))
		}
	}
	return nil
}

// processMessage extracts CloudTrail events from a single SQS message.
func (c *CloudTrailCollector) processMessage(ctx context.Context, creds awsCreds, msg sqsMessage) ([]types.Event, error) {
	// Parse message body: may be an SNS notification wrapper or direct S3 notification.
	bucket, keys, err := parseSQSMessageBody(msg.Body)
	if err != nil {
		return nil, fmt.Errorf("parse message body: %w", err)
	}

	var events []types.Event
	for _, key := range keys {
		// Determine the S3 region from the bucket (use collector region as default).
		fileEvents, err := c.fetchAndParseS3(ctx, creds, bucket, key)
		if err != nil {
			c.logger.Warn("cloudtrail: s3 fetch error",
				slog.String("bucket", bucket),
				slog.String("key", key),
				slog.Any("error", err))
			continue
		}
		events = append(events, fileEvents...)
	}
	return events, nil
}

// fetchAndParseS3 downloads a CloudTrail log file from S3 and parses it.
func (c *CloudTrailCollector) fetchAndParseS3(ctx context.Context, creds awsCreds, bucket, key string) ([]types.Event, error) {
	endpoint := fmt.Sprintf("https://s3.%s.amazonaws.com/%s/%s", c.region, bucket, key)
	req, err := awsSignRequest(ctx, "GET", endpoint, "", c.region, "s3", creds)
	if err != nil {
		return nil, fmt.Errorf("sign s3 request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3 get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("s3 get status %d: %s", resp.StatusCode, body)
	}

	// CloudTrail files are gzip-compressed.
	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(io.LimitReader(reader, 50*1024*1024)) // 50 MB max
	if err != nil {
		return nil, fmt.Errorf("read s3 body: %w", err)
	}

	return parseCloudTrailJSON(data)
}

// ── SQS helpers ──────────────────────────────────────────────────────────────

type sqsMessage struct {
	MessageID     string
	ReceiptHandle string
	Body          string
}

// sqsReceiveResponse is used for XML parsing of ReceiveMessage responses.
type sqsReceiveResponse struct {
	XMLName xml.Name `xml:"ReceiveMessageResponse"`
	Result  struct {
		Messages []struct {
			MessageID     string `xml:"MessageId"`
			ReceiptHandle string `xml:"ReceiptHandle"`
			Body          string `xml:"Body"`
		} `xml:"Message"`
	} `xml:"ReceiveMessageResult"`
}

func (c *CloudTrailCollector) sqsReceive(ctx context.Context, creds awsCreds) ([]sqsMessage, error) {
	params := url.Values{}
	params.Set("Action", "ReceiveMessage")
	params.Set("MaxNumberOfMessages", fmt.Sprintf("%d", c.cfg.MaxMessages))
	params.Set("WaitTimeSeconds", "0")
	params.Set("Version", "2012-11-05")

	req, err := awsSignRequest(ctx, "POST", c.cfg.SQSQueueURL, params.Encode(), c.region, "sqs", creds)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("sqs receive status %d: %s", resp.StatusCode, body)
	}

	var result sqsReceiveResponse
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode sqs response: %w", err)
	}

	msgs := make([]sqsMessage, 0, len(result.Result.Messages))
	for _, m := range result.Result.Messages {
		msgs = append(msgs, sqsMessage{
			MessageID:     m.MessageID,
			ReceiptHandle: m.ReceiptHandle,
			Body:          m.Body,
		})
	}
	return msgs, nil
}

func (c *CloudTrailCollector) sqsDelete(ctx context.Context, creds awsCreds, receiptHandle string) error {
	params := url.Values{}
	params.Set("Action", "DeleteMessage")
	params.Set("ReceiptHandle", receiptHandle)
	params.Set("Version", "2012-11-05")

	req, err := awsSignRequest(ctx, "POST", c.cfg.SQSQueueURL, params.Encode(), c.region, "sqs", creds)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("sqs delete status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// ── CloudTrail JSON parsing ───────────────────────────────────────────────────

// cloudTrailRecord mirrors the relevant fields from a CloudTrail log entry.
type cloudTrailRecord struct {
	EventVersion string `json:"eventVersion"`
	EventID      string `json:"eventID"`
	EventTime    string `json:"eventTime"`
	EventSource  string `json:"eventSource"` // e.g. "iam.amazonaws.com"
	EventName    string `json:"eventName"`   // e.g. "AssumeRole"
	AWSRegion    string `json:"awsRegion"`
	SourceIP     string `json:"sourceIPAddress"`
	UserAgent    string `json:"userAgent"`
	ErrorCode    string `json:"errorCode,omitempty"`
	UserIdentity struct {
		Type        string `json:"type"`
		PrincipalID string `json:"principalId"`
		ARN         string `json:"arn"`
		UserName    string `json:"userName,omitempty"`
	} `json:"userIdentity"`
	Resources []struct {
		ARN  string `json:"ARN"`
		Type string `json:"type,omitempty"`
	} `json:"resources,omitempty"`
}

type cloudTrailFile struct {
	Records []cloudTrailRecord `json:"Records"`
}

func parseCloudTrailJSON(data []byte) ([]types.Event, error) {
	var f cloudTrailFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse cloudtrail json: %w", err)
	}

	events := make([]types.Event, 0, len(f.Records))
	now := uint64(time.Now().UnixNano())
	for _, r := range f.Records {
		principal := r.UserIdentity.ARN
		if principal == "" {
			principal = r.UserIdentity.PrincipalID
		}
		if principal == "" {
			principal = r.UserIdentity.UserName
		}

		resourceARN := ""
		if len(r.Resources) > 0 {
			resourceARN = r.Resources[0].ARN
		}

		// Derive the service short name from the event source (strip ".amazonaws.com").
		service := strings.TrimSuffix(r.EventSource, ".amazonaws.com")

		e := types.Event{
			Type:      types.EventCloudAudit,
			Timestamp: now,
			CloudAudit: &types.CloudAuditEvent{
				Provider:    "aws",
				Service:     service,
				Action:      r.EventName,
				Principal:   principal,
				ResourceARN: resourceARN,
				SourceIP:    r.SourceIP,
				UserAgent:   r.UserAgent,
				ErrorCode:   r.ErrorCode,
				Region:      r.AWSRegion,
				EventID:     r.EventID,
			},
		}
		events = append(events, e)
	}
	return events, nil
}

// ── SQS message body parsing ─────────────────────────────────────────────────

// s3Notification contains the S3 bucket and keys from a CloudTrail notification.
type s3Notification struct {
	S3Bucket    string   `json:"s3Bucket"`
	S3ObjectKey []string `json:"s3ObjectKey"`
}

// snsWrapper wraps an SNS notification delivered to SQS.
type snsWrapper struct {
	Type    string `json:"Type"`
	Message string `json:"Message"`
}

// parseSQSMessageBody parses the SQS message body and extracts the S3 bucket and keys.
// Handles both direct S3 notifications and SNS-wrapped notifications.
func parseSQSMessageBody(body string) (bucket string, keys []string, err error) {
	// Try SNS wrapper first.
	var sns snsWrapper
	if jsonErr := json.Unmarshal([]byte(body), &sns); jsonErr == nil && sns.Type == "Notification" {
		body = sns.Message
	}

	var notif s3Notification
	if err := json.Unmarshal([]byte(body), &notif); err != nil {
		return "", nil, fmt.Errorf("parse s3 notification: %w", err)
	}
	return notif.S3Bucket, notif.S3ObjectKey, nil
}

// ── AWS Signature V4 ──────────────────────────────────────────────────────────

// awsCreds holds AWS credentials for API signing.
type awsCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// awsCredCache resolves and caches AWS credentials with automatic refresh.
type awsCredCache struct {
	mu      sync.Mutex
	creds   awsCreds
	expiry  time.Time
	client  *http.Client
}

func newAWSCredCache(client *http.Client) *awsCredCache {
	return &awsCredCache{client: client}
}

func (c *awsCredCache) get(ctx context.Context) (awsCreds, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.expiry.Add(-5 * time.Minute)) && c.creds.AccessKeyID != "" {
		return c.creds, nil
	}
	creds, expiry, err := resolveAWSCreds(ctx, c.client)
	if err != nil {
		return awsCreds{}, err
	}
	c.creds = creds
	c.expiry = expiry
	return creds, nil
}

// resolveAWSCreds resolves AWS credentials using the standard chain:
//  1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
//  2. IRSA via web identity token file (AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE)
//  3. EC2 instance metadata service (IMDS v2)
func resolveAWSCreds(ctx context.Context, client *http.Client) (awsCreds, time.Time, error) {
	// 1. Environment variables.
	if ak := os.Getenv("AWS_ACCESS_KEY_ID"); ak != "" {
		sk := os.Getenv("AWS_SECRET_ACCESS_KEY")
		st := os.Getenv("AWS_SESSION_TOKEN")
		return awsCreds{AccessKeyID: ak, SecretAccessKey: sk, SessionToken: st},
			time.Now().Add(6 * time.Hour), nil
	}

	// 2. IRSA (IAM Roles for Service Accounts) via web identity token.
	if roleARN := os.Getenv("AWS_ROLE_ARN"); roleARN != "" {
		tokenFile := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
		if tokenFile != "" {
			return assumeRoleWithWebIdentity(ctx, client, roleARN, tokenFile)
		}
	}

	// 3. IMDS v2 (EC2/ECS instance profile).
	return getIMDSCredentials(ctx, client)
}

// assumeRoleWithWebIdentity exchanges a web identity token for temporary credentials.
func assumeRoleWithWebIdentity(ctx context.Context, client *http.Client, roleARN, tokenFile string) (awsCreds, time.Time, error) {
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return awsCreds{}, time.Time{}, fmt.Errorf("read web identity token file: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))

	params := url.Values{}
	params.Set("Action", "AssumeRoleWithWebIdentity")
	params.Set("RoleArn", roleARN)
	params.Set("WebIdentityToken", token)
	params.Set("RoleSessionName", "ebpf-guard-cloudtrail")
	params.Set("Version", "2011-06-15")

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://sts.amazonaws.com/", strings.NewReader(params.Encode()))
	if err != nil {
		return awsCreds{}, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return awsCreds{}, time.Time{}, err
	}
	defer resp.Body.Close()

	// Parse XML response.
	type stsCredentials struct {
		AccessKeyID     string `xml:"AccessKeyId"`
		SecretAccessKey string `xml:"SecretAccessKey"`
		SessionToken    string `xml:"SessionToken"`
		Expiration      string `xml:"Expiration"`
	}
	var result struct {
		XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
		Result  struct {
			Credentials stsCredentials `xml:"Credentials"`
		} `xml:"AssumeRoleWithWebIdentityResult"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return awsCreds{}, time.Time{}, fmt.Errorf("decode sts response: %w", err)
	}

	c := result.Result.Credentials
	expiry, _ := time.Parse(time.RFC3339, c.Expiration)
	if expiry.IsZero() {
		expiry = time.Now().Add(1 * time.Hour)
	}
	return awsCreds{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
	}, expiry, nil
}

// getIMDSCredentials fetches credentials from the EC2 Instance Metadata Service v2.
func getIMDSCredentials(ctx context.Context, client *http.Client) (awsCreds, time.Time, error) {
	// IMDSv2: get a session token first.
	tokenReq, err := http.NewRequestWithContext(ctx, "PUT",
		"http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return awsCreds{}, time.Time{}, err
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return awsCreds{}, time.Time{}, fmt.Errorf("imds token: %w", err)
	}
	imdsToken, err := io.ReadAll(io.LimitReader(tokenResp.Body, 256))
	tokenResp.Body.Close()
	if err != nil {
		return awsCreds{}, time.Time{}, err
	}

	// Get the IAM role name.
	roleReq, err := http.NewRequestWithContext(ctx, "GET",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	if err != nil {
		return awsCreds{}, time.Time{}, err
	}
	roleReq.Header.Set("X-aws-ec2-metadata-token", string(imdsToken))

	roleResp, err := client.Do(roleReq)
	if err != nil {
		return awsCreds{}, time.Time{}, fmt.Errorf("imds role: %w", err)
	}
	roleBody, err := io.ReadAll(io.LimitReader(roleResp.Body, 256))
	roleResp.Body.Close()
	if err != nil {
		return awsCreds{}, time.Time{}, err
	}
	roleName := strings.TrimSpace(string(roleBody))

	// Get credentials for the role.
	credReq, err := http.NewRequestWithContext(ctx, "GET",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/"+roleName, nil)
	if err != nil {
		return awsCreds{}, time.Time{}, err
	}
	credReq.Header.Set("X-aws-ec2-metadata-token", string(imdsToken))

	credResp, err := client.Do(credReq)
	if err != nil {
		return awsCreds{}, time.Time{}, fmt.Errorf("imds credentials: %w", err)
	}
	credBody, err := io.ReadAll(io.LimitReader(credResp.Body, 2048))
	credResp.Body.Close()
	if err != nil {
		return awsCreds{}, time.Time{}, err
	}

	var cred struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      string `json:"Expiration"`
	}
	if err := json.Unmarshal(credBody, &cred); err != nil {
		return awsCreds{}, time.Time{}, fmt.Errorf("parse imds credentials: %w", err)
	}

	expiry, _ := time.Parse(time.RFC3339, cred.Expiration)
	if expiry.IsZero() {
		expiry = time.Now().Add(1 * time.Hour)
	}
	return awsCreds{
		AccessKeyID:     cred.AccessKeyID,
		SecretAccessKey: cred.SecretAccessKey,
		SessionToken:    cred.Token,
	}, expiry, nil
}

// awsSignRequest creates an HTTP request signed with AWS Signature Version 4.
func awsSignRequest(ctx context.Context, method, endpoint, body, region, service string, creds awsCreds) (*http.Request, error) {
	t := time.Now().UTC()
	date := t.Format("20060102")
	datetime := t.Format("20060102T150405Z")

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	bodyHash := awsSHA256Hex(body)

	// Build canonical headers (must be sorted).
	hdrKeys := []string{"content-type", "host", "x-amz-content-sha256", "x-amz-date"}
	hdrVals := map[string]string{
		"content-type":         "application/x-www-form-urlencoded",
		"host":                 u.Host,
		"x-amz-content-sha256": bodyHash,
		"x-amz-date":           datetime,
	}
	if creds.SessionToken != "" {
		hdrKeys = append(hdrKeys, "x-amz-security-token")
		hdrVals["x-amz-security-token"] = creds.SessionToken
	}
	sort.Strings(hdrKeys)

	var canonicalHeaders strings.Builder
	for _, k := range hdrKeys {
		canonicalHeaders.WriteString(k + ":" + hdrVals[k] + "\n")
	}
	signedHeaders := strings.Join(hdrKeys, ";")

	// Canonical request.
	canonicalRequest := strings.Join([]string{
		method,
		u.EscapedPath(),
		u.RawQuery,
		canonicalHeaders.String(),
		signedHeaders,
		bodyHash,
	}, "\n")

	// String to sign.
	credentialScope := strings.Join([]string{date, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		datetime,
		credentialScope,
		awsSHA256Hex(canonicalRequest),
	}, "\n")

	// Derive signing key and compute signature.
	signingKey := awsDeriveSigningKey(creds.SecretAccessKey, date, region, service)
	sig := hex.EncodeToString(awsHMACSHA256(signingKey, stringToSign))

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, credentialScope, signedHeaders, sig,
	)

	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for _, k := range hdrKeys {
		req.Header.Set(k, hdrVals[k])
	}
	req.Header.Set("Authorization", authHeader)
	return req, nil
}

func awsHMACSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func awsSHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func awsDeriveSigningKey(secret, date, region, service string) []byte {
	kDate := awsHMACSHA256([]byte("AWS4"+secret), date)
	kRegion := awsHMACSHA256(kDate, region)
	kService := awsHMACSHA256(kRegion, service)
	return awsHMACSHA256(kService, "aws4_request")
}

// inferAWSRegion extracts the region from a SQS queue URL.
// SQS URLs have the form: https://sqs.{region}.amazonaws.com/...
func inferAWSRegion(queueURL string) string {
	u, err := url.Parse(queueURL)
	if err != nil {
		return "us-east-1"
	}
	parts := strings.SplitN(u.Host, ".", 4)
	if len(parts) >= 2 && parts[0] == "sqs" {
		return parts[1]
	}
	return "us-east-1"
}
