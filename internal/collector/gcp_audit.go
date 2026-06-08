// Package collector provides eBPF-based and cloud event collection.
package collector

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

const (
	pubsubPullURL    = "https://pubsub.googleapis.com/v1/%s:pull"
	pubsubAckURL     = "https://pubsub.googleapis.com/v1/%s:acknowledge"
	gcpTokenURL      = "https://oauth2.googleapis.com/token"
	gcpMetadataToken = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	pubsubScope      = "https://www.googleapis.com/auth/pubsub"
)

// GCPAuditCollector subscribes to a GCP Pub/Sub topic and converts
// Cloud Audit Log entries to types.Event.
type GCPAuditCollector struct {
	logger       *slog.Logger
	cfg          config.GCPAuditCollectorConfig
	client       *http.Client
	dropLogger   *dropLogger
	strategy     BackpressureStrategy
	pollInterval time.Duration
	tokenCache   *gcpTokenCache
	stopped      chan struct{}
}

// NewGCPAuditCollector creates a new GCP Audit Logs collector.
func NewGCPAuditCollector(logger *slog.Logger, cfg config.GCPAuditCollectorConfig, strategy BackpressureStrategy) *GCPAuditCollector {
	d, err := time.ParseDuration(cfg.PollInterval)
	if err != nil || d <= 0 {
		d = 10 * time.Second
	}
	if cfg.MaxMessages <= 0 {
		cfg.MaxMessages = 100
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	return &GCPAuditCollector{
		logger:       logger.With("component", "gcp_audit_collector"),
		cfg:          cfg,
		client:       httpClient,
		dropLogger:   newDropLogger(5 * time.Second),
		strategy:     strategy,
		pollInterval: d,
		tokenCache:   newGCPTokenCache(httpClient, cfg.CredentialsFile),
		stopped:      make(chan struct{}),
	}
}

// Name returns the collector name.
func (g *GCPAuditCollector) Name() string { return "gcp_audit" }

// Close waits for the collector to stop.
func (g *GCPAuditCollector) Close() error {
	<-g.stopped
	return nil
}

// Start subscribes to Pub/Sub and emits cloud audit events. Blocks until ctx is cancelled.
func (g *GCPAuditCollector) Start(ctx context.Context, out chan<- types.Event) error {
	defer close(g.stopped)
	g.logger.Info("starting GCP Audit Logs collector",
		slog.String("subscription", g.cfg.PubSubSubscription),
	)

	ticker := time.NewTicker(g.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			g.logger.Info("stopping GCP Audit Logs collector")
			return nil
		case <-ticker.C:
			if err := g.poll(ctx, out); err != nil {
				g.logger.Warn("gcp_audit: poll error", slog.Any("error", err))
			}
		}
	}
}

// poll pulls messages from Pub/Sub and emits events.
func (g *GCPAuditCollector) poll(ctx context.Context, out chan<- types.Event) error {
	token, err := g.tokenCache.get(ctx)
	if err != nil {
		return fmt.Errorf("resolve gcp token: %w", err)
	}

	msgs, ackIDs, err := g.pubsubPull(ctx, token)
	if err != nil {
		return fmt.Errorf("pubsub pull: %w", err)
	}
	if len(msgs) == 0 {
		return nil
	}

	for _, msg := range msgs {
		e, err := parseGCPAuditLogEntry(msg)
		if err != nil {
			g.logger.Debug("gcp_audit: skip unparseable message", slog.Any("error", err))
			continue
		}
		sendEvent(ctx, out, e, g.strategy, func() {
			g.dropLogger.record(g.logger, g.Name())
		})
	}

	// Acknowledge all processed messages.
	if err := g.pubsubAck(ctx, token, ackIDs); err != nil {
		g.logger.Warn("gcp_audit: acknowledge error", slog.Any("error", err))
	}
	return nil
}

// ── Pub/Sub helpers ───────────────────────────────────────────────────────────

type pubsubPullRequest struct {
	MaxMessages int `json:"maxMessages"`
}

type pubsubPullResponse struct {
	ReceivedMessages []pubsubReceivedMessage `json:"receivedMessages"`
}

type pubsubReceivedMessage struct {
	AckID   string         `json:"ackId"`
	Message pubsubMessage  `json:"message"`
}

type pubsubMessage struct {
	Data        string `json:"data"`        // base64-encoded JSON
	MessageID   string `json:"messageId"`
	PublishTime string `json:"publishTime"`
}

type pubsubAckRequest struct {
	AckIDs []string `json:"ackIds"`
}

func (g *GCPAuditCollector) pubsubPull(ctx context.Context, token string) ([][]byte, []string, error) {
	reqBody, _ := json.Marshal(pubsubPullRequest{MaxMessages: g.cfg.MaxMessages})
	endpoint := fmt.Sprintf(pubsubPullURL, g.cfg.PubSubSubscription)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, nil, fmt.Errorf("pubsub pull status %d: %s", resp.StatusCode, body)
	}

	var result pubsubPullResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("decode pubsub response: %w", err)
	}

	messages := make([][]byte, 0, len(result.ReceivedMessages))
	ackIDs := make([]string, 0, len(result.ReceivedMessages))
	for _, rm := range result.ReceivedMessages {
		data, err := base64.StdEncoding.DecodeString(rm.Message.Data)
		if err != nil {
			data, err = base64.URLEncoding.DecodeString(rm.Message.Data)
			if err != nil {
				continue
			}
		}
		messages = append(messages, data)
		ackIDs = append(ackIDs, rm.AckID)
	}
	return messages, ackIDs, nil
}

func (g *GCPAuditCollector) pubsubAck(ctx context.Context, token string, ackIDs []string) error {
	if len(ackIDs) == 0 {
		return nil
	}
	reqBody, _ := json.Marshal(pubsubAckRequest{AckIDs: ackIDs})
	endpoint := fmt.Sprintf(pubsubAckURL, g.cfg.PubSubSubscription)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pubsub ack status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// ── GCP Log Entry parsing ─────────────────────────────────────────────────────

// gcpLogEntry mirrors the Cloud Logging LogEntry format for audit logs.
type gcpLogEntry struct {
	LogName  string `json:"logName"`
	Resource struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	Timestamp string `json:"timestamp"`
	InsertID  string `json:"insertId"`
	// ProtoPayload contains the AuditLog when @type is google.cloud.audit.AuditLog.
	ProtoPayload *gcpAuditLog `json:"protoPayload,omitempty"`
}

type gcpAuditLog struct {
	Type                string `json:"@type"`
	ServiceName         string `json:"serviceName"`
	MethodName          string `json:"methodName"`
	ResourceName        string `json:"resourceName"`
	AuthenticationInfo  struct {
		PrincipalEmail string `json:"principalEmail"`
	} `json:"authenticationInfo"`
	RequestMetadata struct {
		CallerIP        string `json:"callerIp"`
		CallerUserAgent string `json:"callerSuppliedUserAgent"`
	} `json:"requestMetadata"`
	// Status is present when the operation was denied or failed.
	Status *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status,omitempty"`
}

func parseGCPAuditLogEntry(data []byte) (types.Event, error) {
	var entry gcpLogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return types.Event{}, fmt.Errorf("parse log entry: %w", err)
	}
	if entry.ProtoPayload == nil {
		return types.Event{}, fmt.Errorf("not an audit log entry (no protoPayload)")
	}

	errorCode := ""
	if entry.ProtoPayload.Status != nil && entry.ProtoPayload.Status.Code != 0 {
		errorCode = entry.ProtoPayload.Status.Message
		if errorCode == "" {
			errorCode = fmt.Sprintf("CODE_%d", entry.ProtoPayload.Status.Code)
		}
	}

	// Extract project ID from the resource labels for region tagging.
	region := entry.Resource.Labels["location"]
	if region == "" {
		region = entry.Resource.Labels["zone"]
	}
	if region == "" {
		region = entry.Resource.Labels["region"]
	}

	return types.Event{
		Type:      types.EventCloudAudit,
		Timestamp: uint64(time.Now().UnixNano()),
		CloudAudit: &types.CloudAuditEvent{
			Provider:    "gcp",
			Service:     entry.ProtoPayload.ServiceName,
			Action:      entry.ProtoPayload.MethodName,
			Principal:   entry.ProtoPayload.AuthenticationInfo.PrincipalEmail,
			ResourceARN: entry.ProtoPayload.ResourceName,
			SourceIP:    entry.ProtoPayload.RequestMetadata.CallerIP,
			UserAgent:   entry.ProtoPayload.RequestMetadata.CallerUserAgent,
			ErrorCode:   errorCode,
			Region:      region,
			EventID:     entry.InsertID,
		},
	}, nil
}

// ── GCP credential cache ──────────────────────────────────────────────────────

type gcpTokenCache struct {
	mu              sync.Mutex
	token           string
	expiry          time.Time
	client          *http.Client
	credentialsFile string
}

func newGCPTokenCache(client *http.Client, credentialsFile string) *gcpTokenCache {
	return &gcpTokenCache{client: client, credentialsFile: credentialsFile}
}

func (c *gcpTokenCache) get(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.expiry.Add(-5*time.Minute)) && c.token != "" {
		return c.token, nil
	}
	token, expiry, err := c.resolve(ctx)
	if err != nil {
		return "", err
	}
	c.token = token
	c.expiry = expiry
	return token, nil
}

// resolve obtains an OAuth2 access token via Application Default Credentials.
// Resolution order:
//  1. CredentialsFile (explicit service account JSON key file)
//  2. GOOGLE_APPLICATION_CREDENTIALS environment variable
//  3. GCE/GKE instance metadata server
func (c *gcpTokenCache) resolve(ctx context.Context) (string, time.Time, error) {
	credFile := c.credentialsFile
	if credFile == "" {
		credFile = os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	}
	if credFile != "" {
		return gcpTokenFromKeyFile(ctx, c.client, credFile)
	}
	return gcpTokenFromMetadata(ctx, c.client)
}

// ── GCP service account JWT auth ──────────────────────────────────────────────

// gcpServiceAccountKey mirrors the fields we need from a GCP JSON key file.
type gcpServiceAccountKey struct {
	Type           string `json:"type"`
	PrivateKeyID   string `json:"private_key_id"`
	PrivateKey     string `json:"private_key"`
	ClientEmail    string `json:"client_email"`
	TokenURI       string `json:"token_uri"`
}

func gcpTokenFromKeyFile(ctx context.Context, client *http.Client, path string) (string, time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read gcp credentials file: %w", err)
	}

	var key gcpServiceAccountKey
	if err := json.Unmarshal(data, &key); err != nil {
		return "", time.Time{}, fmt.Errorf("parse gcp credentials file: %w", err)
	}
	if key.Type != "service_account" {
		return "", time.Time{}, fmt.Errorf("unsupported gcp credentials type: %s", key.Type)
	}

	tokenURI := key.TokenURI
	if tokenURI == "" {
		tokenURI = gcpTokenURL
	}

	now := time.Now()
	jwt, err := gcpSignJWT(key, now, pubsubScope, tokenURI)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign gcp jwt: %w", err)
	}

	return gcpExchangeJWT(ctx, client, jwt, tokenURI, now)
}

// gcpSignJWT creates a signed JWT for a GCP service account.
func gcpSignJWT(key gcpServiceAccountKey, now time.Time, scope, audience string) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(
		`{"alg":"RS256","typ":"JWT","kid":"` + key.PrivateKeyID + `"}`,
	))

	iat := now.Unix()
	exp := iat + 3600
	payloadJSON := fmt.Sprintf(
		`{"iss":%q,"scope":%q,"aud":%q,"iat":%d,"exp":%d}`,
		key.ClientEmail, scope, audience, iat, exp,
	)
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	signingInput := header + "." + payload

	privKey, err := parseRSAPrivateKey(key.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("parse rsa private key: %w", err)
	}

	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])
	if err != nil {
		return "", fmt.Errorf("rsa sign: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS#8 first (most service account keys use this format).
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("PKCS8 key is not RSA")
	}

	// Fall back to PKCS#1 (traditional RSA key format).
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// gcpExchangeJWT exchanges a signed JWT for an OAuth2 access token.
func gcpExchangeJWT(ctx context.Context, client *http.Client, jwt, tokenURI string, now time.Time) (string, time.Time, error) {
	body := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURI, strings.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", time.Time{}, fmt.Errorf("token exchange status %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode token response: %w", err)
	}

	expiry := now.Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, expiry, nil
}

// gcpTokenFromMetadata fetches an OAuth2 token from the GCE instance metadata server.
// Used for Workload Identity (GKE) and standard GCE instance service accounts.
func gcpTokenFromMetadata(ctx context.Context, client *http.Client) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", gcpMetadataToken, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("gcp metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", time.Time{}, fmt.Errorf("gcp metadata status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode gcp metadata token: %w", err)
	}

	expiry := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, expiry, nil
}
