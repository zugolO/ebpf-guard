// Package store provides OpenSearch storage backend for cluster deployments.
package store

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// OpenSearchStore implements AlertStore using OpenSearch.
type OpenSearchStore struct {
	client      *http.Client
	addresses   []string
	username    string
	password    string
	indexPrefix string
}

// NewOpenSearchStore creates a new OpenSearch alert store.
func NewOpenSearchStore(cfg OpenSearchConfig) (*OpenSearchStore, error) {
	if len(cfg.Addresses) == 0 {
		return nil, fmt.Errorf("at least one OpenSearch address required")
	}
	if cfg.IndexPrefix == "" {
		cfg.IndexPrefix = "ebpf-guard"
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	store := &OpenSearchStore{
		client:      client,
		addresses:   cfg.Addresses,
		username:    cfg.Username,
		password:    cfg.Password,
		indexPrefix: cfg.IndexPrefix,
	}

	return store, nil
}

// alertDocument represents an alert as stored in OpenSearch.
type alertDocument struct {
	Timestamp   time.Time         `json:"timestamp"`
	RuleID      string            `json:"rule_id"`
	Severity    string            `json:"severity"`
	PID         uint32            `json:"pid"`
	Comm        string            `json:"comm"`
	Message     string            `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	TraceID     string            `json:"trace_id,omitempty"`
	PodName     string            `json:"pod_name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	ContainerID string            `json:"container_id,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// toDocument converts an Alert to an OpenSearch document.
func toDocument(alert types.Alert) alertDocument {
	return alertDocument{
		Timestamp:   alert.Timestamp,
		RuleID:      alert.RuleID,
		Severity:    string(alert.Severity),
		PID:         alert.PID,
		Comm:        alert.Comm,
		Message:     alert.Message,
		Details:     alert.Details,
		TraceID:     alert.TraceID,
		PodName:     alert.Enrichment.PodName,
		Namespace:   alert.Enrichment.Namespace,
		ContainerID: alert.Enrichment.ContainerID,
		Labels:      alert.Enrichment.Labels,
	}
}

// Store persists a single alert.
func (s *OpenSearchStore) Store(ctx context.Context, alert types.Alert) error {
	return s.StoreBatch(ctx, []types.Alert{alert})
}

// StoreBatch persists multiple alerts using the bulk API.
func (s *OpenSearchStore) StoreBatch(ctx context.Context, alerts []types.Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	var buf bytes.Buffer
	indexName := s.indexName()

	for _, alert := range alerts {
		// Index action with explicit _id so QueryByID can retrieve by alert.ID.
		meta := fmt.Sprintf("{\"index\":{\"_index\":%q,\"_id\":%q}}\n", indexName, alert.ID)
		buf.WriteString(meta)

		// Document
		doc := toDocument(alert)
		data, err := json.Marshal(doc)
		if err != nil {
			return fmt.Errorf("marshal alert: %w", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		s.addresses[0]+"/_bulk?refresh=wait_for",
		&buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("bulk index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bulk index failed: %s - %s", resp.Status, string(body))
	}

	return nil
}

// Query retrieves alerts matching the filters.
func (s *OpenSearchStore) Query(ctx context.Context, filters QueryFilters) ([]types.Alert, error) {
	query := s.buildQuery(filters)

	reqBody, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}

	url := fmt.Sprintf("%s/%s/_search", s.addresses[0], s.indexName())
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search failed: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source alertDocument `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	alerts := make([]types.Alert, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		alerts = append(alerts, fromDocument(hit.Source))
	}

	return alerts, nil
}

// buildQuery constructs an OpenSearch query from filters.
func (s *OpenSearchStore) buildQuery(filters QueryFilters) map[string]interface{} {
	must := []map[string]interface{}{}

	if !filters.Since.IsZero() || !filters.Until.IsZero() {
		rangeQuery := map[string]interface{}{"timestamp": map[string]interface{}{}}
		if !filters.Since.IsZero() {
			rangeQuery["timestamp"].(map[string]interface{})["gte"] = filters.Since.Format(time.RFC3339)
		}
		if !filters.Until.IsZero() {
			rangeQuery["timestamp"].(map[string]interface{})["lte"] = filters.Until.Format(time.RFC3339)
		}
		must = append(must, map[string]interface{}{"range": rangeQuery})
	}

	if len(filters.PIDs) > 0 {
		terms := make([]interface{}, len(filters.PIDs))
		for i, pid := range filters.PIDs {
			terms[i] = pid
		}
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{"pid": terms},
		})
	}

	if len(filters.Severity) > 0 {
		terms := make([]interface{}, len(filters.Severity))
		for i, sev := range filters.Severity {
			terms[i] = string(sev)
		}
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{"severity": terms},
		})
	}

	if len(filters.RuleIDs) > 0 {
		terms := make([]interface{}, len(filters.RuleIDs))
		for i, ruleID := range filters.RuleIDs {
			terms[i] = ruleID
		}
		must = append(must, map[string]interface{}{
			"terms": map[string]interface{}{"rule_id": terms},
		})
	}

	if filters.PodName != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"pod_name": filters.PodName},
		})
	}

	if filters.Namespace != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"namespace": filters.Namespace},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"sort": []map[string]interface{}{
			{"timestamp": map[string]interface{}{"order": "desc"}},
		},
	}

	if filters.Limit > 0 {
		query["size"] = filters.Limit
	}
	if filters.Offset > 0 {
		query["from"] = filters.Offset
	}

	return query
}

// fromDocument converts an OpenSearch document to an Alert.
func fromDocument(doc alertDocument) types.Alert {
	return types.Alert{
		Timestamp: doc.Timestamp,
		RuleID:    doc.RuleID,
		Severity:  types.Severity(doc.Severity),
		PID:       doc.PID,
		Comm:      doc.Comm,
		Message:   doc.Message,
		Details:   doc.Details,
		TraceID:   doc.TraceID,
		Enrichment: types.EnrichmentInfo{
			PodName:     doc.PodName,
			Namespace:   doc.Namespace,
			ContainerID: doc.ContainerID,
			Labels:      doc.Labels,
		},
	}
}

// QueryByID retrieves a single alert by ID.
func (s *OpenSearchStore) QueryByID(ctx context.Context, alertID string) (*types.Alert, error) {
	url := fmt.Sprintf("%s/%s/_doc/%s", s.addresses[0], s.indexName(), alertID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get failed: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Found  bool          `json:"found"`
		Source alertDocument `json:"_source"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if !result.Found {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}

	alert := fromDocument(result.Source)
	alert.ID = alertID
	return &alert, nil
}

// Count returns the number of matching alerts.
func (s *OpenSearchStore) Count(ctx context.Context, filters QueryFilters) (int64, error) {
	query := s.buildQuery(filters)
	delete(query, "sort")
	delete(query, "size")
	delete(query, "from")

	reqBody, err := json.Marshal(query)
	if err != nil {
		return 0, fmt.Errorf("marshal query: %w", err)
	}

	url := fmt.Sprintf("%s/%s/_count", s.addresses[0], s.indexName())
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("count: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("count failed: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Count int64 `json:"count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	return result.Count, nil
}

// Delete removes alerts older than the given duration using delete_by_query.
func (s *OpenSearchStore) Delete(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Format(time.RFC3339)

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"lt": cutoff,
				},
			},
		},
	}

	reqBody, err := json.Marshal(query)
	if err != nil {
		return 0, fmt.Errorf("marshal query: %w", err)
	}

	url := fmt.Sprintf("%s/%s/_delete_by_query", s.addresses[0], s.indexName())
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("delete: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("delete failed: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Deleted int64 `json:"deleted"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	return result.Deleted, nil
}

// Close is a no-op for HTTP client.
func (s *OpenSearchStore) Close() error {
	return nil
}

// Healthy checks if OpenSearch is reachable.
func (s *OpenSearchStore) Healthy(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", s.addresses[0]+"/_cluster/health", nil)
	if err != nil {
		return false
	}

	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var result struct {
		Status string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}

	// Consider green and yellow as healthy
	return result.Status == "green" || result.Status == "yellow"
}

// indexName returns the index name for the current date.
func (s *OpenSearchStore) indexName() string {
	return fmt.Sprintf("%s-alerts-%s", s.indexPrefix, time.Now().Format("2006.01.02"))
}

// Ensure OpenSearchStore implements AlertStore interface.
var _ AlertStore = (*OpenSearchStore)(nil)
