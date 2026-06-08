package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestParseCloudTrailJSON(t *testing.T) {
	data := []byte(`{
  "Records": [
    {
      "eventVersion": "1.08",
      "eventID": "event-001",
      "eventTime": "2024-01-01T12:00:00Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "AssumeRole",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "203.0.113.42",
      "userAgent": "aws-cli/2.0",
      "errorCode": "",
      "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAI...",
        "arn": "arn:aws:iam::123456789:user/admin",
        "userName": "admin"
      },
      "resources": [
        {"ARN": "arn:aws:iam::123456789:role/dev-role"}
      ]
    },
    {
      "eventVersion": "1.08",
      "eventID": "event-002",
      "eventTime": "2024-01-01T12:01:00Z",
      "eventSource": "secretsmanager.amazonaws.com",
      "eventName": "GetSecretValue",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "10.0.1.5",
      "userAgent": "python-boto3/1.26",
      "errorCode": "AccessDenied",
      "userIdentity": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::123456789:assumed-role/lambda-role/func"
      }
    }
  ]
}`)

	events, err := parseCloudTrailJSON(data)
	require.NoError(t, err)
	require.Len(t, events, 2)

	e0 := events[0]
	assert.Equal(t, types.EventCloudAudit, e0.Type)
	require.NotNil(t, e0.CloudAudit)
	assert.Equal(t, "aws", e0.CloudAudit.Provider)
	assert.Equal(t, "iam", e0.CloudAudit.Service)
	assert.Equal(t, "AssumeRole", e0.CloudAudit.Action)
	assert.Equal(t, "arn:aws:iam::123456789:user/admin", e0.CloudAudit.Principal)
	assert.Equal(t, "arn:aws:iam::123456789:role/dev-role", e0.CloudAudit.ResourceARN)
	assert.Equal(t, "203.0.113.42", e0.CloudAudit.SourceIP)
	assert.Equal(t, "us-east-1", e0.CloudAudit.Region)
	assert.Equal(t, "event-001", e0.CloudAudit.EventID)
	assert.Empty(t, e0.CloudAudit.ErrorCode)

	e1 := events[1]
	assert.Equal(t, "secretsmanager", e1.CloudAudit.Service)
	assert.Equal(t, "GetSecretValue", e1.CloudAudit.Action)
	assert.Equal(t, "AccessDenied", e1.CloudAudit.ErrorCode)
}

func TestParseCloudTrailJSONEmpty(t *testing.T) {
	data := []byte(`{"Records": []}`)
	events, err := parseCloudTrailJSON(data)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestParseCloudTrailJSONInvalid(t *testing.T) {
	_, err := parseCloudTrailJSON([]byte(`not json`))
	assert.Error(t, err)
}

func TestParseSQSMessageBodyDirect(t *testing.T) {
	body := `{"s3Bucket":"my-ct-bucket","s3ObjectKey":["AWSLogs/123/CloudTrail/us-east-1/2024/01/01/file.json.gz"]}`
	bucket, keys, err := parseSQSMessageBody(body)
	require.NoError(t, err)
	assert.Equal(t, "my-ct-bucket", bucket)
	require.Len(t, keys, 1)
	assert.Contains(t, keys[0], "file.json.gz")
}

func TestParseSQSMessageBodySNSWrapper(t *testing.T) {
	inner := `{"s3Bucket":"my-ct-bucket","s3ObjectKey":["path/to/file.json.gz"]}`
	body := `{"Type":"Notification","TopicArn":"arn:aws:sns:us-east-1:123:ct","Message":` +
		`"{\"s3Bucket\":\"my-ct-bucket\",\"s3ObjectKey\":[\"path\\/to\\/file.json.gz\"]}"}`
	bucket, keys, err := parseSQSMessageBody(body)
	require.NoError(t, err)
	assert.Equal(t, "my-ct-bucket", bucket)
	require.Len(t, keys, 1)
	_ = inner
}

func TestInferAWSRegion(t *testing.T) {
	tests := []struct {
		url    string
		region string
	}{
		{"https://sqs.us-east-1.amazonaws.com/123456789/my-queue", "us-east-1"},
		{"https://sqs.eu-west-2.amazonaws.com/123456789/queue", "eu-west-2"},
		{"invalid-url", "us-east-1"},
		{"", "us-east-1"},
	}
	for _, tt := range tests {
		got := inferAWSRegion(tt.url)
		assert.Equal(t, tt.region, got, "url=%q", tt.url)
	}
}

func TestParseGCPAuditLogEntry(t *testing.T) {
	data := []byte(`{
  "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
  "insertId": "gcp-event-abc",
  "resource": {
    "type": "gce_instance",
    "labels": {"project_id": "my-project", "zone": "us-central1-a"}
  },
  "timestamp": "2024-01-01T12:00:00Z",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.instances.list",
    "resourceName": "projects/my-project/zones/us-central1-a/instances",
    "authenticationInfo": {
      "principalEmail": "user@example.com"
    },
    "requestMetadata": {
      "callerIp": "198.51.100.7",
      "callerSuppliedUserAgent": "google-cloud-sdk/425.0"
    }
  }
}`)

	event, err := parseGCPAuditLogEntry(data)
	require.NoError(t, err)
	assert.Equal(t, types.EventCloudAudit, event.Type)
	require.NotNil(t, event.CloudAudit)
	assert.Equal(t, "gcp", event.CloudAudit.Provider)
	assert.Equal(t, "compute.googleapis.com", event.CloudAudit.Service)
	assert.Equal(t, "v1.compute.instances.list", event.CloudAudit.Action)
	assert.Equal(t, "user@example.com", event.CloudAudit.Principal)
	assert.Equal(t, "198.51.100.7", event.CloudAudit.SourceIP)
	assert.Equal(t, "us-central1-a", event.CloudAudit.Region)
	assert.Equal(t, "gcp-event-abc", event.CloudAudit.EventID)
	assert.Empty(t, event.CloudAudit.ErrorCode)
}

func TestParseGCPAuditLogEntryDenied(t *testing.T) {
	data := []byte(`{
  "insertId": "denied-event",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "iam.googleapis.com",
    "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
    "resourceName": "projects/my-project/serviceAccounts/sa@my-project.iam.gserviceaccount.com",
    "authenticationInfo": {"principalEmail": "attacker@example.com"},
    "requestMetadata": {"callerIp": "203.0.113.1"},
    "status": {"code": 7, "message": "PERMISSION_DENIED"}
  },
  "resource": {"type": "service_account", "labels": {}}
}`)

	event, err := parseGCPAuditLogEntry(data)
	require.NoError(t, err)
	assert.Equal(t, "PERMISSION_DENIED", event.CloudAudit.ErrorCode)
	assert.Equal(t, "google.iam.admin.v1.CreateServiceAccountKey", event.CloudAudit.Action)
}

func TestParseGCPAuditLogEntryNotAudit(t *testing.T) {
	data := []byte(`{"logName":"projects/my-project/logs/stdout","textPayload":"hello"}`)
	_, err := parseGCPAuditLogEntry(data)
	assert.Error(t, err)
}

func TestSyntheticCloudAuditEvent(t *testing.T) {
	s := &SyntheticCollector{}
	for i := 0; i < 20; i++ {
		e := s.generateCloudAuditEvent()
		require.NotNil(t, e)
		assert.NotEmpty(t, e.Provider)
		assert.NotEmpty(t, e.Service)
		assert.NotEmpty(t, e.Action)
		assert.NotEmpty(t, e.Principal)
		assert.NotEmpty(t, e.SourceIP)
		assert.NotEmpty(t, e.Region)
	}
}
