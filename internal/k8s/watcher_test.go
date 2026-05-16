package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeContainerID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "docker prefix",
			input:    "docker://abc123def456",
			expected: "abc123def456",
		},
		{
			name:     "containerd prefix",
			input:    "containerd://abc123def456",
			expected: "abc123def456",
		},
		{
			name:     "cri-o prefix",
			input:    "cri-o://abc123def456",
			expected: "abc123def456",
		},
		{
			name:     "no prefix",
			input:    "abc123def456",
			expected: "abc123def456",
		},
		{
			name:     "uppercase",
			input:    "ABC123DEF456",
			expected: "abc123def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeContainerID(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		name        string
		cgroup      string
		expectedID  string
		expectError bool
	}{
		{
			name: "docker container",
			cgroup: `12:freezer:/docker/abc123def4567890123456789012345678901234567890123456789012345678
11:cpu,cpuacct:/docker/abc123def4567890123456789012345678901234567890123456789012345678`,
			expectedID:  "abc123def4567890123456789012345678901234567890123456789012345678",
			expectError: false,
		},
		{
			name: "containerd container",
			cgroup: `0::/system.slice/containerd.service/cri-containerd-abc123def4567890123456789012345678901234567890123456789012345678.scope`,
			expectedID:  "abc123def4567890123456789012345678901234567890123456789012345678",
			expectError: false,
		},
		{
			name: "no container ID",
			cgroup: `12:freezer:/
11:cpu,cpuacct:/system.slice/nginx.service`,
			expectedID:  "",
			expectError: true,
		},
		{
			name:        "empty cgroup",
			cgroup:      "",
			expectedID:  "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractContainerID(tt.cgroup)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedID, result)
			}
		})
	}
}

func TestCopyMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		expected map[string]string
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty map",
			input:    map[string]string{},
			expected: map[string]string{},
		},
		{
			name: "map with values",
			input: map[string]string{
				"app":     "nginx",
				"version": "1.0",
			},
			expected: map[string]string{
				"app":     "nginx",
				"version": "1.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := copyMap(tt.input)
			assert.Equal(t, tt.expected, result)

			// Verify it's a copy (not the same underlying map)
			if tt.input != nil {
				result["new_key"] = "new_value"
				_, exists := tt.input["new_key"]
				assert.False(t, exists, "modifying result should not affect input")
			}
		})
	}
}
