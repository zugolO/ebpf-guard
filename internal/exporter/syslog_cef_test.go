package exporter

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func startTCPSyslogServer(t *testing.T) (addr string, lines chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ch := make(chan string, 16)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					ch <- sc.Text()
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), ch
}

func TestSyslogCEFNotifier_Disabled(t *testing.T) {
	n := NewSyslogCEFNotifier(SyslogCEFConfig{Enabled: false}, slog.Default())
	assert.False(t, n.Enabled())
}

func TestSyslogCEFNotifier_RFC5424(t *testing.T) {
	addr, lines := startTCPSyslogServer(t)

	n := NewSyslogCEFNotifier(SyslogCEFConfig{
		Enabled: true,
		Network: "tcp",
		Address: addr,
		Format:  "rfc5424",
		AppName: "ebpf-test",
	}, slog.Default())
	require.True(t, n.Enabled())
	defer n.Close()

	alert := makeTestAlert()
	err := n.Send(context.Background(), alert)
	require.NoError(t, err)

	select {
	case line := <-lines:
		assert.True(t, strings.HasPrefix(line, "<"), "must start with priority")
		assert.Contains(t, line, "ebpf-test")
		assert.Contains(t, line, "[ebpf-guard@50000")
		assert.Contains(t, line, `rule="rule_001"`)
		assert.Contains(t, line, "suspicious exec detected")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog message")
	}
}

func TestSyslogCEFNotifier_CEFFormat(t *testing.T) {
	addr, lines := startTCPSyslogServer(t)

	n := NewSyslogCEFNotifier(SyslogCEFConfig{
		Enabled: true,
		Network: "tcp",
		Address: addr,
		Format:  "cef",
		AppName: "ebpf-test",
	}, slog.Default())
	require.True(t, n.Enabled())
	defer n.Close()

	alert := makeTestAlert()
	err := n.Send(context.Background(), alert)
	require.NoError(t, err)

	select {
	case line := <-lines:
		assert.True(t, strings.HasPrefix(line, "CEF:0|"), "must be CEF format")
		assert.Contains(t, line, "ebpf-guard|ebpf-guard|1.0")
		assert.Contains(t, line, "rule_001")
		assert.Contains(t, line, "suser=bash")
		assert.Contains(t, line, "spid=1234")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for CEF message")
	}
}

func TestSyslogCEFNotifier_MinSeverity(t *testing.T) {
	addr, lines := startTCPSyslogServer(t)

	n := NewSyslogCEFNotifier(SyslogCEFConfig{
		Enabled:     true,
		Network:     "tcp",
		Address:     addr,
		Format:      "rfc5424",
		MinSeverity: "critical",
	}, slog.Default())
	defer n.Close()

	alert := makeTestAlert()
	alert.Severity = types.SeverityWarning
	err := n.Send(context.Background(), alert)
	require.NoError(t, err)

	select {
	case <-lines:
		t.Fatal("warning alert should have been filtered out")
	case <-time.After(200 * time.Millisecond):
		// expected: nothing sent
	}
}

func TestSyslogCEFNotifier_Reconnect(t *testing.T) {
	addr, lines := startTCPSyslogServer(t)

	n := NewSyslogCEFNotifier(SyslogCEFConfig{
		Enabled: true,
		Network: "tcp",
		Address: addr,
		Format:  "rfc5424",
	}, slog.Default())
	defer n.Close()

	for i := 0; i < 3; i++ {
		require.NoError(t, n.Send(context.Background(), makeTestAlert()))
	}

	count := 0
	timeout := time.After(2 * time.Second)
	for count < 3 {
		select {
		case <-lines:
			count++
		case <-timeout:
			t.Fatalf("timeout: only received %d/3 messages", count)
		}
	}
}

func TestFormatRFC5424_Escaping(t *testing.T) {
	n := &SyslogCEFNotifier{
		config:  SyslogCEFConfig{Facility: 1},
		appName: "ebpf-guard",
	}
	alert := makeTestAlert()
	// Value with all three special SD chars: backslash, double-quote, close-bracket.
	alert.RuleID = `a"b]c\d`
	msg := n.formatRFC5424(alert)
	// escapeSD must produce: a\"b\]c\\d
	assert.Contains(t, msg, `a\"b\]c\\d`)
}

func TestFormatCEF_Escaping(t *testing.T) {
	n := &SyslogCEFNotifier{config: SyslogCEFConfig{}}
	alert := makeTestAlert()
	// Message contains a real newline and an equals sign.
	alert.Message = "cmd=rm\nend"
	msg := n.formatCEF(alert)
	// Newline must be escaped; equals must be escaped.
	assert.Contains(t, msg, `cmd\=rm\nend`)
	// No raw newlines in the output.
	assert.NotContains(t, msg, "\n")
}

func TestSyslogSeverityMapping(t *testing.T) {
	assert.Equal(t, 2, syslogSeverity(types.SeverityCritical))
	assert.Equal(t, 4, syslogSeverity(types.SeverityWarning))
}

func TestCEFSeverityMapping(t *testing.T) {
	assert.Equal(t, 10, cefSeverity(types.SeverityCritical))
	assert.Equal(t, 4, cefSeverity(types.SeverityWarning))
}
