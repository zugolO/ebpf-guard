package pluginsdk

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAlertfNoArgs(t *testing.T) {
	a := Alertf(SeverityWarning, "plain message")
	if a.Severity != SeverityWarning {
		t.Errorf("Severity = %v, want %v", a.Severity, SeverityWarning)
	}
	if a.Message != "plain message" {
		t.Errorf("Message = %q, want %q", a.Message, "plain message")
	}
}

func TestAlertfWithArgsDoesNotSubstitute(t *testing.T) {
	a := Alertf(SeverityCritical, "outbound C2 connection to port %d from %s", 4444, "curl")
	if a.Severity != SeverityCritical {
		t.Errorf("Severity = %v, want %v", a.Severity, SeverityCritical)
	}
	want := "outbound C2 connection to port %d from %s"
	if a.Message != want {
		t.Errorf("Message = %q, want %q (Alertf currently ignores args and does not perform fmt substitution)", a.Message, want)
	}
}

func TestHandlerFuncMatch(t *testing.T) {
	called := false
	var gotEvent *Event
	var h Handler = HandlerFunc(func(e *Event) *Alert {
		called = true
		gotEvent = e
		return &Alert{Severity: SeverityWarning, Message: "matched"}
	})

	ev := &Event{Type: EventSyscall, PID: 42}
	alert := h.Match(ev)

	if !called {
		t.Fatal("underlying function was not called")
	}
	if gotEvent != ev {
		t.Errorf("gotEvent = %v, want %v", gotEvent, ev)
	}
	if alert == nil || alert.Message != "matched" {
		t.Errorf("alert = %+v, want Message %q", alert, "matched")
	}
}

func TestHandlerFuncMatchNilResult(t *testing.T) {
	var h Handler = HandlerFunc(func(e *Event) *Alert { return nil })
	if got := h.Match(&Event{}); got != nil {
		t.Errorf("Match = %v, want nil", got)
	}
}

func TestRegisterStoresHandler(t *testing.T) {
	t.Cleanup(func() { registeredHandler = nil })

	sentinel := &Alert{Severity: SeverityCritical, Message: "sentinel"}
	Register(HandlerFunc(func(e *Event) *Alert { return sentinel }))

	if registeredHandler == nil {
		t.Fatal("registeredHandler is nil after Register")
	}
	got := registeredHandler.Match(&Event{})
	if got != sentinel {
		t.Errorf("registeredHandler.Match returned %v, want %v", got, sentinel)
	}
}

func TestEventTypeConstants(t *testing.T) {
	cases := map[EventType]uint32{
		EventSyscall:    1,
		EventTCPConnect: 2,
		EventFileAccess: 3,
		EventTLS:        4,
		EventDNS:        5,
		EventPrivesc:    6,
		EventNetClose:   7,
		EventKmodLoad:   8,
		EventCgroupEsc:  9,
		EventGPU:        10,
		EventLSMAudit:   11,
		EventCloudAudit: 13,
	}
	for et, want := range cases {
		if uint32(et) != want {
			t.Errorf("EventType %v = %d, want %d", et, uint32(et), want)
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityWarning != 0 {
		t.Errorf("SeverityWarning = %d, want 0", SeverityWarning)
	}
	if SeverityCritical != 1 {
		t.Errorf("SeverityCritical = %d, want 1", SeverityCritical)
	}
}

func TestABIVersion(t *testing.T) {
	if ABIVersion != 1 {
		t.Errorf("ABIVersion = %d, want 1", ABIVersion)
	}
}

func baseEvent() Event {
	return Event{
		Type:       EventSyscall,
		PID:        100,
		PPID:       1,
		TGID:       100,
		UID:        1000,
		Comm:       "myproc",
		ParentComm: "bash",
	}
}

func marshalUnmarshalRoundTrip(t *testing.T, ev Event, absentKeys []string) Event {
	t.Helper()

	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal into map error: %v", err)
	}

	for _, key := range absentKeys {
		if _, ok := raw[key]; ok {
			t.Errorf("expected key %q to be absent from JSON due to omitempty, got: %s", key, data)
		}
	}

	var out Event
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal into Event error: %v", err)
	}
	if !reflect.DeepEqual(ev, out) {
		t.Errorf("round-trip mismatch:\n got:  %+v\n want: %+v", out, ev)
	}
	return out
}

var allSubKeys = []string{
	"network", "file", "dns", "tls", "syscall",
	"privesc", "kmod", "cgroup_esc", "net_close", "gpu",
}

func absentExcept(keep string) []string {
	var out []string
	for _, k := range allSubKeys {
		if k != keep {
			out = append(out, k)
		}
	}
	return out
}

func TestEventJSONRoundTripNetwork(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventTCPConnect
	ev.Network = &NetworkEvent{Saddr: "10.0.0.1", Daddr: "10.0.0.2", Sport: 1234, Dport: 443, Proto: 6, Family: 2}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("network"))
}

func TestEventJSONRoundTripFile(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventFileAccess
	ev.File = &FileEvent{Filename: "/etc/passwd", Flags: 1, Mode: 0644, Op: 2}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("file"))
}

func TestEventJSONRoundTripDNS(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventDNS
	ev.DNS = &DNSEvent{QName: "evil.example.com", QType: 1, RCode: 0, Direction: 1}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("dns"))
}

func TestEventJSONRoundTripTLS(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventTLS
	ev.TLS = &TLSEvent{Direction: 0, DataLen: 512}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("tls"))
}

func TestEventJSONRoundTripSyscall(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventSyscall
	ev.Syscall = &SyscallEvent{Nr: 59, Ret: 0}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("syscall"))
}

func TestEventJSONRoundTripPrivesc(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventPrivesc
	ev.Privesc = &PrivescEvent{OldCaps: 0, NewCaps: 0xFFFFFFFF}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("privesc"))
}

func TestEventJSONRoundTripKmod(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventKmodLoad
	ev.Kmod = &KmodEvent{ModName: "evilrootkit", FromTmpfs: true}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("kmod"))
}

func TestEventJSONRoundTripCgroupEsc(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventCgroupEsc
	ev.CgroupEsc = &CgroupEscapeEvent{InitCgroupID: 1, NewCgroupID: 2}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("cgroup_esc"))
}

func TestEventJSONRoundTripNetClose(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventNetClose
	ev.NetClose = &NetCloseEvent{Saddr: "10.0.0.1", Daddr: "10.0.0.2", Sport: 1234, Dport: 443, Family: 2, DurationMs: 1500}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("net_close"))
}

func TestEventJSONRoundTripGPU(t *testing.T) {
	ev := baseEvent()
	ev.Type = EventGPU
	ev.GPU = &GPUEvent{Op: 1, DevPtr: 0xDEAD, HostPtr: 0xBEEF, Size: 4096}
	marshalUnmarshalRoundTrip(t, ev, absentExcept("gpu"))
}

func TestEventJSONNoSubStructsAllAbsent(t *testing.T) {
	ev := baseEvent()
	marshalUnmarshalRoundTrip(t, ev, allSubKeys)
}
