package types

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// legacyFileEvent — FileEvent каким он был до волны 8.5 A1 (б): Filename массивом.
// Независимая копия формы, чтобы тест не зависел от продуктового MarshalJSON.
type legacyFileEvent struct {
	Filename        [256]byte
	Flags           int32
	Mode            uint32
	Op              uint8
	FDPathTruncated bool
	FDPath          string
}

func legacyJSON(t *testing.T, name string) []byte {
	t.Helper()
	l := legacyFileEvent{Flags: 577, Mode: 0o644, Op: 2, FDPath: name}
	copy(l.Filename[:], name)
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Старый JSON → новый тип → тот же JSON (побайтно).
func TestFileEventJSON_LegacyRoundTripIsByteIdentical(t *testing.T) {
	for _, name := range []string{"/etc/shadow", "", "/tmp/" + strings.Repeat("a", 251)} {
		old := legacyJSON(t, name)
		var fe FileEvent
		if err := json.Unmarshal(old, &fe); err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if fe.Filename != name || fe.Path() != name {
			t.Fatalf("Filename = %q, want %q", fe.Filename, name)
		}
		got, err := json.Marshal(fe)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, old) {
			t.Fatalf("%q: форма API изменилась\n got: %.120s\nwant: %.120s", name, got, old)
		}
	}
}

// Новая форма Filename (строка) тоже читается.
func TestFileEventJSON_StringFormIsAccepted(t *testing.T) {
	var fe FileEvent
	if err := json.Unmarshal([]byte(`{"Filename":"/etc/passwd","Flags":0,"Mode":0,"Op":0,"FDPathTruncated":false,"FDPath":""}`), &fe); err != nil {
		t.Fatal(err)
	}
	if fe.Filename != "/etc/passwd" {
		t.Fatalf("Filename = %q", fe.Filename)
	}
	if err := json.Unmarshal([]byte(`{"Filename":123}`), &fe); err == nil {
		t.Fatal("число вместо Filename принято молча")
	}
}

// Алерт из стора до правки читается: PreAlertContext несёт Event с File в старой форме.
func TestAlertFromStoreBeforeA1StillReads(t *testing.T) {
	old := legacyJSON(t, "/etc/shadow")
	stored := []byte(`{"id":"a1","rule_id":"r","pre_alert_context":[{"Type":3,"File":` + string(old) + `}]}`)
	var a Alert
	if err := json.Unmarshal(stored, &a); err != nil {
		t.Fatalf("алерт до правки не читается: %v", err)
	}
	if len(a.PreAlertContext) != 1 || a.PreAlertContext[0].File == nil || a.PreAlertContext[0].File.Filename != "/etc/shadow" {
		t.Fatalf("контекст: %+v", a.PreAlertContext)
	}
	// И пишется обратно в той же форме.
	back, err := json.Marshal(a.PreAlertContext[0].File)
	if err != nil || !bytes.Equal(back, old) {
		t.Fatalf("обратная запись изменилась: %v\n%.100s", err, back)
	}
}
