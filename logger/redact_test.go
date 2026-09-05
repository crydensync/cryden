package logger

import (
	"errors"
	"strings"
	"testing"
)

const testHashKey = "a-key-of-its-own-not-the-jwt-secret"

func TestMaskingRedactorReplacesTheDefaultKeys(t *testing.T) {
	sink := &plainLogger{}
	NewMaskingRedactor(sink).Warn("login failed", map[string]string{
		"ip":      "203.0.113.7",
		"user_id": "0192f0c1-8a4e-7a1b-9c3d-4e5f60718293",
		"reason":  "invalid_credentials",
	})

	got := sink.records[0].fields
	if got["ip"] != RedactedMarker || got["user_id"] != RedactedMarker {
		t.Fatalf("ip and user_id should both be masked, got ip=%q user_id=%q", got["ip"], got["user_id"])
	}
	if got["reason"] != "invalid_credentials" {
		t.Fatalf("a field nobody listed should be untouched, got %q", got["reason"])
	}
	if len(got) != 3 {
		t.Fatalf("masking must keep the record's shape, want 3 fields, got %d", len(got))
	}
}

func TestMaskingRedactorLeavesTheCallersMapAlone(t *testing.T) {
	fields := map[string]string{"ip": "203.0.113.7"}
	NewMaskingRedactor(&plainLogger{}).Info("something happened", fields)

	if fields["ip"] != "203.0.113.7" {
		t.Fatalf("the caller's own map was rewritten: %q", fields["ip"])
	}
}

// The wiring the package doc recommends: redact inside the fan-out, so
// the local console keeps the real address and only the sink that leaves
// the building gets the masked one. It works only because redact copies.
func TestRedactorInsideAMultiLoggerOnlyAffectsItsOwnSink(t *testing.T) {
	local, cloud := &plainLogger{}, &plainLogger{}
	NewMultiLogger(local, NewMaskingRedactor(cloud)).Warn("rate limited", map[string]string{"ip": "203.0.113.7"})

	if local.records[0].fields["ip"] != "203.0.113.7" {
		t.Fatalf("the local sink lost the real address: %q", local.records[0].fields["ip"])
	}
	if cloud.records[0].fields["ip"] != RedactedMarker {
		t.Fatalf("the outbound sink kept the real address: %q", cloud.records[0].fields["ip"])
	}
}

func TestHashingRedactorKeepsTheSameValueCorrelatable(t *testing.T) {
	sink := &plainLogger{}
	redactor, err := NewHashingRedactor(sink, testHashKey)
	if err != nil {
		t.Fatalf("NewHashingRedactor: %v", err)
	}

	redactor.Warn("login failed", map[string]string{"ip": "203.0.113.7"})
	redactor.Warn("login failed", map[string]string{"ip": "203.0.113.7"})
	redactor.Warn("login failed", map[string]string{"ip": "198.51.100.9"})

	first, second, other := sink.records[0].fields["ip"], sink.records[1].fields["ip"], sink.records[2].fields["ip"]
	if first != second {
		t.Fatalf("one address hashed two ways, so nothing can be correlated: %q vs %q", first, second)
	}
	if first == other {
		t.Fatalf("two different addresses collapsed to %q", first)
	}
	if !strings.HasPrefix(first, hashedPrefix) {
		t.Fatalf("a digest should say what it is, got %q", first)
	}
	if digest := strings.TrimPrefix(first, hashedPrefix); len(digest) != hashedHexLength {
		t.Fatalf("want a %d-character digest, got %q", hashedHexLength, digest)
	}
	if strings.Contains(first, "203.0.113.7") {
		t.Fatalf("the address survived into %q", first)
	}
}

func TestHashingRedactorDependsOnTheKey(t *testing.T) {
	one, two := &plainLogger{}, &plainLogger{}
	first, err := NewHashingRedactor(one, testHashKey)
	if err != nil {
		t.Fatalf("NewHashingRedactor: %v", err)
	}
	second, err := NewHashingRedactor(two, "a-different-key")
	if err != nil {
		t.Fatalf("NewHashingRedactor: %v", err)
	}

	first.Info("seen", map[string]string{"ip": "203.0.113.7"})
	second.Info("seen", map[string]string{"ip": "203.0.113.7"})

	if one.records[0].fields["ip"] == two.records[0].fields["ip"] {
		t.Fatal("two different keys produced the same digest, so the key is not being used")
	}
}

func TestHashingRedactorRefusesAnEmptyKey(t *testing.T) {
	redactor, err := NewHashingRedactor(&plainLogger{}, "")
	if !errors.Is(err, ErrMissingHashKey) {
		t.Fatalf("want ErrMissingHashKey, got %v", err)
	}
	if redactor != nil {
		t.Fatal("a redactor that cannot hash must not be returned at all")
	}
}

func TestRedactorWithItsOwnKeysReplacesTheDefaults(t *testing.T) {
	sink := &plainLogger{}
	NewMaskingRedactor(sink, "tenant").Info("request", map[string]string{
		"tenant": "acme-inc",
		"ip":     "203.0.113.7",
	})

	got := sink.records[0].fields
	if got["tenant"] != RedactedMarker {
		t.Fatalf("the listed key should be masked, got %q", got["tenant"])
	}
	// Given keys replace the defaults rather than adding to them: a host
	// that wants both passes both, and a host that wants only its own is
	// not overruled by this package's idea of what is sensitive.
	if got["ip"] != "203.0.113.7" {
		t.Fatalf("an unlisted key should be untouched, got %q", got["ip"])
	}
}

func TestRedactorMatchesKeysCaseInsensitively(t *testing.T) {
	sink := &plainLogger{}
	NewMaskingRedactor(sink, "IP").Info("request", map[string]string{
		"ip":      "203.0.113.7",
		"User_ID": "0192f0c1",
		"IP":      "198.51.100.9",
	})

	got := sink.records[0].fields
	for key, value := range got {
		if strings.EqualFold(key, "ip") && value != RedactedMarker {
			t.Fatalf("%q leaked as %q — a case mismatch must not be a hole", key, value)
		}
	}
	if got["User_ID"] != "0192f0c1" {
		t.Fatalf("an unlisted key should be untouched whatever its case, got %q", got["User_ID"])
	}
}

func TestRedactorLeavesEmptyValuesAndEmptyRecordsAlone(t *testing.T) {
	sink := &plainLogger{}
	redactor := NewMaskingRedactor(sink)

	redactor.Info("no fields", nil)
	redactor.Info("empty fields", map[string]string{})
	redactor.Info("blank value", map[string]string{"ip": ""})

	if sink.records[0].fields != nil {
		t.Fatalf("a nil field map should stay nil, got %v", sink.records[0].fields)
	}
	if len(sink.records[1].fields) != 0 {
		t.Fatalf("an empty field map should stay empty, got %v", sink.records[1].fields)
	}
	if got := sink.records[2].fields["ip"]; got != "" {
		t.Fatalf("an empty value has nothing to hide, got %q", got)
	}
}

func TestRedactorIgnoresAnEmptyKeyInTheList(t *testing.T) {
	sink := &plainLogger{}
	NewMaskingRedactor(sink, "", "ip").Info("request", map[string]string{
		"":   "not a field anyone means to redact",
		"ip": "203.0.113.7",
	})

	got := sink.records[0].fields
	if got[""] == RedactedMarker {
		t.Fatal(`an empty key in the list must not turn "" into a redacted field`)
	}
	if got["ip"] != RedactedMarker {
		t.Fatalf("the real key alongside it should still be masked, got %q", got["ip"])
	}
}

func TestRedactorKeepsTheCallContext(t *testing.T) {
	sink := &ctxLogger{}
	redactor, err := NewHashingRedactor(sink, testHashKey)
	if err != nil {
		t.Fatalf("NewHashingRedactor: %v", err)
	}

	ForContext(traceContext("trace-9"), redactor).Warn("login failed", map[string]string{"ip": "203.0.113.7"})

	if got := traceOf(sink.last().ctx); got != "trace-9" {
		t.Fatalf("redacting cost the trace the sink was bought for, got %q", got)
	}
	if sink.bare != 0 {
		t.Fatalf("the record went through a context-free method %d time(s)", sink.bare)
	}
	if got := sink.last().fields["ip"]; !strings.HasPrefix(got, hashedPrefix) {
		t.Fatalf("the value should still be hashed on the context path, got %q", got)
	}
}

func TestRedactorRoutesEveryLevel(t *testing.T) {
	sink := &plainLogger{}
	redactor := NewMaskingRedactor(sink)

	redactor.Debug("d", nil)
	redactor.Info("i", nil)
	redactor.Warn("w", nil)
	redactor.Error("e", nil)

	want := []Level{LevelDebug, LevelInfo, LevelWarn, LevelError}
	if len(sink.records) != len(want) {
		t.Fatalf("want %d records, got %d", len(want), len(sink.records))
	}
	for i, level := range want {
		if sink.records[i].level != level {
			t.Fatalf("record %d arrived as %s, want %s", i, sink.records[i].level, level)
		}
	}
}

func TestRedactorSurvivesANilInner(t *testing.T) {
	// Nothing to assert but the absence of a panic: a log statement is
	// never the point of the call it sits inside.
	NewMaskingRedactor(nil).Error("no sink", map[string]string{"ip": "203.0.113.7"})

	redactor, err := NewHashingRedactor(nil, testHashKey)
	if err != nil {
		t.Fatalf("NewHashingRedactor: %v", err)
	}
	redactor.Error("no sink", map[string]string{"ip": "203.0.113.7"})
}

func TestDefaultRedactedKeysCannotBeEditedByItsCallers(t *testing.T) {
	first := DefaultRedactedKeys()
	if len(first) == 0 {
		t.Fatal("the default set must not be empty")
	}
	first[0] = "clobbered"

	if second := DefaultRedactedKeys(); second[0] == "clobbered" {
		t.Fatal("one caller's edit reached the next caller's defaults")
	}
}
