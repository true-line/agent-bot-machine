package members

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aMemberHQFinalizationRequestRejectsChangedOrNoncanonicalRecord(t *testing.T) {
	record := []byte(`{"schema":"agent-bot-hq/stage2a-member-finalization/v1"}`)
	q := Stage2aMemberHQFinalizationRequest{
		Stage2aStopRequest:    stage2aHelloTestSelectors(),
		FinalizationBase64URL: base64.RawURLEncoding.EncodeToString(record),
		FinalizationSHA256:    stage2aReservationSHA256(record),
	}
	parse := func() error {
		t.Helper()
		raw, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ParseStage2aMemberHQFinalizationRequest(raw)
		return err
	}
	if err := parse(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	q.FinalizationSHA256 = stage2aReservationSHA256([]byte("other"))
	if err := parse(); err == nil {
		t.Fatal("changed digest accepted")
	}
	q.FinalizationSHA256 = stage2aReservationSHA256(record)
	q.FinalizationBase64URL += "="
	if err := parse(); err == nil {
		t.Fatal("padded base64url accepted")
	}
	tooLarge := []byte(strings.Repeat("a", 8193))
	q.FinalizationBase64URL = base64.RawURLEncoding.EncodeToString(tooLarge)
	q.FinalizationSHA256 = stage2aReservationSHA256(tooLarge)
	if err := parse(); err == nil {
		t.Fatal("oversized record accepted")
	}
	duplicate := []byte(`{"x":1,"x":2}`)
	q.FinalizationBase64URL = base64.RawURLEncoding.EncodeToString(duplicate)
	q.FinalizationSHA256 = stage2aReservationSHA256(duplicate)
	if err := parse(); err == nil {
		t.Fatal("duplicate JSON keys accepted")
	}
}
