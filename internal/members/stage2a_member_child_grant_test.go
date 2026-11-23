package members

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aMemberChildGrantRequestRequiresAssignedSelectorAndChallenge(t *testing.T) {
	q := Stage2aMemberChildGrantRequest{Stage2aStopRequest: stage2aHelloTestSelectors(),
		MemberID: "m_lead", MemberSelector: "mb_" + strings.Repeat("a", 64),
		Nonce: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32))), PID: 1234}
	encode := func() []byte {
		t.Helper()
		raw, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := ParseStage2aMemberChildGrantRequest(encode()); err != nil {
		t.Fatal(err)
	}
	q.MemberSelector = "mb_" + strings.Repeat("A", 64)
	if _, err := ParseStage2aMemberChildGrantRequest(encode()); err == nil {
		t.Fatal("noncanonical selector accepted")
	}
	q.MemberSelector = "mb_" + strings.Repeat("a", 64)
	q.Nonce = base64.RawURLEncoding.EncodeToString([]byte("short"))
	if _, err := ParseStage2aMemberChildGrantRequest(encode()); err == nil {
		t.Fatal("short wrapper challenge accepted")
	}
	q.Nonce = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	q.PID = 1
	if _, err := ParseStage2aMemberChildGrantRequest(encode()); err == nil {
		t.Fatal("nonprocess PID accepted")
	}
}
