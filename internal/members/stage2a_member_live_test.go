package members

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStage2aMemberLiveRequestRejectsWrongPeerAndReplayShape(t *testing.T) {
	q := Stage2aMemberLiveRequest{
		Stage2aStopRequest: stage2aHelloTestSelectors(),
		MemberID:           "m_lead", MemberSelector: "mb_" + strings.Repeat("a", 64),
		MemberLaunchID:                 "ln_" + strings.Repeat("1", 24),
		GrantSHA256:                    "sha256:" + strings.Repeat("a", 64),
		ChildObservationEnvelopeSHA256: "sha256:" + strings.Repeat("b", 64),
		LauncherPID:                    101, ChildPID: 102, PeerUID: 301, PeerPID: 101,
		ChallengeNonceBase64URL: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		PriorExpiresAt:          time.Now().UTC().Add(5 * time.Second).Format(time.RFC3339Nano),
	}
	encode := func() []byte {
		t.Helper()
		raw, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := ParseStage2aMemberLiveRequest(encode()); err != nil {
		t.Fatal(err)
	}
	q.PeerPID = 103
	if _, err := ParseStage2aMemberLiveRequest(encode()); err == nil {
		t.Fatal("different kernel peer PID accepted")
	}
	q.PeerPID = q.LauncherPID
	q.ChallengeNonceBase64URL = base64.RawURLEncoding.EncodeToString(make([]byte, 31))
	if _, err := ParseStage2aMemberLiveRequest(encode()); err == nil {
		t.Fatal("short wrapper challenge accepted")
	}
	q.ChallengeNonceBase64URL = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	q.AfterSequence = 1 << 53
	if _, err := ParseStage2aMemberLiveRequest(encode()); err == nil {
		t.Fatal("non-JCS-safe lease sequence accepted")
	}
}
