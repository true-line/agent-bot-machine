package members

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStage2aMemberRuntimeRequestRequiresPreviousEnvelopeOnRenewal(t *testing.T) {
	q := Stage2aMemberRuntimeRequest{
		Stage2aMemberLiveRequest: Stage2aMemberLiveRequest{
			Stage2aStopRequest: stage2aHelloTestSelectors(),
			MemberID:           "m_lead", MemberSelector: "mb_" + strings.Repeat("a", 64),
			MemberLaunchID:                 "ln_" + strings.Repeat("1", 24),
			GrantSHA256:                    "sha256:" + strings.Repeat("a", 64),
			ChildObservationEnvelopeSHA256: "sha256:" + strings.Repeat("b", 64),
			LauncherPID:                    101, ChildPID: 102, PeerUID: 301, PeerPID: 101,
			ChallengeNonceBase64URL: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			PriorExpiresAt:          time.Now().UTC().Add(5 * time.Second).Format(time.RFC3339Nano),
		},
		ReadyEnvelopeSHA256:  "sha256:" + strings.Repeat("c", 64),
		HQFinalizationSHA256: "sha256:" + strings.Repeat("d", 64),
	}
	parse := func() error {
		t.Helper()
		raw, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ParseStage2aMemberRuntimeRequest(raw)
		return err
	}
	if err := parse(); err != nil {
		t.Fatalf("first lease rejected: %v", err)
	}
	previous := "sha256:" + strings.Repeat("d", 64)
	q.PreviousLeaseEnvelopeSHA256 = &previous
	if err := parse(); err == nil {
		t.Fatal("first lease accepted a previous envelope")
	}
	q.AfterSequence = 1
	if err := parse(); err != nil {
		t.Fatalf("renewal rejected: %v", err)
	}
	q.PreviousLeaseEnvelopeSHA256 = nil
	if err := parse(); err == nil {
		t.Fatal("renewal accepted a missing previous envelope")
	}
	previous = "sha256:" + strings.Repeat("g", 64)
	q.PreviousLeaseEnvelopeSHA256 = &previous
	if err := parse(); err == nil {
		t.Fatal("renewal accepted an invalid previous digest")
	}
}
