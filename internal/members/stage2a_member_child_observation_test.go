package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aTwoMemberObservationRequestRejectsReusedProcesses(t *testing.T) {
	q := Stage2aMemberChildObservationRequest{Stage2aStopRequest: stage2aHelloTestSelectors(),
		Members: make([]Stage2aMemberChildObservationInput, 2)}
	for i, id := range []string{"m_lead", "m_spec"} {
		q.Members[i].MemberID = id
		q.Members[i].MemberLaunchID = "ln_" + strings.Repeat(string(rune('1'+i)), 24)
		q.Members[i].MemberSelector = "mb_" + strings.Repeat(string(rune('a'+i)), 64)
		q.Members[i].ChildLauncherPID = 100 + i*2
		q.Members[i].ChildPID = 101 + i*2
		q.Members[i].GrantSHA256 = "sha256:" + strings.Repeat(string(rune('a'+i)), 64)
	}
	encode := func() []byte {
		t.Helper()
		raw, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := ParseStage2aMemberChildObservationRequest(encode()); err != nil {
		t.Fatal(err)
	}
	q.Members[1].ChildPID = q.Members[0].ChildPID
	if _, err := ParseStage2aMemberChildObservationRequest(encode()); err == nil {
		t.Fatal("shared child PID accepted")
	}
	q.Members[1].ChildPID = 103
	q.Members[1].ChildLauncherPID = q.Members[0].ChildLauncherPID
	if _, err := ParseStage2aMemberChildObservationRequest(encode()); err == nil {
		t.Fatal("shared launcher PID accepted")
	}
	q.Members[1].ChildLauncherPID = 102
	q.Members[1].MemberID = "m_lead"
	if _, err := ParseStage2aMemberChildObservationRequest(encode()); err == nil {
		t.Fatal("duplicate member accepted")
	}
}
