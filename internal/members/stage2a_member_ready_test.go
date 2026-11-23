package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemberReadyRequestRequiresTwoExactArmExchanges(t *testing.T) {
	q := Stage2aMemberReadyRequest{Stage2aStopRequest: stage2aHelloTestSelectors(),
		ChildObservationEnvelopeSHA256: "sha256:" + strings.Repeat("a", 64),
		MemberBAuthorityEnvelopeSHA256: "sha256:" + strings.Repeat("b", 64)}
	q.Arms = make([]struct {
		ArmRequest json.RawMessage `json:"arm_request"`
		ArmResult  json.RawMessage `json:"arm_result"`
	}, 2)
	for i := range q.Arms {
		q.Arms[i].ArmRequest = json.RawMessage(`{"kind":"bridge.member.arm.v3.request"}`)
		q.Arms[i].ArmResult = json.RawMessage(`{"kind":"bridge.member.arm.v3.result"}`)
	}
	encode := func() []byte {
		t.Helper()
		raw, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := ParseStage2aMemberReadyRequest(encode()); err != nil {
		t.Fatal(err)
	}
	q.Arms = q.Arms[:1]
	if _, err := ParseStage2aMemberReadyRequest(encode()); err == nil {
		t.Fatal("one B arm accepted as aggregate Ready")
	}
	q.Arms = append(q.Arms, q.Arms[0], q.Arms[0])
	if _, err := ParseStage2aMemberReadyRequest(encode()); err == nil {
		t.Fatal("extra B arm accepted")
	}
	q.Arms = q.Arms[:2]
	q.ChildObservationEnvelopeSHA256 = "sha256:" + strings.Repeat("z", 64)
	if _, err := ParseStage2aMemberReadyRequest(encode()); err == nil {
		t.Fatal("invalid A observation digest accepted")
	}
}
