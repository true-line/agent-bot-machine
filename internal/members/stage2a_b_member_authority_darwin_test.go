//go:build darwin

package members

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStage2aBMemberFD3CarriesExactSignedEnvelopeDigests(t *testing.T) {
	var assigned stage2aMemberSetAssignmentPayload
	assigned.InstallationID, assigned.StartID = "inst_0123456789abcdef", "st_0123456789abcdef01234567"
	assigned.PlanID, assigned.PlanDigest = "plan-20261122T120000Z-abcd", strings.Repeat("a", 64)
	assigned.ReservationSHA256, assigned.HQEpoch = "sha256:"+strings.Repeat("b", 64), strings.Repeat("c", 64)
	assigned.Members[0].MemberID, assigned.Members[1].MemberID = "m_lead", "m_spec"
	assigned.Members[0].MemberSelector = "mb_" + strings.Repeat("d", 64)
	assigned.Members[1].MemberSelector = "mb_" + strings.Repeat("e", 64)
	legacy := stage2aNativeAssignment{BridgeUID: 331, HQUID: 309, RunnerUID: 330}
	legacy.Broker.Path, legacy.Relay.Path = "/reviewed/broker.sock", "/reviewed/relay.sock"
	assignmentEnvelope, authorityEnvelope := []byte("signed-assignment-fixture"), []byte("signed-authority-fixture")
	raw, err := stage2aMarshalBMemberFD3(assigned, assignmentEnvelope, authorityEnvelope,
		legacy, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("bounded B FD3 refused: %v", err)
	}
	var got stage2aNativeMemberAssignment
	if json.Unmarshal(raw, &got) != nil || got.Version != "stage2a-b-assignment/v3" ||
		got.MachinePinPath != SoulAuthorityPin ||
		got.AssignmentEnvelopeBase64URL != base64.RawURLEncoding.EncodeToString(assignmentEnvelope) ||
		got.AuthorityEnvelopeBase64URL != base64.RawURLEncoding.EncodeToString(authorityEnvelope) ||
		got.Selectors.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(assignmentEnvelope) ||
		got.Selectors.AuthorityEnvelopeSHA256 != stage2aReservationSHA256(authorityEnvelope) ||
		got.Selectors.ReservationDigest != assigned.ReservationSHA256 ||
		got.Broker.Path != legacy.Broker.Path || got.Relay.Path != legacy.Relay.Path {
		t.Fatalf("B FD3 lost signed provenance or measured endpoint identity: %+v", got)
	}
	selectors, _ := marshalStage2aReservationJCS([]string{assigned.Members[0].MemberSelector, assigned.Members[1].MemberSelector})
	if got.Selectors.MemberSelectorsSHA256 != stage2aReservationSHA256(selectors) {
		t.Fatal("B FD3 did not bind the exact sorted selector set")
	}
	assigned.Members[1].MemberSelector = assigned.Members[0].MemberSelector
	if _, err := stage2aMarshalBMemberFD3(assigned, assignmentEnvelope, authorityEnvelope,
		legacy, time.Now().Add(5*time.Second)); err == nil {
		t.Fatal("duplicate member selector accepted")
	}
}
