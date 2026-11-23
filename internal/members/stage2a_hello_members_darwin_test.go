//go:build darwin

package members

import (
	"encoding/json"
	"testing"
)

func TestStage2aHelloMembersMustMatchFrozenTwoMemberSoul(t *testing.T) {
	const soulID = "agent_0b3f1e2a-7c4d-4e8f-9a1b-2c3d4e5f6a7b"
	lead := stage2aHelloMember{MemberID: "m_lead", Role: "lead", AdapterID: "claude-code", AdapterVersion: "0.109.0"}
	spec := stage2aHelloMember{MemberID: "m_spec", Role: "specialist", AdapterID: "claude-code", AdapterVersion: "0.109.0"}
	frozen, err := json.Marshal(struct {
		SoulID  string               `json:"soul_id"`
		Members []stage2aHelloMember `json:"members"`
	}{soulID, []stage2aHelloMember{lead, spec}})
	if err != nil {
		t.Fatal(err)
	}
	if !stage2aHelloMembersMatch(frozen, soulID, []stage2aHelloMember{spec, lead}) {
		t.Fatal("same frozen member set in a different Hello order refused")
	}
	mutations := map[string][]stage2aHelloMember{
		"missing member":   {lead},
		"duplicate member": {lead, lead},
		"wrong role":       {lead, {MemberID: spec.MemberID, Role: "lead", AdapterID: spec.AdapterID, AdapterVersion: spec.AdapterVersion}},
		"wrong adapter":    {lead, {MemberID: spec.MemberID, Role: spec.Role, AdapterID: "other", AdapterVersion: spec.AdapterVersion}},
		"wrong version":    {lead, {MemberID: spec.MemberID, Role: spec.Role, AdapterID: spec.AdapterID, AdapterVersion: "0.110.0"}},
	}
	for name, members := range mutations {
		if stage2aHelloMembersMatch(frozen, soulID, members) {
			t.Errorf("%s accepted", name)
		}
	}
	if stage2aHelloMembersMatch(frozen, "agent_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", []stage2aHelloMember{lead, spec}) {
		t.Fatal("different Soul identity accepted")
	}
	if stage2aHelloMembersMatch([]byte(`{"soul_id":"`+soulID+`","members":[],"members":[]}`), soulID,
		[]stage2aHelloMember{lead, spec}) {
		t.Fatal("duplicate frozen key accepted")
	}
}
