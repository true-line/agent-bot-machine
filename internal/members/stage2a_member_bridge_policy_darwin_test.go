//go:build darwin

package members

import (
	"strings"
	"testing"
)

func TestStage2aTwoMemberBridgePolicyMustBeExplicitlyOwnerReviewed(t *testing.T) {
	base := Stage2aBridgeQualification{Model: "fixture-model",
		RequestSHA256:   "sha256:" + strings.Repeat("a", 64),
		HeadersSHA256:   "sha256:" + strings.Repeat("b", 64),
		ClientKeySHA256: stage2aFixtureClientKeySHA256,
		HTTPHost:        "fixture.invalid", MessagesQuery: "v=1", ResponseText: "ok"}
	row := func(id string) stage2aMemberBridgeQualification {
		return stage2aMemberBridgeQualification{MemberID: id, Model: base.Model,
			RequestSHA256: base.RequestSHA256, HeadersSHA256: base.HeadersSHA256,
			ClientKeySHA256: base.ClientKeySHA256, HTTPHost: base.HTTPHost,
			MessagesQuery: base.MessagesQuery, ResponseText: base.ResponseText}
	}
	roles := []stage2aHelloMember{{MemberID: "m_lead"}, {MemberID: "m_spec"}}
	rows := []stage2aMemberBridgeQualification{row("m_lead"), row("m_spec")}
	if !stage2aMemberBridgeQualificationsMatchRoles(rows, roles, base) {
		t.Fatal("two explicit owner-reviewed stock policy rows refused")
	}
	if stage2aMemberBridgeQualificationsMatchRoles(rows[:1], roles, base) {
		t.Fatal("one global policy row treated as two member authorities")
	}
	rows[1].MemberID = "m_lead"
	if stage2aMemberBridgeQualificationsMatchRoles(rows, roles, base) {
		t.Fatal("duplicate member policy row accepted")
	}
	rows[1] = row("m_spec")
	rows[1].RequestSHA256 = "sha256:" + strings.Repeat("c", 64)
	if stage2aMemberBridgeQualificationsMatchRoles(rows, roles, base) {
		t.Fatal("unreviewed per-member request policy accepted")
	}
}
