//go:build darwin

package members

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aMemberSetAssignmentRequiresExactPairedSelectors(t *testing.T) {
	q := Stage2aStopRequest{ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID: "inst_0123456789abcdef", StartID: "st_0123456789abcdef01234567",
		LaunchID: "ln_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64)}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseStage2aMemberSetAssignmentRequest(raw)
	if err != nil || got != q {
		t.Fatalf("exact paired selectors refused: %+v %v", got, err)
	}
	unknown := bytes.Replace(raw, []byte(`{"reservation_sha256":`), []byte(`{"unreviewed":true,"reservation_sha256":`), 1)
	if _, err := ParseStage2aMemberSetAssignmentRequest(unknown); err == nil {
		t.Fatal("unreviewed selector field accepted")
	}
	if _, err := ParseStage2aMemberSetAssignmentRequest([]byte(`{"reservation_sha256":"sha256:` + strings.Repeat("a", 64) + `","reservation_sha256":"sha256:` + strings.Repeat("a", 64) + `"}`)); err == nil {
		t.Fatal("duplicate selector accepted")
	}
	if _, err := NewStage2aService(nil).MemberSetAssign(310, q.HQEpoch, q); err == nil {
		t.Fatal("unreserved assignment signed")
	}
}

func TestStage2aMemberSelectorUsesContractPreimage(t *testing.T) {
	got := stage2aMemberSelector("sha256:"+strings.Repeat("a", 64), "m_lead", "ln_0123456789abcdef01234567")
	if len(got) != 67 || !strings.HasPrefix(got, "mb_") ||
		got == stage2aMemberSelector("sha256:"+strings.Repeat("a", 64), "m_spec", "ln_0123456789abcdef01234567") ||
		got == stage2aMemberSelector("sha256:"+strings.Repeat("b", 64), "m_lead", "ln_0123456789abcdef01234567") {
		t.Fatal("member selector did not bind reservation and member")
	}
	if got := stage2aMemberSelector("sha256:2fcf23c02b279b697825fd0b7fd60b742171bcd3d68194b3cbe3d6b6121fc2aa",
		"m_lead", "ln_0123456789abcdef01234567");
		got != "mb_4093be8cfbe94a55dca9044f834637679d5d41dee5662d1771183a65404f2abd" {
		t.Fatalf("selector differs from Contracts #85: %s", got)
	}
}
