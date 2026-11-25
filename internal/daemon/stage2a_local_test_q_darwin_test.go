//go:build darwin

package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwts/managed-machine/internal/members"
)

func TestStage2aLocalTestQDistinctPairedVerbs(t *testing.T) {
	if !pairedServiceVerb(members.Stage2aLocalTestQPurpose) ||
		!knownVerb(members.Stage2aLocalTestQPurpose) || isStage2aVerb(members.Stage2aLocalTestQPurpose) {
		t.Fatal("Q owner approval does not use its distinct paired challenge")
	}
	if !isStage2aVerb(stage2aLocalTestQIssueVerb) || !knownVerb(stage2aLocalTestQIssueVerb) ||
		pairedServiceVerb(stage2aLocalTestQIssueVerb) {
		t.Fatal("Q signing verb is not separated from owner approval")
	}
	for _, selector := range []string{
		`{"plan_id":"plan-20261124T120001Z-abcd"}`,
	} {
		req := Request{Verb: stage2aLocalTestQIssueVerb,
			Stage2aRequest: base64.RawURLEncoding.EncodeToString([]byte(selector))}
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if id, _ := stage2aFields(&req, raw); id != "" ||
			req.stage2aLocalTestQPlanID != "plan-20261124T120001Z-abcd" {
			t.Fatalf("valid Q selector refused: %q", id)
		}
	}
	for _, selector := range []string{
		`{}`, `{"plan_id":"../other"}`,
		`{"plan_id":"plan-20261124T120001Z-abcd","path":"/tmp/other"}`,
		`{"plan_id":"plan-20261124T120001Z-abcd","plan_id":"plan-20261124T120002Z-abcd"}`,
	} {
		req := Request{Verb: stage2aLocalTestQIssueVerb,
			Stage2aRequest: base64.RawURLEncoding.EncodeToString([]byte(selector))}
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if id, _ := stage2aFields(&req, raw); id == "" {
			t.Fatalf("unreviewed Q selector accepted: %s", selector)
		}
	}
	service := members.NewStage2aService(ed25519.NewKeyFromSeed(make([]byte, 32)))
	if _, err := service.IssueLocalTestQApproval(309, strings.Repeat("a", 64),
		"plan-20261124T120001Z-abcd"); err == nil {
		t.Fatal("generic service issued a Q approval without production pair guard")
	}
}
