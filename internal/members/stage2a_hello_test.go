package members

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func stage2aHelloTestSelectors() Stage2aStopRequest {
	return Stage2aStopRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID:    "soul-one", StartID: "st_0123456789abcdef01234567",
		LaunchID: "ln_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64),
	}
}

func TestStage2aHelloStartRejectsChangedOrNoncanonicalHQBytes(t *testing.T) {
	claim := map[string]any{
		"contract": "hq/v1", "request_id": "req_01234567",
		"soul_id":           "agent_01234567-0123-0123-0123-0123456789ab",
		"definition_digest": "sha256:" + strings.Repeat("d", 64),
		"installation_id":   "soul-one", "requested_profile": "managed-protected",
		"requested_roles": []any{map[string]any{"member_id": "member-a", "role": "worker"}},
	}
	raw, _ := json.Marshal(claim)
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := Stage2aHelloStartRequest{Stage2aStopRequest: stage2aHelloTestSelectors(),
		PeerUID: 501, PeerPID: 12345, HelloPayloadBase64URL: base64.RawURLEncoding.EncodeToString(canonical),
		HelloPayloadSHA256:      fmt.Sprintf("sha256:%x", sha256.Sum256(canonical)),
		BrokerBindReceiptSHA256: "sha256:" + strings.Repeat("e", 64)}
	encoded, _ := json.Marshal(q)
	if _, err := ParseStage2aHelloStartRequest(encoded); err != nil {
		t.Fatalf("canonical Hello refused: %v", err)
	}
	mutations := []Stage2aHelloStartRequest{q, q, q, q}
	mutations[0].PeerPID = 0
	mutations[1].HelloPayloadSHA256 = "sha256:" + strings.Repeat("f", 64)
	mutations[2].HelloPayloadBase64URL += "="
	mutations[3].HelloPayloadBase64URL = base64.RawURLEncoding.EncodeToString(append([]byte(" "), canonical...))
	mutations[3].HelloPayloadSHA256 = fmt.Sprintf("sha256:%x", sha256.Sum256(append([]byte(" "), canonical...)))
	for _, bad := range mutations {
		raw, _ := json.Marshal(bad)
		if _, err := ParseStage2aHelloStartRequest(raw); err == nil {
			t.Fatal("changed peer, digest or canonical bytes accepted")
		}
	}
	unknown := append(encoded[:len(encoded)-1:len(encoded)-1], []byte(`,"peer_role":"runner"}`)...)
	if _, err := ParseStage2aHelloStartRequest(unknown); err == nil {
		t.Fatal("caller-supplied role accepted")
	}
}

func TestStage2aHelloFinalizationRequiresExactSortedRuntimeTuple(t *testing.T) {
	q := Stage2aHelloFinalizeRequest{Stage2aStopRequest: stage2aHelloTestSelectors(),
		StartEnvelopeSHA256: "sha256:" + strings.Repeat("d", 64),
		Expected: Stage2aHelloExpected{
			ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
			StartID:           "st_0123456789abcdef01234567", LaunchID: "ln_0123456789abcdef01234567",
			HQEpoch: strings.Repeat("c", 64), SoulID: "agent_01234567-0123-0123-0123-0123456789ab",
			InstallationID: "soul-one", DefinitionDigest: "sha256:" + strings.Repeat("d", 64),
			DefinitionMeasurement:  "sha256:" + strings.Repeat("e", 64),
			LaunchInputMeasurement: "sha256:" + strings.Repeat("f", 64),
			HelloPayloadSHA256:     "sha256:" + strings.Repeat("1", 64),
			AdmissionDecisionID:    "dec_01234567", InstallationEpoch: 1,
			ProfileInForce: "managed-protected", HQBrokerBindReceiptSHA256: "sha256:" + strings.Repeat("2", 64),
			AdmittedRuntimes: []Stage2aHelloRuntime{
				{MemberID: "a", RuntimeID: "rt_aaaaaaaa", ProfileInForce: "managed-protected"},
				{MemberID: "b", RuntimeID: "rt_bbbbbbbb", ProfileInForce: "managed-protected"},
			},
		}}
	raw, _ := json.Marshal(q)
	if _, err := ParseStage2aHelloFinalizeRequest(raw); err != nil {
		t.Fatalf("valid full tuple refused: %v", err)
	}
	q.Expected.AdmittedRuntimes[0], q.Expected.AdmittedRuntimes[1] = q.Expected.AdmittedRuntimes[1], q.Expected.AdmittedRuntimes[0]
	raw, _ = json.Marshal(q)
	if _, err := ParseStage2aHelloFinalizeRequest(raw); err == nil {
		t.Fatal("unordered runtimes accepted")
	}
	q.Expected.AdmittedRuntimes[0], q.Expected.AdmittedRuntimes[1] = q.Expected.AdmittedRuntimes[1], q.Expected.AdmittedRuntimes[0]
	q.Expected.AdmittedRuntimes[1].RuntimeID = q.Expected.AdmittedRuntimes[0].RuntimeID
	raw, _ = json.Marshal(q)
	if _, err := ParseStage2aHelloFinalizeRequest(raw); err == nil {
		t.Fatal("duplicate runtime ID accepted")
	}
}

func TestStage2aHelloFinalizationMatchesHQV1DecisionFixture(t *testing.T) {
	// Copied unchanged from soul-contracts fixtures/positive/admission-result.ok.json
	// at contract revision 3eadde87; HQ validates and emits this integer shape.
	raw, err := os.ReadFile("testdata/stage2a-hq-v1-admission-result-ok.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Input struct {
			DecisionID        string `json:"decision_id"`
			InstallationEpoch int64  `json:"installation_epoch"`
			Profile           string `json:"profile"`
			AdmittedRuntimes  []struct {
				MemberID  string `json:"member_id"`
				RuntimeID string `json:"runtime_id"`
			} `json:"admitted_runtimes"`
		} `json:"input"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	q := Stage2aHelloFinalizeRequest{Stage2aStopRequest: stage2aHelloTestSelectors(),
		StartEnvelopeSHA256: "sha256:" + strings.Repeat("d", 64)}
	q.Expected = Stage2aHelloExpected{
		ReservationSHA256: q.ReservationSHA256, StartID: q.StartID, LaunchID: q.LaunchID,
		HQEpoch: q.HQEpoch, SoulID: "agent_0b3f1e2a-7c4d-4e8f-9a1b-2c3d4e5f6a7b",
		InstallationID: q.InstallationID, DefinitionDigest: "sha256:" + strings.Repeat("a", 64),
		DefinitionMeasurement:     "sha256:" + strings.Repeat("b", 64),
		LaunchInputMeasurement:    "sha256:" + strings.Repeat("c", 64),
		HelloPayloadSHA256:        "sha256:" + strings.Repeat("e", 64),
		AdmissionDecisionID:       fixture.Input.DecisionID,
		InstallationEpoch:         fixture.Input.InstallationEpoch,
		ProfileInForce:            fixture.Input.Profile,
		HQBrokerBindReceiptSHA256: "sha256:" + strings.Repeat("f", 64),
	}
	for _, rt := range fixture.Input.AdmittedRuntimes {
		q.Expected.AdmittedRuntimes = append(q.Expected.AdmittedRuntimes,
			Stage2aHelloRuntime{MemberID: rt.MemberID, RuntimeID: rt.RuntimeID,
				ProfileInForce: fixture.Input.Profile})
	}
	encoded, _ := json.Marshal(q)
	if _, err := ParseStage2aHelloFinalizeRequest(encoded); err != nil {
		t.Fatalf("HQ v1 decision fixture refused: %v", err)
	}
}
