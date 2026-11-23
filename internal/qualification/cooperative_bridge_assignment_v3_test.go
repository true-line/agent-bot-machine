package qualification

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type cooperativeBridgeFixtureV3 struct {
	IssuerPublicKeyBase64URL string `json:"issuer_public_key_base64url"`
	ReservationEnvelopeJCS   string `json:"reservation_envelope_jcs"`
	BridgeEnvelopeJCS        string `json:"bridge_envelope_jcs"`
}

func TestCooperativeBridgeAssignmentV3ContractsVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-cooperative-b-v3-contract-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture cooperativeBridgeFixtureV3
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid synthetic Contracts B vector")
	}
	key, err := base64.RawURLEncoding.DecodeString(fixture.IssuerPublicKeyBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCooperativeBridgeAssignmentV3([]byte(fixture.ReservationEnvelopeJCS),
		[]byte(fixture.BridgeEnvelopeJCS), key)
	if err != nil || !got.verified || got.ReservationSHA256 != digest([]byte(fixture.ReservationEnvelopeJCS)) ||
		got.AssignmentSHA256 != digest([]byte(fixture.BridgeEnvelopeJCS)) ||
		got.BridgeUID != 333 || got.RunnerUID != 331 || got.InstallationID != "inst_0000000000000001" {
		t.Fatalf("refused signed B vector or lost identity: %+v %v", got, err)
	}
	wrong := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := VerifyCooperativeBridgeAssignmentV3([]byte(fixture.ReservationEnvelopeJCS),
		[]byte(fixture.BridgeEnvelopeJCS), wrong); err == nil {
		t.Fatal("accepted unpinned Machine key")
	}
	if _, err := VerifyCooperativeBridgeAssignmentV3([]byte(fixture.ReservationEnvelopeJCS), nil, key); err == nil {
		t.Fatal("accepted missing private B assignment")
	}
}

func TestCooperativeBridgeAssignmentV3CoherentlySignedRefusals(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-cooperative-b-v3-contract-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture cooperativeBridgeFixtureV3
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid synthetic Contracts B vector")
	}
	decodePayload := func(envelope string) map[string]any {
		t.Helper()
		var signed machineRecordV3
		if json.Unmarshal([]byte(envelope), &signed) != nil {
			t.Fatal("invalid fixture envelope")
		}
		payload, err := base64.RawURLEncoding.DecodeString(signed.PayloadBase64URL)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if json.Unmarshal(payload, &value) != nil {
			t.Fatal("invalid fixture payload")
		}
		return value
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	sign := func(payload map[string]any, purpose string) []byte {
		t.Helper()
		payloadRaw := cooperativeTestJCSV3(t, payload)
		return cooperativeTestJCSV3(t, machineRecordV3{
			SchemaVersion: 3, Purpose: purpose,
			IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(public),
			PayloadSHA256:            digest(payloadRaw),
			PayloadBase64URL:         base64.RawURLEncoding.EncodeToString(payloadRaw),
			SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(private, preimage(purpose, payloadRaw))),
		})
	}
	makePair := func(mutate func(map[string]any, map[string]any)) ([]byte, []byte) {
		t.Helper()
		primary := decodePayload(fixture.ReservationEnvelopeJCS)
		assignment := decodePayload(fixture.BridgeEnvelopeJCS)
		if mutate != nil {
			mutate(primary, assignment)
		}
		bridgeRaw := cooperativeTestJCSV3(t, assignment["bridge"])
		primary["bridge_launch_sha256"] = digest(bridgeRaw)
		assignment["bridge_launch_sha256"] = digest(bridgeRaw)
		reservation := sign(primary, cooperativeReservationPurposeV3)
		assignment["reservation_sha256"] = digest(reservation)
		return reservation, sign(assignment, cooperativeBridgeAssignmentPurposeV3)
	}
	goodPrimary, goodAssignment := makePair(nil)
	if _, err := VerifyCooperativeBridgeAssignmentV3(goodPrimary, goodAssignment, public); err != nil {
		t.Fatal("refused coherently re-signed valid B chain:", err)
	}
	for name, mutate := range map[string]func(map[string]any, map[string]any){
		"direct transport substitution": func(primary, _ map[string]any) {
			primary["adapter_transport"] = "direct-comms"
		},
		"out-of-range B UID": func(_, assignment map[string]any) {
			bridge := assignment["bridge"].(map[string]any)
			bridge["uid"], bridge["gid"] = float64(602), float64(602)
		},
		"root HQ UID": func(primary, _ map[string]any) {
			primary["assignment"].(map[string]any)["hq_uid"] = float64(0)
			primary["endpoints"].(map[string]any)["admission"].(map[string]any)["owner_uid"] = float64(0)
		},
		"chosen B account": func(_, assignment map[string]any) {
			assignment["bridge"].(map[string]any)["account"] = "_abm-br-chosen"
		},
		"altered B argv": func(_, assignment map[string]any) {
			assignment["bridge"].(map[string]any)["argv"].([]any)[0] = "/usr/bin/false"
		},
		"changed broker path": func(_, assignment map[string]any) {
			assignment["endpoints"].(map[string]any)["broker"].(map[string]any)["socket_path"] = "/tmp/broker.sock"
		},
		"changed member peer on both envelopes": func(primary, assignment map[string]any) {
			primary["endpoints"].(map[string]any)["member"].(map[string]any)["expected_peer_uid"] = float64(331)
			assignment["endpoints"].(map[string]any)["member"].(map[string]any)["expected_peer_uid"] = float64(331)
		},
		"extra private field": func(_, assignment map[string]any) {
			assignment["unreviewed"] = true
		},
		"provider config digest": func(primary, _ map[string]any) {
			primary["qualification_provider"].(map[string]any)["config_sha256"] =
				"sha256:0000000000000000000000000000000000000000000000000000000000000000"
		},
	} {
		t.Run(name, func(t *testing.T) {
			primary, assignment := makePair(mutate)
			if _, err := VerifyCooperativeBridgeAssignmentV3(primary, assignment, public); err == nil {
				t.Fatal("accepted coherently signed invalid B chain")
			}
		})
	}
	var wrongPurpose map[string]any
	if json.Unmarshal(goodAssignment, &wrongPurpose) != nil {
		t.Fatal("invalid signed assignment")
	}
	wrongPurpose["purpose"] = cooperativeReservationPurposeV3
	if _, err := VerifyCooperativeBridgeAssignmentV3(goodPrimary,
		cooperativeTestJCSV3(t, wrongPurpose), public); err == nil {
		t.Fatal("accepted primary purpose substituted for private B assignment")
	}
}
