package qualification

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func cooperativeTestJCSV3(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestCooperativeReportReservationJoinV3ContractVector(t *testing.T) {
	fixture, err := os.ReadFile("testdata/stage2a-cooperative-reservation-v3-contract-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var wrapper map[string]json.RawMessage
	if json.Unmarshal(fixture, &wrapper) != nil {
		t.Fatal("invalid Contracts #74 synthetic fixture")
	}
	envelope, err := jsoncanonicalizer.Transform(wrapper["input"])
	if err != nil {
		t.Fatal(err)
	}
	var signed machineRecordV3
	if json.Unmarshal(envelope, &signed) != nil {
		t.Fatal("invalid cooperative envelope")
	}
	key, err := base64.RawURLEncoding.DecodeString(signed.IssuerPublicKeyBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := qSignedRecordV3(envelope, cooperativeReservationPurposeV3, 3, key)
	if err != nil {
		t.Fatal("rejected Contracts #74 signed synthetic vector:", err)
	}
	var reservation map[string]any
	if json.Unmarshal(payload, &reservation) != nil {
		t.Fatal("invalid cooperative payload")
	}
	bindingRaw := cooperativeTestJCSV3(t, reservation["measurement_binding"])
	bindingFields, err := canonicalBytes(bindingRaw, MaxReportBytes)
	if err != nil {
		t.Fatal(err)
	}
	projection, _, err := commonReportProjectionV3(bindingFields)
	if err != nil {
		t.Fatal(err)
	}
	sample, err := os.ReadFile("testdata/stage2a-candidate-host-summary-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if json.Unmarshal(sample, &report) != nil {
		t.Fatal("invalid host summary")
	}
	report["measurement_binding"] = json.RawMessage(projection)
	report["profile_in_force"] = "managed-cooperative"
	report["host"] = map[string]any{"id": "synthetic-host"}
	report["recorded_at"] = reservation["expires_at"]
	run := report["run_evidence"].(map[string]any)
	run["reservation"].(map[string]any)["sha256"] = digest(envelope)
	reportRaw := cooperativeTestJCSV3(t, report)
	if err := cooperativeReportJoinV3(reportRaw, envelope, key); err != nil {
		t.Fatal("rejected signed cooperative Contracts vector and matching host summary:", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"other host":        func(r map[string]any) { r["host"].(map[string]any)["id"] = "other-host" },
		"protected profile": func(r map[string]any) { r["profile_in_force"] = "managed-protected" },
		"bridge claim":      func(r map[string]any) { r["bridge"] = map[string]any{"principals": map[string]any{}} },
		"other reservation": func(r map[string]any) {
			r["run_evidence"].(map[string]any)["reservation"].(map[string]any)["sha256"] =
				"sha256:0000000000000000000000000000000000000000000000000000000000000000"
		},
		"other adapter": func(r map[string]any) {
			r["adapter"].(map[string]any)["package_sha256"] =
				"sha256:0000000000000000000000000000000000000000000000000000000000000000"
		},
		"other code input": func(r map[string]any) {
			r["launch"].(map[string]any)["code_inputs"].([]any)[0].(map[string]any)["path"] =
				"/private/var/db/managed-machine/soul-snapshots/r_wrong/adapter/library.mjs"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed map[string]any
			if json.Unmarshal(reportRaw, &changed) != nil {
				t.Fatal("invalid report")
			}
			mutate(changed)
			if err := cooperativeReportJoinV3(cooperativeTestJCSV3(t, changed), envelope, key); err == nil {
				t.Fatal("accepted changed host report")
			}
		})
	}
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	for name, mutate := range map[string]func(map[string]any){
		"runner substitution": func(p map[string]any) {
			p["assignment"].(map[string]any)["runner_uid"] = float64(332)
		},
		"broker peer substitution": func(p map[string]any) {
			p["endpoints"].(map[string]any)["broker"].(map[string]any)["expected_peer_uid"] = float64(332)
		},
		"R root substitution": func(p map[string]any) {
			p["assignment"].(map[string]any)["runtime_root"] = "/private/var/db/managed-machine/soul-snapshots/r_wrong"
		},
		"H owner substitution": func(p map[string]any) {
			p["endpoints"].(map[string]any)["broker"].(map[string]any)["owner_uid"] = float64(310)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed map[string]any
			if json.Unmarshal(payload, &changed) != nil {
				t.Fatal("invalid payload")
			}
			mutate(changed)
			changedPayload := cooperativeTestJCSV3(t, changed)
			changedEnvelope := cooperativeTestJCSV3(t, machineRecordV3{
				SchemaVersion:            3,
				Purpose:                  cooperativeReservationPurposeV3,
				IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(public),
				PayloadSHA256:            digest(changedPayload),
				PayloadBase64URL:         base64.RawURLEncoding.EncodeToString(changedPayload),
				SignatureBase64URL: base64.RawURLEncoding.EncodeToString(
					ed25519.Sign(private, preimage(cooperativeReservationPurposeV3, changedPayload))),
			})
			var matching map[string]any
			if json.Unmarshal(reportRaw, &matching) != nil {
				t.Fatal("invalid report")
			}
			matching["run_evidence"].(map[string]any)["reservation"].(map[string]any)["sha256"] = digest(changedEnvelope)
			if err := cooperativeReportJoinV3(cooperativeTestJCSV3(t, matching), changedEnvelope, public); err == nil {
				t.Fatal("accepted signed cooperative identity substitution")
			}
		})
	}
	var wrongPurpose map[string]any
	if json.Unmarshal(envelope, &wrongPurpose) != nil {
		t.Fatal("invalid envelope")
	}
	wrongPurpose["purpose"] = "agent-bot/stage2a-reservation/v3"
	if err := cooperativeReportJoinV3(reportRaw, cooperativeTestJCSV3(t, wrongPurpose), key); err == nil {
		t.Fatal("accepted protected reservation purpose in cooperative join")
	}
}
