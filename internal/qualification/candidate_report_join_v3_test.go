package qualification

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestCandidateReportReservationJoinV3ProducerVector(t *testing.T) {
	vector, err := os.ReadFile("testdata/stage2a-candidate-v3-contract-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ReservationEnvelopeJCS string `json:"reservation_envelope_jcs"`
	}
	if json.Unmarshal(vector, &v) != nil {
		t.Fatal("invalid Contracts v0.9.0 reservation fixture")
	}
	var envelope machineRecordV3
	if json.Unmarshal([]byte(v.ReservationEnvelopeJCS), &envelope) != nil {
		t.Fatal("invalid signed reservation fixture")
	}
	key, err := base64.RawURLEncoding.DecodeString(envelope.IssuerPublicKeyBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	sample, err := os.ReadFile("testdata/stage2a-candidate-host-summary-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	report, err := jsoncanonicalizer.Transform(sample)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidateReportJoinV3(report, []byte(v.ReservationEnvelopeJCS), key); err != nil {
		t.Fatal("rejected paired H and Contracts producer vectors:", err)
	}
	var withPrincipals map[string]any
	if json.Unmarshal(report, &withPrincipals) != nil {
		t.Fatal("invalid H producer sample")
	}
	withPrincipals["host"] = map[string]any{"id": "synthetic-host"}
	withPrincipals["bridge"] = map[string]any{"principals": map[string]any{
		"machine_uid": float64(501), "runner_uid": float64(331), "runner_private_gid": float64(331),
	}}
	fullSummary, err := json.Marshal(withPrincipals)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidateReportJoinV3(fullSummary, []byte(v.ReservationEnvelopeJCS), key); err != nil {
		t.Fatal("rejected matching host and runner principals:", err)
	}
	withPrincipals["bridge"].(map[string]any)["principals"].(map[string]any)["runner_uid"] = float64(332)
	wrongRunner, err := json.Marshal(withPrincipals)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidateReportJoinV3(wrongRunner, []byte(v.ReservationEnvelopeJCS), key); err == nil {
		t.Fatal("accepted R reader substitution for report runner")
	}
	for name, mutate := range map[string]func(map[string]any){
		"other reservation": func(r map[string]any) {
			r["run_evidence"].(map[string]any)["reservation"].(map[string]any)["sha256"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		},
		"other challenge": func(r map[string]any) {
			r["run_evidence"].(map[string]any)["challenge_sha256"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		},
		"other adapter": func(r map[string]any) {
			r["adapter"].(map[string]any)["package_sha256"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		},
		"other Soul": func(r map[string]any) {
			r["measurement_binding"].(map[string]any)["soul_id"] = "agent_aaaaaaaa-1234-1234-1234-1234567890ab"
		},
		"other code input": func(r map[string]any) {
			r["launch"].(map[string]any)["code_inputs"].([]any)[0].(map[string]any)["path"] = "/private/var/db/managed-machine/soul-snapshots/r_wrong/file"
		},
		"cooperative profile": func(r map[string]any) { r["profile_in_force"] = "managed-cooperative" },
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if json.Unmarshal(report, &value) != nil {
				t.Fatal("invalid H producer sample")
			}
			mutate(value)
			changed, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := candidateReportJoinV3(changed, []byte(v.ReservationEnvelopeJCS), key); err == nil {
				t.Fatal("accepted changed report/reservation join")
			}
		})
	}
}
