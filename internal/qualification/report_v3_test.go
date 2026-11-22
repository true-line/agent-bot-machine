package qualification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func signedReportV3(t *testing.T, raw []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	sum := sha256.Sum256(preimage(HostPurposeV3, raw))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	envelope, err := json.Marshal(Envelope{
		SchemaVersion: 3, Purpose: HostPurposeV3, HostID: "fixture-physical-mac",
		SignerID: "fixture-signer", ReportSHA256: digest(raw),
		ReportBase64URL:    base64.RawURLEncoding.EncodeToString(raw),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestMeasuredHostReportV3ProfileAndBinding(t *testing.T) {
	now := time.Date(2026, 11, 22, 7, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p, _, _ := fixturePolicy(t, now)
	p.EvidenceSigners[0].HostID = "fixture-physical-mac"
	p.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	verified := VerifiedPolicy{value: p, verified: true, at: now, version: 2}
	for _, name := range []string{"protected", "cooperative"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/stage2a-report-v3-" + name + "-synthetic.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := canonicalBytes(raw, MaxReportBytes); err != nil {
				t.Fatal("contract vector is not canonical:", err)
			}
			envelope := signedReportV3(t, raw, key)
			if _, err := VerifyHostReportV3(envelope, verified, now); err != nil {
				t.Fatal("valid synthetic v3 signature and shape refused:", err)
			}
			if _, err := VerifyHostReportV2(envelope, verified, now); err == nil {
				t.Fatal("v3 accepted as v2")
			}
			legacy := verified
			legacy.version = 1
			if _, err := VerifyHostReportV3(envelope, legacy, now); err == nil {
				t.Fatal("v1 owner policy accepted for v3")
			}
			var original map[string]any
			if json.Unmarshal(raw, &original) != nil {
				t.Fatal("contract vector cannot decode")
			}
			for _, tc := range []struct {
				label string
				edit  func(map[string]any)
			}{
				{"missing binding", func(v map[string]any) { delete(v, "measurement_binding") }},
				{"other host", func(v map[string]any) { v["measurement_binding"].(map[string]any)["host_id"] = "other-host" }},
				{"missing Soul artifact", func(v map[string]any) {
					delete(v["measurement_binding"].(map[string]any), "soul_artifact_sha256")
				}},
				{"malformed Soul artifact", func(v map[string]any) {
					v["measurement_binding"].(map[string]any)["soul_artifact_sha256"] = "sha256:" + strings.Repeat("f", 64)
				}},
				{"wrong profile", func(v map[string]any) { v["measurement_binding"].(map[string]any)["profile_in_force"] = "other" }},
				{"snapshot alias", func(v map[string]any) {
					s := v["measurement_binding"].(map[string]any)["snapshots"].(map[string]any)
					s["launch_inputs"].(map[string]any)["root_path"] = s["definition"].(map[string]any)["root_path"]
				}},
				{"missing finalization", func(v map[string]any) { delete(v["run_evidence"].(map[string]any), "finalization") }},
				{"reservation and finalization same URI", func(v map[string]any) {
					run := v["run_evidence"].(map[string]any)
					run["finalization"].(map[string]any)["uri"] = run["reservation"].(map[string]any)["uri"]
				}},
				{"reservation and finalization same bytes", func(v map[string]any) {
					run := v["run_evidence"].(map[string]any)
					run["finalization"].(map[string]any)["sha256"] = run["reservation"].(map[string]any)["sha256"]
				}},
				{"extra completed digest", func(v map[string]any) {
					v["run_evidence"].(map[string]any)["completed_run"] = map[string]any{"uri": "fixture:bogus", "sha256": "sha256:" + strings.Repeat("f", 64)}
				}},
				{"unexpected field", func(v map[string]any) { v["approved"] = true }},
			} {
				t.Run(tc.label, func(t *testing.T) {
					var changed map[string]any
					if json.Unmarshal(raw, &changed) != nil {
						t.Fatal("decode")
					}
					tc.edit(changed)
					candidate, err := json.Marshal(changed)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := VerifyHostReportV3(signedReportV3(t, candidate, key), verified, now); err == nil {
						t.Fatal("signed inconsistent report accepted")
					}
				})
			}
			if name == "protected" {
				var changed map[string]any
				json.Unmarshal(raw, &changed)
				changed["bridge"].(map[string]any)["assignment"].(map[string]any)["start_id"] = "st_" + strings.Repeat("f", 24)
				candidate, _ := json.Marshal(changed)
				if _, err := VerifyHostReportV3(signedReportV3(t, candidate, key), verified, now); err == nil {
					t.Fatal("bridge start differs from measured binding")
				}
			} else {
				var changed map[string]any
				json.Unmarshal(raw, &changed)
				changed["gates"] = map[string]any{"T01": map[string]any{"outcome": "pass", "evidence": map[string]any{"uri": "fixture:wrong", "sha256": "sha256:" + strings.Repeat("f", 64)}}}
				candidate, _ := json.Marshal(changed)
				if _, err := VerifyHostReportV3(signedReportV3(t, candidate, key), verified, now); err == nil {
					t.Fatal("cooperative report substituted protected gate")
				}
			}
		})
	}
}
