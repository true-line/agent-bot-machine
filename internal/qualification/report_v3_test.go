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
	return signedReportV3ForHost(t, raw, key, "fixture-physical-mac")
}

func signedReportV3ForHost(t *testing.T, raw []byte, key *ecdsa.PrivateKey, hostID string) []byte {
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
		SchemaVersion: 3, Purpose: HostPurposeV3, HostID: hostID,
		SignerID: "fixture-signer", ReportSHA256: digest(raw),
		ReportBase64URL:    base64.RawURLEncoding.EncodeToString(raw),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestDesignatedHostSignerV3Gate(t *testing.T) {
	now := time.Date(2026, 11, 22, 7, 0, 0, 0, time.UTC)
	p, _, _ := fixturePolicy(t, now)
	verified := VerifiedPolicy{value: p, verified: true, at: now, version: 3}
	signer := p.EvidenceSigners[0]
	if err := CheckDesignatedHostSignerV3(verified, signer.HostID, signer.ID, now); err != nil {
		t.Fatal("designated signer refused", err)
	}
	for _, tc := range []struct{ host, signer string }{
		{"other-host", signer.ID}, {signer.HostID, "other-signer"},
	} {
		if CheckDesignatedHostSignerV3(verified, tc.host, tc.signer, now) == nil {
			t.Fatal("undesigned host or signer authorized")
		}
	}
	if CheckDesignatedHostSignerV3(verified, signer.HostID, signer.ID, now.Add(time.Second)) == nil {
		t.Fatal("stale owner policy authorized")
	}
	legacy := verified
	legacy.version = 2
	if CheckDesignatedHostSignerV3(legacy, signer.HostID, signer.ID, now) == nil {
		t.Fatal("v2 policy authorized v3 report signer")
	}
	revoked := verified
	revoked.value.RevocationSnapshot.RevokedEvidenceSignerIDs = []string{signer.ID}
	if CheckDesignatedHostSignerV3(revoked, signer.HostID, signer.ID, now) == nil {
		t.Fatal("revoked signer authorized")
	}
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
	verified := VerifiedPolicy{value: p, verified: true, at: now, version: 3}
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
			var wrongHost map[string]any
			if err := json.Unmarshal(raw, &wrongHost); err != nil {
				t.Fatal(err)
			}
			wrongHost["host"].(map[string]any)["id"] = "other-host"
			wrongHost["measurement_binding"].(map[string]any)["host_id"] = "other-host"
			wrongHostRaw, err := json.Marshal(wrongHost)
			if err != nil {
				t.Fatal(err)
			}
			if err := reportShapeV3(wrongHostRaw); err != nil {
				t.Fatal("coherent wrong-host report failed shape gate:", err)
			}
			if _, err := VerifyHostReportV3(signedReportV3ForHost(t, wrongHostRaw, key, "other-host"), verified, now); err == nil {
				t.Fatal("designated signer authorized a coherent other-host report")
			}
			if _, err := VerifyHostReportV2(envelope, verified, now); err == nil {
				t.Fatal("v3 accepted as v2")
			}
			legacy := verified
			legacy.version = 2
			if _, err := VerifyHostReportV3(envelope, legacy, now); err == nil {
				t.Fatal("v2 owner policy accepted for v3")
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
				{"root binding downgrade", func(v map[string]any) {
					binding := v["measurement_binding"].(map[string]any)
					binding["contract"] = "machine/v1"
					binding["schema_version"] = float64(1)
				}},
				{"mixed admin owner", func(v map[string]any) {
					v["measurement_binding"].(map[string]any)["snapshots"].(map[string]any)["definition"].(map[string]any)["owner_uid"] = float64(0)
				}},
				{"system account owner", func(v map[string]any) {
					s := v["measurement_binding"].(map[string]any)["snapshots"].(map[string]any)
					s["definition"].(map[string]any)["owner_uid"] = float64(399)
					s["launch_inputs"].(map[string]any)["owner_uid"] = float64(399)
				}},
				{"mixed runner read group", func(v map[string]any) {
					v["measurement_binding"].(map[string]any)["snapshots"].(map[string]any)["launch_inputs"].(map[string]any)["owner_gid"] = float64(705)
				}},
				{"admin writable snapshot", func(v map[string]any) {
					v["measurement_binding"].(map[string]any)["snapshots"].(map[string]any)["definition"].(map[string]any)["mode"] = "0750"
				}},
				{"wrong read-only mode", func(v map[string]any) {
					v["measurement_binding"].(map[string]any)["snapshots"].(map[string]any)["definition"].(map[string]any)["mode"] = "0444"
				}},
				{"overflow snapshot device", func(v map[string]any) {
					v["measurement_binding"].(map[string]any)["snapshots"].(map[string]any)["definition"].(map[string]any)["device"] = "18446744073709551616"
				}},
				{"snapshot alias", func(v map[string]any) {
					s := v["measurement_binding"].(map[string]any)["snapshots"].(map[string]any)
					s["launch_inputs"].(map[string]any)["root_path"] = s["definition"].(map[string]any)["root_path"]
				}},
				{"missing finalization", func(v map[string]any) { delete(v["run_evidence"].(map[string]any), "finalization") }},
				{"missing execution completion", func(v map[string]any) { delete(v["run_evidence"].(map[string]any), "execution_completion") }},
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
				{"nonlocal gate manifest", func(v map[string]any) {
					gate := "T21"
					if name == "protected" {
						gate = "T01"
					}
					v["gates"].(map[string]any)[gate].(map[string]any)["evidence"].(map[string]any)["uri"] = "fixture:unresolved-gate"
				}},
				{"gate digest and URI disagree", func(v map[string]any) {
					gate := "T21"
					if name == "protected" {
						gate = "T01"
					}
					v["gates"].(map[string]any)[gate].(map[string]any)["evidence"].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("0", 64)
				}},
				{"unexpected field", func(v map[string]any) { v["approved"] = true }},
				{"numeric render", func(v map[string]any) { v["renders"] = []any{7} }},
				{"duplicate render", func(v map[string]any) { v["renders"] = []any{"instructions", "instructions"} }},
				{"invalid render name", func(v map[string]any) { v["renders"] = []any{"bad/render"} }},
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
				var duplicate map[string]any
				json.Unmarshal(raw, &duplicate)
				duplicateGates := duplicate["gates"].(map[string]any)
				duplicateGates["T02"].(map[string]any)["evidence"] = duplicateGates["T01"].(map[string]any)["evidence"]
				duplicateRaw, _ := json.Marshal(duplicate)
				if _, err := VerifyHostReportV3(signedReportV3(t, duplicateRaw, key), verified, now); err == nil {
					t.Fatal("signed protected report reused a gate manifest")
				}
				var changed map[string]any
				json.Unmarshal(raw, &changed)
				changed["bridge"].(map[string]any)["principals"].(map[string]any)["machine_uid"] = float64(0)
				candidate, _ := json.Marshal(changed)
				if _, err := VerifyHostReportV3(signedReportV3(t, candidate, key), verified, now); err == nil {
					t.Fatal("bridge Machine UID differs from A snapshot owner")
				}
				changed = nil
				json.Unmarshal(raw, &changed)
				s := changed["measurement_binding"].(map[string]any)["snapshots"].(map[string]any)
				s["definition"].(map[string]any)["owner_gid"] = float64(704)
				s["launch_inputs"].(map[string]any)["owner_gid"] = float64(704)
				candidate, _ = json.Marshal(changed)
				if _, err := VerifyHostReportV3(signedReportV3(t, candidate, key), verified, now); err == nil {
					t.Fatal("snapshot group differs from runner primary group")
				}
				changed = nil
				json.Unmarshal(raw, &changed)
				changed["bridge"].(map[string]any)["assignment"].(map[string]any)["start_id"] = "st_" + strings.Repeat("f", 24)
				candidate, _ = json.Marshal(changed)
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
