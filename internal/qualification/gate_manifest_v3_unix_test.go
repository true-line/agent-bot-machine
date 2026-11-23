//go:build darwin || linux

package qualification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveSignedGateManifestsV3RequiresExactObjects(t *testing.T) {
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
	policy := VerifiedPolicy{value: p, verified: true, at: now, version: 3}
	raw, err := os.ReadFile("testdata/stage2a-report-v3-protected-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	paths := make(map[string]string)
	objectRef := func(role, label string) gateObjectRefV3 {
		sha := digest([]byte(label))
		return gateObjectRefV3{Role: role, URI: gateObjectPrefixV3 + "blob/" + strings.TrimPrefix(sha, "sha256:"),
			SHA256: sha, SizeBytes: int64(len(label)), Issuer: "fixture-machine"}
	}
	for _, gate := range []string{"T01", "T02", "T03"} {
		segmentID := "fixture-segment-" + gate
		object, err := canonicalMarshalRecordV3(gateManifestV3{
			SchemaVersion: 1, Kind: "stage2a-physical-gate-manifest", Gate: gate,
			Profile: "managed-protected", HostID: "fixture-physical-mac", CohortID: "fixture-cohort",
			SuiteRevision: strings.Repeat("a", 40), OwnerPlanSHA256: "sha256:" + strings.Repeat("d", 64),
			PrimaryMeasurementBindingSHA256: "sha256:" + strings.Repeat("e", 64),
			PrimarySegmentID:                segmentID, SharedHostObservation: objectRef("host-observation", "host"),
			Segments: []gateSegmentV3{{Sequence: 0, SegmentID: segmentID, Purpose: "initial", ReportAnchor: gate == "T01",
				SegmentManifest:    objectRef("segment-manifest", gate+"-manifest"),
				SegmentAttestation: objectRef("segment-attestation", gate+"-attestation")}},
			Attempts: []gateAttemptV3{},
		})
		if err != nil {
			t.Fatal(err)
		}
		sha := digest(object)
		name := strings.TrimPrefix(sha, "sha256:")
		parent := filepath.Join(root, "objects", "sha256", name[:2])
		if err := os.MkdirAll(parent, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, name)
		if err := os.WriteFile(path, object, 0600); err != nil {
			t.Fatal(err)
		}
		paths[gate] = path
		document["gates"].(map[string]any)[gate].(map[string]any)["evidence"] = map[string]any{
			"uri": gateObjectPrefixV3 + "gate-manifest/" + name, "sha256": sha,
		}
	}
	report, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	envelope := signedReportV3(t, report, key)
	objects, err := ResolveSignedGateManifestsV3(envelope, policy, root, now)
	if err != nil || len(objects) != 3 {
		t.Fatalf("signed gate objects: %v %v", objects, err)
	}
	if parsed, err := parseGateManifestV3(objects["T03"]); err != nil || parsed.Gate != "T03" {
		t.Fatalf("wrong resolved gate: %+v %v", parsed, err)
	}
	for label, change := range map[string]func(map[string]any){
		"wrong profile":   func(m map[string]any) { m["profile"] = "managed-cooperative" },
		"unknown field":   func(m map[string]any) { m["approved"] = true },
		"missing primary": func(m map[string]any) { m["primary_segment_id"] = "other-segment" },
		"sequence gap": func(m map[string]any) {
			m["segments"].([]any)[0].(map[string]any)["sequence"] = float64(1)
		},
		"external raw ref": func(m map[string]any) {
			m["shared_host_observation"].(map[string]any)["uri"] = "file:///tmp/host"
		},
	} {
		t.Run(label, func(t *testing.T) {
			var changed map[string]any
			if err := json.Unmarshal(objects["T03"], &changed); err != nil {
				t.Fatal(err)
			}
			change(changed)
			candidate, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseGateManifestV3(candidate); err == nil {
				t.Fatal("malformed gate manifest accepted")
			}
		})
	}
	var duplicateAnchor map[string]any
	if err := json.Unmarshal(objects["T02"], &duplicateAnchor); err != nil {
		t.Fatal(err)
	}
	duplicateAnchor["segments"].([]any)[0].(map[string]any)["report_anchor"] = true
	secondAnchor, err := json.Marshal(duplicateAnchor)
	if err != nil {
		t.Fatal(err)
	}
	secondSHA := digest(secondAnchor)
	secondName := strings.TrimPrefix(secondSHA, "sha256:")
	secondParent := filepath.Join(root, "objects", "sha256", secondName[:2])
	if err := os.MkdirAll(secondParent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondParent, secondName), secondAnchor, 0600); err != nil {
		t.Fatal(err)
	}
	document["gates"].(map[string]any)["T02"].(map[string]any)["evidence"] = map[string]any{
		"uri": gateObjectPrefixV3 + "gate-manifest/" + secondName, "sha256": secondSHA,
	}
	twoAnchorReport, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHostReportV3(signedReportV3(t, twoAnchorReport, key), policy, now); err != nil {
		t.Fatalf("two-anchor report must pass host signature and shape: %v", err)
	}
	if _, err := ResolveSignedGateManifestsV3(signedReportV3(t, twoAnchorReport, key), policy, root, now); err == nil {
		t.Fatal("two signed report anchors accepted")
	}
	storeVariant := func(raw []byte) reportReference {
		sha := digest(raw)
		name := strings.TrimPrefix(sha, "sha256:")
		parent := filepath.Join(root, "objects", "sha256", name[:2])
		if err := os.MkdirAll(parent, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(parent, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return reportReference{URI: gateObjectPrefixV3 + "gate-manifest/" + name, SHA256: sha}
	}
	for label, change := range map[string]func(map[string]any){
		"other cohort":     func(m map[string]any) { m["cohort_id"] = "other-cohort" },
		"other owner plan": func(m map[string]any) { m["owner_plan_sha256"] = "sha256:" + strings.Repeat("1", 64) },
		"other shared host": func(m map[string]any) {
			sha := digest([]byte("other-host"))
			m["shared_host_observation"] = map[string]any{"role": "host-observation",
				"uri":    gateObjectPrefixV3 + "blob/" + strings.TrimPrefix(sha, "sha256:"),
				"sha256": sha, "size_bytes": 10, "issuer": "fixture-machine"}
		},
	} {
		t.Run(label, func(t *testing.T) {
			var changed map[string]any
			if err := json.Unmarshal(objects["T02"], &changed); err != nil {
				t.Fatal(err)
			}
			change(changed)
			candidate, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseGateManifestV3(candidate); err != nil {
				t.Fatalf("variant should be locally valid: %v", err)
			}
			var reportVariant map[string]any
			if err := json.Unmarshal(report, &reportVariant); err != nil {
				t.Fatal(err)
			}
			reportVariant["gates"].(map[string]any)["T02"].(map[string]any)["evidence"] = storeVariant(candidate)
			variantBytes, err := json.Marshal(reportVariant)
			if err != nil {
				t.Fatal(err)
			}
			variantBytes, err = canonicalizeRecordV3(variantBytes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyHostReportV3(signedReportV3(t, variantBytes, key), policy, now); err != nil {
				t.Fatalf("cross-gate variant must pass host signature and shape: %v", err)
			}
			if _, err := ResolveSignedGateManifestsV3(signedReportV3(t, variantBytes, key), policy, root, now); err == nil {
				t.Fatal("cross-gate mismatch accepted")
			}
		})
	}
	var attemptReport map[string]any
	if err := json.Unmarshal(report, &attemptReport); err != nil {
		t.Fatal(err)
	}
	for _, gate := range []string{"T01", "T02"} {
		var changed map[string]any
		if err := json.Unmarshal(objects[gate], &changed); err != nil {
			t.Fatal(err)
		}
		changed["attempts"] = []any{map[string]any{"sequence": 0, "attempt_id": "reused-attempt",
			"purpose": "negative", "refusal": objectRef("refusal", gate+"-refusal"),
			"terminal_state": objectRef("terminal-state", gate+"-terminal")}}
		candidate, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err = canonicalizeRecordV3(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseGateManifestV3(candidate); err != nil {
			t.Fatalf("attempt variant should be locally valid: %v", err)
		}
		attemptReport["gates"].(map[string]any)[gate].(map[string]any)["evidence"] = storeVariant(candidate)
	}
	attemptBytes, err := json.Marshal(attemptReport)
	if err != nil {
		t.Fatal(err)
	}
	attemptBytes, err = canonicalizeRecordV3(attemptBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHostReportV3(signedReportV3(t, attemptBytes, key), policy, now); err != nil {
		t.Fatalf("attempt variant must pass host signature and shape: %v", err)
	}
	if _, err := ResolveSignedGateManifestsV3(signedReportV3(t, attemptBytes, key), policy, root, now); err == nil {
		t.Fatal("pre-reservation attempt reused across gates")
	}
	if err := os.WriteFile(paths["T02"], []byte(`{"gate":"T01"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSignedGateManifestsV3(envelope, policy, root, now); err == nil {
		t.Fatal("changed referenced gate bytes accepted")
	}
	if err := os.Remove(paths["T03"]); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSignedGateManifestsV3(envelope, policy, root, now); err == nil {
		t.Fatal("missing referenced gate accepted")
	}
}
