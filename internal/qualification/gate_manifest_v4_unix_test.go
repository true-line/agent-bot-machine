//go:build darwin || linux

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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveSignedGateManifestsV4RequiresExactObjects(t *testing.T) {
	now := time.Date(2026, 11, 22, 14, 17, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p, _, _ := fixturePolicy(t, now)
	p.EvidenceSigners[0].HostID = "synthetic-host"
	p.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	policy := VerifiedPolicy{value: p, verified: true, at: now, version: 3}
	vectorsRaw, err := os.ReadFile("testdata/stage2a-v4-completion-contracts83.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]struct {
		Report string `json:"report_jcs"`
	}
	if json.Unmarshal(vectorsRaw, &vectors) != nil {
		t.Fatal("v4 report vectors unavailable")
	}
	sign := func(t *testing.T, report []byte) []byte {
		t.Helper()
		sum := sha256.Sum256(preimage(HostPurposeV4, report))
		r, s, signErr := ecdsa.Sign(rand.Reader, key, sum[:])
		if signErr != nil {
			t.Fatal(signErr)
		}
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		envelope, marshalErr := canonicalMarshalRecordV3(Envelope{
			SchemaVersion: 4, Purpose: HostPurposeV4, HostID: "synthetic-host",
			SignerID: p.EvidenceSigners[0].ID, ReportSHA256: digest(report),
			ReportBase64URL:    base64.RawURLEncoding.EncodeToString(report),
			SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return envelope
	}
	objectRef := func(role, label string) gateObjectRefV3 {
		sha := digest([]byte(label))
		return gateObjectRefV3{Role: role,
			URI:    gateObjectPrefixV3 + "blob/" + strings.TrimPrefix(sha, "sha256:"),
			SHA256: sha, SizeBytes: int64(len(label)), Issuer: "fixture-machine"}
	}
	for _, test := range []struct {
		name  string
		gates []string
	}{
		{"protected", []string{"T01", "T02", "T03"}},
		{"cooperative", []string{"T21"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var document map[string]any
			if json.Unmarshal([]byte(vectors[test.name].Report), &document) != nil {
				t.Fatal("v4 report vector unavailable")
			}
			root := t.TempDir()
			var firstPath string
			for index, gate := range test.gates {
				segmentID := "fixture-segment-" + gate
				object, marshalErr := canonicalMarshalRecordV3(gateManifestV3{
					SchemaVersion: 1, Kind: "stage2a-physical-gate-manifest", Gate: gate,
					Profile: document["profile_in_force"].(string), HostID: "synthetic-host",
					CohortID: "fixture-cohort", SuiteRevision: strings.Repeat("a", 40),
					OwnerPlanSHA256:                 "sha256:" + strings.Repeat("d", 64),
					PrimaryMeasurementBindingSHA256: "sha256:" + strings.Repeat("e", 64),
					PrimarySegmentID:                segmentID,
					SharedHostObservation:           objectRef("host-observation", "host"),
					Segments: []gateSegmentV3{{Sequence: 0, SegmentID: segmentID,
						Purpose: "initial", ReportAnchor: index == 0,
						SegmentManifest:    objectRef("segment-manifest", gate+"-manifest"),
						SegmentAttestation: objectRef("segment-attestation", gate+"-attestation")}},
					Attempts: []gateAttemptV3{},
				})
				if marshalErr != nil {
					t.Fatal(marshalErr)
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
				if index == 0 {
					firstPath = path
				}
				document["gates"].(map[string]any)[gate].(map[string]any)["evidence"] = map[string]any{
					"uri": gateObjectPrefixV3 + "gate-manifest/" + name, "sha256": sha,
				}
			}
			report, err := canonicalMarshalRecordV3(document)
			if err != nil {
				t.Fatal(err)
			}
			envelope := sign(t, report)
			if _, err := VerifyHostReportV4(envelope, policy, now); err != nil {
				t.Fatal("valid v4 host report refused:", err)
			}
			objects, err := ResolveSignedGateManifestsV4(envelope, policy, root, now)
			if err != nil || len(objects) != len(test.gates) {
				t.Fatalf("v4 gate manifests not resolved: %v, %v", objects, err)
			}
			first := test.gates[0]
			document["gates"].(map[string]any)[first].(map[string]any)["evidence"].(map[string]any)["uri"] = "file:///tmp/forged-gate"
			wrongReport, err := canonicalMarshalRecordV3(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ResolveSignedGateManifestsV4(sign(t, wrongReport), policy, root, now); err == nil {
				t.Fatal("external gate-manifest URI accepted")
			}
			if err := os.WriteFile(firstPath, []byte("changed gate bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ResolveSignedGateManifestsV4(envelope, policy, root, now); err == nil {
				t.Fatal("changed gate-manifest bytes accepted")
			}
		})
	}
}
