//go:build darwin || linux

package qualification

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedProtectedReportCohortV3(t *testing.T) {
	for _, name := range []string{"same cohort", "changed H", "changed R", "changed broker", "cross purpose", "altered projection", "altered raw binding digest"} {
		t.Run(name, func(t *testing.T) { checkSignedProtectedReportCohortV3(t, name) })
	}
}

func checkSignedProtectedReportCohortV3(t *testing.T, scenario string) {
	now := time.Date(2026, 11, 22, 12, 0, 10, 0, time.UTC)
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&hostKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p, _, _ := fixturePolicy(t, now)
	p.EvidenceSigners[0].HostID = "fixture-physical-mac"
	p.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	policy := VerifiedPolicy{value: p, verified: true, at: now, version: 3}
	reportRaw, err := os.ReadFile("testdata/stage2a-report-v3-protected-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(reportRaw, &report); err != nil {
		t.Fatal(err)
	}
	bindingRaw, err := os.ReadFile("testdata/stage2a-hr-binding-v3-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(bindingRaw, &binding); err != nil {
		t.Fatal(err)
	}
	base := report["measurement_binding"].(map[string]any)
	base["plan_id"] = "plan-20261122T120000Z-abcd"
	report["bridge"].(map[string]any)["assignment"].(map[string]any)["plan_id"] = base["plan_id"]
	for _, name := range candidateCommonBindingFieldsV3 {
		if name != "contract" && name != "kind" && name != "schema_version" {
			binding[name] = base[name]
		}
	}
	inv := binding["r_inventory"].(map[string]any)
	inv["installation_id"] = binding["installation_id"]
	inv["owner_plan_digest"] = "sha256:" + binding["installed_plan_digest"].(string)
	inv["machine_uid"] = float64(500)
	inv["reader_gid"] = float64(703)
	rootPath, sidecarPath := hrInventoryNamesV3(binding["installation_id"].(string))
	for _, item := range []struct{ name, path string }{{"snapshot", rootPath}, {"sidecar", sidecarPath}} {
		row := inv[item.name].(map[string]any)
		row["path"] = item.path
		row["owner_uid"] = float64(500)
		row["owner_gid"] = float64(703)
	}
	adapter := binding["adapter_release"].(map[string]any)
	adapter["executable_path"] = rootPath + "/adapter"
	if _, err := parseHRMeasurementBindingV3(qJSONFixtureV3(t, binding)); err != nil {
		t.Fatalf("aggregate binding: %v", err)
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("a", ed25519.SeedSize)))
	root := t.TempDir()
	store := func(role string, raw []byte) gateObjectRefV3 { return qWriteBlobFixtureV3(t, root, role, raw) }
	read := func(f protectedSegmentFixtureV3, ref gateObjectRefV3) []byte {
		name := strings.TrimPrefix(ref.SHA256, "sha256:")
		raw, err := os.ReadFile(filepath.Join(f.root, "objects", "sha256", name[:2], name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	clone := func() map[string]any {
		var out map[string]any
		if err := json.Unmarshal(qJSONFixtureV3(t, binding), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	report["suite_revision"] = strings.Repeat("1", 40)
	for i, gateName := range []string{"T01", "T02", "T03"} {
		b := clone()
		if i > 0 {
			b["start_id"] = fmt.Sprintf("st_%024x", i)
			b["launch_id"] = fmt.Sprintf("ln_%024x", i)
		}
		candidate := false
		if i == 2 {
			switch scenario {
			case "changed H":
				b["h_service_descriptor_digest"] = digest([]byte("other H"))
			case "changed R":
				b["r_inventory"].(map[string]any)["snapshot"].(map[string]any)["inode"] = "999999"
			case "changed broker":
				b["broker_executable"].(map[string]any)["sha256"] = digest([]byte("other broker"))
			case "cross purpose":
				candidate = true
				b["kind"] = "stage2a-qualification-candidate-binding"
				a := b["adapter_release"].(map[string]any)
				delete(a, "release_attestation_sha256")
				a["candidate_manifest_sha256"] = a["release_manifest_sha256"]
				delete(a, "release_manifest_sha256")
				b["candidate_adapter"] = a
				delete(b, "adapter_release")
			}
		}
		cfg := &qAggregateConfigV3{private: key, binding: b, session: fmt.Sprintf("%032x", i+1), candidate: candidate}
		f := makeProtectedSegmentWithConfigV3(t, true, true, cfg, 331, 332)
		// Preserve each exact content-addressed object under the common root.
		for role, ref := range f.refs {
			store(role, read(f, ref))
		}
		var manifest physicalSegmentV3
		if err := json.Unmarshal(read(f, f.segment.SegmentManifest), &manifest); err != nil {
			t.Fatal(err)
		}
		manifest.Gate = gateName
		manifest.SegmentID = "fixture-segment-" + gateName
		manifest.ReportAnchor = i == 0
		if i == 2 && scenario == "altered raw binding digest" {
			manifest.MeasurementBindingSHA256 = digest([]byte("forged binding"))
		}
		manifestRaw := qJSONFixtureV3(t, manifest)
		manifestRef := store("segment_manifest", manifestRaw)
		attRaw, err := qSignedRecordV3(read(f, f.segment.SegmentAttestation), physicalSegmentPurposeV3, 1, f.key)
		if err != nil {
			t.Fatal(err)
		}
		var att physicalSegmentAttestationV3
		if err := json.Unmarshal(attRaw, &att); err != nil {
			t.Fatal(err)
		}
		att.Gate = gateName
		att.SegmentID = manifest.SegmentID
		att.ReportAnchor = i == 0
		att.SegmentManifestSHA256 = digest(manifestRaw)
		attRef := store("segment_attestation", qSignFixtureV3(t, att, physicalSegmentPurposeV3, 1, key))
		gate := f.gate
		gate.Gate = gateName
		gate.PrimarySegmentID = manifest.SegmentID
		if i == 2 && scenario == "altered raw binding digest" {
			gate.PrimaryMeasurementBindingSHA256 = manifest.MeasurementBindingSHA256
		}
		gate.SharedHostObservation = store("host-observation", []byte("same host"))
		gate.Segments = []gateSegmentV3{{Sequence: 0, SegmentID: manifest.SegmentID, Purpose: "initial", ReportAnchor: i == 0, SegmentManifest: manifestRef, SegmentAttestation: attRef}}
		gate.Attempts = []gateAttemptV3{}
		gateRaw := qJSONFixtureV3(t, gate)
		gateRef := store("gate-manifest", gateRaw)
		report["gates"].(map[string]any)[gateName].(map[string]any)["evidence"] = map[string]any{"uri": gateObjectPrefixV3 + "gate-manifest/" + strings.TrimPrefix(gateRef.SHA256, "sha256:"), "sha256": gateRef.SHA256}
		if i == 0 {
			run := report["run_evidence"].(map[string]any)
			run["reservation"].(map[string]any)["sha256"] = f.refs["reservation"].SHA256
			run["finalization"].(map[string]any)["sha256"] = f.refs["b_finalization"].SHA256
			run["challenge_sha256"] = digest([]byte("launch challenge"))
			report["bridge"].(map[string]any)["assignment"].(map[string]any)["machine_reservation_sha256"] = f.refs["reservation"].SHA256
		}
	}
	if scenario == "altered projection" {
		// Epoch is intentionally excluded from the cross-start cohort comparison;
		// changing it in the signed report must still fail the anchor projection.
		report["measurement_binding"].(map[string]any)["hq_epoch"] = strings.Repeat("a", 64)
	}
	envelope := signedReportV3(t, qJSONFixtureV3(t, report), hostKey)
	if _, err := VerifyHostReportV3(envelope, policy, now); err != nil {
		t.Fatalf("host report: %v", err)
	}
	gates, err := ResolveSignedGateManifestsV3(envelope, policy, root, now)
	if err != nil {
		t.Fatalf("gate manifests: %v", err)
	}
	for name, raw := range gates {
		gate, err := parseGateManifestV3(raw)
		if err != nil {
			t.Fatal(err)
		}
		seg := gate.Segments[0]
		mraw, err := physicalSegmentObjectV3(root, seg.SegmentManifest, "segment_manifest", maxGateManifestBytesV3)
		if err != nil {
			t.Fatalf("manifest object %s: %v", name, err)
		}
		m, err := parseProtectedSegmentV3(mraw, gate, seg)
		if err != nil {
			t.Fatalf("manifest parse %s: %v", name, err)
		}
		objects := map[string][]byte{}
		for _, role := range protectedSegmentRolesV3 {
			objects[role], err = physicalSegmentObjectV3(root, m.Artifacts[role], role, segmentRoleMaxV3(role))
			if err != nil {
				t.Fatalf("object %s %s: %v", name, role, err)
			}
		}
		chain, err := verifyProtectedAChainV3(objects["reservation"], objects["b_finalization"], objects["stop"], m, key.Public().(ed25519.PublicKey))
		if scenario == "altered raw binding digest" && name == "T03" {
			if err == nil {
				t.Fatal("changed raw digest accepted")
			}
			continue
		}
		if err != nil {
			t.Fatalf("chain %s: %v", name, err)
		}
		q, err := VerifyQPreSignV3(objects["q_wire"], objects["q_index"], objects["q_eof"], objects["reservation"], key.Public().(ed25519.PublicKey), now)
		if err != nil {
			t.Fatalf("Q %s: %v", name, err)
		}
		att, err := physicalSegmentObjectV3(root, seg.SegmentAttestation, "segment_attestation", 64<<10)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyPhysicalAttestationV3(att, mraw, m, chain, q, m.Artifacts, objects["q_eof"], key.Public().(ed25519.PublicKey), now); err != nil {
			t.Fatalf("attestation %s: %v", name, err)
		}
		if _, err := resolveProtectedSegmentV3(root, gate, seg, key.Public().(ed25519.PublicKey), now); err != nil {
			t.Fatalf("segment %s: %v", name, err)
		}
	}
	_, err = ResolveSignedProtectedSegmentsV3(envelope, policy, root, key.Public().(ed25519.PublicKey), now)
	if scenario == "same cohort" && err != nil {
		t.Fatalf("signed three-gate v3 cohort: %v", err)
	}
	if scenario != "same cohort" && err == nil {
		t.Fatalf("%s accepted", scenario)
	}
}
