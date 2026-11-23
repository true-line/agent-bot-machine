package qualification

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type protectedSegmentFixtureV3 struct {
	root    string
	gate    gateManifestV3
	segment gateSegmentV3
	key     ed25519.PublicKey
	now     qFixtureV3
	refs    map[string]gateObjectRefV3
}

func qWriteBlobFixtureV3(t *testing.T, root, role string, raw []byte) gateObjectRefV3 {
	t.Helper()
	sha := digest(raw)
	name := strings.TrimPrefix(sha, "sha256:")
	dir := filepath.Join(root, "objects", "sha256", name[:2])
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return gateObjectRefV3{Role: role, URI: gateObjectPrefixV3 + "blob/" + name, SHA256: sha, SizeBytes: int64(len(raw)), Issuer: "machine-a"}
}

func makeProtectedSegmentFixtureV3(t *testing.T, stopIdle bool, attestationQDigestMatches bool, roleUIDs ...int) protectedSegmentFixtureV3 {
	t.Helper()
	runnerUID, bridgeUID := 310, 311
	if len(roleUIDs) == 2 {
		runnerUID, bridgeUID = roleUIDs[0], roleUIDs[1]
	} else if len(roleUIDs) != 0 {
		t.Fatal("role UID fixture requires both R and B")
	}
	q := makeQFixtureV3(t, 1, true, true, runnerUID, bridgeUID)
	const installation = "fixture-install"
	const soul = "agent_12345678-1234-1234-1234-1234567890ab"
	const start = "st_1234567890abcdef12345678"
	const launch = "ln_1234567890abcdef12345678"
	const plan = "plan-20261122T120000Z-abcd"
	const planDigest = "1111111111111111111111111111111111111111111111111111111111111111"
	const epoch = "2222222222222222222222222222222222222222222222222222222222222222"
	const session = "1234567890abcdef1234567890abcdef"
	const suite = "1111111111111111111111111111111111111111"
	reservationPayload, err := qSignedRecordV3(q.reservation, qReservationPurposeV3, 2, q.key)
	if err != nil {
		t.Fatal(err)
	}
	reservationFields, err := strictObject(reservationPayload, 48<<10)
	if err != nil {
		t.Fatal(err)
	}
	bindingSHA := digest(reservationFields["measurement_binding"])
	finalization := qSignFixtureV3(t, map[string]any{
		"schema":             "agent-bot-machine/stage2a-finalization/v1",
		"reservation_sha256": digest(q.reservation), "installation_id": installation,
		"start_id": start, "launch_id": launch, "plan_id": plan, "plan_digest": planDigest,
		"hq_epoch": epoch, "bridge_pid": 813, "finalized_at": "2026-11-22T11:59:55Z",
		"bind_receipt_sha256": digest([]byte("B bind")), "relay_socket": map[string]any{"path": "/tmp/relay", "socket": map[string]any{}},
	}, "agent-bot/stage2a-finalization/v1", 1, q.private)
	stop := qSignFixtureV3(t, map[string]any{
		"schema":             "agent-bot-machine/stage2a-stop/v1",
		"reservation_sha256": digest(q.reservation), "installation_id": installation,
		"start_id": start, "launch_id": launch, "plan_id": plan, "plan_digest": planDigest,
		"hq_epoch": epoch, "runner_uid": runnerUID, "bridge_uid": bridgeUID, "runner_pid": 812, "bridge_pid": 813,
		"both_uids_idle": stopIdle, "stopped_at": "2026-11-22T12:00:03Z",
	}, "agent-bot/stage2a-stop/v1", 1, q.private)
	root := t.TempDir()
	objects := map[string][]byte{
		"reservation": q.reservation, "b_finalization": finalization, "stop": stop,
		"q_wire": q.wire, "q_index": q.index, "q_eof": q.eof,
		"owner_acp_to_hq":  []byte("fixture owner ACP capture"),
		"hq_acp_to_owner":  []byte("fixture HQ ACP capture"),
		"os_observation":   []byte("fixture OS observation"),
		"installed_inputs": []byte("fixture installed inventory"),
	}
	refs := make(map[string]gateObjectRefV3, len(objects))
	for role, raw := range objects {
		refs[role] = qWriteBlobFixtureV3(t, root, role, raw)
	}
	ownerPlan := digest([]byte("owner plan"))
	manifest := physicalSegmentV3{
		SchemaVersion: 1, Kind: "stage2a-physical-segment", Gate: "T01", Profile: "managed-protected",
		HostID: "fixture-host", CohortID: "fixture-cohort", SuiteRevision: suite,
		OwnerPlanSHA256: ownerPlan, SegmentID: "fixture-segment", Purpose: "initial", ReportAnchor: true,
		TerminalState: "stopped", InstallationID: installation, SoulID: soul, StartID: start, LaunchID: launch,
		MeasurementBindingSHA256: bindingSHA, QSessionStatus: "completed", QSessionID: session,
		QChallengeSHA256: digest([]byte(strings.Repeat("B", 32))), Artifacts: refs,
	}
	// The Q challenge is 32 bytes of 0x42 ('B') in the Q fixture.
	manifestRaw := qJSONFixtureV3(t, manifest)
	manifestRef := qWriteBlobFixtureV3(t, root, "segment_manifest", manifestRaw)
	qWireSHA := refs["q_wire"].SHA256
	if !attestationQDigestMatches {
		qWireSHA = digest([]byte("other wire"))
	}
	attest := physicalSegmentAttestationV3{
		SchemaVersion: 1, Kind: "stage2a-physical-segment-attestation", Gate: manifest.Gate,
		Profile: manifest.Profile, HostID: manifest.HostID, CohortID: manifest.CohortID,
		SuiteRevision: manifest.SuiteRevision, OwnerPlanSHA256: ownerPlan, SegmentID: manifest.SegmentID,
		Purpose: manifest.Purpose, ReportAnchor: true, TerminalState: "stopped",
		InstallationID: installation, SoulID: soul, StartID: start, LaunchID: launch,
		MeasurementBindingSHA256: bindingSHA, QSessionStatus: "completed", QSessionID: session,
		QChallengeSHA256: manifest.QChallengeSHA256, SegmentManifestSHA256: digest(manifestRaw),
		ReservationSHA256: refs["reservation"].SHA256, BFinalizationSHA256: refs["b_finalization"].SHA256,
		StopSHA256: refs["stop"].SHA256, QWireSHA256: qWireSHA, QIndexSHA256: refs["q_index"].SHA256,
		QEOFSHA256: refs["q_eof"].SHA256, OwnerACPToHQSha256: refs["owner_acp_to_hq"].SHA256,
		HQACPToOwnerSHA256:    refs["hq_acp_to_owner"].SHA256,
		OSObservationSHA256:   refs["os_observation"].SHA256,
		InstalledInputsSHA256: refs["installed_inputs"].SHA256, SignedAt: "2026-11-22T12:00:05Z",
	}
	attestation := qSignFixtureV3(t, attest, physicalSegmentPurposeV3, 1, q.private)
	attestationRef := qWriteBlobFixtureV3(t, root, "segment_attestation", attestation)
	gate := gateManifestV3{SchemaVersion: 1, Kind: "stage2a-physical-gate-manifest", Gate: "T01",
		Profile: "managed-protected", HostID: "fixture-host", CohortID: "fixture-cohort",
		SuiteRevision: suite, OwnerPlanSHA256: ownerPlan, PrimaryMeasurementBindingSHA256: bindingSHA,
		PrimarySegmentID: "fixture-segment"}
	segment := gateSegmentV3{Sequence: 0, SegmentID: "fixture-segment", Purpose: "initial", ReportAnchor: true,
		SegmentManifest: manifestRef, SegmentAttestation: attestationRef}
	return protectedSegmentFixtureV3{root: root, gate: gate, segment: segment, key: q.key, now: q, refs: refs}
}

func TestResolveCompletedProtectedSegmentV3(t *testing.T) {
	f := makeProtectedSegmentFixtureV3(t, true, true)
	got, err := resolveProtectedSegmentV3(f.root, f.gate, f.segment, f.key, f.now.now)
	if err != nil || !got.resolved || got.QSessionID != "1234567890abcdef1234567890abcdef" {
		t.Fatalf("signed segment component refused: %+v %v", got, err)
	}
	t.Run("signed non-idle stop", func(t *testing.T) {
		bad := makeProtectedSegmentFixtureV3(t, false, true)
		if _, err := resolveProtectedSegmentV3(bad.root, bad.gate, bad.segment, bad.key, bad.now.now); err == nil {
			t.Fatal("non-idle stop accepted")
		}
	})
	t.Run("signed out-of-range runner and bridge", func(t *testing.T) {
		bad := makeProtectedSegmentFixtureV3(t, true, true, 502, 503)
		if _, err := resolveProtectedSegmentV3(bad.root, bad.gate, bad.segment, bad.key, bad.now.now); err == nil {
			t.Fatal("non-role account UIDs accepted")
		}
	})
	t.Run("signed attestation changes Q digest", func(t *testing.T) {
		bad := makeProtectedSegmentFixtureV3(t, true, false)
		if _, err := resolveProtectedSegmentV3(bad.root, bad.gate, bad.segment, bad.key, bad.now.now); err == nil {
			t.Fatal("changed Q digest accepted")
		}
	})
	t.Run("raw ACP object changed", func(t *testing.T) {
		ref := f.refs["owner_acp_to_hq"]
		name := strings.TrimPrefix(ref.SHA256, "sha256:")
		if err := os.WriteFile(filepath.Join(f.root, "objects", "sha256", name[:2], name), []byte("changed"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveProtectedSegmentV3(f.root, f.gate, f.segment, f.key, f.now.now); err == nil {
			t.Fatal("changed raw object accepted")
		}
	})
	t.Run("wrong A trust anchor", func(t *testing.T) {
		wrong, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fresh := makeProtectedSegmentFixtureV3(t, true, true)
		if _, err := resolveProtectedSegmentV3(fresh.root, fresh.gate, fresh.segment, wrong, fresh.now.now); err == nil {
			t.Fatal("wrong A key accepted")
		}
	})
	t.Run("missing Q EOF blob", func(t *testing.T) {
		fresh := makeProtectedSegmentFixtureV3(t, true, true)
		name := strings.TrimPrefix(fresh.refs["q_eof"].SHA256, "sha256:")
		if err := os.Remove(filepath.Join(fresh.root, "objects", "sha256", name[:2], name)); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveProtectedSegmentV3(fresh.root, fresh.gate, fresh.segment, fresh.key, fresh.now.now); err == nil {
			t.Fatal("missing Q EOF accepted")
		}
	})
}
