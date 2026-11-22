//go:build darwin

package members

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
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

	"github.com/qwts/managed-machine/internal/qualification"
	"golang.org/x/sys/unix"
)

func stage2aVerifiedPolicyForPersist(t *testing.T, now time.Time, hostKey *ecdsa.PrivateKey,
	binding Stage2aMeasurementBinding) qualification.VerifiedPolicy {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&hostKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	root, ownerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sha := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	policy := map[string]any{
		"contract": "control/v3", "kind": "qualification-trust-policy", "policy_revision": 1,
		"owner_key_id": "fixture-owner", "issued_at": now.Add(-2 * time.Hour).Format(time.RFC3339),
		"expires_at": now.Add(time.Hour).Format(time.RFC3339), "max_revocation_age_seconds": 3600,
		"release_workflow": map[string]any{
			"id": "fixture-release", "repository": "true-line/soul-adapters",
			"workflow_path": ".github/workflows/qualify.yml", "source_commit": strings.Repeat("1", 40),
			"oidc_issuer":          "https://token.actions.githubusercontent.com",
			"certificate_identity": "https://github.com/true-line/soul-adapters/.github/workflows/qualify.yml@refs/heads/main",
			"trust_root_sha256":    sha("2"),
		},
		"souls_build_workflow": map[string]any{
			"id": "fixture-souls", "repository": "true-line/agent-bot-souls",
			"workflow_path": ".github/workflows/release.yml", "source_commit": strings.Repeat("3", 40),
			"source_tree": strings.Repeat("4", 40), "oidc_issuer": "https://token.actions.githubusercontent.com",
			"certificate_identity": "https://github.com/true-line/agent-bot-souls/.github/workflows/release.yml@refs/heads/main",
			"trust_root_sha256":    sha("5"), "builder_sha256": sha("6"), "toolchain_sha256": sha("7"),
			"receipt_predicate_type": "https://true-line.ai/soul-contracts/adapter/v2/souls-build",
			"bundle_media_type":      "application/vnd.dev.sigstore.bundle.v0.3+json",
			"dsse_payload_type":      qualification.DSSEPayloadType,
		},
		"frozen_soul_release_provenance_enabled": false,
		"frozen_soul_mapping": map[string]any{
			"soul_id": binding.SoulID, "artifact_sha256": binding.SoulArtifactSHA256,
			"claimed_definition_digest": binding.ClaimedDefinitionDigest,
			"definition_measurement":    binding.DefinitionMeasurement,
		},
		"evidence_signers": []any{map[string]any{
			"id": "fixture-signer", "host_id": binding.HostID, "algorithm": "ES256",
			"public_key_spki_der_base64": base64.StdEncoding.EncodeToString(spki),
		}},
		"revocation_snapshot": map[string]any{
			"updated_at":                 now.Add(-30 * time.Minute).Format(time.RFC3339),
			"revoked_attestation_sha256": []any{}, "revoked_evidence_signer_ids": []any{},
			"revoked_release_workflow_ids": []any{}, "revoked_souls_build_workflow_ids": []any{},
			"revoked_souls_build_receipt_sha256": []any{}, "revoked_frozen_soul_artifact_sha256": []any{},
		},
	}
	payload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(qualification.Envelope{
		SchemaVersion: 3, Purpose: qualification.PolicyPurposeV3, OwnerKeyID: "fixture-owner",
		PolicySHA256:    stage2aQualificationSHA256(payload),
		PolicyBase64URL: base64.RawURLEncoding.EncodeToString(payload),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ownerKey,
			append([]byte(qualification.PolicyPurposeV3+"\x00"), payload...))),
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := qualification.VerifyOwnerPolicyV3(envelope, "fixture-owner", root, 0, "", now)
	if err != nil {
		t.Fatalf("synthetic owner signature refused: %v", err)
	}
	return verified
}

func stage2aSignedHostReportForPersist(t *testing.T, report []byte, key *ecdsa.PrivateKey,
	hostID string) []byte {
	t.Helper()
	digest := sha256.Sum256(append([]byte(qualification.HostPurposeV3+"\x00"), report...))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	envelope, err := json.Marshal(qualification.Envelope{
		SchemaVersion: 3, Purpose: qualification.HostPurposeV3, HostID: hostID,
		SignerID: "fixture-signer", ReportSHA256: stage2aQualificationSHA256(report),
		ReportBase64URL:    base64.RawURLEncoding.EncodeToString(report),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestPersistStage2aQualificationBundleV3VerifiedChain(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("A-owned store requires a nonroot account")
	}
	now := time.Date(2026, 11, 22, 7, 0, 0, 0, time.UTC)
	reportBytes, err := os.ReadFile("../qualification/testdata/stage2a-report-v3-protected-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if json.Unmarshal(reportBytes, &report) != nil {
		t.Fatal("synthetic report could not decode")
	}
	bindingRaw, err := json.Marshal(report["measurement_binding"])
	if err != nil {
		t.Fatal(err)
	}
	var binding Stage2aMeasurementBinding
	if json.Unmarshal(bindingRaw, &binding) != nil {
		t.Fatal("synthetic measurement binding could not decode")
	}
	binding.PlanID = "plan-20261122T060000Z-abcd"
	report["measurement_binding"].(map[string]any)["plan_id"] = binding.PlanID
	assignment := report["bridge"].(map[string]any)["assignment"].(map[string]any)
	assignment["plan_id"] = binding.PlanID
	q := Stage2aStopRequest{InstallationID: binding.InstallationID, StartID: binding.StartID,
		LaunchID: binding.LaunchID, PlanID: binding.PlanID, PlanDigest: binding.InstalledPlanDigest,
		HQEpoch: binding.HQEpoch}
	machinePub, machineKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(raw []byte) ([]byte, error) { return ed25519.Sign(machineKey, raw), nil }
	reservation, err := signStage2aEnvelope(stage2aReservationPayload{
		Assignment: stage2aReservationAssignment{SoulStartAssignment: SoulStartAssignment{
			InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
			PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: q.HQEpoch}},
		MeasurementBinding: binding,
	}, 2, stage2aAdminReservationPurpose, machinePub, sign)
	if err != nil {
		t.Fatal(err)
	}
	q.ReservationSHA256 = stage2aQualificationSHA256(reservation)
	finalization, err := signStage2aEnvelope(Stage2aFinalizationPayload{Stage2aStopRequest: q},
		1, Stage2aFinalizationPurpose, machinePub, sign)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := signStage2aEnvelope(Stage2aStopPayload{ReservationSHA256: q.ReservationSHA256,
		InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
		PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: q.HQEpoch, BothUIDsIdle: true},
		1, Stage2aStopPurpose, machinePub, sign)
	if err != nil {
		t.Fatal(err)
	}
	assignment["machine_reservation_sha256"] = q.ReservationSHA256
	run := report["run_evidence"].(map[string]any)
	run["reservation"].(map[string]any)["sha256"] = q.ReservationSHA256
	run["finalization"].(map[string]any)["sha256"] = stage2aQualificationSHA256(finalization)
	delete(run, "execution_completion")
	candidate, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	pre, signedReport, err := qualification.IssueExecutionCompletionV3(candidate,
		"fixture:issued-execution", now.Add(-time.Hour-time.Second), now, machinePub, sign)
	if err != nil {
		t.Fatalf("pre-sign completion refused: %v", err)
	}
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := stage2aVerifiedPolicyForPersist(t, now, hostKey, binding)
	host := stage2aSignedHostReportForPersist(t, signedReport, hostKey, binding.HostID)
	post, _, err := qualification.IssueReportCommitmentV3(host, pre, policy, now, machinePub, sign)
	if err != nil {
		t.Fatalf("post-sign commitment refused: %v", err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claims := filepath.Join(base, "claims")
	if err := os.Mkdir(claims, 0700); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(claims, &st); err != nil {
		t.Fatal(err)
	}
	store := stage2aAdminClaimStore{path: claims, uid: st.Uid, gid: st.Gid,
		device: st.Dev, inode: st.Ino, birthtime: st.Btim,
		legacyUnspent: func(string, string) error { return nil }}
	dir, err := store.open()
	if err != nil {
		t.Fatalf("synthetic A store refused: %v", err)
	}
	slot := soulStartClaimName(q.InstallationID, q.StartID)
	for name, raw := range map[string][]byte{
		".stage2a-admin-envelope-" + slot:    reservation,
		".stage2a-b-final-" + slot + ".json": finalization,
		".stage2a-stop-" + slot + ".json":    stop,
	} {
		if err := commitStage2aReservation(dir, name, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := spendStage2aAdminName(dir, ".stage2a-closed-"+slot, store.uid, store.gid); err != nil {
		t.Fatal(err)
	}
	dir.Close()
	challenge := bytes.Repeat([]byte{0xbb}, 32)
	sessionID := strings.Repeat("a", 32)
	sourceSHA := "sha256:" + strings.Repeat("c", 64)
	testPlanSHA := "sha256:" + strings.Repeat("d", 64)
	session := stage2aQualificationSessionResultV1{begin: stage2aQualificationBeginV1{
		Schema: stage2aQualificationSchemaV1, Kind: "begin", SessionID: sessionID,
		ChallengeBase64URL: base64.RawURLEncoding.EncodeToString(challenge),
		CohortID:           "reviewed-cohort", InstallationID: q.InstallationID, SoulID: binding.SoulID,
		StartID: q.StartID, HostID: binding.HostID, Profile: binding.ProfileInForce,
		ReservationSHA256: q.ReservationSHA256, TestPlanSHA256: testPlanSHA,
		SuiteRevision: strings.Repeat("a", 40), PSSHA256: "sha256:" + strings.Repeat("e", 64),
		PathRoots: []string{"/private/tmp"}, QUID: 650, QGID: 651,
		DeadlineAt: "2026-11-22T07:30:00Z",
	}, peer: stage2aQualificationPeerV1{pid: 42, uid: 650, gid: 651},
		sourceSHA256: sourceSHA, count: 1, validated: true,
		cleanEOFObserved: true, eofObservedAt: now.Add(-time.Minute)}
	var stream bytes.Buffer
	session.beginFrame, err = writeStage2aQualificationFrame(&stream, session.begin)
	if err != nil {
		t.Fatal(err)
	}
	session.challengeSHA256 = stage2aQualificationSHA256(challenge)
	session.readyFrame = mustStage2aQualificationFrame(t, map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "ready", "session_id": sessionID,
		"challenge_sha256": session.challengeSHA256, "sequence": 0,
		"pid": 42, "uid": 650, "gid": 651, "source_sha256": sourceSHA,
		"captured_at": "2026-11-22T06:00:00.120Z",
	})
	request := map[string]any{"schema": stage2aQualificationSchemaV1, "kind": "observe",
		"session_id": sessionID, "sequence": 1, "gate": "T01", "phase": "before", "event_id": "event-1",
		"processes": []any{}, "paths": []any{}}
	var requests bytes.Buffer
	requestFrame, err := writeStage2aQualificationFrame(&requests, request)
	if err != nil {
		t.Fatal(err)
	}
	session.requestFrames = bytes.Clone(requests.Bytes())
	session.requestsSHA256 = stage2aQualificationSHA256(session.requestFrames)
	observation := map[string]any{"schema": stage2aQualificationSchemaV1, "kind": "observation",
		"session_id": sessionID, "challenge_sha256": session.challengeSHA256,
		"sequence": 1, "request_sha256": stage2aQualificationSHA256(requestFrame[4:]),
		"captured_at": "2026-11-22T06:00:00.120Z", "gate": "T01", "phase": "before", "event_id": "event-1",
		"processes": []any{}, "paths": []any{}}
	var observations bytes.Buffer
	if _, err := writeStage2aQualificationFrame(&observations, observation); err != nil {
		t.Fatal(err)
	}
	session.observationFrames = bytes.Clone(observations.Bytes())
	session.observationsSHA256 = stage2aQualificationSHA256(session.observationFrames)
	session.finishRequestFrame = mustStage2aQualificationFrame(t, map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "finish", "session_id": sessionID,
		"sequence": 2,
	})
	session.finishedFrame = mustStage2aQualificationFrame(t, map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "finished", "session_id": sessionID,
		"challenge_sha256": session.challengeSHA256, "sequence": 2, "observation_count": 1,
		"observations_sha256": session.observationsSHA256, "captured_at": "2026-11-22T06:00:00.120Z",
	})
	path, digest, err := persistStage2aQualificationBundleV3(store, q, binding, session,
		sourceSHA, testPlanSHA, "reviewed-cohort", []string{"/private/tmp"}, 650, 651,
		reservation, finalization, stop, pre, host, post, policy, machinePub, now)
	if err != nil || path == "" || digest == "" {
		t.Fatalf("verified bundle was not persisted: %v", err)
	}
	stored, err := os.ReadFile(path)
	if err != nil || stage2aQualificationSHA256(stored) != digest {
		t.Fatalf("stored bundle digest mismatch: %v", err)
	}
	var bundle stage2aQualificationBundleV1
	if json.Unmarshal(stored, &bundle) != nil ||
		bundle.ReadyFrameBase64URL != base64.RawURLEncoding.EncodeToString(session.readyFrame) ||
		bundle.FinishRequestFrameBase64URL != base64.RawURLEncoding.EncodeToString(session.finishRequestFrame) ||
		bundle.FinishedFrameBase64URL != base64.RawURLEncoding.EncodeToString(session.finishedFrame) ||
		!bundle.CleanEOFObserved || bundle.EOFObservedAt != session.eofObservedAt.Format(time.RFC3339Nano) {
		t.Fatal("stored bundle lost exact framed Q exchange or clean EOF observation")
	}
	// A changed Q observation with stale transcript and finished digests is refused.
	tampered := bytes.Replace(session.observationFrames, []byte(`"event_id":"event-1"`),
		[]byte(`"event_id":"event-2"`), 1)
	if bytes.Equal(tampered, session.observationFrames) {
		t.Fatal("test did not alter the Q observation")
	}
	session.observationFrames = tampered
	if _, _, err := persistStage2aQualificationBundleV3(store, q, binding, session,
		sourceSHA, testPlanSHA, "reviewed-cohort", []string{"/private/tmp"}, 650, 651,
		reservation, finalization, stop, pre, host, post, policy, machinePub, now); err == nil {
		t.Fatal("changed Q observation with stale digests accepted")
	}
}
