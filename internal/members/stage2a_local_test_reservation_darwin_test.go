//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestStage2aLocalTestReservationPurposeAndScope(t *testing.T) {
	vector, private := stage2aLoadContractVectorV3(t)
	public := private.Public().(ed25519.PublicKey)
	var ordinary stage2aReservationPayloadV3
	if stage2aDecodeExact([]byte(vector.ReservationPayloadJCS), &ordinary) != nil {
		t.Fatal("invalid synthetic v3 reservation")
	}
	ordinary.Contract, ordinary.Kind, ordinary.SchemaVersion = "machine/local-test-v1", "stage2a-observed-body-local-test-reservation", 1
	ordinary.Assignment.Schema = stage2aLocalTestAssignmentSchemaV1
	ordinary.MeasurementBinding.Contract, ordinary.MeasurementBinding.SchemaVersion = "machine/local-test-v1", 1
	want := stage2aLocalTestReservationV1{ordinary, stage2aLocalTestStartScopeV1{
		Mode:                 "provider-pending-local-test/v1",
		OneUseStartClaimName: soulStartClaimName(ordinary.Assignment.InstallationID, ordinary.Assignment.StartID),
	}}
	payload, err := marshalStage2aReservationJCS(want)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil || len(fields) != 12 {
		t.Fatal("local-test payload differs from the released 12-field shape")
	}
	signed, _, err := signStage2aVerifiedEnvelopeV3(stage2aVerifiedSigningPayloadV3{
		verified: true, purpose: stage2aLocalTestReservationPurposeV1, payload: payload,
		machineUID: uint32(os.Getuid()), machineGID: uint32(os.Getgid()),
	}, public, func(raw []byte) ([]byte, error) { return ed25519.Sign(private, raw), nil })
	if err != nil {
		t.Fatal(err)
	}
	var envelope stage2aSignedReservation
	if stage2aDecodeExact(signed, &envelope) != nil || envelope.SchemaVersion != 1 {
		t.Fatal("local-test envelope is not schema v1")
	}
	issued, err := time.Parse(time.RFC3339Nano, want.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	digest := stage2aReservationSHA256(signed)
	if _, err := verifyStage2aReservationModeV3(stage2aLocalTestRunV1, signed, digest, payload, public, issued); err != nil {
		t.Fatal("authentic local-test reservation refused:", err)
	}
	for _, mode := range []stage2aReservationRunModeV3{stage2aQualifiedRunV3, stage2aCandidateRunV3, ""} {
		if _, err := verifyStage2aReservationModeV3(mode, signed, digest, payload, public, issued); err == nil {
			t.Fatalf("local-test reservation accepted as %q", mode)
		}
	}
	if _, _, err := verifyStage2aV3Envelope(signed, stage2aReservationPurposeV3, public); err == nil {
		t.Fatal("ordinary purpose accepted local-test signature")
	}
	changed := want
	changed.StartScope.OneUseStartClaimName = "other.json"
	if err := verifyStage2aLocalTestReservationV1(signed, digest, changed, public, issued); err == nil {
		t.Fatal("changed one-use claim accepted")
	}
	if err := verifyStage2aLocalTestReservationV1(signed, digest, want, public, issued.Add(time.Minute)); err == nil {
		t.Fatal("expired local-test lease accepted")
	}
}

func TestStage2aLocalTestAdapterFromSealedRuntime(t *testing.T) {
	vector, _ := stage2aLoadContractVectorV3(t)
	var reservation stage2aReservationPayloadV3
	if stage2aDecodeExact([]byte(vector.ReservationPayloadJCS), &reservation) != nil {
		t.Fatal("invalid synthetic reservation")
	}
	var inventory stage2aDomainInventoryV3
	raw, err := os.ReadFile("testdata/stage2a-machine-hr-v3-synthetic.json")
	var full struct {
		RInventory string `json:"r_inventory_jcs"`
	}
	if err != nil || json.Unmarshal(raw, &full) != nil || stage2aDecodeExact([]byte(full.RInventory), &inventory) != nil {
		t.Fatal("invalid synthetic R inventory")
	}
	a := reservation.MeasurementBinding.Adapter
	q := stage2aInstalledLocalTestV1{
		Owner: stage2aLocalTestOwnerPlan{Enabled: true, SelectedMemberID: "lead", Members: []stage2aLocalTestOwnerMember{{
			MemberID: "lead", CommandPath: a.ExecutablePath, CommandSHA256: a.ExecutableSHA256,
			AdapterManifestSHA256: a.ReleaseManifestSHA256,
		}, {MemberID: "specialist"}}},
		Q: stage2aLocalTestQPlan{Purpose: stage2aLocalTestQPurpose,
			InstallationID:          reservation.Assignment.InstallationID,
			CandidateManifestSHA256: a.ReleaseManifestSHA256},
		ApprovalEnvelopeSHA256: a.ReleaseAttestationSHA256,
	}
	runtime := stage2aInstalledRuntimeV3{
		Policy:    stage2aInstalledPolicy{Binding: Stage2aMeasurementBinding{InstallationID: reservation.Assignment.InstallationID}},
		VerifiedR: stage2aVerifiedDomainRefV3{ref: reservation.MeasurementBinding.RInventory},
		Inventory: inventory,
		Plan: stage2aRuntimeV3Install{Components: []stage2aRuntimeV3ComponentPin{{
			ComponentID: "adapter", ReleaseArtifactSHA256: a.PackageSHA256,
			ReleaseManifestSHA256: a.ReleaseManifestSHA256,
		}}},
	}
	got, code, err := stage2aLocalTestAdapterFromRuntimeV1(runtime, q)
	if err != nil || got.ComponentID != "adapter" || got.ExecutablePath != a.ExecutablePath ||
		got.ReleaseAttestationSHA256 != q.ApprovalEnvelopeSHA256 || len(code) != 2 {
		t.Fatalf("sealed adapter selection failed: %v, %#v", err, got)
	}
	q.Q.CandidateManifestSHA256 = "sha256:" + string(bytes.Repeat([]byte{'0'}, 64))
	if _, _, err := stage2aLocalTestAdapterFromRuntimeV1(runtime, q); err == nil {
		t.Fatal("changed Q manifest accepted")
	}
	q.Q.CandidateManifestSHA256 = a.ReleaseManifestSHA256
	runtime.Plan.Components = append(runtime.Plan.Components, runtime.Plan.Components[0])
	if _, _, err := stage2aLocalTestAdapterFromRuntimeV1(runtime, q); err == nil {
		t.Fatal("ambiguous adapter release accepted")
	}
}
