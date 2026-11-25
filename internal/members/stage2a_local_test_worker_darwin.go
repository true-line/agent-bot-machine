//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"slices"
	"time"
)

// Only the root-installed local-test Q receipt selects this mode. The signed
// Q approval envelope is the local-test attestation named by the released
// adapter_release field; it does not qualify an ordinary released adapter.
func loadStage2aLocalTestWorkerAuthorityV1(runtime stage2aInstalledRuntimeV3, key ed25519.PublicKey,
	checkPair func(string, string, string, func() error) error) (stage2aReservationWorkerAuthorityV3, error) {
	var empty stage2aReservationWorkerAuthorityV3
	if checkPair == nil || len(key) != ed25519.PublicKeySize || runtime.LocalTest == nil ||
		runtime.Policy.LocalTestQPlanID == "" || runtime.Policy.RuntimeV3 == nil {
		return empty, errStage2aReservationAuthority
	}
	q := *runtime.LocalTest
	account, _, state, uid, gid, err := stage2aLocalTestQAccount()
	if err != nil || uid != uint32(runtime.Policy.MachineUID) || gid != uint32(runtime.Policy.MachineGID) ||
		checkPair(state, account.Username, q.Approval.PairCommitment, nil) != nil {
		return empty, errStage2aReservationAuthority
	}
	recheck := func() error {
		if checkPair(state, account.Username, q.Approval.PairCommitment, nil) != nil {
			return errStage2aReservationAuthority
		}
		current, err := stage2aLoadInstalledRuntimeV3(key, runtime.Policy.HQUID,
			runtime.Policy.Binding.HQEpoch, runtime.Policy.Binding.InstallationID)
		if err != nil || !bytes.Equal(current.PolicyRaw, runtime.PolicyRaw) ||
			current.VerifiedR.ref != runtime.VerifiedR.ref || current.LocalTest == nil ||
			!reflect.DeepEqual(*current.LocalTest, q) {
			return errStage2aReservationAuthority
		}
		return nil
	}
	store, _ := runtime.Policy.stores()
	return stage2aReservationWorkerAuthorityV3{
		mode: stage2aLocalTestRunV1, store: store, localTest: &q, recheck: recheck,
		load: func(req stage2aReservationRequest) (stage2aReservationEvidenceV3, error) {
			if recheck() != nil {
				return stage2aReservationEvidenceV3{}, errStage2aReservationAuthority
			}
			adapter, code, err := stage2aLocalTestAdapterFromRuntimeV1(runtime, q)
			if err != nil {
				return stage2aReservationEvidenceV3{}, err
			}
			return loadStage2aReservationEvidenceV3(req, runtime, key, adapter, code)
		},
	}, nil
}

func stage2aLocalTestAdapterFromRuntimeV1(runtime stage2aInstalledRuntimeV3,
	q stage2aInstalledLocalTestV1) (stage2aReservationAdapterV3, []string, error) {
	var empty stage2aReservationAdapterV3
	if !q.Owner.Enabled || len(q.Owner.Members) != 2 || q.Owner.SelectedMemberID != q.Owner.Members[0].MemberID ||
		q.Q.Purpose != stage2aLocalTestQPurpose || q.Q.InstallationID != runtime.Policy.Binding.InstallationID ||
		q.Q.CandidateManifestSHA256 != q.Owner.Members[0].AdapterManifestSHA256 ||
		!stage2aPrefixedDigest.MatchString(q.ApprovalEnvelopeSHA256) ||
		q.Owner.Members[0].CommandPath == "" {
		return empty, nil, errStage2aReservationAuthority
	}
	var artifact, manifest string
	for _, pin := range runtime.Plan.Components {
		if pin.ComponentID == "adapter" {
			if artifact != "" {
				return empty, nil, errStage2aReservationAuthority
			}
			artifact, manifest = pin.ReleaseArtifactSHA256, pin.ReleaseManifestSHA256
		}
	}
	if !stage2aPrefixedDigest.MatchString(artifact) || !stage2aPrefixedDigest.MatchString(manifest) {
		return empty, nil, errStage2aReservationAuthority
	}
	code := make([]string, 0, 32)
	var executable bool
	for _, row := range runtime.Inventory.Files {
		if row.ComponentID != "adapter" {
			continue
		}
		if row.Kind != "regular" {
			return empty, nil, errStage2aReservationAuthority
		}
		installed := filepath.Join(runtime.VerifiedR.ref.Snapshot.Path, row.Path)
		code = append(code, installed)
		if installed == q.Owner.Members[0].CommandPath {
			executable = row.Mode == "0550" && row.SHA256 == q.Owner.Members[0].CommandSHA256
		}
	}
	slices.Sort(code)
	if !executable || len(code) == 0 || len(code) > 512 {
		return empty, nil, errStage2aReservationAuthority
	}
	raw, err := marshalStage2aReservationJCS(code)
	if err != nil {
		return empty, nil, errStage2aReservationAuthority
	}
	return stage2aReservationAdapterV3{
		ComponentID: "adapter", ExecutablePath: q.Owner.Members[0].CommandPath,
		ExecutableSHA256: q.Owner.Members[0].CommandSHA256, PackageSHA256: artifact,
		ReleaseManifestSHA256: manifest, ReleaseAttestationSHA256: q.ApprovalEnvelopeSHA256,
		CodeInputCount: len(code), CodeInputsDigest: stage2aV3PurposeDigest("agent-bot/stage2a-adapter-code-inputs/v3", raw),
	}, code, nil
}

func stage2aLocalTestAuthorityUnexpired(q stage2aInstalledLocalTestV1, now time.Time) bool {
	qUntil, qErr := time.Parse(time.RFC3339Nano, q.Q.ExpiresAt)
	ownerUntil, ownerErr := time.Parse(time.RFC3339Nano, q.Owner.ExpiresAt)
	return qErr == nil && ownerErr == nil && now.Before(qUntil) && now.Before(ownerUntil)
}
