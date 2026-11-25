//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"reflect"
	"time"
)

const stage2aLocalTestReservationPurposeV1 = "agent-bot/stage2a-observed-body-local-test-reservation/v1"
const stage2aLocalTestAssignmentSchemaV1 = "agent-bot-machine/soul-start-assignment-local-test/v1"

type stage2aLocalTestStartScopeV1 struct {
	Mode                 string `json:"mode"`
	OneUseStartClaimName string `json:"one_use_start_claim_name"`
}

// The released local-test contract carries the same measured H/R and broker
// closure as v3, with a separate signed purpose and a visible one-use scope.
// Its installed receipt binds the distinct root-spent Q approval.
type stage2aLocalTestReservationV1 struct {
	stage2aReservationPayloadV3
	StartScope stage2aLocalTestStartScopeV1 `json:"start_scope"`
}

func prepareStage2aLocalTestReservationV1(req stage2aReservationRequest,
	e stage2aReservationEvidenceV3, q stage2aInstalledLocalTestV1, issued time.Time) (stage2aLocalTestReservationV1, error) {
	var empty stage2aLocalTestReservationV1
	qExpiry, err := time.Parse(time.RFC3339Nano, q.Q.ExpiresAt)
	ownerExpiry, ownerErr := time.Parse(time.RFC3339Nano, q.Owner.ExpiresAt)
	if err != nil || ownerErr != nil || !issued.Before(qExpiry) || !issued.Before(ownerExpiry) ||
		len(q.Owner.Members) != 2 || q.Owner.SelectedMemberID != q.Owner.Members[0].MemberID ||
		q.Approval.PlanDigest == "" || q.Q.Purpose != stage2aLocalTestQPurpose ||
		q.Q.InstallationID != req.start.InstallationID ||
		e.adapter.ReleaseAttestationSHA256 != q.ApprovalEnvelopeSHA256 ||
		e.adapter.ExecutablePath != q.Owner.Members[0].CommandPath ||
		e.adapter.ExecutableSHA256 != q.Owner.Members[0].CommandSHA256 {
		return empty, errStage2aReservationAuthority
	}
	base, err := prepareStage2aReservationV3(req, e, issued)
	if err != nil {
		return empty, err
	}
	base.Contract, base.Kind, base.SchemaVersion = "machine/local-test-v1", "stage2a-observed-body-local-test-reservation", 1
	base.Assignment.Schema = stage2aLocalTestAssignmentSchemaV1
	base.MeasurementBinding.Contract, base.MeasurementBinding.SchemaVersion = "machine/local-test-v1", 1
	return stage2aLocalTestReservationV1{base, stage2aLocalTestStartScopeV1{
		Mode:                 "provider-pending-local-test/v1",
		OneUseStartClaimName: soulStartClaimName(req.start.InstallationID, req.start.StartID),
	}}, nil
}

func verifyStage2aLocalTestReservationV1(raw []byte, digest string, expected stage2aLocalTestReservationV1,
	key ed25519.PublicKey, now time.Time) error {
	payload, _, err := verifyStage2aV3Envelope(raw, stage2aLocalTestReservationPurposeV1, key)
	var decoded stage2aLocalTestReservationV1
	if err != nil || stage2aReservationSHA256(raw) != digest ||
		stage2aDecodeExact(payload, &decoded) != nil || !reflect.DeepEqual(decoded, expected) ||
		expected.Contract != "machine/local-test-v1" || expected.Kind != "stage2a-observed-body-local-test-reservation" ||
		expected.SchemaVersion != 1 || expected.Assignment.Schema != stage2aLocalTestAssignmentSchemaV1 ||
		expected.MeasurementBinding.Contract != "machine/local-test-v1" ||
		expected.MeasurementBinding.SchemaVersion != 1 ||
		expected.StartScope.Mode != "provider-pending-local-test/v1" ||
		expected.StartScope.OneUseStartClaimName != soulStartClaimName(expected.Assignment.InstallationID, expected.Assignment.StartID) {
		return errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(expected)
	issued, issuedErr := time.Parse(time.RFC3339Nano, expected.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, expected.ExpiresAt)
	if err != nil || !bytes.Equal(payload, canonical) || issuedErr != nil || expiryErr != nil ||
		now.Before(issued) || !now.Before(expires) || expires.Sub(issued) > 30*time.Second {
		return errStage2aReservationAuthority
	}
	return nil
}

func reserveStage2aLocalTestAdminStartV1(store stage2aAdminClaimStore, req stage2aReservationRequest,
	load func(stage2aReservationRequest) (stage2aReservationEvidenceV3, error),
	q stage2aInstalledLocalTestV1, sign func([]byte) ([]byte, error), now func() time.Time) (stage2aReservation, error) {
	if load == nil || sign == nil || now == nil || !stage2aInstallSealNoIP() {
		return stage2aReservation{}, errStage2aReservationAuthority
	}
	var evidence stage2aReservationEvidenceV3
	var expected stage2aLocalTestReservationV1
	var got stage2aReservation
	err := stage2aAdminSpend(store, req, func() error {
		var err error
		evidence, err = load(req)
		if err != nil || uint32(evidence.base.machineUID) != store.uid ||
			stage2aRecheckVerifiedDomainV3(evidence.h) != nil || stage2aRecheckVerifiedDomainV3(evidence.r) != nil {
			return errStage2aReservationAuthority
		}
		expected, err = prepareStage2aLocalTestReservationV1(req, evidence, q, now())
		return err
	}, func(dir *os.File) error {
		active := stage2aActiveClaimName(req.start.InstallationID)
		if requireUnspentStage2aReservation(dir, active) != nil || !now().Before(evidence.base.expires) {
			return errStage2aReservationAuthority
		}
		if err := spendStage2aAdminName(dir, active, store.uid, store.gid); err != nil {
			return err
		}
		payload, err := marshalStage2aReservationJCS(expected)
		if err != nil {
			return err
		}
		raw, _, err := signStage2aVerifiedEnvelopeV3(stage2aVerifiedSigningPayloadV3{
			verified: true, purpose: stage2aLocalTestReservationPurposeV1,
			payload: payload, machineUID: store.uid, machineGID: store.gid,
		}, evidence.base.enrolledAdminKey, sign)
		if err != nil {
			return err
		}
		digest := stage2aReservationSHA256(raw)
		if verifyStage2aLocalTestReservationV1(raw, digest, expected, evidence.base.enrolledAdminKey, now()) != nil {
			return errStage2aReservationAuthority
		}
		name := ".stage2a-local-test-envelope-" + soulStartClaimName(req.start.InstallationID, req.start.StartID)
		if err := commitStage2aReservation(dir, name, raw); err != nil {
			return err
		}
		got = stage2aReservation{envelope: raw, sha256: digest}
		return nil
	})
	if err != nil {
		return stage2aReservation{}, err
	}
	return got, nil
}
