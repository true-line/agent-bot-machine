//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	stage2aLocalTestReservationPurpose = "agent-bot/stage2a-observed-body-local-test-reservation/v1"
	stage2aLocalTestAssignmentPurpose  = "agent-bot/stage2a-member-set-assignment-local-test/v1"
	stage2aLocalTestBPolicyPurpose     = "agent-bot/stage2a-b-member-authority-local-test/v1"
	stage2aLocalTestIngressPurpose     = "agent-bot/stage2a-observed-body-local-test-ingress-authorization/v1"
	stage2aLocalTestPrewritePurpose    = "agent-bot/stage2a-observed-body-local-test-prewrite-acceptance/v1"
	stage2aLocalTestAncillaryPurpose   = "agent-bot/stage2a-observed-body-local-test-ancillary-final-witness/v1"
	stage2aLocalTestQApprovalPurpose   = "agent-bot/stage2a-observed-body-local-test-q-approval/v1"
	stage2aLocalTestPathPurpose        = "agent-bot/stage2a-child-path-binding-local-test/v1"
)

// These purposes are disjoint from the protected v3 reservation and fixed
// fixture Provider. They remain an isolated source contract until an explicit
// owner-reviewed local-test plan and the cross-component contract are wired.
func stage2aLocalTestPayloadFields(purpose string) (string, []string) {
	switch purpose {
	case stage2aLocalTestReservationPurpose:
		return "stage2a-observed-body-local-test-reservation", []string{
			"admission_challenge_sha256", "assignment", "contract", "expires_at", "host_id",
			"installed_plan_receipt_sha256", "issued_at", "kind", "measurement_binding",
			"member_endpoint", "schema_version", "start_scope",
		}
	case stage2aLocalTestAssignmentPurpose:
		return "stage2a-member-set-assignment", []string{
			"adapter_manifest_relpath", "b_authority", "bridge", "contract",
			"definition_measurement", "expires_at", "frozen_adapter_manifest_sha256",
			"frozen_soul_info_sha256", "host_id", "host_projection_sha256", "hq_epoch",
			"installation_id", "issued_at", "kind", "members", "owner_plan_member_set_sha256",
			"plan_digest", "plan_id", "profile_in_force", "reservation_sha256", "runner_gid",
			"runner_uid", "schema_version", "soul_artifact_sha256", "soul_id", "start_id",
		}
	case stage2aLocalTestBPolicyPurpose:
		return "stage2a-b-member-authority", []string{
			"b_authority", "bridge", "contract", "expires_at", "host_id", "hq_epoch",
			"hq_uid", "installation_id", "issued_at", "kind", "local_test",
			"member_set_assignment_envelope_sha256", "members", "outer_launch_id",
			"owner_plan_member_set_sha256", "plan_digest", "plan_id", "profile_in_force",
			"reservation_sha256", "runner_uid", "schema_version", "soul_id", "start_id",
		}
	case stage2aLocalTestIngressPurpose:
		return "observed-body-local-test-ingress-authorization", []string{
			"expires_at", "ingress_core_sha256", "issued_at", "kind",
			"provider_claim_sha256", "schema", "selectors",
		}
	case stage2aLocalTestPrewritePurpose:
		return "observed-body-local-test-prewrite-acceptance", []string{
			"authorization_envelope_sha256", "expires_at", "hq_epoch", "issued_at",
			"kind", "prewrite_core_sha256", "prewrite_receipt", "schema", "schema_version",
			"selectors",
		}
	case stage2aLocalTestAncillaryPurpose:
		return "observed-body-local-test-ancillary-final-witness", []string{
			"completed_run_sha256", "expires_at", "first", "issued_at", "kind",
			"peer", "peer_sha256", "schema", "schema_version", "second", "selectors",
		}
	case stage2aLocalTestQApprovalPurpose:
		return "observed-body-local-test-q-approval", []string{
			"approval_reference", "expires_at", "issued_at", "kind", "machine_fingerprint", "plan",
			"plan_sha256", "schema", "schema_version",
		}
	case stage2aLocalTestPathPurpose:
		return "stage2a-child-path-binding-local-test", []string{
			"ancillary_order", "cwd", "expires_at", "home", "installation_id",
			"issued_at", "kind", "memory", "runner_account", "runner_home_lexical",
			"schema", "schema_version", "start_id", "start_slot", "target_after",
		}
	default:
		return "", nil
	}
}

func stage2aLocalTestCanonicalPayload(raw []byte, purpose string) error {
	kind, fields := stage2aLocalTestPayloadFields(purpose)
	if kind == "" || len(raw) == 0 || len(raw) > stage2aV3PayloadLimit || stage2aStrictJSON(raw) != nil {
		return errStage2aReservationAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errStage2aReservationAuthority
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != len(fields) {
		return errStage2aReservationAuthority
	}
	for _, field := range fields {
		value, ok := object[field]
		if !ok || bytes.Equal(value, []byte("null")) {
			return errStage2aReservationAuthority
		}
	}
	var gotKind string
	if json.Unmarshal(object["kind"], &gotKind) != nil || gotKind != kind {
		return errStage2aReservationAuthority
	}
	if purpose == stage2aLocalTestIngressPurpose || purpose == stage2aLocalTestPrewritePurpose ||
		purpose == stage2aLocalTestAncillaryPurpose || purpose == stage2aLocalTestQApprovalPurpose ||
		purpose == stage2aLocalTestPathPurpose {
		var schema string
		want := "agent-bot-machine/stage2a-observed-body-local-test-ingress-authorization/v1"
		if purpose == stage2aLocalTestPrewritePurpose {
			want = "agent-bot-machine/stage2a-observed-body-local-test-prewrite-acceptance/v1"
		} else if purpose == stage2aLocalTestAncillaryPurpose {
			want = "agent-bot-machine/stage2a-observed-body-local-test-ancillary-final-witness/v1"
		} else if purpose == stage2aLocalTestQApprovalPurpose {
			want = "agent-bot-machine/stage2a-observed-body-local-test-q-approval/v1"
		} else if purpose == stage2aLocalTestPathPurpose {
			want = "agent-bot-machine/stage2a-child-path-binding-local-test/v1"
		}
		if json.Unmarshal(object["schema"], &schema) != nil || schema != want {
			return errStage2aReservationAuthority
		}
		if purpose == stage2aLocalTestPrewritePurpose || purpose == stage2aLocalTestAncillaryPurpose ||
			purpose == stage2aLocalTestQApprovalPurpose || purpose == stage2aLocalTestPathPurpose {
			var version int
			if json.Unmarshal(object["schema_version"], &version) != nil || version != 1 {
				return errStage2aReservationAuthority
			}
		}
	} else {
		var contract string
		var version int
		if json.Unmarshal(object["contract"], &contract) != nil || contract != "machine/local-test-v1" ||
			json.Unmarshal(object["schema_version"], &version) != nil || version != 1 {
			return errStage2aReservationAuthority
		}
	}
	return nil
}

func verifyStage2aLocalTestEnvelope(raw []byte, purpose string,
	enrolledKey ed25519.PublicKey) ([]byte, error) {
	if len(raw) == 0 || len(raw) > stage2aV3EnvelopeLimit || len(enrolledKey) != ed25519.PublicKeySize ||
		stage2aStrictJSON(raw) != nil {
		return nil, errStage2aReservationAuthority
	}
	var envelope stage2aSignedReservation
	if stage2aDecodeExact(raw, &envelope) != nil || envelope.SchemaVersion != 1 ||
		envelope.Purpose != purpose || envelope.IssuerPublicKeyBase64URL !=
		base64.RawURLEncoding.EncodeToString(enrolledKey) {
		return nil, errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errStage2aReservationAuthority
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(envelope.PayloadBase64URL)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != envelope.PayloadBase64URL ||
		stage2aReservationSHA256(payload) != envelope.PayloadSHA256 ||
		stage2aLocalTestCanonicalPayload(payload, purpose) != nil {
		return nil, errStage2aReservationAuthority
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64URL)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != envelope.SignatureBase64URL ||
		!ed25519.Verify(enrolledKey, append([]byte(purpose+"\x00"), payload...), signature) {
		return nil, errStage2aReservationAuthority
	}
	return payload, nil
}

// Only A's secure account may sign a payload already checked against an
// installed local-test plan. A producer must supply that proof before calling.
func signStage2aVerifiedLocalTestEnvelope(value stage2aVerifiedSigningPayloadV3,
	enrolledKey ed25519.PublicKey, sign func([]byte) ([]byte, error)) ([]byte, error) {
	if !value.verified || value.machineUID < 400 || value.machineGID == 0 ||
		uint32(os.Getuid()) != value.machineUID || uint32(os.Geteuid()) != value.machineUID ||
		uint32(os.Getgid()) != value.machineGID || uint32(os.Getegid()) != value.machineGID ||
		len(enrolledKey) != ed25519.PublicKeySize || sign == nil ||
		stage2aLocalTestCanonicalPayload(value.payload, value.purpose) != nil {
		return nil, errStage2aReservationAuthority
	}
	preimage := append([]byte(value.purpose+"\x00"), value.payload...)
	signature, err := sign(bytes.Clone(preimage))
	if err != nil || !ed25519.Verify(enrolledKey, preimage, signature) {
		return nil, errStage2aReservationAuthority
	}
	envelope, err := marshalStage2aReservationJCS(stage2aSignedReservation{
		SchemaVersion: 1, Purpose: value.purpose,
		IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(enrolledKey),
		PayloadSHA256:            stage2aReservationSHA256(value.payload),
		PayloadBase64URL:         base64.RawURLEncoding.EncodeToString(value.payload),
		SignatureBase64URL:       base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil || len(envelope) > stage2aV3EnvelopeLimit {
		return nil, errStage2aReservationAuthority
	}
	return envelope, nil
}
