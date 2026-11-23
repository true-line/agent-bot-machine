package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const Stage2aHelloStartPurpose = "agent-bot/stage2a-hello-start/v1"
const Stage2aHelloFinalizationPurpose = "agent-bot/stage2a-hello-finalization/v1"
const Stage2aPeerRolePurpose = "agent-bot/stage2a-peer-role/v1"

type Stage2aPeerRequest struct {
	Stage2aStopRequest
	PeerUID int `json:"peer_uid"`
	PeerPID int `json:"peer_pid"`
}

// PeerUID and PeerPID must come from HQ's accepted admission socket. Machine
// reobserves that process before signing; the runner cannot choose its peer.
type Stage2aHelloStartRequest struct {
	Stage2aStopRequest
	PeerUID                 int    `json:"peer_uid"`
	PeerPID                 int    `json:"peer_pid"`
	HelloPayloadBase64URL   string `json:"hello_payload_base64url"`
	HelloPayloadSHA256      string `json:"hello_payload_sha256"`
	BrokerBindReceiptSHA256 string `json:"broker_bind_receipt_sha256"`
}

type Stage2aHelloRuntime struct {
	MemberID       string `json:"member_id"`
	RuntimeID      string `json:"runtime_id"`
	ProfileInForce string `json:"profile_in_force"`
}

// Expected is the complete HQ post-Hello tuple. It is serialized and signed
// unchanged, so a verifier can bind HQ's decision to this exact start.
type Stage2aHelloExpected struct {
	ReservationSHA256         string                `json:"reservation_sha256"`
	StartID                   string                `json:"start_id"`
	LaunchID                  string                `json:"launch_id"`
	HQEpoch                   string                `json:"hq_epoch"`
	SoulID                    string                `json:"soul_id"`
	InstallationID            string                `json:"installation_id"`
	DefinitionDigest          string                `json:"definition_digest"`
	DefinitionMeasurement     string                `json:"definition_measurement"`
	LaunchInputMeasurement    string                `json:"launch_input_measurement"`
	HelloPayloadSHA256        string                `json:"hello_payload_sha256"`
	AdmissionDecisionID       string                `json:"admission_decision_id"`
	InstallationEpoch         int64                 `json:"installation_epoch"`
	ProfileInForce            string                `json:"profile_in_force"`
	HQBrokerBindReceiptSHA256 string                `json:"hq_broker_bind_receipt_sha256"`
	AdmittedRuntimes          []Stage2aHelloRuntime `json:"admitted_runtimes"`
}

type Stage2aHelloFinalizeRequest struct {
	Stage2aStopRequest
	StartEnvelopeSHA256 string               `json:"start_envelope_sha256"`
	Expected            Stage2aHelloExpected `json:"expected"`
}

type Stage2aHelloReply struct {
	EnvelopeBase64URL string `json:"envelope_base64url"`
	SHA256            string `json:"sha256"`
}

type stage2aHelloClaim struct {
	Contract         string               `json:"contract"`
	RequestID        string               `json:"request_id"`
	SoulID           string               `json:"soul_id"`
	DefinitionDigest string               `json:"definition_digest"`
	InstallationID   string               `json:"installation_id"`
	RequestedProfile string               `json:"requested_profile"`
	RequestedRoles   []stage2aHelloMember `json:"requested_roles"`
}

type stage2aHelloMember struct {
	MemberID       string `json:"member_id"`
	Role           string `json:"role"`
	AdapterID      string `json:"adapter_id"`
	AdapterVersion string `json:"adapter_version"`
}

func ParseStage2aHelloStartRequest(raw []byte) (Stage2aHelloStartRequest, error) {
	var q Stage2aHelloStartRequest
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		q.PeerUID <= 0 || q.PeerPID <= 1 || !stage2aPrefixedDigest.MatchString(q.HelloPayloadSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.BrokerBindReceiptSHA256) {
		return Stage2aHelloStartRequest{}, errors.New("invalid Stage 2a Hello start request")
	}
	if _, err := stage2aHelloBytes(q); err != nil {
		return Stage2aHelloStartRequest{}, errors.New("invalid Stage 2a Hello start request")
	}
	return q, nil
}

func ParseStage2aPeerRequest(raw []byte) (Stage2aPeerRequest, error) {
	var q Stage2aPeerRequest
	if len(raw) == 0 || len(raw) > 2048 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		q.PeerUID <= 0 || q.PeerPID <= 1 {
		return Stage2aPeerRequest{}, errors.New("invalid Stage 2a peer request")
	}
	return q, nil
}

func ParseStage2aHelloFinalizeRequest(raw []byte) (Stage2aHelloFinalizeRequest, error) {
	var q Stage2aHelloFinalizeRequest
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.StartEnvelopeSHA256) ||
		!validStage2aHelloExpected(q.Expected) {
		return Stage2aHelloFinalizeRequest{}, errors.New("invalid Stage 2a Hello finalization")
	}
	return q, nil
}

func stage2aDecodeExact(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing Stage 2a JSON")
	}
	return nil
}

func stage2aHelloBytes(q Stage2aHelloStartRequest) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.HelloPayloadBase64URL)
	if err != nil || len(raw) == 0 || len(raw) > 4096 ||
		base64.RawURLEncoding.EncodeToString(raw) != q.HelloPayloadBase64URL ||
		stage2aStrictJSON(raw) != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != q.HelloPayloadSHA256 {
		return nil, errors.New("invalid canonical Hello bytes")
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errors.New("noncanonical Hello bytes")
	}
	return raw, nil
}

func validStage2aHelloExpected(e Stage2aHelloExpected) bool {
	if !stage2aPrefixedDigest.MatchString(e.ReservationSHA256) ||
		!soulStartID.MatchString(e.StartID) || !soulLaunchID.MatchString(e.LaunchID) ||
		!soulHQEpoch.MatchString(e.HQEpoch) || !soulIdentity.MatchString(e.SoulID) ||
		!soulInstallationID.MatchString(e.InstallationID) ||
		!stage2aPrefixedDigest.MatchString(e.DefinitionDigest) ||
		!stage2aPrefixedDigest.MatchString(e.DefinitionMeasurement) ||
		!stage2aPrefixedDigest.MatchString(e.LaunchInputMeasurement) ||
		!stage2aPrefixedDigest.MatchString(e.HelloPayloadSHA256) ||
		!stage2aBindingID.MatchString(e.AdmissionDecisionID) ||
		e.InstallationEpoch < 1 || e.InstallationEpoch > (1<<53)-1 ||
		e.ProfileInForce != "managed-protected" ||
		!stage2aPrefixedDigest.MatchString(e.HQBrokerBindReceiptSHA256) ||
		len(e.AdmittedRuntimes) == 0 || len(e.AdmittedRuntimes) > 32 {
		return false
	}
	previous := ""
	seenRuntimes := make(map[string]bool, len(e.AdmittedRuntimes))
	for _, r := range e.AdmittedRuntimes {
		if !stage2aBindingID.MatchString(r.MemberID) || !stage2aBindingID.MatchString(r.RuntimeID) ||
			r.ProfileInForce != "managed-protected" || strings.Compare(previous, r.MemberID) >= 0 ||
			seenRuntimes[r.RuntimeID] {
			return false
		}
		seenRuntimes[r.RuntimeID] = true
		previous = r.MemberID
	}
	return true
}
