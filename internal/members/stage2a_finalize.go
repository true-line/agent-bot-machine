package members

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const Stage2aFinalizationPurpose = "agent-bot/stage2a-finalization/v1"
const Stage2aLiveLeasePurpose = "agent-bot/stage2a-live-lease/v1"

type Stage2aRelayClaim struct {
	Path   string                 `json:"path"`
	Socket Stage2aKernelNodeClaim `json:"socket"`
}

type Stage2aFinalizeBRequest struct {
	Stage2aStopRequest
	BindReceiptSHA256 string            `json:"bind_receipt_sha256"`
	RelaySocket       Stage2aRelayClaim `json:"relay_socket"`
}

type Stage2aFinalizeBReply struct {
	EnvelopeBase64URL      string `json:"envelope_base64url"`
	SHA256                 string `json:"sha256"`
	FinalizedLiveExpiresAt int64  `json:"finalized_live_expires_at"`
}

type Stage2aFinalizationPayload struct {
	Schema string `json:"schema"`
	Stage2aStopRequest
	BindReceiptSHA256 string            `json:"bind_receipt_sha256"`
	RelaySocket       Stage2aRelayClaim `json:"relay_socket"`
	BridgePID         int               `json:"bridge_pid"`
	FinalizedAt       string            `json:"finalized_at"`
}

type Stage2aLiveReply struct {
	ReservationSHA256      string `json:"reservation_sha256"`
	Phase                  string `json:"phase"`
	BridgePID              int    `json:"bridge_pid"`
	RunnerPID              int    `json:"runner_pid"`
	FinalizationSHA256     string `json:"finalization_sha256,omitempty"`
	BindReceiptSHA256      string `json:"bind_receipt_sha256,omitempty"`
	FinalizedLiveExpiresAt int64  `json:"finalized_live_expires_at,omitempty"`
	LeaseEnvelopeBase64URL string `json:"lease_envelope_base64url,omitempty"`
	LeaseSHA256            string `json:"lease_sha256,omitempty"`
	LeaseSequence          uint64 `json:"lease_sequence,omitempty"`
}

type Stage2aLiveRequest struct {
	Stage2aStopRequest
	Challenge string `json:"challenge"`
}

// A signs each short finalized lease after rechecking the installed policy,
// spent bind/finalization and the same kernel process starts granted to R/B.
// HQ relays this envelope on the already assigned R admission channel; an
// unsigned HQ expiry cannot extend the stock child lifetime.
type Stage2aLiveRoleIdentity struct {
	PID          int    `json:"pid"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	StartSeconds int64  `json:"start_seconds"`
	StartMicros  int32  `json:"start_micros"`
}

type Stage2aLiveLeasePayload struct {
	Schema string `json:"schema"`
	Stage2aStopRequest
	FinalizationSHA256      string                   `json:"finalization_sha256"`
	HelloFinalizationSHA256 string                   `json:"hello_finalization_sha256,omitempty"`
	BindReceiptSHA256       string                   `json:"bind_receipt_sha256"`
	Challenge               string                   `json:"challenge"`
	Runner                  Stage2aLiveRoleIdentity  `json:"runner"`
	Bridge                  Stage2aLiveRoleIdentity  `json:"bridge"`
	ChildLauncher           *Stage2aLiveRoleIdentity `json:"child_launcher,omitempty"`
	Child                   *Stage2aLiveRoleIdentity `json:"child,omitempty"`
	ChildReceiptSHA256      string                   `json:"child_receipt_sha256,omitempty"`
	Sequence                uint64                   `json:"sequence"`
	IssuedAtMS              int64                    `json:"issued_at_ms"`
	ExpiresAtMS             int64                    `json:"expires_at_ms"`
}

func ParseStage2aFinalizeBRequest(raw []byte) (Stage2aFinalizeBRequest, error) {
	var q Stage2aFinalizeBRequest
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errors.New("invalid Stage 2a finalization")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!strings.HasPrefix(q.BindReceiptSHA256, "sha256:") ||
		!stage2aLowerHex64(strings.TrimPrefix(q.BindReceiptSHA256, "sha256:")) ||
		!stage2aAbsolutePath(q.RelaySocket.Path) || len(q.RelaySocket.Path) > 103 ||
		!validStage2aKernelClaim(q.RelaySocket.Socket) {
		return Stage2aFinalizeBRequest{}, errors.New("invalid Stage 2a finalization")
	}
	return q, nil
}

func ParseStage2aLiveRequest(raw []byte) (Stage2aLiveRequest, error) {
	var q Stage2aLiveRequest
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return Stage2aLiveRequest{}, errors.New("invalid Stage 2a Live request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || !validStage2aStopRequest(q.Stage2aStopRequest) {
		return Stage2aLiveRequest{}, errors.New("invalid Stage 2a Live request")
	}
	if !validStage2aLiveChallenge(q.Challenge) {
		return Stage2aLiveRequest{}, errors.New("invalid Stage 2a Live challenge")
	}
	return q, nil
}

func validStage2aLiveChallenge(encoded string) bool {
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil && len(challenge) == 32 && base64.RawURLEncoding.EncodeToString(challenge) == encoded
}
