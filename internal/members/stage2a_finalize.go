package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const Stage2aFinalizationPurpose = "agent-bot/stage2a-finalization/v1"

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

func ParseStage2aLiveRequest(raw []byte) (Stage2aStopRequest, error) {
	return ParseStage2aStopRequest(raw)
}
