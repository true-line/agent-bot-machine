package members

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
)

type SoulCooperativeBObserveRequestV3 struct {
	Stage2aStopRequest
	BridgeAssignmentSHA256 string            `json:"bridge_assignment_sha256"`
	BindReceiptSHA256      string            `json:"bind_receipt_sha256"`
	GrantNonce             string            `json:"grant_nonce"`
	BridgePID              int               `json:"bridge_pid"`
	BridgeStartSeconds     int64             `json:"bridge_start_seconds"`
	BridgeStartMicros      int32             `json:"bridge_start_micros"`
	RelaySocket            Stage2aRelayClaim `json:"relay_socket"`
}

func ParseSoulCooperativeBObserveRequestV3(raw []byte) (SoulCooperativeBObserveRequestV3, error) {
	var q SoulCooperativeBObserveRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF {
		return SoulCooperativeBObserveRequestV3{}, errSoulCooperativeAuthority
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(q.GrantNonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != q.GrantNonce ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.BridgeAssignmentSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.BindReceiptSHA256) ||
		q.BridgePID <= 1 || q.BridgeStartSeconds <= 0 ||
		q.BridgeStartMicros < 0 || q.BridgeStartMicros >= 1_000_000 ||
		!stage2aAbsolutePath(q.RelaySocket.Path) || len(q.RelaySocket.Path) > 103 ||
		!validStage2aKernelClaim(q.RelaySocket.Socket) {
		return SoulCooperativeBObserveRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}
