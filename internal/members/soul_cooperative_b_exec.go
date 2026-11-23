package members

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
)

type SoulCooperativeBExecRequestV3 struct {
	ReservationSHA256 string `json:"reservation_sha256"`
	InstallationID    string `json:"installation_id"`
	StartID           string `json:"start_id"`
	LaunchID          string `json:"launch_id"`
	Nonce             string `json:"nonce"`
	PID               int    `json:"pid"`
}

func ParseSoulCooperativeBExecRequestV3(raw []byte) (SoulCooperativeBExecRequestV3, error) {
	var q SoulCooperativeBExecRequestV3
	if len(raw) == 0 || len(raw) > 2048 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!stage2aPrefixedDigest.MatchString(q.ReservationSHA256) ||
		!soulInstallationID.MatchString(q.InstallationID) || !soulStartID.MatchString(q.StartID) ||
		!soulLaunchID.MatchString(q.LaunchID) || q.PID <= 1 || q.PID > 1<<31-1 {
		return SoulCooperativeBExecRequestV3{}, errSoulCooperativeAuthority
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(q.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != q.Nonce {
		return SoulCooperativeBExecRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}

type SoulCooperativeBExecReplyV3 struct {
	EnvelopeBase64URL                 string `json:"envelope_base64url"`
	SHA256                            string `json:"sha256"`
	ReservationEnvelopeBase64URL      string `json:"reservation_envelope_base64url"`
	BridgeAssignmentEnvelopeBase64URL string `json:"bridge_assignment_envelope_base64url"`
}
