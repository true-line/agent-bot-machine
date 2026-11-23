package members

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

const soulCooperativeBBindContextV3 = "agent-bot-stage2a-cooperative-bridge-bind-v3"

type SoulCooperativeBVerifyRequestV3 struct {
	ReservationSHA256      string `json:"reservation_sha256"`
	BridgeAssignmentSHA256 string `json:"bridge_assignment_sha256"`
	InstallationID         string `json:"installation_id"`
	StartID                string `json:"start_id"`
	LaunchID               string `json:"launch_id"`
	PlanID                 string `json:"plan_id"`
	PlanDigest             string `json:"plan_digest"`
	HQEpoch                string `json:"hq_epoch"`
	Nonce                  string `json:"nonce"`
	Proof                  string `json:"proof"`
}

type SoulCooperativeBVerifyReplyV3 struct {
	Verified bool `json:"verified"`
}

func ParseSoulCooperativeBVerifyRequestV3(raw []byte) (SoulCooperativeBVerifyRequestV3, error) {
	var q SoulCooperativeBVerifyRequestV3
	if len(raw) == 0 || len(raw) > 2048 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!stage2aPrefixedDigest.MatchString(q.ReservationSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.BridgeAssignmentSHA256) ||
		!soulInstallationID.MatchString(q.InstallationID) || !soulStartID.MatchString(q.StartID) ||
		!soulLaunchID.MatchString(q.LaunchID) || !ValidApproval(q.PlanID, q.PlanDigest) ||
		!soulHQEpoch.MatchString(q.HQEpoch) || !stage2aLowerHex64(q.Nonce) ||
		!stage2aLowerHex64(q.Proof) {
		return SoulCooperativeBVerifyRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}

func soulCooperativeBBindPreimageV3(q SoulCooperativeBVerifyRequestV3,
	bridgeUID int, brokerPath string) ([]byte, error) {
	if bridgeUID < 300 || bridgeUID > 399 || !stage2aAbsolutePath(brokerPath) {
		return nil, errSoulCooperativeAuthority
	}
	return []byte(strings.Join([]string{soulCooperativeBBindContextV3, q.Nonce, q.HQEpoch,
		q.InstallationID, q.StartID, q.LaunchID, q.PlanID, q.PlanDigest,
		q.ReservationSHA256, q.BridgeAssignmentSHA256, strconv.Itoa(bridgeUID), brokerPath}, "\x00")), nil
}

func verifySoulCooperativeBBindV3(proofKey []byte, q SoulCooperativeBVerifyRequestV3,
	bridgeUID int, brokerPath string) error {
	if len(proofKey) != 32 {
		return errSoulCooperativeAuthority
	}
	preimage, err := soulCooperativeBBindPreimageV3(q, bridgeUID, brokerPath)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, proofKey)
	_, _ = mac.Write(preimage)
	got, err := hex.DecodeString(q.Proof)
	if err != nil || subtle.ConstantTimeCompare(mac.Sum(nil), got) != 1 {
		return errSoulCooperativeAuthority
	}
	return nil
}
