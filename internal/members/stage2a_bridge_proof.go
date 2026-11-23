package members

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

const stage2aBridgeBindPurpose = "agent-bot-stage2a-bridge-bind-v2"

// Stage2aVerifyBRequest carries only a selector, a broker challenge and its
// proof. Machine derives B's UID and broker path from its signed reservation.
type Stage2aVerifyBRequest struct {
	ReservationSHA256 string `json:"reservation_sha256"`
	InstallationID    string `json:"installation_id"`
	StartID           string `json:"start_id"`
	LaunchID          string `json:"launch_id"`
	PlanID            string `json:"plan_id"`
	PlanDigest        string `json:"plan_digest"`
	HQEpoch           string `json:"hq_epoch"`
	Challenge         string `json:"challenge"`
	Proof             string `json:"proof"`
}

type Stage2aVerifyBReply struct {
	Verified bool `json:"verified"`
}

func ParseStage2aVerifyBRequest(raw []byte) (Stage2aVerifyBRequest, error) {
	var q Stage2aVerifyBRequest
	if len(raw) == 0 || len(raw) > 2048 || stage2aStrictJSON(raw) != nil {
		return q, errors.New("invalid Stage 2a B verification request")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&q) != nil || !validStage2aBridgeSelector(q) {
		return Stage2aVerifyBRequest{}, errors.New("invalid Stage 2a B verification request")
	}
	return q, nil
}

func stage2aLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func stage2aBridgeBindPreimage(q Stage2aVerifyBRequest, a SoulStartAssignment) ([]byte, error) {
	if !validStage2aBridgeSelector(q) || a.InstallationID != q.InstallationID ||
		a.StartID != q.StartID || a.LaunchID != q.LaunchID || a.PlanID != q.PlanID ||
		a.PlanDigest != q.PlanDigest || a.HQEpoch != q.HQEpoch || a.BridgeUID < 300 || a.BridgeUID > 399 ||
		!stage2aAbsolutePath(a.Broker.SocketPath) {
		return nil, errors.New("invalid Stage 2a bridge bind assignment")
	}
	return []byte(strings.Join([]string{
		stage2aBridgeBindPurpose, q.Challenge, q.HQEpoch,
		q.InstallationID, q.StartID, q.LaunchID, q.PlanID, q.PlanDigest,
		q.ReservationSHA256, strconv.Itoa(a.BridgeUID), a.Broker.SocketPath,
	}, "\x00")), nil
}

func validStage2aBridgeSelector(q Stage2aVerifyBRequest) bool {
	return strings.HasPrefix(q.ReservationSHA256, "sha256:") &&
		stage2aLowerHex64(strings.TrimPrefix(q.ReservationSHA256, "sha256:")) &&
		soulInstallationID.MatchString(q.InstallationID) && soulStartID.MatchString(q.StartID) &&
		soulLaunchID.MatchString(q.LaunchID) && ValidApproval(q.PlanID, q.PlanDigest) &&
		soulHQEpoch.MatchString(q.HQEpoch) && stage2aLowerHex64(q.Challenge) &&
		stage2aLowerHex64(q.Proof)
}

func verifyStage2aBridgeBind(key []byte, q Stage2aVerifyBRequest, a SoulStartAssignment) error {
	if len(key) != 32 {
		return errors.New("missing Stage 2a bridge proof key")
	}
	preimage, err := stage2aBridgeBindPreimage(q, a)
	if err != nil {
		return err
	}
	want := hmac.New(sha256.New, key)
	_, _ = want.Write(preimage)
	got, err := hex.DecodeString(q.Proof)
	if err != nil || subtle.ConstantTimeCompare(want.Sum(nil), got) != 1 {
		return errors.New("invalid Stage 2a bridge bind proof")
	}
	return nil
}
