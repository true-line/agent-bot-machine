package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

type SoulCooperativeStartRequestV3 struct {
	SoulCooperativeReserveRequest
	AdmissionChallengeBase64URL string `json:"admission_challenge_base64url"`
}

func ParseSoulCooperativeStartRequestV3(raw []byte) (SoulCooperativeStartRequestV3, error) {
	var q SoulCooperativeStartRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || !q.SoulCooperativeReserveRequest.valid() ||
		q.LaunchID == "" || q.AdmissionChallengeSHA256 == "" {
		return SoulCooperativeStartRequestV3{}, errSoulCooperativeAuthority
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(q.AdmissionChallengeBase64URL)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != q.AdmissionChallengeBase64URL ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(challenge)) != q.AdmissionChallengeSHA256 {
		return SoulCooperativeStartRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}

type SoulCooperativeAttachRequestV3 struct {
	ReservationSHA256           string `json:"reservation_sha256"`
	InstallationID              string `json:"installation_id"`
	StartID                     string `json:"start_id"`
	LaunchID                    string `json:"launch_id"`
	AdmissionChallengeBase64URL string `json:"admission_challenge_base64url"`
	RunnerPID                   int    `json:"runner_pid"`
}

func ParseSoulCooperativeAttachRequestV3(raw []byte) (SoulCooperativeAttachRequestV3, error) {
	var q SoulCooperativeAttachRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!stage2aPrefixedDigest.MatchString(q.ReservationSHA256) ||
		!soulInstallationID.MatchString(q.InstallationID) || !soulStartID.MatchString(q.StartID) ||
		!soulLaunchID.MatchString(q.LaunchID) || q.RunnerPID <= 1 || q.RunnerPID > 1<<31-1 {
		return SoulCooperativeAttachRequestV3{}, errSoulCooperativeAuthority
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(q.AdmissionChallengeBase64URL)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != q.AdmissionChallengeBase64URL {
		return SoulCooperativeAttachRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}
