package members

import (
	"encoding/base64"
	"errors"
	"time"
)

const Stage2aMemberLiveLeasePurpose = "agent-bot/stage2a-member-live-lease/v1"

// H supplies the kernel peer observed on the existing local admission socket.
// A reobserves that exact wrapper and both children before signing a lease.
type Stage2aMemberLiveRequest struct {
	Stage2aStopRequest
	MemberID                       string `json:"member_id"`
	MemberSelector                 string `json:"member_selector"`
	MemberLaunchID                 string `json:"member_launch_id"`
	GrantSHA256                    string `json:"grant_sha256"`
	ChildObservationEnvelopeSHA256 string `json:"child_observation_envelope_sha256"`
	LauncherPID                    int    `json:"launcher_pid"`
	ChildPID                       int    `json:"child_pid"`
	PeerUID                        int    `json:"peer_uid"`
	PeerPID                        int    `json:"peer_pid"`
	ChallengeNonceBase64URL        string `json:"challenge_nonce_base64url"`
	AfterSequence                  uint64 `json:"after_sequence"`
	PriorExpiresAt                 string `json:"prior_expires_at"`
}

func ParseStage2aMemberLiveRequest(raw []byte) (Stage2aMemberLiveRequest, error) {
	var q Stage2aMemberLiveRequest
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || validateStage2aMemberLiveRequest(q) != nil {
		return Stage2aMemberLiveRequest{}, errors.New("invalid Stage 2a member live request")
	}
	return q, nil
}

func validateStage2aMemberLiveRequest(q Stage2aMemberLiveRequest) error {
	if !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aBindingID.MatchString(q.MemberID) ||
		!stage2aMemberSelectorPattern.MatchString(q.MemberSelector) ||
		!soulLaunchID.MatchString(q.MemberLaunchID) ||
		!stage2aPrefixedDigest.MatchString(q.GrantSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.ChildObservationEnvelopeSHA256) ||
		q.LauncherPID <= 1 || q.ChildPID <= 1 || q.LauncherPID == q.ChildPID ||
		q.PeerUID <= 0 || q.PeerPID != q.LauncherPID ||
		q.AfterSequence >= (1<<53)-1 {
		return errors.New("invalid Stage 2a member live request")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(q.ChallengeNonceBase64URL)
	if err != nil || len(nonce) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != q.ChallengeNonceBase64URL {
		return errors.New("invalid Stage 2a member live nonce")
	}
	prior, err := time.Parse(time.RFC3339Nano, q.PriorExpiresAt)
	if err != nil || prior.IsZero() {
		return errors.New("invalid Stage 2a member live expiry")
	}
	return nil
}
