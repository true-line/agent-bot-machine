package members

import (
	"encoding/base64"
	"time"
)

type SoulCooperativeMemberLiveRequestV3 struct {
	Stage2aStopRequest
	AssignmentEnvelopeSHA256 string `json:"assignment_envelope_sha256"`
	MemberBAuthoritySHA256   string `json:"member_b_authority_sha256"`
	MemberID                 string `json:"member_id"`
	MemberLaunchID           string `json:"member_launch_id"`
	MemberSelector           string `json:"member_selector"`
	GrantSHA256              string `json:"grant_sha256"`
	ReadySHA256              string `json:"ready_sha256"`
	LauncherPID              int    `json:"launcher_pid"`
	LauncherStartSeconds     int64  `json:"launcher_start_seconds"`
	LauncherStartMicros      int32  `json:"launcher_start_micros"`
	ChildPID                 int    `json:"child_pid"`
	ChildStartSeconds        int64  `json:"child_start_seconds"`
	ChildStartMicros         int32  `json:"child_start_micros"`
	PeerUID                  int    `json:"peer_uid"`
	PeerPID                  int    `json:"peer_pid"`
	ChallengeNonceBase64URL  string `json:"challenge_nonce_base64url"`
	AfterSequence            uint64 `json:"after_sequence"`
	PriorExpiresAt           string `json:"prior_expires_at"`
}

type SoulCooperativeMemberLiveReplyV3 struct {
	ReadyEnvelopeBase64URL          string `json:"ready_envelope_base64url,omitempty"`
	ReadySHA256                     string `json:"ready_sha256,omitempty"`
	BridgeObservedEnvelopeBase64URL string `json:"bridge_observed_envelope_base64url,omitempty"`
	BridgeObservedSHA256            string `json:"bridge_observed_sha256,omitempty"`
	LeaseEnvelopeBase64URL          string `json:"lease_envelope_base64url"`
	LeaseSHA256                     string `json:"lease_sha256"`
	LeaseSequence                   uint64 `json:"lease_sequence"`
}

func ParseSoulCooperativeMemberLiveRequestV3(raw []byte) (SoulCooperativeMemberLiveRequestV3, error) {
	var q SoulCooperativeMemberLiveRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.AssignmentEnvelopeSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.MemberBAuthoritySHA256) ||
		!stage2aPrefixedDigest.MatchString(q.ReadySHA256) ||
		!stage2aPrefixedDigest.MatchString(q.GrantSHA256) ||
		(q.MemberID != "m_lead" && q.MemberID != "m_spec") ||
		!soulLaunchID.MatchString(q.MemberLaunchID) ||
		!stage2aMemberSelectorPattern.MatchString(q.MemberSelector) ||
		q.LauncherPID <= 1 || q.ChildPID <= 1 || q.LauncherPID == q.ChildPID ||
		q.LauncherStartSeconds <= 0 || q.ChildStartSeconds <= 0 ||
		q.LauncherStartMicros < 0 || q.LauncherStartMicros >= 1_000_000 ||
		q.ChildStartMicros < 0 || q.ChildStartMicros >= 1_000_000 ||
		q.PeerUID <= 0 || q.PeerPID != q.LauncherPID || q.AfterSequence >= (1<<53)-1 {
		return SoulCooperativeMemberLiveRequestV3{}, errSoulCooperativeAuthority
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(q.ChallengeNonceBase64URL)
	if err != nil || len(nonce) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != q.ChallengeNonceBase64URL {
		return SoulCooperativeMemberLiveRequestV3{}, errSoulCooperativeAuthority
	}
	prior, err := time.Parse(time.RFC3339Nano, q.PriorExpiresAt)
	if err != nil || prior.IsZero() {
		return SoulCooperativeMemberLiveRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}
