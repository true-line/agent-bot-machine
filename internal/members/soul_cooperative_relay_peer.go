package members

import (
	"encoding/base64"
)

const SoulCooperativeRelayPeerPurposeV3 = "agent-bot/soul-cooperative-relay-peer/v3"

type SoulCooperativeRelayPeerSnapshotV3 struct {
	UID                int    `json:"uid"`
	PID                int    `json:"pid"`
	PIDVersion         uint32 `json:"pid_version"`
	StartSeconds       int64  `json:"start_seconds"`
	StartMicros        int32  `json:"start_micros"`
	ParentPID          int    `json:"parent_pid"`
	ParentUID          int    `json:"parent_uid"`
	ParentStartSeconds int64  `json:"parent_start_seconds"`
	ParentStartMicros  int32  `json:"parent_start_micros"`
}

type SoulCooperativeRelayPeerRequestV3 struct {
	Stage2aStopRequest
	MemberID                string                             `json:"member_id"`
	MemberLaunchID          string                             `json:"member_launch_id"`
	MemberSelector          string                             `json:"member_selector"`
	ReadySHA256             string                             `json:"ready_sha256"`
	BridgeObservedSHA256    string                             `json:"bridge_observed_sha256"`
	BLeaseSHA256            string                             `json:"b_lease_sha256"`
	BLeaseSequence          uint64                             `json:"b_lease_sequence"`
	MemberLeaseSHA256       string                             `json:"member_lease_sha256"`
	MemberLeaseSequence     uint64                             `json:"member_lease_sequence"`
	BridgePID               int                                `json:"bridge_pid"`
	BridgeStartSeconds      int64                              `json:"bridge_start_seconds"`
	BridgeStartMicros       int32                              `json:"bridge_start_micros"`
	RelaySocket             Stage2aRelayClaim                  `json:"relay_socket"`
	RelaySocketBirthtimeNS  string                             `json:"relay_socket_birthtime_ns"`
	CLIPath                 string                             `json:"cli_path"`
	CLISHA256               string                             `json:"cli_sha256"`
	ChallengeNonceBase64URL string                             `json:"challenge_nonce_base64url"`
	Peer                    SoulCooperativeRelayPeerSnapshotV3 `json:"peer"`
}

type SoulCooperativeRelayPeerReplyV3 struct {
	PeerEnvelopeBase64URL        string `json:"peer_envelope_base64url"`
	PeerSHA256                   string `json:"peer_sha256"`
	MemberLeaseEnvelopeBase64URL string `json:"member_lease_envelope_base64url"`
	MemberLeaseSHA256            string `json:"member_lease_sha256"`
}

func stage2aPositiveDecimal(value string) bool {
	if len(value) == 0 || len(value) > 19 || value[0] == '0' {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func ParseSoulCooperativeRelayPeerRequestV3(raw []byte) (SoulCooperativeRelayPeerRequestV3, error) {
	var q SoulCooperativeRelayPeerRequestV3
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		(q.MemberID != "m_lead" && q.MemberID != "m_spec") ||
		!soulLaunchID.MatchString(q.MemberLaunchID) ||
		!stage2aMemberSelectorPattern.MatchString(q.MemberSelector) ||
		!stage2aPrefixedDigest.MatchString(q.ReadySHA256) ||
		!stage2aPrefixedDigest.MatchString(q.BridgeObservedSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.BLeaseSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.MemberLeaseSHA256) ||
		q.BLeaseSequence == 0 || q.MemberLeaseSequence == 0 ||
		q.BridgePID <= 1 || q.BridgeStartSeconds <= 0 ||
		q.BridgeStartMicros < 0 || q.BridgeStartMicros >= 1_000_000 ||
		!stage2aAbsolutePath(q.RelaySocket.Path) ||
		!validStage2aKernelClaim(q.RelaySocket.Socket) ||
		!stage2aPositiveDecimal(q.RelaySocketBirthtimeNS) ||
		!stage2aAbsolutePath(q.CLIPath) ||
		!stage2aPrefixedDigest.MatchString(q.CLISHA256) ||
		q.Peer.UID <= 0 || q.Peer.PID <= 1 || q.Peer.PIDVersion == 0 ||
		q.Peer.StartSeconds <= 0 || q.Peer.StartMicros < 0 ||
		q.Peer.StartMicros >= 1_000_000 || q.Peer.ParentPID <= 1 ||
		q.Peer.ParentUID <= 0 || q.Peer.ParentStartSeconds <= 0 ||
		q.Peer.ParentStartMicros < 0 || q.Peer.ParentStartMicros >= 1_000_000 {
		return SoulCooperativeRelayPeerRequestV3{}, errSoulCooperativeAuthority
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(q.ChallengeNonceBase64URL)
	if err != nil || len(nonce) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != q.ChallengeNonceBase64URL {
		return SoulCooperativeRelayPeerRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}
