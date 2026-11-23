package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type SoulCooperativeChildObserveRequestV3 struct {
	Stage2aStopRequest
	Members []SoulCooperativeChildObserveInputV3 `json:"members"`
}

type SoulCooperativeChildObserveInputV3 struct {
	MemberID              string `json:"member_id"`
	MemberLaunchID        string `json:"member_launch_id"`
	MemberSelector        string `json:"member_selector"`
	ChildLauncherPID      int    `json:"child_launcher_pid"`
	ChildPID              int    `json:"child_pid"`
	GrantSHA256           string `json:"grant_sha256"`
	HObservationBase64URL string `json:"h_observation_base64url"`
	HObservationSHA256    string `json:"h_observation_sha256"`
}

type soulCooperativeHProcessV3 struct {
	UID          int   `json:"uid"`
	GID          int   `json:"gid"`
	PID          int   `json:"pid"`
	StartSeconds int64 `json:"start_seconds"`
	StartMicros  int32 `json:"start_micros"`
}

type soulCooperativeHChildReceiptV3 struct {
	Plugin                   string                    `json:"plugin"`
	Kind                     string                    `json:"kind"`
	Schema                   string                    `json:"schema"`
	ReservationSHA256        string                    `json:"reservation_sha256"`
	AssignmentEnvelopeSHA256 string                    `json:"assignment_envelope_sha256"`
	InstallationID           string                    `json:"installation_id"`
	StartID                  string                    `json:"start_id"`
	LaunchID                 string                    `json:"launch_id"`
	HQEpoch                  string                    `json:"hq_epoch"`
	MemberID                 string                    `json:"member_id"`
	MemberLaunchID           string                    `json:"member_launch_id"`
	MemberSelector           string                    `json:"member_selector"`
	GrantSHA256              string                    `json:"grant_sha256"`
	LauncherProcess          soulCooperativeHProcessV3 `json:"launcher_process"`
	ChildProcess             soulCooperativeHProcessV3 `json:"child_process"`
	At                       int64                     `json:"at"`
	Profile                  string                    `json:"profile"`
	Seq                      int64                     `json:"seq"`
}

func ParseSoulCooperativeChildObserveRequestV3(raw []byte) (SoulCooperativeChildObserveRequestV3, error) {
	var q SoulCooperativeChildObserveRequestV3
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		len(q.Members) != 2 || q.Members[0].MemberID != "m_lead" ||
		q.Members[1].MemberID != "m_spec" ||
		q.Members[0].ChildLauncherPID == q.Members[1].ChildLauncherPID ||
		q.Members[0].ChildPID == q.Members[1].ChildPID {
		return SoulCooperativeChildObserveRequestV3{}, errSoulCooperativeAuthority
	}
	for _, row := range q.Members {
		if !soulLaunchID.MatchString(row.MemberLaunchID) ||
			!stage2aMemberSelectorPattern.MatchString(row.MemberSelector) ||
			!stage2aPrefixedDigest.MatchString(row.GrantSHA256) ||
			!stage2aPrefixedDigest.MatchString(row.HObservationSHA256) ||
			row.ChildLauncherPID <= 1 || row.ChildPID <= 1 ||
			row.ChildLauncherPID == row.ChildPID {
			return SoulCooperativeChildObserveRequestV3{}, errSoulCooperativeAuthority
		}
		if _, _, err := decodeSoulCooperativeHChildReceipt(row); err != nil {
			return SoulCooperativeChildObserveRequestV3{}, errSoulCooperativeAuthority
		}
	}
	return q, nil
}

func decodeSoulCooperativeHChildReceipt(in SoulCooperativeChildObserveInputV3) (
	[]byte, soulCooperativeHChildReceiptV3, error) {
	var row soulCooperativeHChildReceiptV3
	if len(in.HObservationBase64URL) == 0 ||
		len(in.HObservationBase64URL) > base64.RawURLEncoding.EncodedLen(2048) {
		return nil, row, errSoulCooperativeAuthority
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(in.HObservationBase64URL)
	if err != nil || len(raw) == 0 || len(raw) > 2048 ||
		base64.RawURLEncoding.EncodeToString(raw) != in.HObservationBase64URL ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != in.HObservationSHA256 ||
		stage2aStrictJSON(raw) != nil || stage2aDecodeExact(raw, &row) != nil {
		return nil, soulCooperativeHChildReceiptV3{}, errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) ||
		row.Plugin != "hq" || row.Kind != "hq.soul.member.observed" ||
		row.Schema != "agent-bot-hq/stage2a-cooperative-member-observed/v1" ||
		row.Profile != "managed-cooperative" || row.Seq <= 0 || row.At <= 0 ||
		!stage2aPrefixedDigest.MatchString(row.ReservationSHA256) ||
		!stage2aPrefixedDigest.MatchString(row.AssignmentEnvelopeSHA256) ||
		!stage2aPrefixedDigest.MatchString(row.GrantSHA256) ||
		row.MemberID != in.MemberID || row.MemberLaunchID != in.MemberLaunchID ||
		row.MemberSelector != in.MemberSelector || row.GrantSHA256 != in.GrantSHA256 ||
		row.LauncherProcess.PID != in.ChildLauncherPID || row.ChildProcess.PID != in.ChildPID ||
		row.LauncherProcess.StartSeconds <= 0 || row.ChildProcess.StartSeconds <= 0 ||
		row.LauncherProcess.StartMicros < 0 || row.LauncherProcess.StartMicros >= 1_000_000 ||
		row.ChildProcess.StartMicros < 0 || row.ChildProcess.StartMicros >= 1_000_000 ||
		time.Since(time.UnixMilli(row.At)) > 30*time.Second ||
		time.Until(time.UnixMilli(row.At)) > time.Second {
		return nil, soulCooperativeHChildReceiptV3{}, errSoulCooperativeAuthority
	}
	return raw, row, nil
}
