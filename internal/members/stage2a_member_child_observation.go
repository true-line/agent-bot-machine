package members

import (
	"errors"
)

const Stage2aMemberChildObservationPurpose = "agent-bot/stage2a-member-set-child-observation/v1"

type Stage2aMemberChildObservationRequest struct {
	Stage2aStopRequest
	Members []Stage2aMemberChildObservationInput `json:"members"`
}

type Stage2aMemberChildObservationInput struct {
	MemberID         string `json:"member_id"`
	MemberLaunchID   string `json:"member_launch_id"`
	MemberSelector   string `json:"member_selector"`
	ChildLauncherPID int    `json:"child_launcher_pid"`
	ChildPID         int    `json:"child_pid"`
	GrantSHA256      string `json:"grant_sha256"`
}

func ParseStage2aMemberChildObservationRequest(raw []byte) (Stage2aMemberChildObservationRequest, error) {
	var q Stage2aMemberChildObservationRequest
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		len(q.Members) != 2 ||
		q.Members[0].MemberID >= q.Members[1].MemberID ||
		q.Members[0].ChildLauncherPID == q.Members[1].ChildLauncherPID ||
		q.Members[0].ChildPID == q.Members[1].ChildPID {
		return Stage2aMemberChildObservationRequest{}, errors.New("invalid Stage 2a two-member child observation request")
	}
	for _, member := range q.Members {
		if !stage2aBindingID.MatchString(member.MemberID) ||
			!soulLaunchID.MatchString(member.MemberLaunchID) ||
			!stage2aMemberSelectorPattern.MatchString(member.MemberSelector) ||
			member.ChildLauncherPID <= 1 || member.ChildPID <= 1 ||
			member.ChildLauncherPID == member.ChildPID ||
			!stage2aPrefixedDigest.MatchString(member.GrantSHA256) {
			return Stage2aMemberChildObservationRequest{}, errors.New("invalid Stage 2a member child observation")
		}
	}
	return q, nil
}
