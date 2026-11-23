//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"
)

const stage2aBMemberAuthorityPurpose = "agent-bot/stage2a-b-member-authority/v1"

type stage2aBMemberAuthorityPayload struct {
	Contract                          string `json:"contract"`
	Kind                              string `json:"kind"`
	SchemaVersion                     int    `json:"schema_version"`
	ProfileInForce                    string `json:"profile_in_force"`
	HostID                            string `json:"host_id"`
	InstallationID                    string `json:"installation_id"`
	SoulID                            string `json:"soul_id"`
	StartID                           string `json:"start_id"`
	HQEpoch                           string `json:"hq_epoch"`
	PlanID                            string `json:"plan_id"`
	PlanDigest                        string `json:"plan_digest"`
	ReservationSHA256                 string `json:"reservation_sha256"`
	MemberSetAssignmentEnvelopeSHA256 string `json:"member_set_assignment_envelope_sha256"`
	OwnerPlanMemberSetSHA256          string `json:"owner_plan_member_set_sha256"`
	BAuthority                        struct {
		Purpose        string `json:"purpose"`
		EnvelopeSHA256 string `json:"envelope_sha256"`
	} `json:"b_authority"`
	HQUID     int                              `json:"hq_uid"`
	RunnerUID int                              `json:"runner_uid"`
	Bridge    json.RawMessage                  `json:"bridge"`
	Members   [2]stage2aBMemberAuthorityMember `json:"members"`
	IssuedAt  string                           `json:"issued_at"`
	ExpiresAt string                           `json:"expires_at"`
}

type stage2aBMemberAuthorityMember struct {
	MemberID          string                     `json:"member_id"`
	LaunchID          string                     `json:"launch_id"`
	MemberSelector    string                     `json:"member_selector"`
	AdjacentCLIPath   string                     `json:"adjacent_cli_path"`
	AdjacentCLISHA256 string                     `json:"adjacent_cli_sha256"`
	Qualification     Stage2aBridgeQualification `json:"qualification"`
}

type stage2aNativeMemberSelectors struct {
	InstallationID           string `json:"installation_id"`
	StartID                  string `json:"start_id"`
	PlanID                   string `json:"plan_id"`
	PlanDigest               string `json:"plan_digest"`
	ReservationDigest        string `json:"reservation_digest"`
	AssignmentEnvelopeSHA256 string `json:"assignment_envelope_sha256"`
	AuthorityEnvelopeSHA256  string `json:"authority_envelope_sha256"`
	MemberSelectorsSHA256    string `json:"member_selectors_sha256"`
}

type stage2aNativeMemberAssignment struct {
	Version                     string                       `json:"version"`
	MachinePinPath              string                       `json:"machine_pin_path"`
	AssignmentEnvelopeBase64URL string                       `json:"assignment_envelope_base64url"`
	AuthorityEnvelopeBase64URL  string                       `json:"authority_envelope_base64url"`
	Selectors                   stage2aNativeMemberSelectors `json:"selectors"`
	Epoch                       string                       `json:"hq_epoch"`
	BridgeUID                   uint32                       `json:"bridge_uid"`
	HQUID                       uint32                       `json:"hq_uid"`
	RunnerUID                   uint32                       `json:"runner_uid"`
	Expires                     time.Time                    `json:"expires_at"`
	Broker                      stage2aNativeEndpoint        `json:"broker"`
	Relay                       stage2aNativeEndpoint        `json:"relay"`
}

// The A-side FD3 producer never accepts an envelope supplied by H. It verifies
// its own cached assignment against the secure-admin key and exact reservation,
// then signs only the two reviewed policy rows and the existing endpoint set.
// The broker/relay inode samples remain separate runtime FD3 custody facts.
func (s *Stage2aService) stage2aBuildBMemberFD3(r *stage2aLiveReservation,
	p stage2aInstalledPolicy, legacy stage2aNativeAssignment, expires time.Time) ([]byte, error) {
	if r == nil || len(r.memberSetAssignmentEnvelope) == 0 ||
		!time.Now().Before(r.memberSetAssignmentExpires) ||
		!time.Now().Before(expires) || len(s.key) != ed25519.PrivateKeySize {
		return nil, errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	rawAssignment, err := verifyStage2aStoredARecordV3(r.memberSetAssignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, key)
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	var assignment stage2aMemberSetAssignmentPayload
	if json.Unmarshal(rawAssignment, &assignment) != nil {
		return nil, errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(assignment)
	if err != nil || !bytes.Equal(rawAssignment, canonical) ||
		assignment.Contract != "machine/v3" || assignment.Kind != "stage2a-member-set-assignment" ||
		assignment.SchemaVersion != 1 || assignment.ProfileInForce != "managed-protected" ||
		assignment.ReservationSHA256 != r.digest || assignment.PlanID != r.payload.Assignment.PlanID ||
		assignment.PlanDigest != r.request.PlanDigest || assignment.SoulID != r.payload.Assignment.SoulID ||
		assignment.InstallationID != r.request.InstallationID || assignment.StartID != r.request.StartID ||
		assignment.HQEpoch != r.request.HQEpoch || assignment.HostID != p.Binding.HostID ||
		assignment.RunnerUID != p.Runner.UID || assignment.RunnerGID != p.Runner.GID ||
		assignment.Bridge.Account != p.Bridge.Account || assignment.Bridge.UID != p.Bridge.UID ||
		assignment.Bridge.GID != p.Bridge.GID ||
		!reflect.DeepEqual(assignment.Bridge.Endpoints.Broker, r.payload.Assignment.Broker) ||
		!reflect.DeepEqual(assignment.Bridge.Endpoints.Member, r.payload.Assignment.Member) ||
		!reflect.DeepEqual(assignment.Bridge.Endpoints.Relay, r.payload.Assignment.Relay) ||
		assignment.BAuthority.Purpose != stage2aReservationPurposeV3 ||
		assignment.BAuthority.EnvelopeSHA256 != r.digest {
		return nil, errStage2aReservationAuthority
	}
	assignmentExpires, err := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
	if err != nil || !assignmentExpires.Equal(r.memberSetAssignmentExpires) {
		return nil, errStage2aReservationAuthority
	}
	roles := []stage2aHelloMember{
		{MemberID: assignment.Members[0].MemberID, Role: assignment.Members[0].Role,
			AdapterID: assignment.Members[0].AdapterID, AdapterVersion: assignment.Members[0].AdapterVersion},
		{MemberID: assignment.Members[1].MemberID, Role: assignment.Members[1].Role,
			AdapterID: assignment.Members[1].AdapterID, AdapterVersion: assignment.Members[1].AdapterVersion},
	}
	selectedAdapterID, _ := p.LaunchInputs.EffectiveConfig["adapter_id"].(string)
	selectedAdapter, _ := p.LaunchInputs.HostProjection.Adapters[selectedAdapterID].(map[string]any)
	command, _ := selectedAdapter["command"].([]any)
	if len(command) != 1 {
		return nil, errStage2aReservationAuthority
	}
	selectedCommand, _ := command[0].(string)
	if selectedCommand != assignment.Members[0].CommandPath ||
		p.LaunchInputs.ComponentDigests["adapter"] != assignment.Members[0].CommandSHA256 {
		return nil, errStage2aReservationAuthority
	}
	cliPath, cliSHA, ok := stage2aFrozenStockAdapterCLI(p, roles,
		assignment.Members[0].CommandPath, assignment.Members[0].CommandSHA256)
	if !ok {
		return nil, errStage2aReservationAuthority
	}
	projectionSHA, err := stage2aOwnerMemberSetDigest(roles,
		assignment.Members[0].CommandPath, assignment.Members[0].CommandSHA256, cliPath, cliSHA)
	if err != nil || assignment.OwnerPlanMemberSetSHA256 != projectionSHA {
		return nil, errStage2aReservationAuthority
	}
	if !stage2aMemberBridgeQualificationsMatchRoles(p.MemberBridgeQualifications, roles, p.BridgeQualification) ||
		!stage2aOwnerReviewedTwoMemberSet(p, roles, assignment.Members[0].CommandPath, assignment.Members[0].CommandSHA256) ||
		assignment.Members[0].MemberSelector == assignment.Members[1].MemberSelector ||
		assignment.Members[0].LaunchID == assignment.Members[1].LaunchID ||
		assignment.Members[0].MemberSelector != stage2aMemberSelector(r.digest, roles[0].MemberID, assignment.Members[0].LaunchID) ||
		assignment.Members[1].MemberSelector != stage2aMemberSelector(r.digest, roles[1].MemberID, assignment.Members[1].LaunchID) {
		return nil, errStage2aReservationAuthority
	}
	for _, member := range assignment.Members {
		if member.CommandPath != assignment.Members[0].CommandPath ||
			member.CommandSHA256 != assignment.Members[0].CommandSHA256 ||
			member.AdjacentCLIPath != cliPath ||
			member.AdjacentCLISHA256 != cliSHA {
			return nil, errStage2aReservationAuthority
		}
	}
	bridge, err := marshalStage2aReservationJCS(assignment.Bridge)
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	now := time.Now()
	until := minStage2aTime(expires, r.memberSetAssignmentExpires)
	if !until.After(now) {
		return nil, errStage2aReservationAuthority
	}
	payload := stage2aBMemberAuthorityPayload{Contract: "machine/v3", Kind: "stage2a-b-member-authority",
		SchemaVersion: 1, ProfileInForce: "managed-protected", HostID: assignment.HostID,
		InstallationID: assignment.InstallationID, SoulID: assignment.SoulID,
		StartID: assignment.StartID, HQEpoch: assignment.HQEpoch,
		PlanID: assignment.PlanID, PlanDigest: assignment.PlanDigest,
		ReservationSHA256:                 r.digest,
		MemberSetAssignmentEnvelopeSHA256: stage2aReservationSHA256(r.memberSetAssignmentEnvelope),
		OwnerPlanMemberSetSHA256:          assignment.OwnerPlanMemberSetSHA256,
		BAuthority:                        assignment.BAuthority, HQUID: p.HQUID, RunnerUID: p.Runner.UID,
		Bridge: bridge, IssuedAt: now.UTC().Format(time.RFC3339Nano),
		ExpiresAt: until.UTC().Format(time.RFC3339Nano)}
	for i, member := range assignment.Members {
		payload.Members[i] = stage2aBMemberAuthorityMember{MemberID: member.MemberID,
			LaunchID: member.LaunchID, MemberSelector: member.MemberSelector,
			AdjacentCLIPath: member.AdjacentCLIPath, AdjacentCLISHA256: member.AdjacentCLISHA256,
			Qualification: p.MemberBridgeQualifications[i].qualification()}
	}
	authorityEnvelope, err := signStage2aEnvelope(payload, 1, stage2aBMemberAuthorityPurpose, key, s.sign)
	if err != nil || !time.Now().Before(until) || stage2aRecheckExecutionCode(r, p) != nil {
		return nil, errStage2aReservationAuthority
	}
	return stage2aMarshalBMemberFD3(assignment, r.memberSetAssignmentEnvelope,
		authorityEnvelope, legacy, until)
}

func stage2aMarshalBMemberFD3(assignment stage2aMemberSetAssignmentPayload,
	assignmentEnvelope, authorityEnvelope []byte, legacy stage2aNativeAssignment,
	until time.Time) ([]byte, error) {
	if len(assignmentEnvelope) == 0 || len(authorityEnvelope) == 0 ||
		!time.Now().Before(until) ||
		assignment.Members[0].MemberID >= assignment.Members[1].MemberID ||
		assignment.Members[0].MemberSelector == assignment.Members[1].MemberSelector ||
		legacy.BridgeUID == 0 || legacy.HQUID == 0 || legacy.RunnerUID == 0 {
		return nil, errStage2aReservationAuthority
	}
	selectors, err := marshalStage2aReservationJCS([]string{assignment.Members[0].MemberSelector, assignment.Members[1].MemberSelector})
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	fd3 := stage2aNativeMemberAssignment{
		Version: "stage2a-b-assignment/v3", MachinePinPath: SoulAuthorityPin,
		AssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(assignmentEnvelope),
		AuthorityEnvelopeBase64URL:  base64.RawURLEncoding.EncodeToString(authorityEnvelope),
		Selectors: stage2aNativeMemberSelectors{InstallationID: assignment.InstallationID,
			StartID: assignment.StartID, PlanID: assignment.PlanID, PlanDigest: assignment.PlanDigest,
			ReservationDigest:        assignment.ReservationSHA256,
			AssignmentEnvelopeSHA256: stage2aReservationSHA256(assignmentEnvelope),
			AuthorityEnvelopeSHA256:  stage2aReservationSHA256(authorityEnvelope),
			MemberSelectorsSHA256:    stage2aReservationSHA256(selectors)},
		Epoch: assignment.HQEpoch, BridgeUID: legacy.BridgeUID,
		HQUID: legacy.HQUID, RunnerUID: legacy.RunnerUID, Expires: until,
		Broker: legacy.Broker, Relay: legacy.Relay,
	}
	raw, err := json.Marshal(fd3)
	if err != nil || len(raw) == 0 || len(raw) > stage2aBridgeMaxAssignment ||
		stage2aStrictJSON(raw) != nil || !time.Now().Before(until) {
		return nil, errStage2aReservationAuthority
	}
	return raw, nil
}
