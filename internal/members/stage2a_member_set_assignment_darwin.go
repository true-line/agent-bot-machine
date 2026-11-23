//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"
)

const stage2aMemberSetAssignmentPurpose = "agent-bot/stage2a-member-set-assignment/v1"
const stage2aMemberSelectorPurpose = "agent-bot/stage2a-member-selector/v1"

// HQ can request the exact A-selected cohort after the one-use reservation,
// before B starts and before Hello. B's future two-member FD3 input must bind
// this A-signed assignment; H cannot expand the legacy one-member policy.
// The returned selectors are non-bearer names; no child or B route is granted.
type Stage2aMemberSetAssignmentRequest = Stage2aStopRequest

func ParseStage2aMemberSetAssignmentRequest(raw []byte) (Stage2aMemberSetAssignmentRequest, error) {
	return ParseStage2aStopRequest(raw)
}

type stage2aMemberSetAssignmentPayload struct {
	Contract                 string `json:"contract"`
	Kind                     string `json:"kind"`
	SchemaVersion            int    `json:"schema_version"`
	ProfileInForce           string `json:"profile_in_force"`
	HostID                   string `json:"host_id"`
	InstallationID           string `json:"installation_id"`
	SoulID                   string `json:"soul_id"`
	StartID                  string `json:"start_id"`
	HQEpoch                  string `json:"hq_epoch"`
	PlanID                   string `json:"plan_id"`
	PlanDigest               string `json:"plan_digest"`
	OwnerPlanMemberSetSHA256 string `json:"owner_plan_member_set_sha256"`
	ReservationSHA256        string `json:"reservation_sha256"`
	BAuthority               struct {
		Purpose        string `json:"purpose"`
		EnvelopeSHA256 string `json:"envelope_sha256"`
	} `json:"b_authority"`
	SoulArtifactSHA256          string `json:"soul_artifact_sha256"`
	FrozenSoulInfoSHA256        string `json:"frozen_soul_info_sha256"`
	AdapterManifestRelpath      string `json:"adapter_manifest_relpath"`
	FrozenAdapterManifestSHA256 string `json:"frozen_adapter_manifest_sha256"`
	HostProjectionSHA256        string `json:"host_projection_sha256"`
	DefinitionMeasurement       string `json:"definition_measurement"`
	RunnerUID                   int    `json:"runner_uid"`
	RunnerGID                   int    `json:"runner_gid"`
	Bridge                      struct {
		Account   string `json:"account"`
		UID       int    `json:"uid"`
		GID       int    `json:"gid"`
		Endpoints struct {
			Broker SoulStartEndpoint `json:"broker"`
			Member SoulStartEndpoint `json:"member"`
			Relay  SoulStartEndpoint `json:"relay"`
		} `json:"endpoints"`
	} `json:"bridge"`
	Members   [2]stage2aAssignedMember `json:"members"`
	IssuedAt  string                   `json:"issued_at"`
	ExpiresAt string                   `json:"expires_at"`
}

type stage2aAssignedMember struct {
	MemberID          string `json:"member_id"`
	Role              string `json:"role"`
	AdapterID         string `json:"adapter_id"`
	AdapterVersion    string `json:"adapter_version"`
	CommandPath       string `json:"command_path"`
	CommandSHA256     string `json:"command_sha256"`
	AdjacentCLIPath   string `json:"adjacent_cli_path"`
	AdjacentCLISHA256 string `json:"adjacent_cli_sha256"`
	LaunchID          string `json:"launch_id"`
	MemberSelector    string `json:"member_selector"`
}

func (s *Stage2aService) MemberSetAssign(hqUID int, epoch string,
	q Stage2aMemberSetAssignmentRequest) (Stage2aHelloReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aHelloReply
	if !validStage2aStopRequest(q) || q.HQEpoch != epoch || len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	r, p, expires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || !stage2aMatchesStopSelectors(r, q, hqUID) ||
		r.hello != nil || r.runnerPID != 0 || r.bridgePID != 0 ||
		r.twoMemberChildren != nil || r.childPID != 0 || r.childLauncherPID != 0 ||
		len(r.bridgeAssignment) != 0 || len(r.finalizationEnvelope) != 0 || r.bindReceiptSHA256 != "" ||
		p.Binding.ProfileInForce != "managed-protected" ||
		os.Getuid() != p.MachineUID || os.Geteuid() != p.MachineUID ||
		os.Getgid() != p.MachineGID || os.Getegid() != p.MachineGID ||
		stage2aRecheckExecutionCode(r, p) != nil {
		return reply, errStage2aReservationAuthority
	}
	if len(r.memberSetAssignmentEnvelope) != 0 {
		if !time.Now().Before(r.memberSetAssignmentExpires) {
			return reply, errStage2aReservationExpired
		}
		return Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(r.memberSetAssignmentEnvelope),
			SHA256: stage2aReservationSHA256(r.memberSetAssignmentEnvelope)}, nil
	}
	payload, err := stage2aBuildMemberSetAssignment(r, p, expires)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	envelope, err := signStage2aEnvelope(payload, 1, stage2aMemberSetAssignmentPurpose,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 16<<10 ||
		!time.Now().Before(expires) ||
		stage2aRecheckExecutionCode(r, p) != nil {
		return reply, errStage2aReservationAuthority
	}
	r.memberSetAssignmentEnvelope = envelope
	r.memberSetAssignmentExpires, err = time.Parse(time.RFC3339Nano, payload.ExpiresAt)
	if err != nil || !time.Now().Before(r.memberSetAssignmentExpires) {
		r.memberSetAssignmentEnvelope = nil
		return reply, errStage2aReservationExpired
	}
	return Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: stage2aReservationSHA256(envelope)}, nil
}

func stage2aBuildMemberSetAssignment(r *stage2aLiveReservation,
	p stage2aInstalledPolicy, expires time.Time) (stage2aMemberSetAssignmentPayload, error) {
	var result stage2aMemberSetAssignmentPayload
	if r == nil || stage2aStrictJSON(p.Plan) != nil {
		return result, errStage2aReservationAuthority
	}
	info, err := stage2aReadFrozenClaimFile(p.Binding.Snapshots.Definition, p.Definition, "Contents/SoulInfo.json")
	if err != nil || stage2aStrictJSON(info) != nil {
		return result, errStage2aReservationAuthority
	}
	var frozen struct {
		SoulID  string               `json:"soul_id"`
		Members []stage2aHelloMember `json:"members"`
	}
	if json.Unmarshal(info, &frozen) != nil || frozen.SoulID != p.Binding.SoulID ||
		len(frozen.Members) != 2 || !stage2aHelloMembersMatch(info, frozen.SoulID, frozen.Members) {
		return result, errStage2aReservationAuthority
	}
	roles := slices.Clone(frozen.Members)
	slices.SortFunc(roles, func(a, b stage2aHelloMember) int {
		if a.MemberID < b.MemberID {
			return -1
		}
		if a.MemberID > b.MemberID {
			return 1
		}
		return 0
	})
	var plan Plan
	if json.Unmarshal(p.Plan, &plan) != nil || plan.SoulProtectedLaunch == nil ||
		plan.Purpose != SoulProtectedLaunchInstallPurpose {
		return result, errStage2aReservationAuthority
	}
	adapterID, _ := p.LaunchInputs.EffectiveConfig["adapter_id"].(string)
	adapter, _ := p.LaunchInputs.HostProjection.Adapters[adapterID].(map[string]any)
	command, _ := adapter["command"].([]any)
	if len(command) != 1 {
		return result, errStage2aReservationAuthority
	}
	commandPath, _ := command[0].(string)
	commandSHA := p.LaunchInputs.ComponentDigests["adapter"]
	if !stage2aOwnerReviewedTwoMemberSet(p, roles, commandPath, commandSHA) {
		return result, errStage2aReservationAuthority
	}
	cliPath, cliSHA, ok := stage2aFrozenStockAdapterCLI(p, roles, commandPath, commandSHA)
	if !ok {
		return result, errStage2aReservationAuthority
	}
	manifest, err := stage2aReadFrozenClaimFile(p.Binding.Snapshots.Definition, p.Definition, "Contents/opt/stock-claude.json")
	if err != nil {
		return result, errStage2aReservationAuthority
	}
	projection, err := marshalStage2aReservationJCS(p.LaunchInputs.HostProjection)
	if err != nil {
		return result, errStage2aReservationAuthority
	}
	now := time.Now()
	until := minStage2aTime(now.Add(20*time.Second), expires)
	if !until.After(now) {
		return result, errStage2aReservationAuthority
	}
	a := r.payload.Assignment
	result = stage2aMemberSetAssignmentPayload{
		Contract: "machine/v3", Kind: "stage2a-member-set-assignment", SchemaVersion: 1,
		ProfileInForce: "managed-protected", HostID: p.Binding.HostID,
		InstallationID: a.InstallationID, SoulID: a.SoulID, StartID: a.StartID, HQEpoch: a.HQEpoch,
		PlanID: a.PlanID, PlanDigest: a.PlanDigest,
		OwnerPlanMemberSetSHA256:    plan.SoulProtectedLaunch.OwnerPlanMemberSetSHA256,
		ReservationSHA256:           r.digest,
		SoulArtifactSHA256:          "sha256:" + string(a.SoulArtifactSHA256),
		FrozenSoulInfoSHA256:        stage2aReservationSHA256(info),
		AdapterManifestRelpath:      "Contents/opt/stock-claude.json",
		FrozenAdapterManifestSHA256: stage2aReservationSHA256(manifest),
		HostProjectionSHA256:        stage2aReservationSHA256(projection),
		DefinitionMeasurement:       p.Binding.DefinitionMeasurement,
		RunnerUID:                   p.Runner.UID, RunnerGID: p.Runner.GID,
		IssuedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: until.UTC().Format(time.RFC3339Nano),
	}
	result.BAuthority.Purpose = stage2aReservationPurposeV3
	result.BAuthority.EnvelopeSHA256 = r.digest
	result.Bridge.Account, result.Bridge.UID, result.Bridge.GID = p.Bridge.Account, p.Bridge.UID, p.Bridge.GID
	result.Bridge.Endpoints.Broker = a.Broker
	result.Bridge.Endpoints.Member = a.Member
	result.Bridge.Endpoints.Relay = a.Relay
	for i, role := range roles {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return stage2aMemberSetAssignmentPayload{}, errStage2aReservationAuthority
		}
		launchID := fmt.Sprintf("ln_%x", random)
		selector := stage2aMemberSelector(r.digest, role.MemberID, launchID)
		result.Members[i] = stage2aAssignedMember{
			MemberID: role.MemberID, Role: role.Role, AdapterID: role.AdapterID,
			AdapterVersion: role.AdapterVersion, CommandPath: commandPath, CommandSHA256: commandSHA,
			AdjacentCLIPath: cliPath, AdjacentCLISHA256: cliSHA,
			LaunchID: launchID, MemberSelector: selector,
		}
	}
	if result.Members[0].LaunchID == result.Members[1].LaunchID ||
		result.Members[0].MemberSelector == result.Members[1].MemberSelector ||
		!stage2aPrefixedDigest.MatchString(result.SoulArtifactSHA256) {
		return stage2aMemberSetAssignmentPayload{}, errStage2aReservationAuthority
	}
	return result, nil
}

func stage2aMemberSelector(reservationSHA256, memberID, launchID string) string {
	sum := sha256.Sum256([]byte(stage2aMemberSelectorPurpose + "\x00" + reservationSHA256 + "\x00" + memberID + "\x00" + launchID))
	return fmt.Sprintf("mb_%x", sum)
}
