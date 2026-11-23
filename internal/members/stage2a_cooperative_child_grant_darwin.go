//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"reflect"
	"time"
)

const stage2aCooperativeChildGrantPurpose = "agent-bot/soul-cooperative-child-grant/v1"

// This is a separate authority from Stage2aRoleGrant. Its only consumer is
// the cooperative R wrapper; a protected child cannot accept this purpose.
type stage2aCooperativeChildGrant struct {
	Contract                 string `json:"contract"`
	ProfileInForce           string `json:"profile_in_force"`
	ReservationSHA256        string `json:"reservation_sha256"`
	BridgeAssignmentSHA256   string `json:"bridge_assignment_sha256"`
	AssignmentEnvelopeSHA256 string `json:"assignment_envelope_sha256"`
	MemberBAuthoritySHA256   string `json:"member_b_authority_sha256"`
	InstallationID           string `json:"installation_id"`
	StartID                  string `json:"start_id"`
	HQEpoch                  string `json:"hq_epoch"`
	MemberID                 string `json:"member_id"`
	MemberLaunchID           string `json:"member_launch_id"`
	MemberSelector           string `json:"member_selector"`
	Nonce                    string `json:"nonce"`
	PID                      int    `json:"pid"`
	InvocationSHA256         string `json:"invocation_sha256"`
	ExpiresAt                string `json:"expires_at"`
}

type stage2aCooperativeChildInvocation struct {
	ReservationEnvelopeBase64URL      string                      `json:"reservation_envelope_base64url"`
	BridgeEnvelopeBase64URL           string                      `json:"bridge_envelope_base64url"`
	AssignmentEnvelopeBase64URL       string                      `json:"assignment_envelope_base64url"`
	MemberBAuthorityEnvelopeBase64URL string                      `json:"member_b_authority_envelope_base64url"`
	Runner                            SoulRunner                  `json:"runner"`
	Launch                            Stage2aLaunchInputRecords   `json:"launch_inputs"`
	RuntimeV3                         stage2aDomainInventoryRefV3 `json:"runtime_v3"`
	MemberID                          string                      `json:"member_id"`
	MemberLaunchID                    string                      `json:"member_launch_id"`
	MemberSelector                    string                      `json:"member_selector"`
	Executable                        string                      `json:"executable"`
	ExecutableSHA256                  string                      `json:"executable_sha256"`
	RelaySocket                       string                      `json:"relay_socket"`
	SandboxPath                       string                      `json:"sandbox_path"`
	SandboxSHA256                     string                      `json:"sandbox_sha256"`
	Workdir                           string                      `json:"workdir"`
	Environment                       map[string]string           `json:"environment"`
}

// The caller holds A's pair and installation locks, loads these retained
// envelopes from A custody, and supplies a durable exclusive spend. The
// routine still verifies every signature and selection before signing.
func prepareStage2aCooperativeChildGrant(in SoulCooperativeInstalledAuthority,
	reservationEnvelope, bridgeEnvelope, assignmentEnvelope, memberBAuthorityEnvelope []byte,
	memberID, memberLaunchID, memberSelector, nonce string, wrapperPID int,
	now time.Time, key ed25519.PublicKey, sign func([]byte) ([]byte, error),
	spend func(string) error) (Stage2aExecReply, error) {
	var empty Stage2aExecReply
	p := in.Policy
	nonceBytes, nonceErr := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if p.Schema != soulCooperativeTwoMemberInstallSchemaV3 ||
		p.Profile != "managed-cooperative" || !in.matchesInstalledRecord() ||
		p.validate() != nil || len(key) != ed25519.PublicKeySize ||
		os.Getuid() != p.MachineUID || os.Geteuid() != p.MachineUID ||
		os.Getgid() != p.MachineGID || os.Getegid() != p.MachineGID ||
		base64.RawURLEncoding.EncodeToString(key) != p.MachinePublicKey ||
		sign == nil || spend == nil || wrapperPID <= 1 ||
		nonceErr != nil || len(nonceBytes) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonceBytes) != nonce ||
		!stage2aMemberSelectorPattern.MatchString(memberSelector) ||
		!soulLaunchID.MatchString(memberLaunchID) ||
		(memberID != "m_lead" && memberID != "m_spec") {
		return empty, errSoulCooperativeAuthority
	}
	pin, err := stage2aReadRootFile(SoulAuthorityPin, ed25519.PublicKeySize, 0444)
	if err != nil || !bytes.Equal(pin, key) {
		return empty, errSoulCooperativeAuthority
	}
	root, err := stage2aReadRootFile(ReceiptPath(in.PlanID), 256<<10, 0644)
	if err != nil || !bytes.Equal(root, in.RootReceipt) {
		return empty, errSoulCooperativeAuthority
	}
	reservation, bridge, assignment, member, reservationSHA, bridgeSHA, assignmentSHA, until,
		err := verifyStage2aCooperativeChildSelection(reservationEnvelope, bridgeEnvelope,
		assignmentEnvelope, memberID, memberLaunchID, memberSelector, key, now)
	if err != nil || reservation.Assignment.PlanID != in.PlanID ||
		reservation.Assignment.PlanDigest != in.PlanDigest ||
		reservation.HostID != p.HostID ||
		reservation.Assignment.InstallationID != p.Runner.InstallationID ||
		reservation.Assignment.StartID != p.ReviewedStartID ||
		reservation.Assignment.HQEpoch != p.HQEpoch ||
		reservation.MeasurementBinding.RInventory.InventoryDigest != in.ObservedRInventorySHA256 ||
		assignment.OwnerPlanMemberSetSHA256 != p.OwnerPlanMemberSetSHA256 ||
		assignment.RunnerUID != p.Runner.UID || assignment.RunnerGID != p.Runner.GID ||
		assignment.DefinitionMeasurement != p.DefinitionMeasurement ||
		assignment.Bridge.UID != p.Bridge.UID || assignment.Bridge.GID != p.Bridge.GID ||
		!reflect.DeepEqual(assignment.Bridge.Endpoints, bridge.Endpoints) ||
		member.CommandSHA256 != p.LaunchInputs.ComponentDigests["adapter"] ||
		p.LaunchInputs.EffectiveConfig["profile"] != "managed-cooperative" ||
		!stage2aSystemImageSelected(*p.LaunchInputs, "/usr/bin/sandbox-exec") ||
		trustedPath(OSHost{}, SoulChildSandbox, false) != nil ||
		checkDarwinACLs(pathAncestry(SoulChildSandbox)) != nil {
		return empty, errSoulCooperativeAuthority
	}
	memberBAuthoritySHA, memberBAuthorityExpiry, err := verifyStage2aCooperativeBAuthority(
		memberBAuthorityEnvelope, reservation, bridge, assignment,
		reservationSHA, bridgeSHA, assignmentSHA, key, now)
	if err != nil || memberBAuthorityExpiry.Before(until) {
		return empty, errSoulCooperativeAuthority
	}
	profile, err := openPinnedFile(SoulChildSandbox, harnessSHA(soulChildProfile))
	if err != nil || profile.Close() != nil {
		return empty, errSoulCooperativeAuthority
	}
	launcher, err := observeStage2aRoleProcess(wrapperPID, p.Runner.UID, p.Runner.GID, "child")
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	start := SoulStartAssignment{InstallationID: p.Runner.InstallationID,
		StartID: p.ReviewedStartID, RunnerUID: p.Runner.UID, RunnerGID: p.Runner.GID}
	start.Relay.SocketPath = bridge.Endpoints.Relay.SocketPath
	workdir, environment, err := stage2aMemberChildEnvironment(p.Runner, start,
		*p.LaunchInputs, memberSelector)
	if err != nil || member.CommandPath == "" || workdir == "" {
		return empty, errSoulCooperativeAuthority
	}
	approved, err := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	until = minStage2aTime(until, now.Add(stage2aMemberChildGrantLife))
	until = minStage2aTime(until, approved)
	if !until.After(now) {
		return empty, errSoulCooperativeAuthority
	}
	invocation := stage2aCooperativeChildInvocation{
		ReservationEnvelopeBase64URL:      base64.RawURLEncoding.EncodeToString(reservationEnvelope),
		BridgeEnvelopeBase64URL:           base64.RawURLEncoding.EncodeToString(bridgeEnvelope),
		AssignmentEnvelopeBase64URL:       base64.RawURLEncoding.EncodeToString(assignmentEnvelope),
		MemberBAuthorityEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(memberBAuthorityEnvelope),
		Runner:                            p.Runner, Launch: *p.LaunchInputs,
		RuntimeV3: reservation.MeasurementBinding.RInventory,
		MemberID:  memberID, MemberLaunchID: memberLaunchID, MemberSelector: memberSelector,
		Executable: member.CommandPath, ExecutableSHA256: member.CommandSHA256,
		RelaySocket: bridge.Endpoints.Relay.SocketPath,
		SandboxPath: SoulChildSandbox, SandboxSHA256: "sha256:" + harnessSHA(soulChildProfile),
		Workdir: workdir, Environment: environment}
	invocationRaw, err := marshalStage2aReservationJCS(invocation)
	if err != nil || len(invocationRaw) > stage2aExecMaxFrame/2 {
		return empty, errSoulCooperativeAuthority
	}
	grant := stage2aCooperativeChildGrant{Contract: "machine/v3",
		ProfileInForce:    "managed-cooperative",
		ReservationSHA256: reservationSHA, BridgeAssignmentSHA256: bridgeSHA,
		AssignmentEnvelopeSHA256: assignmentSHA,
		MemberBAuthoritySHA256:   memberBAuthoritySHA,
		InstallationID:           p.Runner.InstallationID, StartID: p.ReviewedStartID,
		HQEpoch: p.HQEpoch, MemberID: memberID, MemberLaunchID: memberLaunchID,
		MemberSelector: memberSelector, Nonce: nonce, PID: wrapperPID,
		InvocationSHA256: stage2aReservationSHA256(invocationRaw),
		ExpiresAt:        until.UTC().Format(time.RFC3339Nano)}
	name := ".stage2a-cooperative-child-exec-" +
		soulStartClaimName(p.Runner.InstallationID, p.ReviewedStartID) + "-" + memberSelector
	if spend(name) != nil ||
		checkStage2aGrantedRoleProcess(wrapperPID, p.Runner.UID, p.Runner.GID, "child", launcher) != nil {
		return empty, errSoulCooperativeAuthority
	}
	envelope, err := signStage2aEnvelope(grant, 1, stage2aCooperativeChildGrantPurpose, key, sign)
	if err != nil || !time.Now().Before(until) ||
		checkStage2aGrantedRoleProcess(wrapperPID, p.Runner.UID, p.Runner.GID, "child", launcher) != nil {
		return empty, errSoulCooperativeAuthority
	}
	reply := Stage2aExecReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256:              stage2aReservationSHA256(envelope),
		InvocationBase64URL: base64.RawURLEncoding.EncodeToString(invocationRaw)}
	if len(reply.EnvelopeBase64URL)+len(reply.InvocationBase64URL) > stage2aExecMaxFrame-1024 {
		return empty, errSoulCooperativeAuthority
	}
	return reply, nil
}

func verifyStage2aCooperativeChildSelection(reservationEnvelope, bridgeEnvelope,
	assignmentEnvelope []byte, memberID, memberLaunchID, memberSelector string,
	key ed25519.PublicKey, now time.Time) (soulCooperativeBReservationViewV3,
	soulCooperativeBridgeAssignmentPayloadV3, soulCooperativeMemberSetAssignmentV3,
	stage2aAssignedMember, string, string, string, time.Time, error) {
	var r soulCooperativeBReservationViewV3
	var b soulCooperativeBridgeAssignmentPayloadV3
	var a soulCooperativeMemberSetAssignmentV3
	var m stage2aAssignedMember
	bad := func() (soulCooperativeBReservationViewV3, soulCooperativeBridgeAssignmentPayloadV3,
		soulCooperativeMemberSetAssignmentV3, stage2aAssignedMember, string, string, string,
		time.Time, error) {
		return r, b, a, m, "", "", "", time.Time{}, errSoulCooperativeAuthority
	}
	rRaw, rSHA, err := verifySoulCooperativeEnvelopeV3(reservationEnvelope, key)
	if err != nil || stage2aDecodeExact(rRaw, &r) != nil {
		return bad()
	}
	bRaw, bSHA, err := verifySoulCooperativePurposeV3(bridgeEnvelope, key,
		soulCooperativeBridgeAssignmentPurposeV3)
	if err != nil || stage2aDecodeExact(bRaw, &b) != nil {
		return bad()
	}
	aRaw, err := verifyStage2aStoredARecordV3(assignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, key)
	if err != nil || stage2aDecodeExact(aRaw, &a) != nil {
		return bad()
	}
	aSHA := stage2aReservationSHA256(assignmentEnvelope)
	rExpiry, e1 := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	bExpiry, e2 := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	aExpiry, e3 := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || !now.Before(rExpiry) ||
		!now.Before(bExpiry) || !now.Before(aExpiry) ||
		r.Contract != "machine/v3" || r.Kind != "soul-cooperative-reservation" ||
		r.SchemaVersion != 3 || r.AdapterTransport != "brokered-b" ||
		b.Contract != "machine/v3" || b.Kind != "soul-cooperative-bridge-assignment" ||
		b.SchemaVersion != 3 || a.Contract != "machine/v3" ||
		a.Kind != "stage2a-member-set-assignment" || a.SchemaVersion != 1 ||
		a.ProfileInForce != "managed-cooperative" ||
		a.ReservationSHA256 != rSHA || b.ReservationSHA256 != rSHA ||
		a.BAuthority.Purpose != soulCooperativeBridgeAssignmentPurposeV3 ||
		a.BAuthority.EnvelopeSHA256 != bSHA ||
		a.HostID != r.HostID || b.HostID != r.HostID ||
		a.InstallationID != r.Assignment.InstallationID ||
		b.InstallationID != a.InstallationID ||
		a.StartID != r.Assignment.StartID || b.StartID != a.StartID ||
		a.HQEpoch != r.Assignment.HQEpoch || b.HQEpoch != a.HQEpoch ||
		a.PlanID != r.Assignment.PlanID || b.PlanID != a.PlanID ||
		a.PlanDigest != r.Assignment.PlanDigest || b.PlanDigest != a.PlanDigest ||
		b.LaunchID != r.Assignment.LaunchID ||
		!reflect.DeepEqual(r.Endpoints.Relay, b.Endpoints.Relay) ||
		!reflect.DeepEqual(r.Endpoints.Member, b.Endpoints.Member) ||
		a.Members[0].MemberID != "m_lead" ||
		a.Members[1].MemberID != "m_spec" {
		return bad()
	}
	for _, candidate := range a.Members {
		if candidate.MemberID == memberID {
			m = candidate
		}
	}
	if m.MemberID == "" || m.LaunchID != memberLaunchID ||
		m.MemberSelector != memberSelector ||
		m.MemberSelector != stage2aMemberSelector(rSHA, memberID, memberLaunchID) ||
		!soulLaunchID.MatchString(memberLaunchID) ||
		!stage2aAbsolutePath(m.CommandPath) ||
		!stage2aPrefixedDigest.MatchString(m.CommandSHA256) ||
		!stage2aAbsolutePath(b.Endpoints.Relay.SocketPath) ||
		b.Endpoints.Relay.ExpectedPeerUID != r.Assignment.RunnerUID {
		return bad()
	}
	return r, b, a, m, rSHA, bSHA, aSHA,
		minStage2aTime(rExpiry, minStage2aTime(bExpiry, aExpiry)), nil
}

// #87 is a second A signature, issued only after B's live child was observed.
// Its member rows must describe precisely the two members of the already
// signed assignment; a detached #85 bridge assignment cannot replace it.
func verifyStage2aCooperativeBAuthority(envelope []byte,
	reservation soulCooperativeBReservationViewV3,
	bridge soulCooperativeBridgeAssignmentPayloadV3,
	assignment soulCooperativeMemberSetAssignmentV3,
	reservationSHA, bridgeSHA, assignmentSHA string,
	key ed25519.PublicKey, now time.Time) (string, time.Time, error) {
	raw, err := verifyStage2aStoredARecordV3(envelope,
		stage2aBMemberAuthorityPurpose, 1, key)
	var authority stage2aBMemberAuthorityPayload
	if err != nil || stage2aDecodeExact(raw, &authority) != nil ||
		authority.Contract != "machine/v3" ||
		authority.Kind != "stage2a-b-member-authority" ||
		authority.SchemaVersion != 1 ||
		authority.ProfileInForce != "managed-cooperative" ||
		authority.HostID != assignment.HostID ||
		authority.InstallationID != assignment.InstallationID ||
		authority.SoulID != assignment.SoulID ||
		authority.StartID != assignment.StartID ||
		authority.HQEpoch != assignment.HQEpoch ||
		authority.PlanID != assignment.PlanID ||
		authority.PlanDigest != assignment.PlanDigest ||
		authority.ReservationSHA256 != reservationSHA ||
		authority.MemberSetAssignmentEnvelopeSHA256 != assignmentSHA ||
		authority.OwnerPlanMemberSetSHA256 != assignment.OwnerPlanMemberSetSHA256 ||
		authority.BAuthority.Purpose != soulCooperativeBridgeAssignmentPurposeV3 ||
		authority.BAuthority.EnvelopeSHA256 != bridgeSHA ||
		authority.HQUID != reservation.Assignment.HQUID ||
		authority.RunnerUID != reservation.Assignment.RunnerUID ||
		authority.Members[0].MemberID != "m_lead" ||
		authority.Members[1].MemberID != "m_spec" {
		return "", time.Time{}, errSoulCooperativeAuthority
	}
	bridgeRaw, err := marshalStage2aReservationJCS(assignment.Bridge)
	if err != nil || !bytes.Equal(authority.Bridge, bridgeRaw) ||
		!reflect.DeepEqual(assignment.Bridge.Endpoints, bridge.Endpoints) {
		return "", time.Time{}, errSoulCooperativeAuthority
	}
	for i, member := range assignment.Members {
		row := authority.Members[i]
		if row.MemberID != member.MemberID || row.LaunchID != member.LaunchID ||
			row.MemberSelector != member.MemberSelector ||
			row.AdjacentCLIPath != member.AdjacentCLIPath ||
			row.AdjacentCLISHA256 != member.AdjacentCLISHA256 {
			return "", time.Time{}, errSoulCooperativeAuthority
		}
	}
	issued, e1 := time.Parse(time.RFC3339Nano, authority.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, authority.ExpiresAt)
	if e1 != nil || e2 != nil || issued.After(now) || !now.Before(expires) ||
		!expires.After(issued) || expires.Sub(issued) > 30*time.Second {
		return "", time.Time{}, errSoulCooperativeAuthority
	}
	return stage2aReservationSHA256(envelope), expires, nil
}
