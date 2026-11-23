//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"time"
)

type soulCooperativeMemberSetAssignmentV3 struct {
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
		Account   string                      `json:"account"`
		UID       int                         `json:"uid"`
		GID       int                         `json:"gid"`
		Endpoints soulCooperativeBEndpointsV3 `json:"endpoints"`
	} `json:"bridge"`
	Members   [2]stage2aAssignedMember `json:"members"`
	IssuedAt  string                   `json:"issued_at"`
	ExpiresAt string                   `json:"expires_at"`
}

// This paired A callback consumes only A's installed, root-rechecked
// cooperative authority and its own signed reservation/B assignment. It
// reobserves frozen SoulInfo and the stock adapter manifest before assigning
// either member. A caller holds the pair and installation locks and persists
// the resulting one-use assignment before returning it to H.
func signSoulCooperativeMemberSetAssignmentV3(in SoulCooperativeInstalledAuthority,
	reservationEnvelope, bridgeEnvelope []byte, parents soulCooperativeBParentsV3,
	definitionSnapshot, launchInputsSnapshot Stage2aSnapshotIdentity,
	now time.Time, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) ([]byte, string, error) {
	p := in.Policy
	if p.Schema != soulCooperativeTwoMemberInstallSchemaV3 || p.validate() != nil ||
		len(key) != ed25519.PublicKeySize || sign == nil || len(bridgeEnvelope) == 0 ||
		definitionSnapshot.RootPath != p.Runner.PackageRoot ||
		definitionSnapshot.OwnerUID != uint32(p.MachineUID) ||
		definitionSnapshot.OwnerGID != uint32(p.Runner.GID) || definitionSnapshot.Mode != "0555" ||
		launchInputsSnapshot.RootPath != cooperativeReviewedInputsRoot(p.Runner.InstallationID) ||
		launchInputsSnapshot.OwnerUID != uint32(p.MachineUID) ||
		launchInputsSnapshot.OwnerGID != uint32(p.Runner.GID) || launchInputsSnapshot.Mode != "0555" {
		return nil, "", errSoulCooperativeAuthority
	}
	var bridgeSigned soulCooperativeEnvelopeV3
	if stage2aDecodeExact(bridgeEnvelope, &bridgeSigned) != nil ||
		bridgeSigned.Purpose != soulCooperativeBridgeAssignmentPurposeV3 ||
		bridgeSigned.SchemaVersion != 3 ||
		bridgeSigned.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(key) {
		return nil, "", errSoulCooperativeAuthority
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(bridgeSigned.SignatureBase64URL)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, "", errSoulCooperativeAuthority
	}
	// Reproduce the entire B envelope from the authenticated reservation and
	// retained parent identities. The supplied signature is accepted only if
	// it verifies against those exact A-derived bytes.
	wantBridge, _, err := signSoulCooperativeBridgeAssignmentV3(in, reservationEnvelope,
		parents, now, key, func([]byte) ([]byte, error) { return signature, nil })
	if err != nil || !bytes.Equal(wantBridge, bridgeEnvelope) {
		return nil, "", errSoulCooperativeAuthority
	}
	reservationRaw, reservationSHA, err := verifySoulCooperativeEnvelopeV3(reservationEnvelope, key)
	var reservation soulCooperativeBReservationViewV3
	if err != nil || json.Unmarshal(reservationRaw, &reservation) != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	expires, err := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return nil, "", errSoulCooperativeAuthority
	}
	observed, digest, err := observeStage2aSourceAt(definitionSnapshot.RootPath,
		uint32(p.MachineUID), uint32(p.Runner.GID), p.Definition, false)
	if err != nil || observed != definitionSnapshot || digest != p.DefinitionMeasurement {
		return nil, "", errSoulCooperativeAuthority
	}
	files, err := stage2aExpandedRuntimeRecords(p.LaunchInputs.Files)
	if err != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	observedInputs, _, err := observeStage2aRuntimeAt(launchInputsSnapshot.RootPath,
		uint32(p.MachineUID), uint32(p.Runner.GID), files, false)
	if err != nil || observedInputs != launchInputsSnapshot {
		return nil, "", errSoulCooperativeAuthority
	}
	adapters, err := stage2aReadProjectedFile(launchInputsSnapshot, p.LaunchInputs.Files, "host/adapters.json")
	if err != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	installation, err := stage2aReadProjectedFile(launchInputsSnapshot, p.LaunchInputs.Files, "host/installation.json")
	if err != nil || CheckStage2aHostProjectionBytes(*p.LaunchInputs, adapters, installation) != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	info, err := stage2aReadFrozenClaimFile(definitionSnapshot, p.Definition, "Contents/SoulInfo.json")
	if err != nil || stage2aStrictJSON(info) != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	var frozen struct {
		SoulID  string               `json:"soul_id"`
		Members []stage2aHelloMember `json:"members"`
	}
	if json.Unmarshal(info, &frozen) != nil || frozen.SoulID != p.Runner.SoulID ||
		len(frozen.Members) != 2 || !stage2aHelloMembersMatch(info, frozen.SoulID, frozen.Members) {
		return nil, "", errSoulCooperativeAuthority
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
	if roles[0].MemberID != "m_lead" || roles[0].Role != "lead" ||
		roles[1].MemberID != "m_spec" || roles[1].Role != "specialist" ||
		roles[0].MemberID != p.MemberBridgeQualifications[0].MemberID ||
		roles[1].MemberID != p.MemberBridgeQualifications[1].MemberID ||
		roles[0].AdapterID != roles[1].AdapterID || roles[0].AdapterVersion != roles[1].AdapterVersion {
		return nil, "", errSoulCooperativeAuthority
	}
	adapter, _ := p.LaunchInputs.HostProjection.Adapters[roles[0].AdapterID].(map[string]any)
	command, _ := adapter["command"].([]any)
	if len(command) != 1 {
		return nil, "", errSoulCooperativeAuthority
	}
	commandPath, _ := command[0].(string)
	commandSHA := p.LaunchInputs.ComponentDigests["adapter"]
	const manifestPath = "Contents/opt/stock-claude.json"
	manifest, err := stage2aReadFrozenClaimFile(definitionSnapshot, p.Definition, manifestPath)
	if err != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	cliPath, cliSHA, ok := stage2aStockManifestCLI(manifest, roles, commandPath, commandSHA, p.LaunchInputs.Files)
	if !ok {
		return nil, "", errSoulCooperativeAuthority
	}
	projectionDigest, err := stage2aOwnerMemberSetDigest(roles, commandPath, commandSHA, cliPath, cliSHA)
	if err != nil || projectionDigest != p.OwnerPlanMemberSetSHA256 {
		return nil, "", errSoulCooperativeAuthority
	}
	projection, err := marshalStage2aReservationJCS(p.LaunchInputs.HostProjection)
	if err != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	_, endpoints, _, err := soulCooperativeBLaunchIntentV3(p, reservation.Assignment.StartID, parents)
	if err != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	until := minStage2aTime(now.Add(20*time.Second), expires)
	if !until.After(now) {
		return nil, "", errSoulCooperativeAuthority
	}
	payload := soulCooperativeMemberSetAssignmentV3{Contract: "machine/v3", Kind: "stage2a-member-set-assignment",
		SchemaVersion: 1, ProfileInForce: "managed-cooperative", HostID: p.HostID,
		InstallationID: p.Runner.InstallationID, SoulID: p.Runner.SoulID, StartID: p.ReviewedStartID,
		HQEpoch: p.HQEpoch, PlanID: in.PlanID, PlanDigest: in.PlanDigest,
		OwnerPlanMemberSetSHA256: p.OwnerPlanMemberSetSHA256, ReservationSHA256: reservationSHA,
		SoulArtifactSHA256:   "sha256:" + p.ArtifactSHA256,
		FrozenSoulInfoSHA256: stage2aReservationSHA256(info), AdapterManifestRelpath: manifestPath,
		FrozenAdapterManifestSHA256: stage2aReservationSHA256(manifest),
		HostProjectionSHA256:        stage2aReservationSHA256(projection),
		DefinitionMeasurement:       p.DefinitionMeasurement, RunnerUID: p.Runner.UID, RunnerGID: p.Runner.GID,
		IssuedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: until.UTC().Format(time.RFC3339Nano)}
	payload.BAuthority.Purpose = soulCooperativeBridgeAssignmentPurposeV3
	payload.BAuthority.EnvelopeSHA256 = stage2aReservationSHA256(bridgeEnvelope)
	payload.Bridge.Account, payload.Bridge.UID, payload.Bridge.GID = p.Bridge.Account, p.Bridge.UID, p.Bridge.GID
	payload.Bridge.Endpoints = endpoints
	for i, role := range roles {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", errSoulCooperativeAuthority
		}
		launchID := fmt.Sprintf("ln_%x", random)
		payload.Members[i] = stage2aAssignedMember{MemberID: role.MemberID, Role: role.Role,
			AdapterID: role.AdapterID, AdapterVersion: role.AdapterVersion,
			CommandPath: commandPath, CommandSHA256: commandSHA,
			AdjacentCLIPath: cliPath, AdjacentCLISHA256: cliSHA,
			LaunchID: launchID, MemberSelector: stage2aMemberSelector(reservationSHA, role.MemberID, launchID)}
	}
	if payload.Members[0].LaunchID == payload.Members[1].LaunchID ||
		payload.Members[0].MemberSelector == payload.Members[1].MemberSelector ||
		!reflect.DeepEqual(payload.Bridge.Endpoints, endpoints) {
		return nil, "", errSoulCooperativeAuthority
	}
	envelope, err := signStage2aEnvelope(payload, 1, stage2aMemberSetAssignmentPurpose, key, sign)
	if err != nil || !time.Now().Before(until) {
		return nil, "", errSoulCooperativeAuthority
	}
	return envelope, stage2aReservationSHA256(envelope), nil
}
