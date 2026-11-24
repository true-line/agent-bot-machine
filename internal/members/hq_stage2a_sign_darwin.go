package members

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func buildHQStage2aDescriptor(rec launchRecord, approved Approval, h stage2aDomainInventoryRefV3,
	inv stage2aDomainInventoryV3) (stage2aHServiceDescriptorPayloadV3, error) {
	var empty stage2aHServiceDescriptorPayloadV3
	s, launch := rec.Service.Stage2a, rec.Stage2a
	if s == nil || launch == nil || approved.Purpose != UpgradePurpose || !ValidApproval(approved.PlanID, approved.PlanDigest) ||
		h.InstallationID != s.InstallationID || h.Domain != "H-code" || h.OwnerPlanDigest != "sha256:"+approved.PlanDigest ||
		h.MachineUID != uint32(s.MachineUID) || h.ReaderUID != uint32(s.ReaderUID) || h.ReaderGID != uint32(s.ReaderGID) ||
		h.Snapshot.Path != launch.Root || h.Sidecar.Path != launch.InventoryPath || h.InventoryDigest != s.InventoryDigest ||
		inv.Limits != s.InventoryLimits || inv.Domain != h.Domain || inv.InstallationID != h.InstallationID ||
		len(launch.RuntimeArgv) < 7 || len(launch.OuterArgv) < 4 {
		return empty, errStage2aReservationAuthority
	}
	selected := make(map[string]string, len(inv.Files))
	for _, row := range inv.Files {
		selected[row.Path] = row.SHA256
	}
	required := []string{hqStage2aHelper, hqStage2aNode, hqStage2aEntry, hqStage2aGuard,
		s.PreloaderPath, hqStage2aCooperativeMachine, hqStage2aCooperativeProof,
		hqStage2aCooperativeStart, hqStage2aCooperativeBridge, hqStage2aCooperativeInstall}
	if hqStage2aBrokeredRelayRequired(s) {
		required = append(required, hqStage2aRelayPeer)
	}
	for _, name := range required {
		if !stage2aPrefixedDigest.MatchString(selected[name]) {
			return empty, errStage2aReservationAuthority
		}
	}
	if selected[hqStage2aNode] != "sha256:"+rec.Service.NodeSHA256 || selected[hqStage2aGuard] != s.GuardModuleSHA256 {
		return empty, errStage2aReservationAuthority
	}
	components := make([]stage2aHReleaseComponentV3, 0, len(s.Components))
	for _, c := range s.Components {
		component := stage2aHReleaseComponentV3{ComponentID: c.ComponentID,
			SourceRepository: c.SourceRepository, SourceCommit: c.SourceCommit,
			ReleaseArtifactSHA256: c.ArtifactSHA256, ReleaseManifestSHA256: c.ManifestSHA256}
		if c.SourceTag != "" {
			tag := c.SourceTag
			component.SourceTag = &tag
		}
		components = append(components, component)
	}
	return stage2aHServiceDescriptorPayloadV3{Contract: "machine/v3", Kind: "stage2a-h-service-descriptor", SchemaVersion: 3,
		HostID: s.HostID, HQInstallationID: s.InstallationID, OwnerPlanDigest: h.OwnerPlanDigest, HInventory: h, Components: components,
		OuterLaunch: stage2aHOuterLaunchV3{RubyPath: "/usr/bin/ruby", RubySHA256: launch.RubySHA256,
			HelperPath: filepath.Join(launch.Root, hqStage2aHelper), HelperSHA256: selected[hqStage2aHelper], Argv: launch.OuterArgv},
		Runtime: stage2aHRuntimeV3{NodePath: filepath.Join(launch.Root, hqStage2aNode), NodeSHA256: selected[hqStage2aNode],
			PreloaderPath: filepath.Join(launch.Root, s.PreloaderPath), PreloaderSHA256: selected[s.PreloaderPath],
			EntryPath: filepath.Join(launch.Root, hqStage2aEntry), EntrySHA256: selected[hqStage2aEntry],
			GuardModulePath: filepath.Join(launch.Root, hqStage2aGuard), GuardModuleSHA256: selected[hqStage2aGuard], Argv: launch.RuntimeArgv}}, nil
}

// Recover a publication completed by A just before the caller could journal
// its witness. An unsigned, changed, or differently approved descriptor is
// preserved for review. This lookup only supports withdrawal, never launch.
func recoverHQStage2aDescriptorWitness(rec launchRecord, approval Approval) (stage2aDomainSidecarRefV3, stage2aDomainInventoryRefV3, string, error) {
	var empty stage2aDomainSidecarRefV3
	s := rec.Service.Stage2a
	if s == nil || rec.Stage2a == nil {
		return empty, stage2aDomainInventoryRefV3{}, "", errStage2aReservationAuthority
	}
	key, err := readStage2aRolePin()
	if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(key)) != s.AuthorityKeySHA256 {
		return empty, stage2aDomainInventoryRefV3{}, "", errStage2aReservationAuthority
	}
	witness, envelope, err := stage2aV3SidecarAt(hqStage2aDescriptor, uint32(s.MachineUID), uint32(s.ReaderGID))
	if err != nil || !validHQStage2aDescriptorWitness(*s, witness) {
		return empty, stage2aDomainInventoryRefV3{}, "", errStage2aReservationAuthority
	}
	payload, descriptorDigest, err := stage2aDecodeHDescriptorV3(envelope, key)
	if err != nil || payload.HInventory.Sidecar.Path != rec.Stage2a.InventoryPath {
		return empty, stage2aDomainInventoryRefV3{}, "", errStage2aReservationAuthority
	}
	sidecar, raw, err := stage2aV3SidecarAt(rec.Stage2a.InventoryPath, uint32(s.MachineUID), uint32(s.ReaderGID))
	if err != nil || sidecar != payload.HInventory.Sidecar {
		return empty, stage2aDomainInventoryRefV3{}, "", errStage2aReservationAuthority
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != s.InventoryDigest {
		return empty, stage2aDomainInventoryRefV3{}, "", errStage2aReservationAuthority
	}
	want, err := buildHQStage2aDescriptor(rec, approval, payload.HInventory, inv)
	if err != nil || !reflect.DeepEqual(payload, want) {
		return empty, stage2aDomainInventoryRefV3{}, "", errStage2aReservationAuthority
	}
	return witness, payload.HInventory, descriptorDigest, nil
}

// H publication uses the exact stored paired-owner plan and a separately
// checked R runtime witness. The H descriptor itself stays independent of R.
type hqStage2aSigningAuthority struct {
	saved         Saved
	daemonDir     string
	owner         string
	pair          upgradePairGuard
	verifyRuntime func(launchRecord, stage2aVerifiedDomainRefV3) error
}

type hqStage2aSignedPublication struct {
	Descriptor       stage2aDomainSidecarRefV3   `json:"descriptor"`
	DescriptorDigest string                      `json:"descriptor_digest"`
	Runtime          stage2aDomainInventoryRefV3 `json:"runtime"`
}

// Issue and publish only after the trusted A-install authority verifies the
// paired operation and approved limits, reviewed source and manifest bytes,
// and the exact v3 R install and runtime guard.
func (service *Stage2aService) signAndPublishHQStage2a(rec launchRecord, approved Approval, h stage2aDomainInventoryRefV3,
	r stage2aVerifiedDomainRefV3, authority hqStage2aSigningAuthority) (hqStage2aSignedPublication, error) {
	var empty hqStage2aSignedPublication
	s := rec.Service.Stage2a
	if s == nil || s.CooperativeOnly || rec.Stage2a == nil || !hqStage2aIsOfflineAdmin(*s) || len(service.key) != ed25519.PrivateKeySize ||
		authority.verifyRuntime == nil ||
		!r.verified || r.ref.Domain != "R-runtime" || r.ref.MachineUID != h.MachineUID ||
		r.ref.ReaderUID == h.ReaderUID || r.ref.ReaderGID == h.ReaderGID || !matchesHQStage2aRuntimeNames(r.ref) ||
		stage2aRecheckVerifiedDomainV3(r) != nil {
		return empty, errStage2aReservationAuthority
	}
	published, err := service.publishReviewedHQStage2a(rec, approved, h, authority, func(stage2aHServiceDescriptorPayloadV3) error {
		if err := authority.verifyRuntime(rec, r); err != nil {
			return err
		}
		return stage2aRecheckVerifiedDomainV3(r)
	})
	if err != nil {
		return empty, err
	}
	return hqStage2aSignedPublication{Descriptor: published.witness, DescriptorDigest: published.descriptorDigest, Runtime: r.ref}, nil
}

func (service *Stage2aService) publishReviewedHQStage2a(rec launchRecord, approved Approval, h stage2aDomainInventoryRefV3,
	authority hqStage2aSigningAuthority, authorize func(stage2aHServiceDescriptorPayloadV3) error) (stage2aCooperativeHDescriptorV3, error) {
	var empty stage2aCooperativeHDescriptorV3
	s := rec.Service.Stage2a
	if s == nil || s.validate() != nil || rec.Stage2a == nil || authorize == nil || !hqStage2aIsOfflineAdmin(*s) || len(service.key) != ed25519.PrivateKeySize {
		return empty, errStage2aReservationAuthority
	}
	installed, err := stage2aObserveInstalledDomainV3(h.Snapshot.Path, h.Sidecar.Path, h.MachineUID, h.ReaderUID, h.ReaderGID,
		h.OwnerPlanDigest, h.ReviewedSourceInventoryDigest)
	if err != nil || installed.ref != h {
		return empty, errStage2aReservationAuthority
	}
	_, raw, err := stage2aV3SidecarAt(h.Sidecar.Path, h.MachineUID, h.ReaderGID)
	if err != nil {
		return empty, err
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != h.InventoryDigest {
		return empty, errStage2aReservationAuthority
	}
	key := service.key.Public().(ed25519.PublicKey)
	if err := checkHQStage2aPairedApproval(authority.saved, rec, approved, key, authority.daemonDir, authority.owner, authority.pair, true); err != nil {
		return empty, err
	}
	if err := checkHQStage2aApprovedReleaseSources(rec.Service, inv); err != nil {
		return empty, err
	}
	payload, err := buildHQStage2aDescriptor(rec, approved, h, inv)
	if err != nil {
		return empty, err
	}
	raw, err = json.Marshal(payload)
	if err != nil {
		return empty, err
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	if err := checkHQStage2aPairedApproval(authority.saved, rec, approved, key, authority.daemonDir, authority.owner, authority.pair, true); err != nil {
		return empty, err
	}
	if err := authorize(payload); err != nil {
		return empty, err
	}
	envelope, descriptorDigest, err := signStage2aHServiceDescriptorV3(canonical, installed, stage2aVerifiedHInstallPlanV3{
		verified: true, descriptor: payload, authorityKeySHA256: s.AuthorityKeySHA256, machineGID: uint32(s.MachineGID),
	}, key, service.sign)
	if err != nil {
		return empty, err
	}
	decoded, verifiedDigest, err := stage2aDecodeHDescriptorV3(envelope, key)
	if err != nil || descriptorDigest != verifiedDigest || !reflect.DeepEqual(decoded, payload) {
		return empty, errStage2aReservationAuthority
	}
	witness, err := publishHQStage2aDescriptorAsAdmin(*s, key, envelope)
	if err != nil {
		return empty, err
	}
	return stage2aCooperativeHDescriptorV3{verifiedH: installed, envelope: envelope, descriptorDigest: descriptorDigest, witness: witness}, nil
}

func matchesHQStage2aRuntimeNames(ref stage2aDomainInventoryRefV3) bool {
	namespace, snapshot, sidecar, err := stage2aDomainNamesV3("R-runtime", ref.InstallationID)
	return err == nil && ref.Snapshot.Path == filepath.Join(namespace, snapshot) && ref.Sidecar.Path == filepath.Join(namespace, sidecar)
}

// Reconciliation can verify a previously started candidate without recreating
// its in-memory signing or launch permission. Both exact sealed roots and the
// independently signed descriptor must still match the recorded witnesses.
func recheckDurableHQStage2aCandidate(rec launchRecord, approval Approval, state *hqStage2aJournalDescriptor) error {
	s := rec.Service.Stage2a
	if s == nil || state == nil || state.Descriptor == nil ||
		(s.CooperativeOnly && state.Runtime != nil) ||
		(!s.CooperativeOnly && (state.Runtime == nil || !hqStage2aRuntimeMatches(rec, *state.Runtime))) ||
		checkHQStage2aDescriptorDirectory(*s, state.Directory) != nil {
		return errStage2aReservationAuthority
	}
	witness, h, _, err := recoverHQStage2aDescriptorWitness(rec, approval)
	if err != nil || witness != *state.Descriptor {
		return errStage2aReservationAuthority
	}
	if err := recheckHQStage2aDomainFiles(h); err != nil {
		return err
	}
	if s.CooperativeOnly {
		return nil
	}
	return recheckHQStage2aDomainFiles(*state.Runtime)
}

func recheckHQStage2aDomainFiles(ref stage2aDomainInventoryRefV3) error {
	namespace, snapshot, sidecar, err := stage2aDomainNamesV3(ref.Domain, ref.InstallationID)
	if err != nil || ref.Contract != "machine/v3" || ref.Kind != "stage2a-inventory-ref" || ref.SchemaVersion != 3 ||
		ref.Snapshot.Path != filepath.Join(namespace, snapshot) || ref.Sidecar.Path != filepath.Join(namespace, sidecar) ||
		!stage2aPrefixedDigest.MatchString(ref.OwnerPlanDigest) || ref.InventoryDigest != ref.ReviewedSourceInventoryDigest {
		return errStage2aReservationAuthority
	}
	if _, _, err := stage2aInstalledDomainAccountsV3(ref.MachineUID, ref.ReaderUID, ref.ReaderGID); err != nil {
		return err
	}
	if _, err := stage2aInstalledDirectoryIdentity(namespace, int(ref.MachineUID), int(ref.ReaderGID), 0750); err != nil {
		return err
	}
	witness, raw, err := stage2aV3SidecarAt(ref.Sidecar.Path, ref.MachineUID, ref.ReaderGID)
	if err != nil || witness != ref.Sidecar {
		return errStage2aReservationAuthority
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != ref.InventoryDigest || inv.Domain != ref.Domain || inv.InstallationID != ref.InstallationID ||
		len(inv.Files) != ref.FileCount || len(inv.Directories) != ref.DirectoryCount || inv.TotalBytes != ref.TotalBytes {
		return errStage2aReservationAuthority
	}
	identity, digest, err := stage2aObserveDomainV3At(ref.Snapshot.Path, ref.MachineUID, ref.ReaderGID, raw)
	if err != nil || stage2aV3SnapshotRef(identity) != ref.Snapshot || digest != ref.InventoryDigest {
		return errStage2aReservationAuthority
	}
	return nil
}
