package members

import "path/filepath"

func matchesHQStage2aRuntimeNames(ref stage2aDomainInventoryRefV3) bool {
	namespace, snapshot, sidecar, err := stage2aDomainNamesV3("R-runtime", ref.InstallationID)
	return err == nil && ref.Snapshot.Path == filepath.Join(namespace, snapshot) && ref.Sidecar.Path == filepath.Join(namespace, sidecar)
}

// The descriptor bytes were checked against the enrolled signing key and the
// owner plan before their exact witness was journaled. Recovery reopens those
// same bytes and the two measured trees. It cannot obtain launch permission.
func recheckDurableHQStage2aCandidate(rec launchRecord, approved Approval, state *hqStage2aJournalDescriptor) error {
	s, launch := rec.Service.Stage2a, rec.Stage2a
	if s == nil || launch == nil || state == nil || state.Descriptor == nil || state.H == nil || state.Runtime == nil ||
		!validHQStage2aDescriptorWitness(*s, *state.Descriptor) || !hqStage2aRuntimeMatches(rec, *state.Runtime) ||
		checkHQStage2aDescriptorDirectory(*s, state.Directory) != nil {
		return errStage2aReservationAuthority
	}
	h := *state.H
	if h.Domain != "H-code" || h.InstallationID != s.InstallationID || h.OwnerPlanDigest != "sha256:"+approved.PlanDigest ||
		h.InventoryDigest != s.InventoryDigest || h.MachineUID != uint32(s.MachineUID) || h.ReaderUID != uint32(s.ReaderUID) ||
		h.ReaderGID != uint32(s.ReaderGID) || h.Snapshot.Path != launch.Root || h.Sidecar.Path != launch.InventoryPath {
		return errStage2aReservationAuthority
	}
	witness, _, err := stage2aV3SidecarAt(hqStage2aDescriptor, uint32(s.MachineUID), uint32(s.ReaderGID))
	if err != nil || witness != *state.Descriptor {
		return errStage2aReservationAuthority
	}
	if err := recheckHQStage2aDomainFiles(h); err != nil {
		return err
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
