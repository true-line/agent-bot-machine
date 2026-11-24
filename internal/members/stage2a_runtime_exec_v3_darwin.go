//go:build darwin

package members

import (
	"errors"
	"os"
	"path/filepath"
)

// In protected v3, the legacy package_sha256 field is the bare suffix of
// the domain-separated definition inventory digest. The definition snapshot
// is the selected package root; .soul transport bytes have their own digest.
// Apply sealing, reservation input loading, and the R child separately
// reobserve the frozen files against this reviewed inventory.
func stage2aProtectedPackageMeasurementV3(p stage2aInstalledPolicy) bool {
	digest, _, err := Stage2aDefinitionDigest(p.Definition)
	return err == nil && p.Runner.PackageRoot == p.Binding.Snapshots.Definition.RootPath &&
		p.Runner.PackageSHA256 == p.Binding.PackageSHA256 &&
		p.Binding.DefinitionMeasurement == digest &&
		digest == "sha256:"+p.Binding.PackageSHA256
}

// The runner's v3 R reference has already passed its no-follow installed
// inventory check before this final join. Legacy bindings retain their
// existing package field meaning.
func stage2aRunnerPackageMatchesRuntimeV3(ref stage2aDomainInventoryRefV3,
	runner SoulRunner, binding Stage2aMeasurementBinding, definitionDigest string) bool {
	if ref.Contract != "machine/v3" {
		return true
	}
	return ref.Domain == "R-runtime" && definitionDigest == "sha256:"+binding.PackageSHA256 &&
		runner.PackageSHA256 == binding.PackageSHA256 &&
		runner.PackageRoot == binding.Snapshots.Definition.RootPath
}

// A's signed v3 reservation names this exact R snapshot. R independently
// reopens it before exec and requires the actual Node and Souls entrypoint to
// be the two fixed, reviewed rows in that snapshot. Legacy launch-input rows
// may still describe configuration, but cannot authorize executable bytes.
func stage2aCheckRunnerCodeV3(ref stage2aDomainInventoryRefV3, node, entry string) (stage2aDomainInventoryV3, error) {
	var empty stage2aDomainInventoryV3
	if ref.Domain != "R-runtime" || ref.ReaderUID != uint32(os.Getuid()) ||
		ref.ReaderUID != uint32(os.Geteuid()) || ref.ReaderGID != uint32(os.Getgid()) ||
		ref.ReaderGID != uint32(os.Getegid()) || recheckHQStage2aDomainFiles(ref) != nil {
		return empty, errStage2aReservationAuthority
	}
	_, raw, err := stage2aV3SidecarAt(ref.Sidecar.Path, ref.MachineUID, ref.ReaderGID)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != ref.InventoryDigest || inv.Domain != "R-runtime" ||
		inv.InstallationID != ref.InstallationID || stage2aRunnerCodeRowsV3(ref, inv, node, entry) != nil {
		return empty, errStage2aReservationAuthority
	}
	if recheckHQStage2aDomainFiles(ref) != nil {
		return empty, errStage2aReservationAuthority
	}
	return inv, nil
}

func stage2aRunnerCodeRowsV3(ref stage2aDomainInventoryRefV3,
	inv stage2aDomainInventoryV3, node, entry string) error {
	invalid := errors.New("runner executable or entry is outside the sealed R inventory")
	if !stage2aAbsolutePath(ref.Snapshot.Path) || !stage2aAbsolutePath(node) ||
		!stage2aAbsolutePath(entry) || node == entry {
		return invalid
	}
	var foundNode, foundEntry bool
	for _, row := range inv.Files {
		path := filepath.Join(ref.Snapshot.Path, filepath.FromSlash(row.Path))
		switch {
		case path == node:
			if row.Path != "runtime/bin/node" || row.ComponentID != "node" || row.Mode != "0550" || foundNode {
				return invalid
			}
			foundNode = true
		case path == entry:
			if row.Path != "runtime/bin/agent-bot-souls.mjs" || row.ComponentID != "souls" ||
				(row.Mode != "0440" && row.Mode != "0550") || foundEntry {
				return invalid
			}
			foundEntry = true
		}
	}
	if !foundNode || !foundEntry {
		return invalid
	}
	return nil
}

// The v3 selected command is authorized by the sealed R inventory. The
// legacy definition/launch-input snapshot check cannot describe this path.
func stage2aSelectedCommandRecordedV3(p stage2aInstalledPolicy, inv stage2aDomainInventoryV3) bool {
	return p.RuntimeV3 != nil && p.LaunchInputs.SelectedCommand == p.Node &&
		stage2aRunnerCodeRowsV3(*p.RuntimeV3, inv, p.Node, p.Entry) == nil
}

// The child grant is A-signed, but R still opens the complete sealed tree and
// binds the actual stock adapter exec to the adapter component's reviewed row.
func stage2aCheckChildCodeV3(ref stage2aDomainInventoryRefV3,
	executable, executableSHA256 string) (stage2aDomainInventoryV3, error) {
	var empty stage2aDomainInventoryV3
	if ref.Domain != "R-runtime" || ref.ReaderUID != uint32(os.Getuid()) ||
		ref.ReaderUID != uint32(os.Geteuid()) || ref.ReaderGID != uint32(os.Getgid()) ||
		ref.ReaderGID != uint32(os.Getegid()) || recheckHQStage2aDomainFiles(ref) != nil {
		return empty, errStage2aReservationAuthority
	}
	_, raw, err := stage2aV3SidecarAt(ref.Sidecar.Path, ref.MachineUID, ref.ReaderGID)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != ref.InventoryDigest || inv.Domain != "R-runtime" ||
		inv.InstallationID != ref.InstallationID ||
		stage2aChildCodeRowsV3(ref, inv, executable, executableSHA256) != nil ||
		recheckHQStage2aDomainFiles(ref) != nil {
		return empty, errStage2aReservationAuthority
	}
	return inv, nil
}

func stage2aChildCodeRowsV3(ref stage2aDomainInventoryRefV3, inv stage2aDomainInventoryV3,
	executable, executableSHA256 string) error {
	invalid := errors.New("stock ACP or adjacent CLI is outside the sealed R inventory")
	if !stage2aAbsolutePath(ref.Snapshot.Path) || !stage2aAbsolutePath(executable) ||
		!stage2aPrefixedDigest.MatchString(executableSHA256) {
		return invalid
	}
	cli := filepath.Join(ref.Snapshot.Path, "runtime/bin/claude")
	if executable != filepath.Join(ref.Snapshot.Path, "runtime/bin/claude-agent-acp") ||
		filepath.Dir(executable) != filepath.Dir(cli) {
		return invalid
	}
	foundACP, foundCLI := false, false
	for _, row := range inv.Files {
		switch filepath.Join(ref.Snapshot.Path, filepath.FromSlash(row.Path)) {
		case executable:
			if foundACP || row.Path != "runtime/bin/claude-agent-acp" || row.ComponentID != "adapter" ||
				row.Mode != "0550" || row.SHA256 != executableSHA256 {
				return invalid
			}
			foundACP = true
		case cli:
			if foundCLI || row.Path != "runtime/bin/claude" || row.ComponentID != "adapter" ||
				row.Mode != "0550" || !stage2aPrefixedDigest.MatchString(row.SHA256) {
				return invalid
			}
			foundCLI = true
		}
	}
	if !foundACP || !foundCLI {
		return invalid
	}
	return nil
}
