package members

import (
	"os"
	"path/filepath"
	"strings"
)

// verifyHQStage2aReleaseRows checks reviewed rows against the complete
// Darwin extraction previously matched to its pinned archive and Node.
// Protected apply authenticates the owner-approved exact source and artifact
// pins and checks the complete canonical release manifest for each component.
func verifyHQStage2aReleaseRows(service HQService, raw []byte) (stage2aDomainInventoryV3, error) {
	var empty stage2aDomainInventoryV3
	s := service.Stage2a
	inventory, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || s == nil || inventory.Domain != "H-code" || inventory.InstallationID != s.InstallationID ||
		inventory.Limits != s.InventoryLimits || digest != s.InventoryDigest {
		return empty, refuse(RefusedPath, "Stage 2a HQ requires the exact canonical H inventory under the reviewed limits")
	}
	required := map[string]string{
		hqStage2aNode: "node", hqStage2aHelper: "hq", hqStage2aEntry: "hq",
		s.PreloaderPath: "hq", hqStage2aGuard: "hq",
		hqStage2aCooperativeMachine: "hq", hqStage2aCooperativeProof: "hq",
		hqStage2aCooperativeStart: "hq", hqStage2aCooperativeBridge: "hq", hqStage2aCooperativeInstall: "hq",
	}
	for _, row := range inventory.Files {
		component := required[row.Path]
		if component != "" && (row.ComponentID != component || row.ReleasePath != row.Path || row.SizeBytes == 0) {
			return empty, refuse(RefusedPath, "Stage 2a HQ launch file %q does not map to the verified release", row.Path)
		}
		var source string
		switch row.ComponentID {
		case "node":
			if row.Path != hqStage2aNode || row.SHA256 != "sha256:"+service.NodeSHA256 || row.Mode != "0550" {
				return empty, refuse(RefusedPath, "Stage 2a HQ Node does not match the verified runtime")
			}
			source = service.Node
		case "hq":
			if component != "" && row.Mode != "0440" {
				return empty, refuse(RefusedPath, "invalid Stage 2a HQ launch file mode for %q", row.Path)
			}
			source = filepath.Join(service.ReleaseDir, row.ReleasePath)
		default:
			return empty, refuse(RefusedPath, "unexpected Stage 2a HQ release component %q", row.ComponentID)
		}
		if row.Path == hqStage2aGuard && row.SHA256 != s.GuardModuleSHA256 {
			return empty, refuse(RefusedPath, "Stage 2a HQ runtime guard does not match the reviewed file digest")
		}
		if err := verifyHQStage2aSelectedFile(source, strings.TrimPrefix(row.SHA256, "sha256:"), int64(row.SizeBytes)); err != nil {
			return empty, err
		}
		delete(required, row.Path)
	}
	if len(required) != 0 {
		return empty, refuse(RefusedPath, "Stage 2a HQ inventory omits a required launch or cooperative module")
	}
	return inventory, nil
}

func verifyHQStage2aSelectedFile(path, digest string, size int64) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return refuse(RefusedPath, "Stage 2a HQ selected file %q differs from the reviewed inventory", path)
	}
	f, err := openPinnedFileLimit(path, digest, size)
	if err != nil {
		return err
	}
	return f.Close()
}
