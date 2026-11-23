package members

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func reviewHQStage2aService(in Input, h Host, owner, hq Account, capability string) (*hqStage2aLaunch, error) {
	s := in.HQService.Stage2a
	others, extra := sharing(hq)
	if in.UpgradeFrom == nil || capability != launchControlV2 || len(in.Members) != 0 ||
		hq.UID != s.ReaderUID || hq.GID != s.ReaderGID || hq.Group != DarwinHQAccount || hq.DarwinRole != darwinHQRoleName ||
		owner.GID == s.ReaderGID || len(others) != 0 || len(extra) != 0 {
		return nil, refuse(RefusedAccount, "Stage 2a HQ requires the existing paired dedicated role and distinct Machine authority")
	}
	inspect, ok := h.(interface {
		PrivateDarwinRoleGroup(string, int) (bool, error)
	})
	if !ok {
		return nil, refuse(RefusedAccount, "Stage 2a HQ group custody cannot be verified")
	}
	private, err := inspect.PrivateDarwinRoleGroup(DarwinHQAccount, hq.GID)
	if err != nil || !private {
		return nil, refuse(RefusedAccount, "Stage 2a HQ requires a private reader group")
	}
	machine, found, err := h.Account(s.MachineAccount)
	if err != nil || !found || machine.UID != s.MachineUID || machine.GID != s.MachineGID {
		return nil, refuse(RefusedAccount, "Stage 2a Machine authority differs from the service request")
	}
	if err := trustedPath(h, "/usr/bin/ruby", false); err != nil {
		return nil, err
	}
	if s.Components[0].ArtifactSource != in.HQService.Archive || s.Components[0].ArtifactSHA256 != "sha256:"+in.HQService.ArtifactSHA256 {
		return nil, refuse(RefusedPath, "Stage 2a HQ release evidence does not name this service archive")
	}
	pin, err := readStage2aRolePin()
	if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(pin)) != s.AuthorityKeySHA256 {
		return nil, refuse(RefusedPath, "Stage 2a HQ authority differs from the independently installed A pin")
	}
	inventory, err := stage2aReadRootFile(s.InventorySource, 2<<20, 0444, 0644)
	if err != nil {
		return nil, refuse(RefusedPath, "Stage 2a HQ inventory differs from the reviewed digest")
	}
	inv, err := verifyHQStage2aReleaseRows(*in.HQService, inventory)
	if err != nil {
		return nil, err
	}
	if err := checkHQStage2aApprovedReleaseSources(*in.HQService, inv); err != nil {
		return nil, err
	}
	ruby, err := os.Open("/usr/bin/ruby")
	if err != nil {
		return nil, err
	}
	defer ruby.Close()
	digest := sha256.New()
	if n, err := io.Copy(digest, io.LimitReader(ruby, (64<<20)+1)); err != nil || n == 0 || n > 64<<20 {
		return nil, refuse(RefusedPath, "cannot pin the system Ruby for Stage 2a HQ")
	}
	launch, err := s.launch(in.Invoker, fmt.Sprintf("sha256:%x", digest.Sum(nil)))
	if err != nil {
		return nil, err
	}
	manager, err := managerBytes()
	if err != nil {
		return nil, err
	}
	launch.LauncherSHA256 = "sha256:" + harnessSHA(manager)
	return launch, nil
}
