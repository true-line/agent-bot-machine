//go:build darwin

package members

import (
	"crypto/ed25519"
	"slices"
	"strconv"
	"strings"
)

// Witness requests must come from the exact loaded, measured H process.
// The peer PID is obtained by the daemon from LOCAL_PEERPID, never from JSON.
func observeStage2aDirectHQPeerV3(live *soulCooperativeLiveV3, peerPID int,
	key ed25519.PublicKey) (soulKernelProcessSnapshot, error) {
	var empty soulKernelProcessSnapshot
	if live == nil || peerPID <= 1 || len(key) != ed25519.PublicKeySize {
		return empty, errSoulCooperativeAuthority
	}
	hq, found, err := (OSHost{}).Account(DarwinHQAccount)
	if err != nil || !found || hq.UID != live.installed.Policy.HQUID {
		return empty, errSoulCooperativeAuthority
	}
	h, descriptor, err := loadStage2aInstalledHV3(live.installed.Policy.HostID,
		live.installed.Policy.MachineUID, live.installed.Policy.HQUID,
		hq.GID, key)
	if err != nil || len(descriptor.OuterLaunch.Argv) < 5 ||
		h.descriptorDigest != live.hDescriptorDigest || h.verifiedH.ref != live.h.ref ||
		stage2aRecheckVerifiedDomainV3(h.verifiedH) != nil ||
		!slices.Equal(descriptor.Runtime.Argv, descriptor.OuterLaunch.Argv[4:]) {
		return empty, errSoulCooperativeAuthority
	}
	launch, err := hqProgramOutput(launchctl, "print", "system/"+launchLabel)
	if err != nil || !stage2aDirectHQLaunchPIDV3(launch, descriptor.OuterLaunch.Argv, peerPID) {
		return empty, errSoulCooperativeAuthority
	}
	observed, err := observeSoulProcess(peerPID, descriptor.Runtime.NodePath, descriptor.Runtime.Argv)
	if err != nil || observed.Kernel.ParentPID != 1 ||
		observed.Kernel.RealUID != uint32(live.installed.Policy.HQUID) ||
		observed.Kernel.EffectiveUID != uint32(live.installed.Policy.HQUID) ||
		observed.Kernel.SavedUID != uint32(live.installed.Policy.HQUID) ||
		observed.Kernel.PrimaryGroupGID != uint32(hq.GID) {
		return empty, errSoulCooperativeAuthority
	}
	return observed.Kernel, nil
}

func stage2aDirectHQLaunchPIDV3(out []byte, want []string, peerPID int) bool {
	if len(want) < 5 || want[0] != "/usr/bin/ruby" {
		return false
	}
	var source, program, pid string
	var args []string
	inArgs := false
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if inArgs {
			if line == "}" {
				inArgs = false
			} else {
				args = append(args, line)
			}
			continue
		}
		switch {
		case line == "arguments = {":
			inArgs = true
		case strings.HasPrefix(line, "path = ") && source == "":
			source = strings.TrimPrefix(line, "path = ")
		case strings.HasPrefix(line, "program = "):
			program = strings.TrimPrefix(line, "program = ")
		case strings.HasPrefix(line, "pid = "):
			pid = strings.TrimPrefix(line, "pid = ")
		}
	}
	parsed, err := strconv.Atoi(pid)
	return err == nil && parsed == peerPID && source == launchPlist && program == want[0] && slices.Equal(args, want)
}
