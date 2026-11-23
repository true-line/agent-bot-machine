//go:build darwin

package members

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const soulCooperativeLaunchLabel = "ai.true-line.agent-bot-soul-cooperative."
const soulCooperativeLaunchDirectory = launchRuntimeDir + "/cooperative-launch"

type soulCooperativeLaunchPaths struct {
	label, plist, stagingDir, stagedRequest, requestDir, request, activeRequest, cancel, completionDir string
}

func cooperativeLaunchPaths(installationID string) (soulCooperativeLaunchPaths, error) {
	if !soulInstallationID.MatchString(installationID) {
		return soulCooperativeLaunchPaths{}, errSoulCooperativeAuthority
	}
	slot := soulEndpointInstallationSlot(installationID)
	if len(slot) != 20 || strings.ContainsAny(slot, "<>\x00\n\r") {
		return soulCooperativeLaunchPaths{}, errSoulCooperativeAuthority
	}
	base := filepath.Join(soulCooperativeLaunchDirectory, slot)
	label := soulCooperativeLaunchLabel + slot
	requestDir := filepath.Join(base, "requests")
	return soulCooperativeLaunchPaths{label: label,
		plist:         "/Library/LaunchDaemons/" + label + ".plist",
		stagingDir:    filepath.Join(base, "staging"),
		stagedRequest: filepath.Join(base, "staging", "request.staged"),
		requestDir:    requestDir, request: filepath.Join(requestDir, "request.json"),
		activeRequest: filepath.Join(requestDir, "request.active"),
		cancel:        filepath.Join(requestDir, "cancel.json"),
		completionDir: filepath.Join(base, "completions")}, nil
}

// WatchPaths is a wakeup only. The dispatcher authenticates an A-owned,
// one-use signed request before opening the sealed R runtime. It has no
// listener and makes no outbound connection to A.
func renderSoulCooperativeLaunchd(p SoulCooperativeLaunchPolicy) (string, error) {
	paths, err := cooperativeLaunchPaths(p.Runner.InstallationID)
	if err != nil || p.Schema != soulCooperativeRuntimeInstallSchemaV3 || p.validate() != nil ||
		p.LauncherPath != SoulLauncher || p.Runner.Account != soulRunnerName(p.Runner.InstallationID) {
		return "", errSoulCooperativeAuthority
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>UserName</key><string>%s</string>
<key>GroupName</key><string>%s</string>
<key>Umask</key><integer>63</integer>
<key>RunAtLoad</key><false/>
<key>KeepAlive</key><false/>
<key>ProgramArguments</key><array>
<string>%s</string><string>cooperative-dispatch</string><string>%s</string>
</array>
<key>WatchPaths</key><array><string>%s</string></array>
</dict></plist>
`, paths.label, p.Runner.Account, p.Runner.Account, SoulLauncher,
		p.Runner.InstallationID, paths.requestDir), nil
}

// This is called only inside the exact owner-approved root apply. The two
// directories are deliberately asymmetric: A can publish an immutable request
// which R may read, and R can write a completion which A may read. Neither
// directory grants a new socket endpoint.
func installSoulCooperativeLaunchd(p SoulCooperativeLaunchPolicy) (func(), error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, errSoulCooperativeAuthority
	}
	paths, err := cooperativeLaunchPaths(p.Runner.InstallationID)
	if err != nil {
		return nil, err
	}
	plist, err := renderSoulCooperativeLaunchd(p)
	if err != nil {
		return nil, err
	}
	for _, d := range []struct {
		path     string
		uid, gid int
		mode     uint16
	}{
		{soulCooperativeLaunchDirectory, 0, 0, 0711},
		{filepath.Dir(paths.requestDir), 0, 0, 0711},
		{paths.stagingDir, p.MachineUID, p.Runner.GID, 02700},
		{paths.requestDir, p.MachineUID, p.Runner.GID, 02750},
		{paths.completionDir, p.MachineUID, p.Runner.GID, 02770},
		{filepath.Dir(p.StateRoot), p.Runner.UID, p.Runner.GID, 0700},
		{p.StateRoot, p.Runner.UID, p.Runner.GID, 0700},
	} {
		if err := stage2aEnsureInstallDirectory(d.path, d.uid, d.gid, d.mode); err != nil {
			return nil, err
		}
	}
	for _, leaf := range []string{paths.stagedRequest, paths.request, paths.activeRequest, paths.cancel,
		filepath.Join(paths.completionDir, "completion.json")} {
		if _, err := os.Lstat(leaf); !errors.Is(err, os.ErrNotExist) {
			return nil, errSoulCooperativeAuthority
		}
	}
	if _, err := os.Lstat(paths.plist); !errors.Is(err, os.ErrNotExist) {
		return nil, errSoulCooperativeAuthority
	}
	if err := stage2aInstallRootFile(paths.plist, []byte(plist), 0644); err != nil {
		return nil, err
	}
	loaded := false
	undo := func() {
		if loaded {
			_ = runProgram(launchctl, "bootout", "system/"+paths.label)
		}
		if raw, err := stage2aReadRootFile(paths.plist, int64(len(plist)), 0644); err == nil && bytes.Equal(raw, []byte(plist)) {
			_ = os.Remove(paths.plist)
		}
	}
	if err := runProgram(launchctl, "bootstrap", "system", paths.plist); err != nil {
		undo()
		return nil, err
	}
	loaded = true
	// A loaded job is only an installed trigger, not evidence of a Soul run.
	return undo, nil
}
