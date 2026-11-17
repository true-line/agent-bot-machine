package members

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

const (
	launchLabel  = "ai.true-line.agent-bot-hq"
	launchPlist  = "/Library/LaunchDaemons/" + launchLabel + ".plist"
	launchSocket = "/private/var/agent-bot-hq-control.sock"
	launchState  = "/var/agent-bot-hq/.agent-bot-hq"
)

// The owner approves the exact manager job, artifact, interpreter and owner UID.
type launchRecord struct {
	Service  HQService `json:"service"`
	Plist    string    `json:"plist"`
	OwnerUID int       `json:"owner_uid"`
}

func appendLaunchDaemon(p *Plan, in Input, h Host) error {
	s := in.HQService
	if p.HQAccount != DarwinHQAccount || p.SharedHQAdvice() != "" || in.Invoker == DarwinHQAccount || !accountName.MatchString(in.Invoker) {
		return refuse(RefusedAccount, "the macOS service needs the dedicated HQ account and a separate owner")
	}
	owner, ok, err := h.Account(in.Invoker)
	if err != nil {
		return err
	}
	if !ok || owner.UID <= 0 {
		return refuse(RefusedAccount, "owner must resolve to a non-root UID")
	}
	hq, exists, err := h.Account(DarwinHQAccount)
	if err != nil {
		return err
	}
	if exists && (hq.UID == owner.UID || hq.Home != HQHome(PlatformDarwin, DarwinHQAccount) || hq.Shell != DarwinNoLoginShell) {
		return refuse(RefusedAccount, "HQ needs its own locked role account and private home")
	}
	if err := verifyDarwinRelease(*s, h); err != nil {
		return err
	}
	// All interpolated strings have passed the portable path/account grammar.
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!-- Managed by managed-machine members. -->
<!-- archive %s node %s owner UID %d -->
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>UserName</key><string>%s</string>
<key>GroupName</key><string>%s</string>
<key>Umask</key><integer>63</integer>
<key>ProgramArguments</key><array>
<string>/usr/bin/ruby</string><string>--disable-gems</string><string>%s</string><string>launch</string>
<string>%s</string><string>%s</string><string>run</string><string>--home</string><string>%s</string>
<string>--owner-account</string><string>%s</string></array>
<key>Sockets</key><dict><key>owner-control</key><dict>
<key>SockPathName</key><string>%s</string><key>SockPathMode</key><integer>438</integer>
<key>SockType</key><string>stream</string></dict></dict>
</dict></plist>
`, s.ArtifactSHA256, s.NodeSHA256, owner.UID, launchLabel, DarwinHQAccount, DarwinHQAccount, filepath.Join(s.ReleaseDir, "helpers/darwin-owner.rb"), s.Node, filepath.Join(s.ReleaseDir, "hq/main.mjs"), launchState, in.Invoker, launchSocket)
	if err := trustedPath(h, filepath.Dir(launchPlist), true); err != nil {
		return err
	}
	action := ActionCreate
	ent, exists, err := h.Lstat(launchPlist)
	if err != nil {
		return err
	}
	if exists {
		if !ent.Regular || ent.Owner != "root" || ent.Group != "wheel" || ent.Mode != 0644 {
			return refuse(RefusedPath, "existing LaunchDaemon has foreign metadata")
		}
		actual, ok, err := h.ReadFile(launchPlist)
		if err != nil {
			return err
		}
		if !ok || actual != plist {
			return refuse(RefusedPath, "existing LaunchDaemon differs from the approved job; reconcile before installing")
		}
		action = ActionWrite
	}
	raw, err := json.Marshal(launchRecord{Service: *s, Plist: plist, OwnerUID: owner.UID})
	if err != nil {
		return err
	}
	p.Steps = append(p.Steps, Step{Kind: KindService, Target: launchLabel, Action: action, Owner: in.Invoker, Content: string(raw), Detail: "install the approved LaunchDaemon and verify status as its owner"})
	return nil
}
