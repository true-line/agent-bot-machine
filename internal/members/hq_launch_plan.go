package members

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

const (
	launchLabel         = "ai.true-line.agent-bot-hq"
	launchPlist         = "/Library/LaunchDaemons/" + launchLabel + ".plist"
	launchControlV1     = "darwin-owner-control/v1"
	launchControlV2     = "darwin-owner-control/v2"
	launchRuntimeDir    = "/Library/Application Support/" + launchLabel
	launchRuntimeSocket = launchRuntimeDir + "/owner-control.sock"
	launchSocket        = "/private/var/agent-bot-hq-control.sock"
	launchState         = "/var/agent-bot-hq/.agent-bot-hq"
)

// The owner approves the exact manager job, artifact, interpreter and owner UID.
type launchRecord struct {
	Service    HQService        `json:"service"`
	Plist      string           `json:"plist"`
	OwnerUID   int              `json:"owner_uid"`
	RuntimeDir *launchDirectory `json:"runtime_directory,omitempty"`
	Stage2a    *hqStage2aLaunch `json:"stage2a,omitempty"`
}

type launchDirectory struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	Owner  string `json:"owner"`
	Group  string `json:"group"`
	Mode   string `json:"mode"`
}

func socketForCapability(capability string) string {
	if capability == launchControlV2 {
		return launchRuntimeSocket
	}
	return launchSocket
}

func pathAncestry(path string) []string {
	var paths []string
	for {
		paths = append(paths, path)
		if path == filepath.Dir(path) {
			return paths
		}
		path = filepath.Dir(path)
	}
}

func planLaunchDirectory(h Host, checkACL func([]string) error) (*launchDirectory, error) {
	parent := filepath.Dir(launchRuntimeDir)
	if err := trustedPath(h, parent, true); err != nil {
		return nil, err
	}
	ent, exists, err := h.Lstat(launchRuntimeDir)
	if err != nil {
		return nil, err
	}
	dir := &launchDirectory{Path: launchRuntimeDir, Owner: "root", Group: "wheel", Mode: "0755", Action: ActionCreate}
	if exists {
		if !ent.Dir || ent.Owner != dir.Owner || ent.Group != dir.Group || ent.Mode != 0755 {
			return nil, refuse(RefusedPath, "existing HQ runtime directory must be root:wheel 0755")
		}
		dir.Action = ActionNone
		parent = launchRuntimeDir
	}
	if runtime.GOOS == "darwin" {
		if err := checkACL(pathAncestry(parent)); err != nil {
			return nil, err
		}
	}
	return dir, nil
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
	capability, err := verifyDarwinRelease(*s, h)
	if err != nil {
		return err
	}
	if s.Stage2a == nil {
		if err := checkUnselectedHQBootstrap(*s); err != nil {
			return err
		}
	}
	rec := launchRecord{Service: *s, OwnerUID: owner.UID}
	if s.Stage2a != nil {
		rec.Stage2a, err = reviewHQStage2aService(in, h, owner, hq, capability)
		if err != nil {
			return err
		}
	}
	plist := renderLaunchPlist(*s, owner.UID, in.Invoker, capability)
	if rec.Stage2a != nil {
		plist = renderHQStage2aPlist(plist, rec.Stage2a.OuterArgv)
	}
	rec.Plist = plist
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
		if !ok || (actual != plist && in.UpgradeFrom == nil) {
			return refuse(RefusedPath, "existing LaunchDaemon differs from the approved job; reconcile before installing")
		}
		action = ActionWrite
	}
	detail := "install the approved LaunchDaemon and verify status as its owner"
	if capability == launchControlV2 {
		checkACL := checkDarwinACLs
		if in.upgradeObservation != nil {
			checkACL = in.upgradeObservation.acl
		}
		rec.RuntimeDir, err = planLaunchDirectory(h, checkACL)
		if err != nil {
			return err
		}
		if exists && rec.RuntimeDir.Action == ActionCreate {
			return refuse(RefusedPath, "the installed HQ LaunchDaemon is missing its approved runtime directory; reconcile before installing")
		}
		verb := "verify"
		if rec.RuntimeDir.Action == ActionCreate {
			verb = "create"
		}
		detail = fmt.Sprintf("%s %s as root:wheel 0755, install the approved LaunchDaemon and verify status as its owner", verb, launchRuntimeDir)
	}
	if in.UpgradeFrom != nil {
		return appendServiceUpgrade(p, in, h, rec)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	p.Steps = append(p.Steps, Step{Kind: KindService, Target: launchLabel, Action: action, Owner: in.Invoker, Content: string(raw), Detail: detail})
	return nil
}

func renderLaunchPlist(s HQService, uid int, owner, capability string) string {
	// All interpolated strings have passed the portable path/account grammar.
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
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
`, s.ArtifactSHA256, s.NodeSHA256, uid, launchLabel, DarwinHQAccount, DarwinHQAccount, filepath.Join(s.ReleaseDir, "helpers/darwin-owner.rb"), s.Node, filepath.Join(s.ReleaseDir, "hq/main.mjs"), launchState, owner, socketForCapability(capability))
}

func matchesReviewedHQPlist(rec launchRecord, owner, capability string) bool {
	want := renderLaunchPlist(rec.Service, rec.OwnerUID, owner, capability)
	if rec.Stage2a == nil || rec.Service.Stage2a == nil {
		return rec.Stage2a == nil && rec.Service.Stage2a == nil && rec.Plist == want
	}
	plan := rec.Stage2a
	if !stage2aPrefixedDigest.MatchString(plan.RubySHA256) || !stage2aPrefixedDigest.MatchString(plan.LauncherSHA256) {
		return false
	}
	derived, err := rec.Service.Stage2a.launch(owner, plan.RubySHA256)
	if err != nil {
		return false
	}
	derived.LauncherSHA256 = plan.LauncherSHA256
	return reflect.DeepEqual(plan, derived) && rec.Plist == renderHQStage2aPlist(want, derived.OuterArgv)
}

func renderHQStage2aPlist(base string, argv []string) string {
	const start = "<key>ProgramArguments</key><array>\n"
	const end = "</array>"
	before, tail, _ := strings.Cut(base, start)
	_, after, _ := strings.Cut(tail, end)
	var arguments strings.Builder
	for _, arg := range argv {
		arguments.WriteString("<string>")
		_ = xml.EscapeText(&arguments, []byte(arg))
		arguments.WriteString("</string>\n")
	}
	return before + start + arguments.String() + end + after
}

// The protected service runs the candidate as H only through the approved
// launchd argv. Base service capability and peer probes still run as H.
func probeBaseHQRole(rec launchRecord, probe func() error) error {
	if rec.Stage2a != nil || rec.Service.Stage2a != nil {
		return nil
	}
	return probe()
}
