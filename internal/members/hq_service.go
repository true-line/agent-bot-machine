package members

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	hqServiceName = "agent-bot-hq.service"
	hqSocketName  = "agent-bot-hq.socket"
	hqSystemDir   = "/etc/systemd/system"
	hqControlDir  = "/run/agent-bot-hq"
	hqState       = "/var/lib/agent-bot-hq/.agent-bot-hq"
)

var systemdPath = regexp.MustCompile(`^/[a-zA-Z0-9._/+:-]+$`)

// launchd receives separate argv entries, so the installed Darwin HQ release
// may use macOS's standard Application Support directory. Keep the exception
// inside that fixed release root; Linux unit arguments remain space-free.
var darwinHQReleasePath = regexp.MustCompile(`^/Library/Application Support/ai\.true-line\.agent-bot-hq/releases/[a-zA-Z0-9._/+:-]+$`)
var digestHex = regexp.MustCompile(`^[a-f0-9]{64}$`)

// HQService identifies an installed, operator-approved interim release.
// Machine never downloads, extracts, or executes the payload as root.
type HQService struct {
	Archive        string            `json:"archive,omitempty"`
	ReleaseDir     string            `json:"release_dir"`
	ArtifactSHA256 string            `json:"artifact_sha256"`
	Node           string            `json:"node"`
	NodeSHA256     string            `json:"node_sha256"`
	Stage2a        *hqStage2aService `json:"stage2a,omitempty"`
}

func decodeHQService(raw []byte) (*HQService, error) {
	var svc HQService
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&svc); err != nil {
		return nil, fmt.Errorf("invalid HQ service record: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("trailing data in HQ service record")
	}
	return &svc, svc.validate()
}

func (s HQService) validate() error {
	if s.Stage2a != nil {
		if err := s.Stage2a.validate(); err != nil {
			return err
		}
	}
	paths := []string{s.ReleaseDir, s.Node}
	if s.Archive != "" {
		paths = append(paths, s.Archive)
	}
	for _, p := range paths {
		if !(systemdPath.MatchString(p) || darwinHQReleasePath.MatchString(p)) || filepath.Clean(p) != p || p == "/" {
			return refuse(RefusedPath, "HQ service paths must be clean absolute service arguments")
		}
	}
	if filepath.Base(s.ReleaseDir) != "hq" || !digestHex.MatchString(s.ArtifactSHA256) || !digestHex.MatchString(s.NodeSHA256) {
		return refuse(RefusedList, "expected a versioned extraction ending in /hq and both lowercase SHA-256 digests")
	}
	return nil
}

func trustedPath(h Host, p string, directory bool) error {
	if parent := filepath.Dir(p); parent != p {
		if err := trustedPath(h, parent, true); err != nil {
			return err
		}
	}
	return trustedEntry(h, p, directory)
}

func trustedEntry(h Host, p string, directory bool) error {
	e, ok, err := h.Lstat(p)
	if err != nil {
		return err
	}
	if !ok || e.Owner != "root" || e.Mode&0o022 != 0 || directory && !e.Dir || !directory && (!e.Regular || e.Mode&0o6000 != 0) {
		kind := "regular file"
		if directory {
			kind = "directory"
		}
		return refuse(RefusedPath, "%s must be a root-owned %s without symlinks or group/other writes", p, kind)
	}
	return nil
}

// Check every installed entry, then reproduce build-interim-release.mjs's GNU
// tar bytes. Extra files, changed modes and substituted runtime modules affect
// the digest. A protected ancestry keeps the approved tree stable after apply.
func (s HQService) verify(h Host) error {
	if err := s.validate(); err != nil {
		return err
	}
	if err := trustedPath(h, s.ReleaseDir, true); err != nil {
		return err
	}
	if err := trustedPath(h, s.Node, false); err != nil {
		return err
	}
	entry, _, err := h.Lstat(s.Node)
	if err != nil {
		return err
	}
	if entry.Mode&0o111 == 0 {
		return refuse(RefusedPath, "Node must be executable")
	}
	for _, required := range []string{"hq/main.mjs", "governance/interim-release.json"} {
		if err := trustedPath(h, filepath.Join(s.ReleaseDir, required), false); err != nil {
			return err
		}
	}
	var fileBytes int64
	count := 0
	err = filepath.WalkDir(s.ReleaseDir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := trustedEntry(h, p, e.IsDir()); err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if !e.IsDir() && info.Mode()&0o111 != 0 {
			if err := checkHQFileCapabilities(p); err != nil {
				return err
			}
		}
		count++
		fileBytes += info.Size()
		if count > 10000 || fileBytes > 256<<20 {
			return refuse(RefusedPath, "HQ release exceeds verification limits")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := checkHQFileCapabilities(s.Node); err != nil {
		return err
	}
	node, err := os.Open(s.Node)
	if err != nil {
		return err
	}
	defer node.Close()
	hash := sha256.New()
	if n, err := io.Copy(hash, io.LimitReader(node, (256<<20)+1)); err != nil || n > 256<<20 || hex.EncodeToString(hash.Sum(nil)) != s.NodeSHA256 {
		return refuse(RefusedPath, "installed Node digest does not match the HQ service record")
	}
	hash.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/tar", "--sort=name", "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner", "--mode=u+rwX,go+rX,go-w", "--format=ustar", "-cf", "-", "-C", filepath.Dir(s.ReleaseDir), "hq")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Stdout = hash
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reconstruct installed HQ artifact: %w", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != s.ArtifactSHA256 {
		return refuse(RefusedPath, "installed HQ tree does not reproduce the approved artifact SHA-256")
	}
	return nil
}

func appendHQService(p *Plan, in Input, h Host) error {
	s := in.HQService
	if s.Archive != "" {
		return refuse(RefusedList, "archive is used only by the macOS installer")
	}
	if in.Platform != "" || p.HQAccount != DefaultHQAccount || p.SharedHQAdvice() != "" || in.Invoker == DefaultHQAccount || !accountName.MatchString(in.Invoker) {
		return refuse(RefusedAccount, "the Linux HQ service needs the dedicated HQ account and a separate owner")
	}
	owner, ok, err := h.Account(in.Invoker)
	if err != nil {
		return err
	}
	if !ok || owner.UID <= 0 {
		return refuse(RefusedAccount, "the approved owner must resolve to an unprivileged UID")
	}
	if hq, exists, err := h.Account(DefaultHQAccount); err != nil {
		return err
	} else if exists && (hq.Home != HQHome("", DefaultHQAccount) || hq.UID == owner.UID) {
		return refuse(RefusedAccount, "HQ must have its dedicated home and a UID distinct from the owner")
	}
	if _, exists, err := h.Lstat(hqControlDir); err != nil {
		return err
	} else if exists {
		if err := trustedPath(h, hqControlDir, true); err != nil {
			return err
		}
	}
	if p.Dir == hqControlDir || strings.HasPrefix(hqControlDir+"/", p.Dir+"/") {
		return refuse(RefusedPath, "the public control socket needs a separate parent from the harness endpoint list")
	}
	if err := s.verify(h); err != nil {
		return err
	}
	control := header + fmt.Sprintf(`[Unit]
Description=HQ owner control socket
[Socket]
ListenStream=%s/control.sock
SocketUser=%d
SocketMode=0600
DirectoryMode=0755
FileDescriptorName=owner-control
RemoveOnStop=true
[Install]
WantedBy=sockets.target
`, hqControlDir, owner.UID)
	main := filepath.Join(s.ReleaseDir, "hq/main.mjs")
	unit := header + "# HQ archive SHA-256 " + s.ArtifactSHA256 + "\n# Node SHA-256 " + s.NodeSHA256 + "\n" + fmt.Sprintf(`[Unit]
Description=HQ local authority
Requires=%s
Wants=%s
After=%s %s
[Service]
Type=exec
User=%s
Group=%s
UMask=0077
Sockets=%s
ExecStartPre=/usr/bin/systemctl is-active --quiet %s
ExecStartPre=%s %s check-owner-control
ExecStart=%s %s run --home %s --owner-account %s
`, hqSocketName, EgressUnitName, hqSocketName, EgressUnitName, DefaultHQAccount, DefaultHQAccount, hqSocketName, EgressUnitName, s.Node, main, s.Node, main, hqState, in.Invoker)
	for _, file := range []struct{ name, content string }{{hqServiceName, unit}, {hqSocketName, control}} {
		step, err := ownedFileStep(h, filepath.Join(hqSystemDir, file.name), "0644", file.content)
		if err != nil {
			return err
		}
		// Upgrading an installed release needs a separate cutover and rollback.
		if step.Action == ActionRepair {
			return refuse(RefusedPath, "installed %s differs; stop and reconcile the existing installation before this first-install operation", file.name)
		}
		p.Steps = append(p.Steps, step)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	p.Steps = append(p.Steps, Step{Kind: KindService, Target: hqSocketName, Action: ActionWrite, Owner: in.Invoker, Content: string(raw), Detail: "verify owner-control support as the service account, enable its socket and verify status as the owner"})
	return nil
}

func confirmsHQOwner(out []byte, owner string, uid string) bool {
	return confirmsServiceOwner(out, owner, uid, DefaultHQAccount, hqControlDir+"/control.sock", "SO_PEERCRED")
}

func confirmsServiceOwner(out []byte, owner, uid, serviceAccount, socket, peerCheck string) bool {
	var status struct {
		HQ struct {
			Account string
			Sockets struct {
				OwnerControl struct {
					Account   string
					UID       *int
					Path      string
					PeerCheck string `json:"peer_check"`
				}
			}
		}
	}
	if json.Unmarshal(out, &status) != nil {
		return false
	}
	control := status.HQ.Sockets.OwnerControl
	return status.HQ.Account == serviceAccount && control.Account == owner && control.UID != nil && strconv.Itoa(*control.UID) == uid && control.Path == socket && control.PeerCheck == peerCheck
}
