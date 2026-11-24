//go:build darwin

package guestowner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/qwts/managed-machine/internal/daemon"
	"golang.org/x/sys/unix"
)

var (
	errGuestObservation = errors.New("guest observation refused")
	vmNamePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	macPattern          = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	buildPattern        = regexp.MustCompile(`^[0-9]{2}[A-Z][0-9]{1,5}$`)
	shaPattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func exactSHA(v string) bool { return shaPattern.MatchString(v) }

const tartGuestPublicKeyPath = "/opt/homebrew/var/agent-machine/daemon.pub"
const protectedTartRoot = "/private/var/db/agent-bot-stage2a-tart"

type tartVMStatus struct {
	OS      string `json:"OS"`
	MAC     string `json:"MACAddress"`
	Running bool   `json:"Running"`
	State   string `json:"State"`
}

type boundedTartOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedTartOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errGuestObservation
	}
	return b.Buffer.Write(p)
}

func checkedTartFile(path, expectedSHA string) error {
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, protectedTartRoot+string(filepath.Separator)) ||
		!exactSHA(expectedSHA) {
		return errGuestObservation
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errGuestObservation
		}
		// macOS ACLs can grant this administrator write access even when the
		// mode bits and root ownership look safe. Such a path is not pinned.
		if err := unix.Access(current, unix.W_OK); err == nil ||
			(err != syscall.EACCES && err != syscall.EPERM && err != syscall.EROFS) {
			return errGuestObservation
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errGuestObservation
		}
		if current == path && !info.Mode().IsRegular() {
			return errGuestObservation
		}
		if current != path && !info.IsDir() {
			return errGuestObservation
		}
		if current == "/" {
			break
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return errGuestObservation
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 128*1024*1024+1)); err != nil {
		return errGuestObservation
	}
	info, err := f.Stat()
	if err != nil || info.Size() > 128*1024*1024 || hex.EncodeToString(h.Sum(nil)) != expectedSHA {
		return errGuestObservation
	}
	return nil
}

func checkedTartBundle(ctx context.Context, path string) error {
	if path != filepath.Join(protectedTartRoot, "tart.app") {
		return errGuestObservation
	}
	count := 0
	if err := filepath.WalkDir(path, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || count > 64 {
			return errGuestObservation
		}
		count++
		info, err := entry.Info()
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) ||
			info.Mode().Perm()&0o022 != 0 {
			return errGuestObservation
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errGuestObservation
		}
		if err := unix.Access(name, unix.W_OK); err == nil ||
			(err != syscall.EACCES && err != syscall.EPERM && err != syscall.EROFS) {
			return errGuestObservation
		}
		return nil
	}); err != nil || count == 0 {
		return errGuestObservation
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/codesign", "--verify", "--deep", "--strict", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = nil
	cmd.Stdout = &boundedTartOutput{limit: 2048}
	cmd.Stderr = &boundedTartOutput{limit: 2048}
	if err := cmd.Run(); err != nil || call.Err() != nil {
		return errGuestObservation
	}
	return nil
}

func runPinnedTart(ctx context.Context, path, home string, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home}
	cmd.Stdin = nil
	stdout := &boundedTartOutput{limit: 8192}
	stderr := &boundedTartOutput{limit: 2048}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil || call.Err() != nil {
		return nil, errGuestObservation
	}
	return stdout.Bytes(), nil
}

func ObserveTartGuest(ctx context.Context, caller daemon.Caller, vmName, expectedMAC, expectedBuild,
	wrapperSHA, appSHA string) (daemon.GuestTartObservation, error) {
	var observed daemon.GuestTartObservation
	if !vmNamePattern.MatchString(vmName) || !macPattern.MatchString(expectedMAC) ||
		!buildPattern.MatchString(expectedBuild) || caller.UID < 501 {
		return observed, errGuestObservation
	}
	base := protectedTartRoot
	wrapper := filepath.Join(base, "tartctl")
	app := filepath.Join(base, "tart.app", "Contents", "MacOS", "tart")
	if err := checkedTartFile(wrapper, wrapperSHA); err != nil {
		return observed, err
	}
	if err := checkedTartFile(app, appSHA); err != nil {
		return observed, err
	}
	if err := checkedTartBundle(ctx, filepath.Join(base, "tart.app")); err != nil {
		return observed, err
	}
	readStatus := func() (tartVMStatus, error) {
		var s tartVMStatus
		out, err := runPinnedTart(ctx, wrapper, caller.RegisteredHome, "get", vmName, "--format", "json")
		if err != nil || json.Unmarshal(out, &s) != nil || !s.Running || s.State != "running" || s.OS != "darwin" || s.MAC != expectedMAC {
			return s, errGuestObservation
		}
		return s, nil
	}
	if _, err := readStatus(); err != nil {
		return observed, err
	}
	pubText, err := runPinnedTart(ctx, wrapper, caller.RegisteredHome, "exec", vmName,
		"/usr/bin/base64", "-i", tartGuestPublicKeyPath)
	if err != nil {
		return observed, err
	}
	pub, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(pubText)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return observed, errGuestObservation
	}
	macText, err := runPinnedTart(ctx, wrapper, caller.RegisteredHome, "exec", vmName, "/sbin/ifconfig", "en0")
	if err != nil {
		return observed, err
	}
	macLine := regexp.MustCompile(`(?m)^\s*ether ([0-9a-f:]{17})\s*$`).FindSubmatch(macText)
	if len(macLine) != 2 || string(macLine[1]) != expectedMAC {
		return observed, errGuestObservation
	}
	buildText, err := runPinnedTart(ctx, wrapper, caller.RegisteredHome, "exec", vmName, "/usr/bin/sw_vers", "-buildVersion")
	if err != nil || strings.TrimSpace(string(buildText)) != expectedBuild {
		return observed, errGuestObservation
	}
	if _, err := readStatus(); err != nil {
		return observed, err
	}
	return daemon.GuestTartObservation{VMName: vmName, MAC: expectedMAC, Build: expectedBuild,
		WrapperSHA: wrapperSHA, AppSHA: appSHA, Machine: pub}, nil
}

// The Darwin-only observer does not use guest SSH. Tart's direct host/guest
// channel binds the named live VM to its local MAC and Machine public key.
