package daemon

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func uninstallMacPackage(deps Deps) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return removeMacPackage(deps, executable, []string{"/opt/homebrew", "/usr/local"}, noSystemHQ, readMachineUserJob)
}

func removeMacPackage(deps Deps, executable string, prefixes []string, checkHQ func() error, readJob func(int, string, string) ([]byte, bool, error)) error {
	caller, err := deps.caller()
	if err != nil {
		return err
	}
	if why := caller.Refuse(); why != "" {
		return errors.New(why)
	}
	if !caller.DarwinAdmin {
		return errors.New("run uninstall as the macOS Homebrew prefix administrator")
	}
	prefix, err := activeMachinePackage(executable, prefixes)
	if err != nil {
		return err
	}
	owner, err := PrefixOwner(prefix)
	if err != nil || (owner != caller.Username && owner != strconv.Itoa(caller.UID)) {
		return errors.New("uninstall requires the owner of the active Homebrew prefix")
	}
	if os.Getenv(channelEnv) != "" && filepath.Clean(os.Getenv(channelEnv)) != filepath.Join(prefix, "var", "agent-machine") {
		return errors.New("unset AGENT_MACHINE_CHANNEL before removing the installed Machine")
	}
	if deps.LockLifecycle == nil {
		return errors.New("missing macOS package lifecycle coordination")
	}
	lock, err := deps.LockLifecycle(caller.RegisteredHome, caller.UID)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := checkHQ(); err != nil {
		return err
	}
	if err := verifyHomebrewRemovalPrefix(prefix, caller.RegisteredHome); err != nil {
		return err
	}
	if err := stopPackageServices(deps, prefix, caller, readJob); err != nil {
		return err
	}
	if err := checkHQ(); err != nil {
		return err
	}
	if err := uninstallHomebrewFormula(prefix, caller.RegisteredHome); err != nil {
		return err
	}
	for _, path := range []string{"bin/managed-machine", "bin/agent-machine", "bin/agent-bot-keyd", "opt/managed-machine"} {
		if _, err := os.Lstat(filepath.Join(prefix, path)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("Homebrew did not remove the Machine package links")
		}
	}
	kegs, err := os.ReadDir(filepath.Join(prefix, "Cellar", "managed-machine"))
	if !errors.Is(err, os.ErrNotExist) && (err != nil || len(kegs) != 0) {
		return errors.New("Homebrew retained Machine kegs; inspect them before removing anything else")
	}
	return nil
}

func activeMachinePackage(executable string, prefixes []string) (string, error) {
	var selected string
	for _, prefix := range prefixes {
		opt := filepath.Join(prefix, "opt", "managed-machine")
		if _, err := os.Lstat(opt); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return "", err
		}
		keg, err := filepath.EvalSymlinks(opt)
		if err != nil || filepath.Dir(keg) != filepath.Join(prefix, "Cellar", "managed-machine") {
			return "", errors.New("cannot verify the active Homebrew Machine keg")
		}
		entries, err := os.ReadDir(filepath.Dir(keg))
		if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(keg) {
			return "", errors.New("the Machine Cellar contains more than the active keg or cannot be inspected; reconcile old versions with Homebrew and retry")
		}
		for _, name := range []string{"managed-machine", "agent-machine", "agent-bot-keyd"} {
			link, err := os.Stat(filepath.Join(prefix, "bin", name))
			targetPath := filepath.Join(keg, "bin", name)
			if name == "agent-machine" {
				alias, err := os.Readlink(targetPath)
				if err != nil || alias != "managed-machine" {
					return "", errors.New("cannot verify the Machine command alias")
				}
				targetPath = filepath.Join(keg, "bin", "managed-machine")
			}
			target, targetErr := os.Lstat(targetPath)
			if err != nil || targetErr != nil || !target.Mode().IsRegular() || !os.SameFile(link, target) {
				return "", errors.New("cannot verify the active Homebrew Machine package links")
			}
		}
		running, err := os.Stat(executable)
		core, coreErr := os.Lstat(filepath.Join(keg, "bin", "managed-machine"))
		if err != nil || coreErr != nil || !core.Mode().IsRegular() || !os.SameFile(running, core) || selected != "" {
			return "", errors.New("run uninstall with the active Homebrew Machine executable; a staged, custom or second installation must be reconciled separately")
		}
		receipt := filepath.Join(keg, "INSTALL_RECEIPT.json")
		info, err := os.Lstat(receipt)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return "", errors.New("cannot verify the Machine Homebrew receipt")
		}
		f, err := os.Open(receipt)
		if err != nil {
			return "", err
		}
		var tab struct{ Source struct{ Tap string } }
		dec := json.NewDecoder(io.LimitReader(f, 1<<20))
		err = dec.Decode(&tab)
		extra := dec.Decode(new(any))
		f.Close()
		if err != nil || extra != io.EOF || tab.Source.Tap != machineTap {
			return "", errors.New("Homebrew receipt does not identify the Machine tap")
		}
		selected = prefix
	}
	if selected == "" {
		return "", errors.New("no verified Homebrew installation; for a manually installed binary, uninstall its user services first and remove only the reviewed binary from its original install prefix")
	}
	return selected, nil
}

func removeStoppedPackageSocket(original packageLeaf, uid int, unlinkStopped func(int, string, int, unix.Stat_t) error) error {
	path := original.path
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !original.unchanged(info) {
		return errors.New("preserving a replaced Machine endpoint")
	}
	parent := filepath.Dir(path)
	real, err := filepath.EvalSymlinks(parent)
	if err != nil || real != parent {
		return errors.New("preserving a socket in an unverified Machine directory")
	}
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var dir, leaf unix.Stat_t
	if unix.Fstat(fd, &dir) != nil || int(dir.Uid) != uid || dir.Mode&0022 != 0 || !safeMembersPlanACL(fd, true) {
		return errors.New("preserving a socket in a directory with unverified ownership or permissions")
	}
	if unix.Fstatat(fd, filepath.Base(path), &leaf, unix.AT_SYMLINK_NOFOLLOW) != nil || leaf.Mode&unix.S_IFMT != unix.S_IFSOCK || int(leaf.Uid) != uid || leaf.Nlink != 1 || leaf.Ino != info.Sys().(*syscall.Stat_t).Ino {
		return errors.New("preserving a changed or foreign Machine endpoint")
	}
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		return errors.New("preserving a live Machine or keyd endpoint; stop the owning service and retry")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return errors.New("cannot verify that the Machine or keyd endpoint is stale")
	}
	var again unix.Stat_t
	if err := unix.Fstatat(fd, filepath.Base(path), &again, unix.AT_SYMLINK_NOFOLLOW); err != nil || !samePackageNode(leaf, again) {
		return errors.New("preserving a changed Machine endpoint")
	}
	if err := unlinkStopped(fd, path, uid, leaf); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("could not safely unlink the stopped %s endpoint: %w", filepath.Base(path), err)
	}
	return nil
}

func legacyMacSocketUnlink(fd int, path string, uid int, original unix.Stat_t) error {
	name := filepath.Base(path)
	const atNoDeleteBusy = 0x4000
	err := unix.Unlinkat(fd, name, atNoDeleteBusy)
	if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOTSUP) {
		return err
	}
	release, err := unix.Sysctl("kern.osrelease")
	major, _, _ := strings.Cut(release, ".")
	version, parseErr := strconv.Atoi(major)
	if err != nil || parseErr != nil || version != 24 {
		return errors.New("guarded socket removal is unavailable")
	}
	// Darwin 24 has no AT_NODELETEBUSY. The caller holds the administrator
	// lifecycle lock, has unloaded both jobs, checked the parent ACL/owner and
	// confirmed ECONNREFUSED. Also require no remaining same-owner Machine/keyd
	// process (including a foreground daemon) before removing this stale node.
	return unlinkQuiescentSocket(fd, path, uid, original, darwinCustodyPIDs)
}

func unlinkQuiescentSocket(fd int, path string, uid int, original unix.Stat_t, processes func(int) ([]byte, error)) error {
	name := filepath.Base(path)
	var before, after unix.Stat_t
	if err := unix.Fstatat(fd, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !samePackageNode(original, before) || before.Mode&unix.S_IFMT != unix.S_IFSOCK || int(before.Uid) != uid || before.Nlink != 1 {
		return errors.New("preserving changed socket")
	}
	pids, err := processes(uid)
	if err != nil {
		return errors.New("could not establish that Machine and keyd have stopped")
	}
	for _, pid := range strings.Fields(string(pids)) {
		if pid != strconv.Itoa(os.Getpid()) {
			return errors.New("another Machine or keyd process still exists; wait for it to stop and retry")
		}
	}
	if err := verifyPackageSocketParent(fd, path, uid); err != nil {
		return err
	}
	if err := unusedMachineSocket(path); err != nil {
		return err
	}
	if err := verifyPackageSocketParent(fd, path, uid); err != nil {
		return err
	}
	if err := unix.Fstatat(fd, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !samePackageNode(before, after) {
		return errors.New("preserving changed socket")
	}
	return unix.Unlinkat(fd, name, 0)
}

// A pathname probe and an fd-relative unlink must still address the same
// protected directory. In particular, a moved parent retains its old FD.
func verifyPackageSocketParent(fd int, path string, uid int) error {
	parent := filepath.Dir(path)
	physical, err := filepath.EvalSymlinks(parent)
	var held, named unix.Stat_t
	if err != nil || physical != parent || unix.Fstat(fd, &held) != nil || unix.Lstat(parent, &named) != nil ||
		named.Mode&unix.S_IFMT != unix.S_IFDIR || int(held.Uid) != uid || held.Mode&0022 != 0 ||
		!samePackageNode(held, named) || !safeMembersPlanACL(fd, true) {
		return errors.New("preserving a Machine endpoint whose protected directory changed")
	}
	return nil
}

func samePackageNode(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Gen == b.Gen && a.Btim == b.Btim && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid
}

var homebrewKegVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([_-][A-Za-z0-9._-]+)?$`)

func isPackageProgram(prefix, program string, keyd bool) bool {
	if filepath.Clean(program) != program {
		return false
	}
	name := filepath.Base(program)
	if keyd && name != "agent-bot-keyd" || !keyd && name != "managed-machine" && name != "agent-machine" {
		return false
	}
	dir := filepath.Dir(program)
	if dir == filepath.Join(prefix, "bin") || dir == filepath.Join(prefix, "opt", "managed-machine", "bin") {
		return true
	}
	version := filepath.Dir(dir)
	return filepath.Base(dir) == "bin" && filepath.Dir(version) == filepath.Join(prefix, "Cellar", "managed-machine") && homebrewKegVersion.MatchString(filepath.Base(version))
}

func inspectPackageServices(prefix string, caller Caller, readJob func(int, string, string) ([]byte, bool, error)) ([]packageLeaf, error) {
	var plists []packageLeaf
	agents := filepath.Join(caller.RegisteredHome, "Library", "LaunchAgents")
	if info, err := os.Lstat(agents); err == nil {
		if !info.IsDir() || int(info.Sys().(*syscall.Stat_t).Uid) != caller.UID || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("preserving an unverified LaunchAgents directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	state := filepath.Join(caller.RegisteredHome, ".local", "state", "agent-bot")
	for _, label := range []string{darwinServiceLabel, darwinKeydServiceLabel} {
		keyd := label == darwinKeydServiceLabel
		path := filepath.Join(agents, label+".plist")
		leaf := packageLeaf{path: path}
		info, err := os.Lstat(path)
		if err == nil {
			if !info.Mode().IsRegular() || info.Size() > 64<<10 || int(info.Sys().(*syscall.Stat_t).Uid) != caller.UID || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
				return nil, errors.New("preserving an unverified Machine LaunchAgent file")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			var plist struct {
				Arrays []struct {
					Args []string `xml:"string"`
				} `xml:"dict>array"`
			}
			if xml.Unmarshal(data, &plist) != nil || len(plist.Arrays) == 0 || len(plist.Arrays[0].Args) == 0 {
				return nil, errors.New("preserving an unrecognized Machine LaunchAgent")
			}
			program := plist.Arrays[0].Args[0]
			want := darwinAgent(caller.RegisteredHome, program)
			if keyd {
				want = keydAgent(state, program)
			}
			if !isPackageProgram(prefix, program, keyd) || !bytes.Equal(data, []byte(want)) {
				return nil, errors.New("preserving a customized or unrelated Machine LaunchAgent")
			}
			leaf.info, leaf.body = info, data
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		plists = append(plists, leaf)
		for _, domain := range []string{"gui", "user"} {
			job, loaded, err := readJob(caller.UID, domain, label)
			if err != nil {
				return nil, err
			}
			if !loaded {
				continue
			}
			var source, program string
			var args []string
			inArgs := false
			for _, raw := range strings.Split(string(job), "\n") {
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
				case strings.HasPrefix(line, "program = ") && program == "":
					program = strings.TrimPrefix(line, "program = ")
				}
			}
			if source != path || !isPackageProgram(prefix, program, keyd) || len(args) == 0 || !isPackageProgram(prefix, args[0], keyd) {
				return nil, errors.New("preserving an unverified loaded Machine service")
			}
			want := []string{"daemon", "run"}
			if keyd {
				want = []string{"serve", "--state-dir", state}
			}
			if !slices.Equal(args[1:], want) {
				return nil, errors.New("preserving a loaded Machine service with unrelated arguments")
			}
		}
	}
	return plists, nil
}

type packageLeaf struct {
	path string
	info os.FileInfo
	body []byte
}

// Snapshot both unit files and all three endpoint identities before bootout.
// launchd may unlink an endpoint itself. A replacement, including a new file
// in a previously absent slot, never acquires the old file's removal authority.
func stopPackageServices(deps Deps, prefix string, caller Caller, readJob func(int, string, string) ([]byte, bool, error)) error {
	if deps.Deactivate == nil {
		return errors.New("missing Machine service manager")
	}
	leaves, err := inspectPackageServices(prefix, caller, readJob)
	if err != nil {
		return err
	}
	private := filepath.Join(caller.RegisteredHome, ".local", "state", "agent-bot", "keyd")
	for _, path := range []string{filepath.Join(prefix, "var", "agent-machine", "daemon.sock"), filepath.Join(private, "keyd.sock"), filepath.Join(private, "owner.sock")} {
		leaf := packageLeaf{path: path}
		info, err := os.Lstat(path)
		if err == nil {
			st := info.Sys().(*syscall.Stat_t)
			if info.Mode()&os.ModeSocket == 0 || int(st.Uid) != caller.UID || st.Nlink != 1 {
				return errors.New("preserving a foreign or unrelated Machine endpoint")
			}
			leaf.info = info
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		leaves = append(leaves, leaf)
	}
	// Each verified job can be stopped independently. Keep all files for a
	// retry if either stop failed.
	machineErr := deps.Deactivate(leaves[0].path)
	keydErr := deps.Deactivate(leaves[1].path)
	if err := errors.Join(machineErr, keydErr); err != nil {
		return err
	}
	for i, leaf := range leaves {
		current, err := os.Lstat(leaf.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !leaf.unchanged(current) {
			return errors.New("preserving a Machine service file that changed during unload")
		}
		if i < 2 {
			body, err := os.ReadFile(leaf.path)
			if err != nil || !bytes.Equal(body, leaf.body) {
				return errors.New("preserving a Machine LaunchAgent changed during unload")
			}
			if err := os.Remove(leaf.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if err := removeStoppedPackageSocket(leaf, caller.UID, legacyMacSocketUnlink); err != nil {
			return err
		}
	}
	return nil
}

func (l packageLeaf) unchanged(current os.FileInfo) bool {
	if l.info == nil || !os.SameFile(l.info, current) || l.info.Mode() != current.Mode() {
		return false
	}
	a, b := l.info.Sys().(*syscall.Stat_t), current.Sys().(*syscall.Stat_t)
	return a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Birthtimespec == b.Birthtimespec && a.Gen == b.Gen
}
