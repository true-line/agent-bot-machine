package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/qwts/managed-machine/internal/provider/brew"
	"golang.org/x/sys/unix"
)

// An explicit, exact-file recovery selector can bridge one manually staged
// prior Machine keyd into the current adjacent package. It refuses unrelated
// directories, bytes changed through the post-signature recheck, and any
// signature outside Machine's bundled keyd requirement. The secure admin
// account remains trusted after that check; loaded-job and binary readback
// are required after activation. Normal preflight checks the exact plist and
// loaded job before replacing either registration.
func approvedPriorKeyd(prior, current, digest string, uid int) bool {
	return approvedPriorKeydWithChecks(prior, current, digest, uid, openDeviceKeydParent, verifyDeviceCode)
}

func approvedPriorKeydWithChecks(prior, current, digest string, uid int,
	openParent func(string) (*os.File, string, error),
	verifyCode func(context.Context, string, string, string) error) bool {
	if !exactKey(digest) || prior == current || filepath.Base(prior) != "agent-bot-keyd" ||
		filepath.Base(current) != "agent-bot-keyd" || !filepath.IsAbs(prior) ||
		filepath.Clean(prior) != prior ||
		filepath.Dir(filepath.Dir(prior)) != filepath.Dir(filepath.Dir(current)) {
		return false
	}
	parent, directory, err := openParent(prior)
	if err != nil {
		return false
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), "agent-bot-keyd", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), prior)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<20 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || stat.Mode&07777 != 0700 || stat.Nlink != 1 {
		return false
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 16<<20)); err != nil || hex.EncodeToString(h.Sum(nil)) != digest {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if verifyCode(ctx, directory, "agent-bot-keyd", deviceKeydRequirement) != nil {
		return false
	}
	var named, after unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), "agent-bot-keyd", &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		unix.Fstat(int(f.Fd()), &after) != nil || named.Dev != stat.Dev || named.Ino != stat.Ino ||
		after.Dev != stat.Dev || after.Ino != stat.Ino || named.Size != stat.Size || after.Size != stat.Size {
		return false
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false
	}
	h.Reset()
	_, err = io.Copy(h, io.LimitReader(f, 16<<20))
	return err == nil && hex.EncodeToString(h.Sum(nil)) == digest
}

var macPackagePrefixes = [...]string{"/opt/homebrew", "/usr/local"}
var machineFormulaNames = [...]string{brew.MachineFormula, brew.LegacyMachineFormula}

type homebrewMachinePackage struct {
	prefix string
	name   string
}

func uninstallMacPackage(deps Deps) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return removeMacPackage(deps, executable, macPackagePrefixes[:], packageObservers{noSystemHQ: noSystemHQ, grantAbsent: checkPackageLaunchGrant, job: readMachineUserJob, processes: darwinCustodyPIDs})
}

func removeMacPackage(deps Deps, executable string, prefixes []string, observe packageObservers) error {
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
	pkg, err := activeMachinePackage(executable, prefixes)
	if err != nil {
		return err
	}
	prefix := pkg.prefix
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
	if err := observe.requireHQAbsent(); err != nil {
		return err
	}
	if err := verifyHomebrewRemovalPrefix(prefix, caller.RegisteredHome); err != nil {
		return err
	}
	if err := stopPackageServices(deps, prefix, caller, observe); err != nil {
		return err
	}
	if err := observe.requireHQAbsent(); err != nil {
		return err
	}
	if err := uninstallHomebrewFormula(prefix, pkg.name, caller.RegisteredHome); err != nil {
		return err
	}
	for _, path := range []string{"bin/managed-machine", "bin/agent-machine", "bin/agent-bot-keyd", "opt/managed-machine", "opt/agent-bot-machine"} {
		if _, err := os.Lstat(filepath.Join(prefix, path)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("Homebrew did not remove the Machine package links")
		}
	}
	for _, name := range machineFormulaNames {
		kegs, err := os.ReadDir(filepath.Join(prefix, "Cellar", name))
		if !errors.Is(err, os.ErrNotExist) && (err != nil || len(kegs) != 0) {
			return errors.New("Homebrew retained Machine kegs; inspect them before removing anything else")
		}
	}
	return lock.Close()
}

func activeMachinePackage(executable string, prefixes []string) (homebrewMachinePackage, error) {
	var selected homebrewMachinePackage
	for _, prefix := range prefixes {
		name, keg, err := machinePackageOpt(prefix)
		if err != nil {
			return homebrewMachinePackage{}, err
		}
		if keg == "" {
			continue
		}
		entries, err := os.ReadDir(filepath.Dir(keg))
		if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(keg) {
			return homebrewMachinePackage{}, errors.New("the Machine Cellar contains more than the active keg or cannot be inspected; reconcile old versions with Homebrew and retry")
		}
		if err := verifyOtherMachineRack(prefix, name, filepath.Dir(keg)); err != nil {
			return homebrewMachinePackage{}, err
		}
		for _, name := range []string{"managed-machine", "agent-machine", "agent-bot-keyd"} {
			link, err := os.Stat(filepath.Join(prefix, "bin", name))
			targetPath := filepath.Join(keg, "bin", name)
			if name == "agent-machine" {
				alias, err := os.Readlink(targetPath)
				if err != nil || alias != "managed-machine" {
					return homebrewMachinePackage{}, errors.New("cannot verify the Machine command alias")
				}
				targetPath = filepath.Join(keg, "bin", "managed-machine")
			}
			target, targetErr := os.Lstat(targetPath)
			if err != nil || targetErr != nil || !target.Mode().IsRegular() || !os.SameFile(link, target) {
				return homebrewMachinePackage{}, errors.New("cannot verify the active Homebrew Machine package links")
			}
		}
		running, err := os.Stat(executable)
		core, coreErr := os.Lstat(filepath.Join(keg, "bin", "managed-machine"))
		if err != nil || coreErr != nil || !core.Mode().IsRegular() || !os.SameFile(running, core) || selected.prefix != "" {
			return homebrewMachinePackage{}, errors.New("run uninstall with the active Homebrew Machine executable; a staged, custom or second installation must be reconciled separately")
		}
		receipt := filepath.Join(keg, "INSTALL_RECEIPT.json")
		info, err := os.Lstat(receipt)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return homebrewMachinePackage{}, errors.New("cannot verify the Machine Homebrew receipt")
		}
		f, err := os.Open(receipt)
		if err != nil {
			return homebrewMachinePackage{}, err
		}
		var tab struct{ Source struct{ Tap string } }
		dec := json.NewDecoder(io.LimitReader(f, 1<<20))
		err = dec.Decode(&tab)
		extra := dec.Decode(new(any))
		f.Close()
		if err != nil || extra != io.EOF || tab.Source.Tap != machineTap {
			return homebrewMachinePackage{}, errors.New("Homebrew receipt does not identify the Machine tap")
		}
		selected = homebrewMachinePackage{prefix: prefix, name: name}
	}
	if selected.prefix == "" {
		return homebrewMachinePackage{}, errors.New("no verified Homebrew installation; for a manually installed binary, uninstall its user services first and remove only the reviewed binary from its original install prefix")
	}
	return selected, nil
}

func machinePackageOpt(prefix string) (name, keg string, err error) {
	for _, candidate := range machineFormulaNames {
		opt := filepath.Join(prefix, "opt", candidate)
		if _, err := os.Lstat(opt); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return "", "", err
		}
		resolved, err := filepath.EvalSymlinks(opt)
		if err != nil {
			return "", "", errors.New("cannot verify the active Homebrew Machine keg")
		}
		// Homebrew keeps the old opt link pointing to the renamed keg.
		if name == brew.MachineFormula && candidate == brew.LegacyMachineFormula && resolved == keg {
			continue
		}
		if keg != "" || filepath.Dir(resolved) != filepath.Join(prefix, "Cellar", candidate) {
			return "", "", errors.New("cannot verify one active Homebrew Machine keg")
		}
		name, keg = candidate, resolved
	}
	return name, keg, nil
}

func verifyOtherMachineRack(prefix, name, activeRack string) error {
	other := brew.LegacyMachineFormula
	if name == other {
		other = brew.MachineFormula
	}
	rack := filepath.Join(prefix, "Cellar", other)
	info, err := os.Lstat(rack)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil && info.IsDir() {
		if entries, err := os.ReadDir(rack); err == nil && len(entries) == 0 {
			return nil
		}
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 && other == brew.LegacyMachineFormula {
		if resolved, err := filepath.EvalSymlinks(rack); err == nil && resolved == activeRack {
			return nil
		}
	}
	return errors.New("another Machine Homebrew rack exists or cannot be inspected; reconcile it with Homebrew before uninstalling")
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

func (observe packageObservers) legacyMacSocketUnlink(fd int, path string, uid int, original unix.Stat_t) error {
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
	return unlinkQuiescentSocket(fd, path, uid, original, observe.processes)
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
	quiet, err := packageProcessesStopped(uid, processes)
	if err != nil {
		return err
	}
	if !quiet {
		return errors.New("another Machine or keyd process still exists; wait for it to stop and retry")
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
	if dir == filepath.Join(prefix, "bin") {
		return true
	}
	for _, name := range machineFormulaNames {
		if dir == filepath.Join(prefix, "opt", name, "bin") {
			return true
		}
	}
	return isPackageKegBin(prefix, dir)
}

func isPackageKegBin(prefix, dir string) bool {
	version := filepath.Dir(dir)
	rack := filepath.Dir(version)
	return filepath.Base(dir) == "bin" && filepath.Dir(rack) == filepath.Join(prefix, "Cellar") &&
		slices.Contains(machineFormulaNames[:], filepath.Base(rack)) && homebrewKegVersion.MatchString(filepath.Base(version))
}

type packageObservers struct {
	noSystemHQ  func() error
	grantAbsent func() error
	job         func(int, string, string) ([]byte, bool, error)
	processes   func(int) ([]byte, error)
}

func (observe packageObservers) requireHQAbsent() error {
	if err := observe.grantAbsent(); err != nil {
		return err
	}
	return observe.noSystemHQ()
}

type packageServiceSnapshot struct {
	retainedKeyd bool
	plists       []packageLeaf
	pids         []int
}

func inspectPackageServices(prefix string, caller Caller, readJob func(int, string, string) ([]byte, bool, error)) (*packageServiceSnapshot, error) {
	return inspectUserServices(caller, readJob, true, false, func(program string, keyd, fromPlist bool) bool {
		return isPackageProgram(prefix, program, keyd)
	})
}

// Both products use the same keyd label and may select the same binary and
// arguments. Only Machine's exact plist establishes who installed that job.
func inspectServiceLifecycle(caller Caller, root, executable, verb string, readJob func(int, string, string) ([]byte, bool, error), priorKeydPath, priorKeydSHA string) (serviceUnitReview, error) {
	if filepath.Clean(root) != filepath.Clean(caller.RegisteredHome) || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return serviceUnitReview{}, errors.New("cannot identify the Machine executable or registered service home")
	}
	keyd, err := KeydBinary(executable)
	if err != nil {
		return serviceUnitReview{}, err
	}
	_, err = os.Stat(keyd)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return serviceUnitReview{}, err
	}
	bundled := err == nil
	removing := verb == "stop" || verb == "uninstall"
	// Machine-only startup does not operate on keyd. During teardown a
	// previously installed Machine keyd still needs to be accounted for.
	includeKeyd := bundled || removing
	var priorMachine string
	snapshot, err := inspectUserServices(caller, readJob, includeKeyd, removing && !bundled, func(program string, isKeyd, fromPlist bool) bool {
		// A manually installed executable may have moved during an upgrade.
		// Recover the old executable and its sibling only from Machine's exact
		// registered LaunchAgent, not from the shared keyd label or live argv.
		if !isKeyd && fromPlist && filepath.IsAbs(program) && filepath.Clean(program) == program &&
			(filepath.Base(program) == "managed-machine" || filepath.Base(program) == "agent-machine") {
			priorMachine = program
		}
		if priorMachine != "" {
			if !isKeyd && program == priorMachine {
				return true
			}
			priorKeyd, err := KeydBinary(priorMachine)
			if isKeyd && err == nil && program == priorKeyd {
				return true
			}
		}
		if isKeyd && program == keyd || !isKeyd && program == executable {
			return true
		}
		if isKeyd && verb == "start" && priorKeydSHA != "" && program == priorKeydPath &&
			approvedPriorKeyd(program, keyd, priorKeydSHA, caller.UID) {
			return true
		}
		for _, prefix := range macPackagePrefixes {
			if isPackageProgram(prefix, executable, false) && isPackageProgram(prefix, program, isKeyd) {
				return true
			}
		}
		return false
	})
	if err != nil {
		return serviceUnitReview{}, err
	}
	return serviceUnitReview{retainKeyd: snapshot.retainedKeyd, remove: func() error {
		for _, leaf := range snapshot.plists {
			if err := leaf.removePlist(); err != nil {
				return err
			}
		}
		return nil
	}}, nil
}

func inspectUserServices(caller Caller, readJob func(int, string, string) ([]byte, bool, error), includeKeyd, allowIndependentKeyd bool, accept func(string, bool, bool) bool) (*packageServiceSnapshot, error) {
	var snapshot packageServiceSnapshot
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
		if keyd && !includeKeyd {
			continue
		}
		path := filepath.Join(agents, label+".plist")
		leaf := packageLeaf{path: path}
		var recordedProgram string
		var independent bool
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
				Keys    []string `xml:"dict>key"`
				Strings []string `xml:"dict>string"`
				Arrays  []struct {
					Args []string `xml:"string"`
				} `xml:"dict>array"`
			}
			if xml.Unmarshal(data, &plist) != nil || len(plist.Arrays) == 0 {
				return nil, errors.New("preserving an unrecognized Machine LaunchAgent")
			}
			var program string
			for _, array := range plist.Arrays {
				args := array.Args
				valid := keyd && len(args) == 4 && args[1] == "serve" && args[2] == "--state-dir" && args[3] == state ||
					!keyd && len(args) == 3 && args[1] == "daemon" && args[2] == "run"
				if valid {
					if program != "" {
						return nil, errors.New("preserving an unrecognized Machine LaunchAgent")
					}
					program = args[0]
				}
			}
			if program == "" {
				return nil, errors.New("preserving an unrecognized Machine LaunchAgent")
			}
			var managed bool
			if keyd {
				// Installation and removal recognize the same exact Machine releases.
				managed = machineKeydRegistration(data, state)
			} else {
				managed = machineAgentRegistration(string(data), caller.RegisteredHome, program)
			}
			// Identity publishes its own bin/label registration after its plist.
			// Only a Machine-only teardown can leave that separate service alone.
			if keyd && allowIndependentKeyd && !managed &&
				len(plist.Keys) >= 2 && plist.Keys[0] == "Label" && plist.Keys[1] == "ProgramArguments" &&
				len(plist.Strings) == 1 && plist.Strings[0] == label &&
				slices.Equal(plist.Arrays[0].Args, []string{program, "serve", "--state-dir", state}) &&
				independentKeydRecorded(state, program, caller.UID) {
				snapshot.retainedKeyd = true
				independent = true
			} else if !managed || !accept(program, keyd, true) {
				return nil, errors.New("preserving a customized or unrelated Machine LaunchAgent")
			}
			recordedProgram = program
			leaf.info, leaf.body = info, data
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if !independent {
			snapshot.plists = append(snapshot.plists, leaf)
		}
		for _, domain := range []string{"gui", "user"} {
			job, loaded, err := readJob(caller.UID, domain, label)
			if err != nil {
				return nil, err
			}
			if !loaded {
				continue
			}
			var source, program string
			var pid int
			var args []string
			if keyd && leaf.info == nil {
				return nil, errors.New("preserving a loaded keyd without its Machine LaunchAgent file; verify it with its owning service manager")
			}
			argsSeen := false
			inArgs := false
			for _, raw := range strings.Split(string(job), "\n") {
				if inArgs {
					if raw == "\t}" {
						inArgs = false
					} else {
						value, ok := strings.CutPrefix(raw, "\t\t")
						if !ok {
							return nil, errors.New("cannot verify the loaded Machine service arguments")
						}
						args = append(args, value)
					}
					continue
				}
				line, top := strings.CutPrefix(raw, "\t")
				if !top || strings.HasPrefix(line, "\t") {
					continue
				}
				switch {
				case strings.HasPrefix(line, "pid = "):
					rawPID := strings.TrimPrefix(line, "pid = ")
					n, err := strconv.Atoi(rawPID)
					if pid != 0 || err != nil || n <= 0 || strconv.Itoa(n) != rawPID {
						return nil, errors.New("cannot verify the Machine service process ID")
					}
					pid = n
				case line == "arguments = {":
					if argsSeen {
						return nil, errors.New("cannot verify multiple Machine argument lists")
					}
					argsSeen = true
					inArgs = true
				case strings.HasPrefix(line, "path = "):
					if source != "" {
						return nil, errors.New("cannot verify multiple Machine service paths")
					}
					source = strings.TrimPrefix(line, "path = ")
				case strings.HasPrefix(line, "program = "):
					if program != "" {
						return nil, errors.New("cannot verify multiple Machine service programs")
					}
					program = strings.TrimPrefix(line, "program = ")
				}
			}
			if inArgs || source != path || len(args) == 0 || args[0] != program || (!independent && !accept(program, keyd, false)) ||
				keyd && program != recordedProgram {
				return nil, errors.New("preserving an unverified loaded Machine service")
			}
			want := []string{"daemon", "run"}
			if keyd {
				want = []string{"serve", "--state-dir", state}
			}
			if pid > 0 && !slices.Contains(snapshot.pids, pid) {
				snapshot.pids = append(snapshot.pids, pid)
			}
			if !slices.Equal(args[1:], want) {
				return nil, errors.New("preserving a loaded Machine service with unrelated arguments")
			}
		}
	}
	return &snapshot, nil
}

// Read only Identity's installation metadata, never its custody data.
func independentKeydRecorded(state, program string, uid int) bool {
	if !filepath.IsAbs(program) || filepath.Clean(program) != program {
		return false
	}
	file, err := os.OpenFile(filepath.Join(state, "keyd", "keyd.json"), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || int(info.Sys().(*syscall.Stat_t).Uid) != uid {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	var record struct {
		Bin   string
		Label *string
	}
	return err == nil && len(data) <= 64<<10 && json.Unmarshal(data, &record) == nil &&
		record.Bin == program && (record.Label == nil || *record.Label == darwinKeydServiceLabel)
}

type packageLeaf struct {
	path string
	info os.FileInfo
	body []byte
}

// Snapshot both unit files and all three endpoint identities before bootout.
// launchd may unlink an endpoint itself. A replacement, including a new file
// in a previously absent slot, never acquires the old file's removal authority.
func stopPackageServices(deps Deps, prefix string, caller Caller, observe packageObservers) error {
	if deps.Deactivate == nil {
		return errors.New("missing Machine service manager")
	}
	snapshot, err := inspectPackageServices(prefix, caller, observe.job)
	if err != nil {
		return err
	}
	leaves := snapshot.plists
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
	if err := observe.waitForStop(caller.UID, snapshot.pids, 3*time.Second); err != nil {
		return err
	}
	for i, leaf := range leaves {
		if i < 2 {
			if err := leaf.removePlist(); err != nil {
				return err
			}
			continue
		}
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
		if err := removeStoppedPackageSocket(leaf, caller.UID, observe.legacyMacSocketUnlink); err != nil {
			return err
		}
	}
	return nil
}

func (leaf packageLeaf) removePlist() error {
	current, err := os.Lstat(leaf.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !leaf.unchanged(current) {
		return errors.New("preserving a Machine LaunchAgent that changed during unload")
	}
	body, err := os.ReadFile(leaf.path)
	if err != nil || !bytes.Equal(body, leaf.body) {
		return errors.New("preserving a Machine LaunchAgent changed during unload")
	}
	if err := os.Remove(leaf.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// A successful bootout can precede both deregistration and process exit.
func (observe packageObservers) waitForStop(uid int, pids []int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		pending := ""
		for _, label := range []string{darwinServiceLabel, darwinKeydServiceLabel} {
			for _, domain := range []string{"gui", "user"} {
				_, loaded, err := observe.job(uid, domain, label)
				if err != nil {
					return err
				}
				if loaded && pending == "" {
					pending = label + " remains registered in the " + domain + " launchd domain"
				}
			}
		}
		// Signal zero observes the original process. A reused PID also keeps removal pending.
		for _, pid := range pids {
			switch err := unix.Kill(pid, 0); {
			case err == nil:
				if pending == "" {
					pending = "a process from the original Machine or keyd registration has not exited"
				}
			case !errors.Is(err, unix.ESRCH):
				return errors.New("cannot establish that the original Machine service process exited")
			}
		}
		if pending == "" {
			// On retry, launchd may no longer report a PID. Check the same
			// fixed owner and executables even if there are no socket files.
			quiet, err := packageProcessesStopped(uid, observe.processes)
			if err != nil {
				return err
			}
			if quiet {
				return nil
			}
			pending = "another Machine or keyd process is running under the package owner"
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%s; wait for shutdown or stop the foreground service and retry uninstall", pending)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func packageProcessesStopped(uid int, processes func(int) ([]byte, error)) (bool, error) {
	pids, err := processes(uid)
	if err != nil {
		return false, errors.New("could not establish that Machine and keyd have stopped")
	}
	for _, pid := range strings.Fields(string(pids)) {
		if pid != strconv.Itoa(os.Getpid()) {
			return false, nil
		}
	}
	return true, nil
}

func (l packageLeaf) unchanged(current os.FileInfo) bool {
	if l.info == nil || !os.SameFile(l.info, current) || l.info.Mode() != current.Mode() {
		return false
	}
	a, b := l.info.Sys().(*syscall.Stat_t), current.Sys().(*syscall.Stat_t)
	return a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Birthtimespec == b.Birthtimespec && a.Gen == b.Gen
}
