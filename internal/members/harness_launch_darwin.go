package members

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

//go:embed darwin/harness-egress.sb
var harnessProfile []byte

func harnessSHA(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func managerBytes() ([]byte, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > maxReleaseBytes {
		return nil, errors.New("invalid running Machine executable")
	}
	return io.ReadAll(io.LimitReader(f, maxReleaseBytes+1))
}

func planHarnessRequest(file, priorID string, h Host) (*HarnessPolicyRecord, error) {
	if priorID != "" {
		f, live, err := readInstalledHarness()
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return retirementRequest(live, priorID)
	}
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("expected a regular harness adapter list")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil {
		return nil, err
	}
	adapters, err := harnessInput(raw)
	if err != nil {
		return nil, err
	}
	me, err := managerBytes()
	if err != nil {
		return nil, err
	}
	hq, ok, err := h.Account(DarwinHQAccount)
	if err != nil {
		return nil, fmt.Errorf("resolve dedicated HQ account: %w", err)
	}
	if !ok {
		return nil, errors.New("dedicated HQ account must already exist")
	}
	for i, a := range adapters {
		if !accountName.MatchString(a.Account) {
			return nil, errors.New("invalid harness account")
		}
		record, ok, e := h.Account(a.Account)
		if e != nil {
			return nil, fmt.Errorf("resolve reviewed harness account: %w", e)
		}
		if !ok {
			return nil, errors.New("reviewed harness account must already exist")
		}
		adapters[i].UID = record.UID
	}
	return &HarnessPolicyRecord{
		Schema: "agent-bot-harness-launch/v1", Action: "install", HQUID: hq.UID,
		Launcher: HarnessArtifact{Path: HarnessLauncher, SHA256: harnessSHA(me)},
		Sandbox:  HarnessArtifact{Path: HarnessSandbox, SHA256: harnessSHA(harnessProfile)},
		Adapters: adapters,
	}, nil
}

func retirementRequest(live installedHarness, priorID string) (*HarnessPolicyRecord, error) {
	if live.ID != priorID {
		return nil, errors.New("retirement needs the current installed plan ID")
	}
	p := live.Policy
	p.Action = "retire"
	p.InstalledID = live.ID
	p.InstalledDigest = live.Digest
	return &p, nil
}

func verifyHarnessExecutable(path, digest string) error {
	h := OSHost{}
	if e := trustedPath(h, path, false); e != nil {
		return e
	}
	if e := checkDarwinACLs(pathAncestry(path)); e != nil {
		return e
	}
	entry, ok, e := h.Lstat(path)
	if e != nil || !ok || entry.Mode&0111 != 0111 {
		return errors.New("reviewed native executable is not executable by its target account")
	}
	f, e := openPinnedFile(path, digest)
	if e != nil {
		return e
	}
	defer f.Close()
	return checkDarwinNode(f)
}

func inspectHarnessLaunch(p HarnessPolicyRecord) error {
	if p.Action == "retire" {
		f, installed, e := readInstalledHarness()
		if e != nil {
			return e
		}
		defer f.Close()
		previous := p.installation()
		want, _ := harnessJSON(previous)
		actual, _ := harnessJSON(installed.Policy)
		if installed.ID != p.InstalledID || installed.Digest != p.InstalledDigest || actual != want {
			return errors.New("the installed grant differs from the reviewed retirement")
		}
		return nil
	}
	raw, e := managerBytes()
	if e != nil {
		return e
	}
	if harnessSHA(raw) != p.Launcher.SHA256 || harnessSHA(harnessProfile) != p.Sandbox.SHA256 {
		return errors.New("launcher or policy differs from this Machine release")
	}
	for _, a := range p.Adapters {
		if e := verifyHarnessExecutable(a.Executable, a.SHA256); e != nil {
			return e
		}
	}
	return nil
}

func readInstalledHarness() (*os.File, installedHarness, error) {
	var grant installedHarness
	h := OSHost{}
	fail := func(err error) (*os.File, installedHarness, error) { return nil, installedHarness{}, err }
	if e := trustedPath(h, HarnessPolicy, false); e != nil {
		return fail(e)
	}
	if e := checkDarwinACLs(pathAncestry(HarnessPolicy)); e != nil {
		return fail(e)
	}
	f, e := os.OpenFile(HarnessPolicy, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return fail(e)
	}
	reject := func(err error) (*os.File, installedHarness, error) { f.Close(); return fail(err) }
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); e != nil {
		return reject(errors.New("harness launch policy is busy; retry after its current operation finishes"))
	}
	st, e := f.Stat()
	if e != nil {
		return reject(e)
	}
	current, e := os.Lstat(HarnessPolicy)
	if e != nil || !os.SameFile(current, st) || !st.Mode().IsRegular() || st.Mode() != 0644 {
		return reject(errors.New("changed harness launch policy"))
	}
	x := st.Sys().(*syscall.Stat_t)
	if x.Uid != 0 || x.Gid != 0 || x.Nlink != 1 {
		return reject(errors.New("invalid harness launch policy metadata"))
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(raw) > 65536 || json.Unmarshal(raw, &grant) != nil {
		return reject(errors.New("invalid installed harness grant"))
	}
	encoded, e := harnessJSON(grant)
	if e != nil || !bytes.Equal(raw, []byte(encoded)) || !ValidApproval(grant.ID, grant.Digest) || grant.Policy.Action != "install" {
		return reject(errors.New("invalid installed harness grant encoding"))
	}
	plan, e := grant.Policy.plan()
	if e != nil {
		return reject(e)
	}
	sum, e := plan.Digest()
	if e != nil || sum != grant.Digest {
		return reject(errors.New("installed harness grant differs from its installation digest"))
	}
	return f, grant, nil
}

func matchingInstalledHarness(digest string, host Host) (string, error) {
	if _, present, err := host.Lstat(HarnessPolicy); err != nil || !present {
		return "", err
	}
	f, grant, e := readInstalledHarness()
	if e != nil {
		return "", e
	}
	defer f.Close()
	if grant.Digest != digest {
		return "", fmt.Errorf("retire installed harness rule %s before proposing a replacement", grant.ID)
	}
	return grant.ID, nil
}
