package members

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
)

// Every ancestor above the product tree must be protected. The two
// root-managed product directories also have exact access requirements.
func checkBrokerParent(h Host, parent string) error {
	if err := trustedPath(h, filepath.Dir(launchRuntimeDir), true); err != nil {
		return err
	}
	dirs := []string{launchRuntimeDir}
	if parent == DarwinBrokerDir {
		dirs = append(dirs, DarwinBrokerDir)
	} else if parent != launchRuntimeDir {
		return refuse(RefusedPath, "unexpected Darwin broker parent")
	}
	for _, dir := range dirs {
		e, ok, err := h.Lstat(dir)
		if err != nil {
			return err
		}
		if !ok || !e.Dir || e.Owner != "root" || e.Group != "wheel" || e.Mode != 0755 {
			return refuse(RefusedPath, "%s must be an existing root:wheel 0755 directory", dir)
		}
	}
	return nil
}

func brokerDirectoryStep(h Host, dir, owner, group string, mode uint32) (Step, error) {
	step := Step{Kind: KindDirectory, Target: dir, Owner: owner, Group: group, Mode: fmt.Sprintf("%04o", mode), Action: ActionCreate}
	e, exists, err := h.Lstat(dir)
	if err != nil || !exists {
		return step, err
	}
	if !e.Dir || e.Owner != owner || e.Group != group || e.Mode != mode {
		return Step{}, refuse(RefusedPath, "existing broker directory %s must be %s:%s %s", dir, owner, group, step.Mode)
	}
	step.Action = ActionNone
	return step, nil
}

// Only explicitly named broker directories are added. An existing directory
// with different access is refused. Omitted directories are left alone.
func appendDarwinBrokerDirectories(p *Plan, h Host) error {
	if err := checkBrokerParent(h, launchRuntimeDir); err != nil {
		return err
	}
	checker, ok := h.(interface{ CheckDarwinACLs([]string) error })
	if !ok {
		return errors.New("Darwin broker directories require host ACL inspection")
	}
	paths := pathAncestry(launchRuntimeDir)
	base, err := brokerDirectoryStep(h, DarwinBrokerDir, "root", "wheel", 0755)
	if err != nil {
		return err
	}
	dirs := []Step{base}
	for _, account := range p.Members {
		child, err := brokerDirectoryStep(h, path.Join(DarwinBrokerDir, account), DarwinHQAccount, account, 02750)
		if err != nil {
			return err
		}
		dirs = append(dirs, child)
	}
	for _, dir := range dirs {
		if dir.Action == ActionNone {
			paths = append(paths, dir.Target)
		}
	}
	if err := checker.CheckDarwinACLs(paths); err != nil {
		return err
	}
	p.Steps = append(p.Steps, dirs...)
	return nil
}

func (OSHost) CheckDarwinACLs(paths []string) error { return checkDarwinACLs(paths) }
