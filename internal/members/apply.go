package members

import (
	"fmt"
	"path"
	"runtime"
	"strconv"
	"strings"
)

// ReceiptsDir holds one receipt per applied plan. It belongs to root: a
// receipt is also the record that an approval was used, so no other account
// may be able to remove it.
const ReceiptsDir = "/var/lib/managed-machine/members/receipts"

// DarwinReceiptsDir is ReceiptsDir on macOS, which has no /var/lib.
const DarwinReceiptsDir = "/var/db/managed-machine/members/receipts"

func receiptsDir() string {
	if runtime.GOOS == "darwin" {
		return DarwinReceiptsDir
	}
	return ReceiptsDir
}

// Root is everything an apply changes, and the two things only root can
// read. The real one is OSRoot; tests inject a recording one.
type Root interface {
	// PasswordField returns an account's field in the shadow file.
	PasswordField(account string) (string, bool, error)
	// ReadSudoers returns the launch rule that is installed now.
	ReadSudoers() (string, bool, error)
	// CreateAccount creates a locked account with a private group, home
	// HomeBase/<name> at 0700 and shell NoLoginShell.
	CreateAccount(name string) error
	// CreateHQAccount creates the locked service account HQ runs in, with a
	// private group, home HQHomeBase/<name> at 0700 and shell NoLoginShell.
	CreateHQAccount(name string) error
	// SetMode sets the mode of an existing directory.
	SetMode(p string, mode uint32) error
	// EnsureDir creates p if it is missing and sets its owner, group and mode.
	EnsureDir(p, owner, group string, mode uint32) error
	// RemoveDir removes a directory and what it holds.
	RemoveDir(p string) error
	// WriteFile replaces p, owned by root. When validate is set the content
	// is checked as a sudoers file before it is moved into place.
	WriteFile(p string, mode uint32, content string, validate bool) error
	// Claim records that planID is being applied. It reports false when a
	// receipt for planID already exists.
	Claim(planID string, receipt []byte) (bool, error)
	// Finish replaces the receipt Claim wrote.
	Finish(planID string, receipt []byte) error
}

// locked reports whether a shadow password field allows no password login:
// it starts with ! or *. An empty field is an account with no password at
// all, which anyone can enter, and is not locked.
func locked(field string) bool {
	return strings.HasPrefix(field, "!") || strings.HasPrefix(field, "*")
}

// Precheck is what a plan cannot see without privilege: that an existing
// member account has no password, and that a launch rule already installed
// is one this tool wrote. It changes nothing.
func Precheck(p Plan, r Root) error {
	for _, s := range p.Steps {
		what := "member"
		switch {
		case s.Action == ActionCreate:
			continue
		case s.Kind == KindAccount:
		case s.Kind == KindHQAccount && s.Mode != "":
			// A dedicated HQ account. One that is shared carries no mode
			// and is left alone: it is a person's account and has a password.
			what = "HQ"
		default:
			continue
		}
		field, ok, err := r.PasswordField(s.Target)
		if err != nil {
			return err
		}
		if !ok {
			return refuse(RefusedAccount, "%s account %s has no shadow entry, so its password cannot be checked", what, s.Target)
		}
		if !locked(field) {
			return refuse(RefusedAccount, "%s account %s has a password or an empty one; a dedicated account is locked", what, s.Target)
		}
	}
	if p.Dir == DarwinDir {
		// A macOS plan installs no launch rule.
		return nil
	}
	have, ok, err := r.ReadSudoers()
	if err != nil {
		return err
	}
	if ok && !strings.HasPrefix(have, header) {
		return refuse(RefusedPath, "%s exists and was not written by this tool", SudoersPath)
	}
	return nil
}

// StepError is the step an apply stopped at.
type StepError struct {
	Step Step
	Err  error
}

func (e *StepError) Error() string {
	return fmt.Sprintf("%s %s %s: %v", e.Step.Action, e.Step.Kind, e.Step.Target, e.Err)
}

func (e *StepError) Unwrap() error { return e.Err }

// Apply carries out the steps of p in order and stops at the first failure.
// Accounts come first and the launch rule last, so the rule never names an
// account that does not exist. It does not check an approval: the command
// does that before it calls Apply.
func Apply(p Plan, h Host, r Root) error {
	for _, s := range p.Steps {
		if s.Action == ActionNone {
			continue
		}
		if err := applyStep(s, h, r); err != nil {
			return &StepError{Step: s, Err: err}
		}
	}
	return nil
}

func applyStep(s Step, h Host, r Root) error {
	mode, err := strconv.ParseUint(s.Mode, 8, 32)
	if s.Mode != "" && err != nil {
		return fmt.Errorf("mode %q is not octal", s.Mode)
	}
	switch s.Kind {
	case KindAccount, KindHQAccount:
		switch s.Action {
		case ActionCreate:
			create := r.CreateAccount
			if s.Kind == KindHQAccount {
				create = r.CreateHQAccount
			}
			if err := create(s.Target); err != nil {
				return err
			}
			field, ok, err := r.PasswordField(s.Target)
			if err != nil {
				return err
			}
			if !ok || !locked(field) {
				return fmt.Errorf("the new account is not locked")
			}
			return nil
		case ActionRepair:
			a, ok, err := h.Account(s.Target)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("the account is gone")
			}
			return r.SetMode(a.Home, 0o700)
		}
	case KindDirectory:
		switch s.Action {
		case ActionCreate, ActionRepair:
			return r.EnsureDir(s.Target, s.Owner, s.Group, uint32(mode))
		case ActionRemove:
			return r.RemoveDir(s.Target)
		}
	case KindFile:
		switch s.Action {
		case ActionCreate, ActionRepair, ActionWrite:
			return r.WriteFile(s.Target, uint32(mode), s.Content, s.Target == SudoersPath)
		}
	}
	return fmt.Errorf("no way to %s a %s", s.Action, s.Kind)
}

// Receipt is the record of one apply. It holds no secret.
type Receipt struct {
	PlanID     string   `json:"plan_id"`
	PlanDigest string   `json:"plan_digest"`
	Owner      string   `json:"owner"`
	HQAccount  string   `json:"hq_account"`
	Dir        string   `json:"dir"`
	Members    []string `json:"members"`
	Changes    int      `json:"changes"`
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at,omitempty"`
	// Result is started, applied or failed.
	Result string `json:"result"`
	// FailedAt names the step a failed apply stopped at.
	FailedAt string `json:"failed_at,omitempty"`
}

// ReceiptPath is the receipt of one plan.
func ReceiptPath(planID string) string {
	return path.Join(receiptsDir(), planID+".json")
}
