//go:build windows

package members

import "errors"

// OSHost has no Windows form: member accounts are Linux only, and the
// command refuses before it reads the host.
type OSHost struct{}

var errUnsupported = errors.New("member accounts are Linux only")

func (OSHost) Account(string) (Account, bool, error) { return Account{}, false, errUnsupported }
func (OSHost) Lstat(string) (Entry, bool, error)     { return Entry{}, false, errUnsupported }
func (OSHost) ReadFile(string) (string, bool, error) { return "", false, errUnsupported }
func (OSHost) List(string) ([]string, error)         { return nil, errUnsupported }

// OSRoot has no Windows form either.
type OSRoot struct{}

func (OSRoot) PasswordField(string) (string, bool, error)     { return "", false, errUnsupported }
func (OSRoot) ReadSudoers() (string, bool, error)             { return "", false, errUnsupported }
func (OSRoot) CreateAccount(string) error                     { return errUnsupported }
func (OSRoot) CreateHQAccount(string) error                   { return errUnsupported }
func (OSRoot) SetMode(string, uint32) error                   { return errUnsupported }
func (OSRoot) EnsureDir(string, string, string, uint32) error { return errUnsupported }
func (OSRoot) RemoveDir(string) error                         { return errUnsupported }
func (OSRoot) WriteFile(string, uint32, string, bool) error   { return errUnsupported }
func (OSRoot) Claim(string, []byte) (bool, error)             { return false, errUnsupported }
func (OSRoot) Finish(string, []byte) error                    { return errUnsupported }

// AncestorEnvs has nothing to read on Windows.
func AncestorEnvs() []map[string]string { return nil }
