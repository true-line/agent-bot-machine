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
