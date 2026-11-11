//go:build !windows

package members

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// OSHost reads the running host. Accounts come from the system's account
// database through os/user, and the lists of who shares a group from
// /etc/passwd and /etc/group, which is where a local member account lives.
type OSHost struct {
	// Passwd and Group are the account files; empty means the system's.
	Passwd string
	Group  string
}

func (h OSHost) file(set, def string) string {
	if set != "" {
		return set
	}
	return def
}

// fields returns the colon-separated records of an account file.
func fields(path string) ([][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Split(line, ":"))
	}
	return out, sc.Err()
}

// Account implements Host.
func (h OSHost) Account(name string) (Account, bool, error) {
	u, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return Account{}, false, nil
		}
		return Account{}, false, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return Account{}, false, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return Account{}, false, err
	}
	a := Account{Name: u.Username, UID: uid, GID: gid, Group: u.Gid, Home: u.HomeDir}
	if g, err := user.LookupGroupId(u.Gid); err == nil {
		a.Group = g.Name
	}
	gids, err := u.GroupIds()
	if err != nil {
		return Account{}, false, err
	}
	for _, id := range gids {
		g, err := user.LookupGroupId(id)
		if err != nil {
			a.Groups = append(a.Groups, id)
			continue
		}
		a.Groups = append(a.Groups, g.Name)
	}
	if runtime.GOOS == "darwin" && h.Passwd == "" && h.Group == "" {
		// macOS keeps accounts in Directory Services, not in the files.
		if err := darwinSharing(&a); err != nil {
			return Account{}, false, err
		}
		return a, true, nil
	}
	sort.Strings(a.Groups)
	passwd, err := fields(h.file(h.Passwd, "/etc/passwd"))
	if err != nil {
		return Account{}, false, err
	}
	for _, f := range passwd {
		if len(f) >= 7 && f[3] == u.Gid {
			a.PrimaryUsers = append(a.PrimaryUsers, f[0])
		}
		if len(f) >= 7 && f[0] == name {
			a.Shell = f[6]
		}
	}
	groups, err := fields(h.file(h.Group, "/etc/group"))
	if err != nil {
		return Account{}, false, err
	}
	for _, f := range groups {
		if len(f) >= 4 && f[2] == u.Gid && f[3] != "" {
			a.GroupMembers = append(a.GroupMembers, strings.Split(f[3], ",")...)
		}
	}
	return a, true, nil
}

func name(id uint32, lookup func(string) (string, error)) string {
	s := strconv.FormatUint(uint64(id), 10)
	if n, err := lookup(s); err == nil {
		return n
	}
	return s
}

// Lstat implements Host. An owner or group with no name is reported by
// number, which matches no account name.
func (h OSHost) Lstat(p string) (Entry, bool, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Entry{}, false, nil
		}
		return Entry{}, false, err
	}
	e := Entry{Dir: fi.IsDir(), Regular: fi.Mode().IsRegular(), Mode: uint32(fi.Mode().Perm())}
	if fi.Mode()&fs.ModeSetuid != 0 {
		e.Mode |= 0o4000
	}
	if fi.Mode()&fs.ModeSetgid != 0 {
		e.Mode |= 0o2000
	}
	if fi.Mode()&fs.ModeSticky != 0 {
		e.Mode |= 0o1000
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		e.Owner = name(st.Uid, func(s string) (string, error) {
			u, err := user.LookupId(s)
			if err != nil {
				return "", err
			}
			return u.Username, nil
		})
		e.Group = name(st.Gid, func(s string) (string, error) {
			g, err := user.LookupGroupId(s)
			if err != nil {
				return "", err
			}
			return g.Name, nil
		})
	}
	return e, true, nil
}

// ReadFile implements Host.
func (h OSHost) ReadFile(p string) (string, bool, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	return string(raw), true, nil
}

// List implements Host.
func (h OSHost) List(p string) ([]string, error) {
	entries, err := os.ReadDir(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out, nil
}
