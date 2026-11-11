//go:build !windows

package members

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// macOS keeps accounts in Directory Services. This file reads and creates
// them through dscl, and reads the environment of the processes above an
// apply through ps, because there is no /proc. The parsing is plain Go and
// is tested on every platform; the programs run only on macOS.
const (
	dsclPath = "/usr/bin/dscl"
	psPath   = "/bin/ps"
	// Role accounts on macOS have ids below 500. This tool takes the first
	// id from 300 to 399 that no account and no group uses.
	darwinIDFirst = 300
	darwinIDLast  = 399
)

// runOutput runs a program with the fixed root environment and returns what
// it printed. Tests replace it.
var runOutput = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = rootEnv
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// parseDsclAttr reads the output of `dscl . -read <record> <attr>`. dscl
// prints "Attr: value", or "Attr:" and the value on the next line when the
// value has a space, or "No such key: Attr".
func parseDsclAttr(out, attr string) (string, bool) {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, line := range lines {
		rest, ok := strings.CutPrefix(line, attr+":")
		if !ok {
			continue
		}
		if v := strings.TrimSpace(rest); v != "" {
			return v, true
		}
		var more []string
		for _, l := range lines[i+1:] {
			if !strings.HasPrefix(l, " ") {
				break
			}
			more = append(more, strings.TrimSpace(l))
		}
		return strings.Join(more, " "), true
	}
	return "", false
}

// dsclAttr returns one attribute of one record. found is false when the
// record or the attribute does not exist.
func dsclAttr(record, attr string) (value string, found bool, err error) {
	out, err := runOutput(dsclPath, ".", "-read", record, attr)
	if err != nil {
		if strings.Contains(out, "eDSRecordNotFound") {
			return "", false, nil
		}
		return "", false, fmt.Errorf("dscl -read %s %s: %v: %s", record, attr, err, strings.TrimSpace(out))
	}
	value, found = parseDsclAttr(out, attr)
	return value, found, nil
}

// parseDsclList reads `dscl . -list <path> <attr>`: one record per line,
// the name and then the value. A record without the attribute has no value
// and is left out.
func parseDsclList(out string) map[string]string {
	records := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			records[f[0]] = f[len(f)-1]
		}
	}
	return records
}

func dsclList(path, attr string) (map[string]string, error) {
	out, err := runOutput(dsclPath, ".", "-list", path, attr)
	if err != nil {
		return nil, fmt.Errorf("dscl -list %s %s: %v: %s", path, attr, err, strings.TrimSpace(out))
	}
	return parseDsclList(out), nil
}

// darwinAutomaticGroup reports a group macOS puts every local account in.
// Being in one says nothing about who an account shares with.
func darwinAutomaticGroup(name string) bool {
	switch name {
	case "everyone", "localaccounts", "netaccounts", "_lpoperator":
		// _lpoperator nests localaccounts and netaccounts.
		return true
	}
	return strings.HasPrefix(name, "com.apple.")
}

// darwinSharing fills in who shares an account's primary group, which
// other groups it is in, and its shell.
func darwinSharing(a *Account) error {
	// A group that even the nobody account is in holds every account, by
	// name or through a nested group, whatever it is called.
	everyones := map[string]bool{}
	if nobody, err := user.Lookup("nobody"); err == nil {
		if ids, err := nobody.GroupIds(); err == nil {
			for _, id := range ids {
				if g, err := user.LookupGroupId(id); err == nil {
					everyones[g.Name] = true
				}
			}
		}
	}
	var groups []string
	for _, g := range a.Groups {
		if !darwinAutomaticGroup(g) && !everyones[g] {
			groups = append(groups, g)
		}
	}
	sort.Strings(groups)
	a.Groups = groups
	primary, err := dsclList("/Users", "PrimaryGroupID")
	if err != nil {
		return err
	}
	gid := strconv.Itoa(a.GID)
	for name, id := range primary {
		if id == gid {
			a.PrimaryUsers = append(a.PrimaryUsers, name)
		}
	}
	sort.Strings(a.PrimaryUsers)
	members, ok, err := dsclAttr("/Groups/"+a.Group, "GroupMembership")
	if err != nil {
		return err
	}
	if ok {
		a.GroupMembers = strings.Fields(members)
	}
	shell, _, err := dsclAttr("/Users/"+a.Name, "UserShell")
	if err != nil {
		return err
	}
	a.Shell = shell
	return nil
}

// darwinPasswordField returns "*" for an account nobody can log in to: its
// Password attribute is "*" and it has no AuthenticationAuthority, which is
// where macOS keeps a real password. Anything else is reported as set.
func darwinPasswordField(account string) (string, bool, error) {
	record := "/Users/" + account
	password, ok, err := dsclAttr(record, "Password")
	if err != nil {
		return "", false, err
	}
	if !ok {
		if _, exists, err := dsclAttr(record, "UniqueID"); err != nil || !exists {
			return "", false, err
		}
		return "", true, nil
	}
	_, hasAuthority, err := dsclAttr(record, "AuthenticationAuthority")
	if err != nil {
		return "", false, err
	}
	if password == "*" && !hasAuthority {
		return "*", true, nil
	}
	return "set", true, nil
}

// freeDarwinID returns the first id in the role range that neither an
// account nor a group uses.
func freeDarwinID(users, groups map[string]string) (int, error) {
	used := map[string]bool{}
	for _, id := range users {
		used[id] = true
	}
	for _, id := range groups {
		used[id] = true
	}
	for id := darwinIDFirst; id <= darwinIDLast; id++ {
		if !used[strconv.Itoa(id)] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no free account id from %d to %d", darwinIDFirst, darwinIDLast)
}

// darwinCreateHQAccount creates the HQ role account: a private group of the
// same name, no password, no login shell, hidden from the login window, and
// a home only it can enter.
func darwinCreateHQAccount(name string) error {
	users, err := dsclList("/Users", "UniqueID")
	if err != nil {
		return err
	}
	groups, err := dsclList("/Groups", "PrimaryGroupID")
	if err != nil {
		return err
	}
	if _, ok := groups[name]; ok {
		return fmt.Errorf("a group named %s already exists", name)
	}
	id, err := freeDarwinID(users, groups)
	if err != nil {
		return err
	}
	num := strconv.Itoa(id)
	home := HQHome(PlatformDarwin, name)
	group, account := "/Groups/"+name, "/Users/"+name
	for _, args := range [][]string{
		{group},
		{group, "PrimaryGroupID", num},
		{group, "Password", "*"},
		{group, "RealName", "Agent Bot HQ"},
		{account},
		{account, "UniqueID", num},
		{account, "PrimaryGroupID", num},
		{account, "UserShell", DarwinNoLoginShell},
		{account, "NFSHomeDirectory", home},
		{account, "RealName", "Agent Bot HQ"},
		{account, "Password", "*"},
		{account, "IsHidden", "1"},
	} {
		if err := runProgram(dsclPath, append([]string{".", "-create"}, args...)...); err != nil {
			return err
		}
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	if err := os.Lchown(home, id, id); err != nil {
		return err
	}
	return os.Chmod(home, 0o700)
}

var envToken = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// parsePsEnv reads the output of `ps -E -ww -o command=`: the command line
// and then the environment, separated by spaces. Every word of the form
// NAME=value is taken as a variable; the first one of a name wins. A value
// with a space is cut short, which does not matter here: the markers of an
// agent session are looked up by name and by short values.
func parsePsEnv(out string) map[string]string {
	env := map[string]string{}
	for _, word := range strings.Fields(out) {
		if !envToken.MatchString(word) {
			continue
		}
		k, v, _ := strings.Cut(word, "=")
		if _, ok := env[k]; !ok {
			env[k] = v
		}
	}
	return env
}

// darwinAncestorEnvs is AncestorEnvs on macOS, as far as ps shows them.
func darwinAncestorEnvs() []map[string]string {
	var out []map[string]string
	pid := os.Getppid()
	for hops := 0; pid > 1 && hops < 64; hops++ {
		p := strconv.Itoa(pid)
		if raw, err := runOutput(psPath, "-E", "-ww", "-o", "command=", "-p", p); err == nil {
			out = append(out, parsePsEnv(raw))
		}
		raw, err := runOutput(psPath, "-o", "ppid=", "-p", p)
		if err != nil {
			break
		}
		next, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || next == pid {
			break
		}
		pid = next
	}
	return out
}
