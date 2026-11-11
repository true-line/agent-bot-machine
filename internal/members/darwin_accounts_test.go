//go:build !windows

package members

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseDsclAttr(t *testing.T) {
	for _, c := range []struct {
		out, attr, want string
		found           bool
	}{
		{"UserShell: /usr/bin/false\n", "UserShell", "/usr/bin/false", true},
		{"RealName:\n Agent Bot HQ\n", "RealName", "Agent Bot HQ", true},
		{"GroupMembership: admin owner\n", "GroupMembership", "admin owner", true},
		{"No such key: AuthenticationAuthority\n", "AuthenticationAuthority", "", false},
		{"Password: *\n", "Password", "*", true},
	} {
		got, found := parseDsclAttr(c.out, c.attr)
		if got != c.want || found != c.found {
			t.Errorf("%q: got %q %v", c.out, got, found)
		}
	}
}

func TestDarwinIDsAndGroups(t *testing.T) {
	users := parseDsclList("_www            70\nroot           0\nowner          501\n_taken     300\nnovalue\n")
	if users["_www"] != "70" || users["owner"] != "501" || len(users) != 4 {
		t.Fatalf("users %v", users)
	}
	id, err := freeDarwinID(users, map[string]string{"g": "301"})
	if err != nil || id != 302 {
		t.Fatalf("free id %d %v", id, err)
	}
	full := map[string]string{}
	for i := darwinIDFirst; i <= darwinIDLast; i++ {
		full[string(rune('a'+i%26))+strings.Repeat("x", i)] = strings.TrimSpace(strings.Join([]string{itoa(i)}, ""))
	}
	if _, err := freeDarwinID(full, nil); err == nil {
		t.Fatal("a full id range gave an id")
	}
	for name, want := range map[string]bool{"everyone": true, "localaccounts": true, "com.apple.sharepoint.group.1": true, "staff": false, "admin": false, "_agent-bot-hq": false} {
		if darwinAutomaticGroup(name) != want {
			t.Errorf("automatic %s", name)
		}
	}
}

func itoa(i int) string {
	raw, _ := json.Marshal(i)
	return string(raw)
}

func TestDarwinPasswordField(t *testing.T) {
	old := runOutput
	t.Cleanup(func() { runOutput = old })
	records := map[string]map[string]string{
		"/Users/_agent-bot-hq": {"Password": "*", "UniqueID": "300"},
		"/Users/owner":         {"Password": "********", "UniqueID": "501", "AuthenticationAuthority": ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>"},
		"/Users/odd":           {"Password": "*", "UniqueID": "502", "AuthenticationAuthority": ";ShadowHash;"},
		"/Users/bare":          {"UniqueID": "503"},
	}
	runOutput = func(name string, args ...string) (string, error) {
		rec, ok := records[args[2]]
		if !ok {
			return "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n", errors.New("exit status 56")
		}
		if v, ok := rec[args[3]]; ok {
			return args[3] + ": " + v + "\n", nil
		}
		return "No such key: " + args[3] + "\n", nil
	}
	for account, want := range map[string]struct {
		locked, known bool
	}{"_agent-bot-hq": {true, true}, "owner": {false, true}, "odd": {false, true}, "bare": {false, true}, "ghost": {false, false}} {
		field, known, err := darwinPasswordField(account)
		if err != nil || known != want.known || locked(field) != want.locked {
			t.Errorf("%s: field %q known %v err %v", account, field, known, err)
		}
	}
}

func TestParsePsEnv(t *testing.T) {
	env := parsePsEnv("bash -c sudo mm members apply x=1 TERM=xterm CLAUDECODE=1 PATH=/usr/bin:/bin NOTE=two words CLAUDECODE=0\n")
	if env["CLAUDECODE"] != "1" || env["TERM"] != "xterm" || env["NOTE"] != "two" {
		t.Fatalf("env %v", env)
	}
	if _, ok := env["words"]; ok {
		t.Fatalf("a bare word became a variable: %v", env)
	}
}
