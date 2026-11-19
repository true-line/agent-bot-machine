package daemon

import (
	"context"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Ordinary accounts are selected explicitly. Confirm a local Directory
// Services record, the same NSS identity, and non-administrative membership.
var ordinaryHQAccount = eligibleOrdinaryHQ
var ordinaryName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func eligibleOrdinaryHQ(u *user.User) bool {
	if runtime.GOOS != "darwin" || !ordinaryName.MatchString(u.Username) || agentAccount(u.Username) || u.Username == "admin" ||
		!strings.HasPrefix(u.HomeDir, "/Users/") || filepath.Clean(u.HomeDir) != u.HomeDir || filepath.Dir(u.HomeDir) != "/Users" {
		return false
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil || uid < 501 || uint64(uid) >= 1<<31 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	read := exec.CommandContext(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+u.Username, "UniqueID")
	read.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	raw, err := read.Output()
	if err != nil || strings.TrimSpace(string(raw)) != "UniqueID: "+u.Uid {
		return false
	}
	admin, err := user.LookupGroup("admin")
	if err != nil {
		return false
	}
	groups, err := u.GroupIds()
	if err != nil || len(groups) == 0 {
		return false
	}
	for _, gid := range groups {
		if gid == admin.Gid || gid == "0" {
			return false
		}
	}
	return true
}
