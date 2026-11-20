//go:build darwin || linux

package daemon

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/qwts/managed-machine/internal/plan"
	"github.com/qwts/managed-machine/internal/statedir"
	"golang.org/x/sys/unix"
)

const (
	planPageSize      = 64
	maxPlanEntries    = 8192
	maxSavedPlanBytes = 256 << 10
)

// Walk from the service owner's home using pinned directory descriptors.
// File names come exclusively from fixed components and validated plan IDs.
func openMembersPlans(home string) (*os.File, error) {
	if !filepath.IsAbs(home) {
		return nil, errMembersPlans
	}
	state, err := statedir.Path(runtime.GOOS, func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(home, filepath.Join(state, "members", "plans"))
	if err != nil {
		return nil, err
	}
	return openOwnerSubdir(home, rel)
}

// openOwnerSubdir pins each component beneath the registered service home.
// Every directory must belong to the service UID and exclude foreign writers.
func openOwnerSubdir(home, rel string) (*os.File, error) {
	if !filepath.IsAbs(home) || !filepath.IsLocal(rel) {
		return nil, errMembersPlans
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_DIRECTORY
	fd, err := unix.Open(home, flags, 0)
	if err != nil {
		return nil, err
	}
	if !trustedOwnerDir(fd) {
		unix.Close(fd)
		return nil, errMembersPlans
	}
	for _, component := range strings.Split(rel, string(os.PathSeparator)) {
		next, err := unix.Openat(fd, component, flags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
		if !trustedOwnerDir(fd) {
			unix.Close(fd)
			return nil, errMembersPlans
		}
	}
	return os.NewFile(uintptr(fd), filepath.Join(home, rel)), nil
}

func trustedOwnerDir(fd int) bool {
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil && int(stat.Uid) == os.Geteuid() && stat.Mode&0o022 == 0 && safeMembersPlanACL(fd, true)
}

type planPage struct {
	IDs  []string `json:"plan_ids"`
	Next string   `json:"next_after,omitempty"`
}

func readMembersPlans(home, option, id string) ([]byte, error) {
	if (option != "list" && option != "get") || ((id != "" || option == "get") && !plan.ValidID(id)) {
		return nil, errMembersPlans
	}
	dir, err := openMembersPlans(home)
	if errors.Is(err, os.ErrNotExist) && option == "list" {
		return json.Marshal(planPage{IDs: []string{}})
	}
	if err != nil {
		return nil, errMembersPlans
	}
	defer dir.Close()
	if option == "list" {
		entries, err := dir.Readdirnames(maxPlanEntries + 1)
		if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > maxPlanEntries {
			return nil, errMembersPlans
		}
		page := planPage{IDs: []string{}}
		for _, name := range entries {
			savedID, isJSON := strings.CutSuffix(name, ".json")
			if !isJSON || !plan.ValidID(savedID) || savedID <= id {
				continue
			}
			f, err := openSavedPlan(dir, name)
			if err == nil {
				f.Close()
				page.IDs = append(page.IDs, savedID)
			}
		}
		sort.Strings(page.IDs)
		if len(page.IDs) > planPageSize {
			page.IDs = page.IDs[:planPageSize]
			page.Next = page.IDs[planPageSize-1]
		}
		return json.Marshal(page)
	}
	raw, err := readSavedPlanFile(dir, id)
	if err != nil {
		return nil, err
	}
	return membersPlanBody(id, raw)
}

func readSavedPlanFile(dir *os.File, id string) ([]byte, error) {
	if !plan.ValidID(id) {
		return nil, errMembersPlans
	}
	f, err := openSavedPlan(dir, id+".json")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSavedPlanBytes+1))
	if err != nil || len(raw) > maxSavedPlanBytes {
		return nil, errMembersPlans
	}
	return raw, nil
}

func openSavedPlan(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errMembersPlans
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || int(stat.Uid) != os.Geteuid() ||
		stat.Mode&0o077 != 0 || stat.Nlink != 1 || stat.Size > maxSavedPlanBytes || !safeMembersPlanACL(fd, false) {
		unix.Close(fd)
		return nil, errMembersPlans
	}
	return os.NewFile(uintptr(fd), "saved members plan"), nil
}
