package members

import (
	"errors"
	"strconv"
	"strings"
)

// verifyStage2aInstalledGroup checks the effective Directory Services names
// behind an installed R role group. A owns the snapshot tree and has no need
// to join R's private group; no third role may gain its group authority.
func verifyStage2aInstalledGroup(group string, gid int, admin string, adminUID int, runner string, runnerUID int) error {
	invalid := errors.New("Stage 2a installed A/role group differs from the approved identities")
	if !accountName.MatchString(group) || !accountName.MatchString(admin) || !accountName.MatchString(runner) ||
		group == admin || group != runner || admin == runner || gid <= 0 || adminUID <= 0 || runnerUID <= 0 ||
		adminUID == runnerUID {
		return invalid
	}
	groupID := strconv.Itoa(gid)
	value, found, err := dsclAttr("/Groups/"+group, "PrimaryGroupID")
	if err != nil || !found || value != groupID {
		return invalid
	}
	if owners, err := darwinSearchIDOwners("/Groups", "PrimaryGroupID", groupID); err != nil || len(owners) != 1 || owners[0] != group {
		return invalid
	}
	// R is the sole primary member. No third account may enter through its
	// primary group, including a directory-backed account.
	if owners, err := darwinSearchIDOwners("/Users", "PrimaryGroupID", groupID); err != nil || len(owners) != 1 || owners[0] != runner {
		return invalid
	}
	members, _, err := dsclAttr("/Groups/"+group, "GroupMembership")
	if err != nil || !stage2aRoleOnlyMembership(strings.Fields(members), runner) {
		return invalid
	}
	for name, uid := range map[string]int{admin: adminUID, runner: runnerUID} {
		owners, err := darwinSearchIDOwners("/Users", "UniqueID", strconv.Itoa(uid))
		if err != nil || len(owners) != 1 || owners[0] != name {
			return invalid
		}
	}
	if nested, _, err := dsclAttr("/Groups/"+group, "NestedGroups"); err != nil || nested != "" {
		return invalid
	}
	// macOS may also store the primary role's UUID explicitly. No other UUID
	// may enter this group, including A's.
	uuids, _, err := dsclAttr("/Groups/"+group, "GroupMembers")
	if err != nil {
		return invalid
	}
	if uuids != "" {
		roleGUID, found, err := dsclAttr("/Users/"+runner, "GeneratedUID")
		if err != nil || !found || roleGUID == "" {
			return invalid
		}
		seen := make(map[string]bool, 1)
		for _, guid := range strings.Fields(uuids) {
			if guid != roleGUID || seen[guid] {
				return invalid
			}
			seen[guid] = true
		}
	}
	return nil
}

func stage2aRoleOnlyMembership(values []string, role string) bool {
	return len(values) == 0 || (len(values) == 1 && values[0] == role)
}
