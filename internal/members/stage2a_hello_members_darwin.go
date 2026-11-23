//go:build darwin

package members

import (
	"cmp"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
)

var stage2aHelloRole = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var stage2aHelloAdapterVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$`)

// A reads SoulInfo from the descriptor-checked frozen definition at Hello.
// The claimed roles cannot expand or change the owner's measured member set.
func stage2aHelloMatchesFrozenMembers(p stage2aInstalledPolicy, requested []stage2aHelloMember) bool {
	raw, err := stage2aReadFrozenClaimFile(p.Binding.Snapshots.Definition,
		p.Definition, "Contents/SoulInfo.json")
	return err == nil && stage2aHelloMembersMatch(raw, p.Binding.SoulID, requested)
}

func stage2aHelloMembersMatch(raw []byte, soulID string, requested []stage2aHelloMember) bool {
	if stage2aStrictJSON(raw) != nil || !soulIdentity.MatchString(soulID) ||
		len(requested) == 0 || len(requested) > 32 {
		return false
	}
	var frozen struct {
		SoulID  string               `json:"soul_id"`
		Members []stage2aHelloMember `json:"members"`
	}
	if json.Unmarshal(raw, &frozen) != nil || frozen.SoulID != soulID ||
		len(frozen.Members) != len(requested) {
		return false
	}
	valid := func(members []stage2aHelloMember) bool {
		seen := make(map[string]bool, len(members))
		leads := 0
		for _, member := range members {
			if !stage2aBindingID.MatchString(member.MemberID) || seen[member.MemberID] ||
				!stage2aHelloRole.MatchString(member.Role) ||
				!stage2aBindingID.MatchString(member.AdapterID) ||
				!stage2aHelloAdapterVersion.MatchString(member.AdapterVersion) {
				return false
			}
			seen[member.MemberID] = true
			if member.Role == "lead" {
				leads++
			}
		}
		return leads == 1
	}
	if !valid(frozen.Members) || !valid(requested) {
		return false
	}
	got := slices.Clone(requested)
	want := slices.Clone(frozen.Members)
	slices.SortFunc(got, func(a, b stage2aHelloMember) int { return cmp.Compare(a.MemberID, b.MemberID) })
	slices.SortFunc(want, func(a, b stage2aHelloMember) int { return cmp.Compare(a.MemberID, b.MemberID) })
	return reflect.DeepEqual(got, want)
}
