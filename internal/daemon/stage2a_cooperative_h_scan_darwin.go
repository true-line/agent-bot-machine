//go:build darwin

package daemon

import (
	"errors"
	"io"
	"os/user"
	"strings"

	"github.com/qwts/managed-machine/internal/members"
	"github.com/qwts/managed-machine/internal/plan"
)

var errCooperativeHPlan = errors.New("unique installed cooperative H owner plan unavailable")

// The H descriptor carries its owner-plan digest but no PlanID. Scan only A's
// no-follow Saved directory and refuse zero or multiple exact canonical
// matches; no HQ request supplies these plan bytes or an owner path.
func findUniqueCooperativeHPlan(machineAccount, ownerPlanDigest string) (members.Saved, error) {
	if !stage2aExecDigest.MatchString(ownerPlanDigest) {
		return members.Saved{}, errCooperativeHPlan
	}
	account, err := user.Lookup(machineAccount)
	if err != nil || account.Username != machineAccount || account.HomeDir == "" {
		return members.Saved{}, errCooperativeHPlan
	}
	dir, err := openMembersPlans(account.HomeDir)
	if err != nil {
		return members.Saved{}, errCooperativeHPlan
	}
	defer dir.Close()
	names, err := dir.Readdirnames(maxPlanEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(names) > maxPlanEntries {
		return members.Saved{}, errCooperativeHPlan
	}
	var found members.Saved
	for _, name := range names {
		id, ok := strings.CutSuffix(name, ".json")
		if !ok || !plan.ValidID(id) {
			continue
		}
		raw, err := readSavedPlanFile(dir, id)
		if err != nil {
			return members.Saved{}, errCooperativeHPlan
		}
		saved, _, err := decodeSavedMembersPlan(id, raw)
		if err != nil {
			return members.Saved{}, errCooperativeHPlan
		}
		if "sha256:"+saved.PlanDigest == ownerPlanDigest {
			if found.PlanID != "" {
				return members.Saved{}, errCooperativeHPlan
			}
			found = saved
		}
	}
	if found.PlanID == "" {
		return members.Saved{}, errCooperativeHPlan
	}
	return found, nil
}
