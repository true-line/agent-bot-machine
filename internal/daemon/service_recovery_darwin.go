package daemon

import "github.com/qwts/managed-machine/internal/members"

func currentRecoveryPlan(home, owner, id, digest string, uid int) (string, error) {
	dir, err := openMembersPlans(home)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	raw, err := readSavedPlanFile(dir, id)
	if err != nil {
		return "", err
	}
	saved, canonical, err := decodeSavedMembersPlan(id, raw)
	if err != nil || saved.PlanDigest != digest {
		return "", errRecoveryPlan
	}
	if err := members.CheckDarwinHQRecovery(saved, owner, uid); err != nil {
		return "", err
	}
	return string(canonical), nil
}
