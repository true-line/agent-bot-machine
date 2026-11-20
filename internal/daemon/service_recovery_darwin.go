package daemon

import "github.com/qwts/managed-machine/internal/members"

func currentPairedServicePlan(verb, home, owner, id, digest string, uid int) (string, error) {
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
	switch verb {
	case harnessInstallVerb, harnessRetireVerb:
		err = members.CheckDarwinHarnessLaunch(saved, verb, owner, uid)
	case upgradeVerb:
		err = members.CheckDarwinHQUpgrade(saved, owner, uid)
	case recoveryVerb:
		err = members.CheckDarwinHQRecovery(saved, owner, uid)
	default:
		return "", errRecoveryPlan
	}
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}
