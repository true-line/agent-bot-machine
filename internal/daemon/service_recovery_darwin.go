package daemon

import "github.com/qwts/managed-machine/internal/members"

var checkPackageLaunchGrant = members.CheckDarwinHarnessLaunchRemoval
var unusedMachineSocket = members.CheckDetachedDarwinSocket

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
	case harnessAccountsVerb:
		err = members.CheckDarwinHarnessAccounts(saved, owner, uid)
	case soulRunnerAccountsVerb:
		err = members.CheckDarwinSoulRunnerAccounts(saved, owner, uid)
	case soulBridgeAccountsVerb:
		err = members.CheckDarwinSoulBridgeAccounts(saved, owner, uid)
	case members.SoulProtectedLaunchInstallPurpose:
		err = members.CheckDarwinSoulProtectedLaunch(saved, owner, uid)
	case members.SoulProtectedLaunchRetirePurpose:
		err = members.CheckDarwinSoulProtectedRetire(saved, owner, uid)
	case harnessInstallVerb, harnessRetireVerb:
		err = members.CheckDarwinHarnessLaunch(saved, verb, owner, uid)
	case harnessQualificationVerb:
		err = members.CheckDarwinHarnessQualification(saved, owner, uid)
	case upgradeVerb:
		err = members.CheckDarwinHQUpgrade(saved, owner, uid)
	case recoveryVerb:
		err = members.CheckDarwinHQRecovery(saved, owner, uid)
	case stage2aCooperativeRecoveryVerb:
		err = members.CheckDarwinSoulCooperativeLaunch(saved, owner, uid)
	case members.SoulCooperativeLaunchInstallPurpose:
		err = members.CheckDarwinSoulCooperativeLaunch(saved, owner, uid)
	default:
		return "", errRecoveryPlan
	}
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}
