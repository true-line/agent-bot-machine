package members

import "testing"

func bridgeFixture() []SoulBridge {
	runners := runnerFixture()
	return []SoulBridge{
		{SoulID: runners[0].SoulID, InstallationID: runners[0].InstallationID, Account: SoulBridgeName(runners[0].InstallationID), UID: 333, GID: 333},
		{SoulID: runners[1].SoulID, InstallationID: runners[1].InstallationID, Account: SoulBridgeName(runners[1].InstallationID), UID: 334, GID: 334},
	}
}

func TestSoulBridgeMappingRequiresOneCredentialPrincipalPerInstallation(t *testing.T) {
	runners, bridges := runnerFixture(), bridgeFixture()
	shared := []HarnessAdapter{{Account: "_shared-c", UID: 330}}
	if err := ValidateSoulBridges(runners, bridges, 309, shared); err != nil {
		t.Fatalf("distinct protected principals: %v", err)
	}
	for name, edit := range map[string]func([]SoulBridge){
		"shared credential UID":     func(b []SoulBridge) { b[1].UID, b[1].GID = b[0].UID, b[0].GID },
		"shared credential account": func(b []SoulBridge) { b[1].Account = b[0].Account },
		"shared harness UID":        func(b []SoulBridge) { b[1].UID, b[1].GID = 330, 330 },
		"shared harness name":       func(b []SoulBridge) { b[1].Account = "_shared-c" },
		"runner UID":                func(b []SoulBridge) { b[1].UID, b[1].GID = runners[0].UID, runners[0].GID },
		"HQ UID":                    func(b []SoulBridge) { b[1].UID, b[1].GID = 309, 309 },
		"different group":           func(b []SoulBridge) { b[1].GID++ },
		"wrong Soul":                func(b []SoulBridge) { b[1].SoulID = "agent_ffffffff-ffff-ffff-ffff-ffffffffffff" },
		"wrong installation":        func(b []SoulBridge) { b[1].InstallationID = "inst_unknown" },
		"chosen account":            func(b []SoulBridge) { b[1].Account = "_lead" },
		"reordered":                 func(b []SoulBridge) { b[0], b[1] = b[1], b[0] },
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]SoulBridge(nil), bridges...)
			edit(changed)
			if err := ValidateSoulBridges(runners, changed, 309, shared); err == nil {
				t.Fatal("accepted an unisolated bridge principal")
			}
		})
	}
	if err := ValidateSoulBridges(runners, bridges[:1], 309, shared); err == nil {
		t.Fatal("accepted a runner installation without a bridge")
	}
}
