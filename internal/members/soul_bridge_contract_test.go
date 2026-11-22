package members

import (
	"strings"
	"testing"
)

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
	if err := ValidateSoulBridges(runners, bridges, 309, append(shared, HarnessAdapter{Account: "_shared-c", UID: 330})); err != nil {
		t.Fatalf("consistent repeated harness tuple refused: %v", err)
	}
	if err := ValidateSoulBridges(runners, bridges, 309, append(shared, HarnessAdapter{Account: "_shared-c", UID: 336})); err == nil {
		t.Fatal("accepted one shared harness name with two UIDs")
	}
	if err := ValidateSoulBridges(runners, bridges, 309, append(shared, HarnessAdapter{Account: "_other-c", UID: 330})); err == nil {
		t.Fatal("accepted one shared harness UID with two account names")
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

func TestSoulStartSelectsOnlyReviewedBridgeAndKernelUID(t *testing.T) {
	bridges := bridgeFixture()
	request := SoulRunRequest{PlanDigest: strings.Repeat("c", 64), InstallationID: bridges[1].InstallationID,
		StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("d", 64)}
	got, err := SelectSoulBridge(bridges, request.PlanDigest, request, 334)
	if err != nil || got != bridges[1] {
		t.Fatalf("select reviewed bridge = %+v, %v", got, err)
	}
	for name, change := range map[string]func(*SoulRunRequest){
		"sibling installation": func(r *SoulRunRequest) { r.InstallationID = bridges[0].InstallationID },
		"unknown installation": func(r *SoulRunRequest) { r.InstallationID = "inst_unknown" },
		"invalid start":        func(r *SoulRunRequest) { r.StartID = "st_bad" },
		"missing epoch":        func(r *SoulRunRequest) { r.HQEpoch = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			change(&changed)
			if _, err := SelectSoulBridge(bridges, request.PlanDigest, changed, 334); err == nil {
				t.Fatal("unreviewed bridge selection accepted")
			}
		})
	}
	if _, err := SelectSoulBridge(bridges, strings.Repeat("e", 64), request, 334); err == nil {
		t.Fatal("changed installed policy accepted")
	}
	if _, err := SelectSoulBridge(bridges, request.PlanDigest, request, 333); err == nil {
		t.Fatal("sibling bridge UID accepted")
	}
	for name, change := range map[string]func([]SoulBridge) []SoulBridge{
		"duplicate installation": func(b []SoulBridge) []SoulBridge { return append(b, b[1]) },
		"chosen account":         func(b []SoulBridge) []SoulBridge { b[1].Account = "_unreviewed"; return b },
		"wrong group":            func(b []SoulBridge) []SoulBridge { b[1].GID = 333; return b },
		"wrong Soul":             func(b []SoulBridge) []SoulBridge { b[1].SoulID = "invalid"; return b },
	} {
		t.Run(name, func(t *testing.T) {
			changed := change(append([]SoulBridge(nil), bridges...))
			if _, err := SelectSoulBridge(changed, request.PlanDigest, request, 334); err == nil {
				t.Fatal("corrupt installed bridge selection accepted")
			}
		})
	}
}
