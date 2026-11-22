package members

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
)

// SoulBridge is the credential-sidecar principal for one Soul installation.
// Its UID is separate from that installation's package runner, HQ, and every
// other bridge. A bridge account is not a reusable harness credential account.
// This record alone gives no launch or broker authority.
type SoulBridge struct {
	SoulID         string `json:"soul_id"`
	InstallationID string `json:"installation_id"`
	Account        string `json:"account"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
}

// SoulBridgeName makes account assignment independent of a caller's chosen
// name. The namespace is disjoint from Soul-runner and harness role names.
func SoulBridgeName(installationID string) string {
	sum := sha256.Sum256([]byte("agent-bot-soul-bridge/v1\x00" + installationID))
	return fmt.Sprintf("_abm-br-%x", sum[:10])
}

func darwinSoulBridgeHome(name string) string {
	return path.Join(DarwinHQHomeBase, "agent-bot-soul-bridge-"+name)
}

// ValidateSoulBridges closes the same-UID token-state and socket-replacement
// route that a network-only sandbox cannot close for shared credential roles.
// Each reviewed Soul installation gets exactly one dedicated bridge and one
// different package runner. The installed rule must additionally verify the
// host roles, package bytes, broker admission and per-start endpoints.
func ValidateSoulBridges(runners []SoulRunner, bridges []SoulBridge, hqUID int, sharedHarnesses []HarnessAdapter) error {
	invalid := errors.New("invalid protected Soul bridge mapping")
	if len(bridges) == 0 || len(bridges) != len(runners) || len(bridges) > 64 {
		return invalid
	}
	accounts := make([]HarnessAdapter, 0, len(bridges)+len(sharedHarnesses))
	accounts = append(accounts, sharedHarnesses...)
	seenAccount := map[string]int{}
	seenUID := map[int]string{hqUID: DarwinHQAccount}
	for _, harness := range sharedHarnesses {
		if !accountName.MatchString(harness.Account) || harness.UID < 300 || harness.UID > 399 ||
			(seenAccount[harness.Account] != 0 && seenAccount[harness.Account] != harness.UID) ||
			(seenUID[harness.UID] != "" && seenUID[harness.UID] != harness.Account) {
			return invalid
		}
		seenAccount[harness.Account], seenUID[harness.UID] = harness.UID, harness.Account
	}
	for i, bridge := range bridges {
		runner := runners[i]
		if !soulIdentity.MatchString(bridge.SoulID) || bridge.SoulID != runner.SoulID ||
			!soulInstallationID.MatchString(bridge.InstallationID) || bridge.InstallationID != runner.InstallationID ||
			bridge.Account != SoulBridgeName(bridge.InstallationID) || !accountName.MatchString(bridge.Account) ||
			seenAccount[bridge.Account] != 0 || bridge.UID < 300 || bridge.UID > 399 || bridge.UID == hqUID ||
			bridge.GID != bridge.UID || seenUID[bridge.UID] != "" {
			return invalid
		}
		seenAccount[bridge.Account], seenUID[bridge.UID] = bridge.UID, bridge.Account
		accounts = append(accounts, HarnessAdapter{Account: bridge.Account, UID: bridge.UID})
	}
	return ValidateSoulRunners(runners, hqUID, accounts)
}

// SelectSoulBridge selects only the installed credential-sidecar principal for
// this start. The caller must have validated the complete reviewed mapping at
// installation and must authenticate the start before invoking a launcher.
// Neither a request nor an adjacent installation can choose a bridge account.
func SelectSoulBridge(bridges []SoulBridge, installedDigest string, request SoulRunRequest, uid int) (SoulBridge, error) {
	invalid := errors.New("Soul start has no reviewed bridge principal")
	if !request.valid() || request.PlanDigest != installedDigest {
		return SoulBridge{}, invalid
	}
	var selected SoulBridge
	for _, bridge := range bridges {
		if bridge.InstallationID != request.InstallationID {
			continue
		}
		if selected.InstallationID != "" || !soulIdentity.MatchString(bridge.SoulID) ||
			bridge.Account != SoulBridgeName(bridge.InstallationID) ||
			bridge.UID != uid || bridge.GID != uid {
			return SoulBridge{}, invalid
		}
		selected = bridge
	}
	if selected.InstallationID == "" {
		return SoulBridge{}, invalid
	}
	return selected, nil
}
