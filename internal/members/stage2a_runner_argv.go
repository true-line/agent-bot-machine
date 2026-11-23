package members

import (
	"errors"
	"slices"
)

const (
	stage2aAdmissionSocketTemplate = "{stage2a-admission-socket}"
	stage2aRelaySocketTemplate     = "{stage2a-relay-socket}"
)

// The owner reviews and measures this exact template at installation. Only
// Machine substitutes the two per-start endpoints it derives from the signed
// start ID; no caller supplies either path or another argument.
func stage2aRunnerArgvTemplate(node, entry, packageRoot, profile string) []string {
	return []string{node, entry, "run", "--soul", packageRoot,
		"--admission-socket", stage2aAdmissionSocketTemplate,
		"--broker-socket", stage2aRelaySocketTemplate,
		"--profile", profile, "--protected-start-fd", "3"}
}

func stage2aRunnerArgvForStart(launch Stage2aLaunchInputRecords,
	node, entry, packageRoot, profile string, runner SoulRunner,
	bridge SoulBridge, hqUID int, startID string) ([]string, SoulBridgeEndpoints, error) {
	if launch.SelectedCommand != node ||
		!slices.Equal(launch.Argv, stage2aRunnerArgvTemplate(node, entry, packageRoot, profile)) {
		return nil, SoulBridgeEndpoints{}, errors.New("protected Soul argv differs from reviewed template")
	}
	endpoints, err := DeriveSoulBridgeEndpoints(runner, bridge, hqUID, startID)
	if err != nil {
		return nil, SoulBridgeEndpoints{}, err
	}
	return []string{node, entry, "run", "--soul", packageRoot,
		"--admission-socket", endpoints.Admission.SocketPath,
		"--broker-socket", endpoints.Relay.SocketPath,
		"--profile", profile, "--protected-start-fd", "3"}, endpoints, nil
}
