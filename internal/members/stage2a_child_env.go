package members

import (
	"errors"
	"path/filepath"
	"strings"
)

// SHA-256 of the literal fixture key "ssh-placeholder"; it contains no
// provider credential and is shared by Darwin validation and portable plans.
const stage2aFixtureClientKeySHA256 = "sha256:da4fec28d868ca5cf8f00f43869f703f138bd4211683b8637a751b904860ddf0"

// A and the R-UID launcher derive these bytes from the same installed
// qualification and Machine-derived relay. No caller-supplied environment is
// merged into the stock adapter process.
func stage2aChildEnvironment(runner SoulRunner, start SoulStartAssignment,
	input Stage2aLaunchInputRecords) (string, map[string]string, error) {
	return stage2aMemberChildEnvironment(runner, start, input, "")
}

// A two-member grant supplies the selector from the signed assignment. The
// selector partitions every mutable directory used by the stock adapter.
func stage2aMemberChildEnvironment(runner SoulRunner, start SoulStartAssignment,
	input Stage2aLaunchInputRecords, memberSelector string) (string, map[string]string, error) {
	invalid := errors.New("invalid protected stock child environment")
	if runner.Account != soulRunnerName(runner.InstallationID) ||
		start.InstallationID != runner.InstallationID || !soulStartID.MatchString(start.StartID) ||
		start.RunnerUID != runner.UID || start.RunnerGID != runner.GID ||
		!stage2aAbsolutePath(start.Relay.SocketPath) {
		return "", nil, invalid
	}
	config, ok := input.EffectiveConfig["adapter_child_env"].(map[string]any)
	if !ok || len(config) != 8 || config["base_url"] != "http://fixture.invalid" ||
		config["client_key_sha256"] != stage2aFixtureClientKeySHA256 ||
		config["disable_nonessential_traffic"] != true {
		return "", nil, invalid
	}
	model, ok := config["model"].(string)
	if !ok || !stage2aBindingID.MatchString(model) {
		return "", nil, invalid
	}
	stateName, err := stage2aChildStateName(runner.InstallationID, start.StartID, memberSelector)
	if err != nil {
		return "", nil, invalid
	}
	root := filepath.Join(darwinSoulRunnerHome(runner.Account), "state", stateName)
	workdir := filepath.Join(root, "work")
	tmp := filepath.Join(root, "tmpdir")
	env := map[string]string{
		"PATH": "/usr/bin:/bin", "HOME": filepath.Join(root, "home"),
		"TMPDIR": tmp, "TMP": tmp, "TEMP": tmp,
		"XDG_CONFIG_HOME":                          filepath.Join(root, "xdg_config_home"),
		"XDG_CACHE_HOME":                           filepath.Join(root, "xdg_cache_home"),
		"XDG_DATA_HOME":                            filepath.Join(root, "xdg_data_home"),
		"XDG_STATE_HOME":                           filepath.Join(root, "xdg_state_home"),
		"XDG_RUNTIME_DIR":                          filepath.Join(root, "xdg_runtime_dir"),
		"XDG_CONFIG_DIRS":                          filepath.Join(root, "xdg_config_home"),
		"XDG_DATA_DIRS":                            filepath.Join(root, "xdg_data_home"),
		"CLAUDE_CODE_TMPDIR":                       tmp,
		"ANTHROPIC_UNIX_SOCKET":                    start.Relay.SocketPath,
		"ANTHROPIC_API_KEY":                        "ssh-placeholder",
		"ANTHROPIC_BASE_URL":                       "http://fixture.invalid",
		"ANTHROPIC_MODEL":                          model,
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
	}
	return workdir, env, nil
}

func stage2aChildStateName(installationID, startID, memberSelector string) (string, error) {
	if !soulInstallationID.MatchString(installationID) || !soulStartID.MatchString(startID) ||
		(memberSelector != "" && (len(memberSelector) != 67 ||
			!strings.HasPrefix(memberSelector, "mb_") || !soulDigest.MatchString(memberSelector[3:]))) {
		return "", errors.New("invalid protected stock child state selector")
	}
	name := "child-" + soulEndpointStartSlot(installationID, startID)
	if memberSelector != "" {
		name += "-" + memberSelector
	}
	return name, nil
}
