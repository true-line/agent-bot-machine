package members

import (
	"errors"
	"path/filepath"
)

// A and the R-UID launcher derive these bytes from the same installed
// qualification and Machine-derived relay. No caller-supplied environment is
// merged into the stock adapter process.
func stage2aChildEnvironment(runner SoulRunner, start SoulStartAssignment,
	input Stage2aLaunchInputRecords) (string, map[string]string, error) {
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
	root := filepath.Join(darwinSoulRunnerHome(runner.Account), "state", "child-"+soulEndpointStartSlot(runner.InstallationID, start.StartID))
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
