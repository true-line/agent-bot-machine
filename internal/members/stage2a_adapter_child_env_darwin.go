package members

import (
	"errors"
	"path/filepath"
)

// The child environment is part of A's owner-reviewed launch-input object.
// R receives that object through the signed start and may derive only the
// per-start relay path and its private temporary directories. In particular,
// an install plan cannot choose a Unix socket or inject arbitrary child env.
const stage2aAdapterChildEnvSchema = "agent-bot-souls/adapter-child-env/v1"
const stage2aFixtureClientKeySHA256 = "sha256:da4fec28d868ca5cf8f00f43869f703f138bd4211683b8637a751b904860ddf0"

func stage2aAdapterChildEnv(input Stage2aLaunchInputRecords, qualification *Stage2aBridgeQualification, root string) error {
	invalid := errors.New("invalid protected adapter child environment")
	if input.EffectiveConfig["profile"] != "managed-protected" {
		return invalid
	}
	raw, ok := input.EffectiveConfig["adapter_child_env"].(map[string]any)
	if !ok || len(raw) != 8 || len(input.EffectiveConfig) != 3 {
		return invalid
	}
	adapterID, adapterOK := input.EffectiveConfig["adapter_id"].(string)
	if !adapterOK || !stage2aBindingID.MatchString(adapterID) {
		return invalid
	}
	// The stock child has no caller-selected argv or adapter route env. Its
	// one executable is part of A's frozen runtime inventory, and the named
	// adapter component digest must identify that exact executable's bytes.
	adapter, ok := input.HostProjection.Adapters[adapterID].(map[string]any)
	if !ok {
		return invalid
	}
	command, ok := adapter["command"].([]any)
	if !ok || len(command) != 1 {
		return invalid
	}
	executable, ok := command[0].(string)
	if !ok || !stage2aAbsolutePath(executable) || filepath.Base(executable) != "claude-agent-acp" {
		return invalid
	}
	if env, present := adapter["env"]; present {
		values, ok := env.(map[string]any)
		if !ok || len(values) != 0 {
			return invalid
		}
	}
	relative, err := filepath.Rel(root, executable)
	if err != nil || !stage2aRecordPath(relative) {
		return invalid
	}
	measured := false
	for _, file := range input.Files {
		if file.Path == relative && file.Kind == "regular" && stage2aReadOnlyMode(file.Mode) &&
			(file.Mode[2]-'0')&1 != 0 && input.ComponentDigests["adapter"] == "sha256:"+file.SHA256 {
			measured = true
		}
	}
	if !measured {
		return invalid
	}
	if raw["schema"] != stage2aAdapterChildEnvSchema ||
		raw["provider"] != "anthropic-messages" ||
		raw["base_url"] != "http://fixture.invalid" ||
		raw["http_host"] != "fixture.invalid" ||
		raw["disable_nonessential_traffic"] != true {
		return invalid
	}
	key, keyOK := raw["client_key_sha256"].(string)
	model, modelOK := raw["model"].(string)
	query, queryOK := raw["messages_query"].(string)
	if !keyOK || key != stage2aFixtureClientKeySHA256 ||
		!modelOK || !stage2aBindingID.MatchString(model) ||
		!queryOK || !stage2aMessagesQuery.MatchString(query) {
		return invalid
	}
	if qualification != nil && (key != qualification.ClientKeySHA256 ||
		model != qualification.Model || query != qualification.MessagesQuery ||
		raw["http_host"] != qualification.HTTPHost) {
		return invalid
	}
	return nil
}
