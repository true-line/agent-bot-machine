package members

import (
	"errors"
	"path/filepath"
	"strings"
)

// The child environment is part of A's owner-reviewed launch-input object.
// R receives that object through the signed start and may derive only the
// per-start relay path and its private temporary directories. In particular,
// an install plan cannot choose a Unix socket or inject arbitrary child env.
const stage2aAdapterChildEnvSchema = "agent-bot-souls/adapter-child-env/v1"

func stage2aAdapterChildEnv(input Stage2aLaunchInputRecords, qualification *Stage2aBridgeQualification, root string) error {
	return stage2aAdapterChildEnvWithRows(input, qualification, root, nil)
}

func stage2aAdapterChildEnvV3(input Stage2aLaunchInputRecords, qualification *Stage2aBridgeQualification,
	ref stage2aDomainInventoryRefV3, inv stage2aDomainInventoryV3) error {
	if ref.Domain != "R-runtime" || inv.Domain != "R-runtime" ||
		ref.InstallationID != inv.InstallationID || !stage2aAbsolutePath(ref.Snapshot.Path) ||
		len(inv.Files) == 0 {
		return errStage2aReservationAuthority
	}
	return stage2aAdapterChildEnvWithRows(input, qualification, ref.Snapshot.Path, inv.Files)
}

func stage2aAdapterChildEnvWithRows(input Stage2aLaunchInputRecords,
	qualification *Stage2aBridgeQualification, root string, rFiles []stage2aDomainFileV3) error {
	invalid := errors.New("invalid protected adapter child environment")
	if input.EffectiveConfig["profile"] != "managed-protected" {
		return invalid
	}
	raw, ok := input.EffectiveConfig["adapter_child_env"].(map[string]any)
	if !ok || len(raw) != 8 || len(input.EffectiveConfig) != 4 {
		return invalid
	}
	sandbox, ok := input.EffectiveConfig["adapter_child_sandbox"].(map[string]any)
	if !ok || len(sandbox) != 2 || sandbox["path"] != SoulChildSandbox ||
		sandbox["sha256"] != "sha256:"+harnessSHA(soulChildProfile) ||
		!stage2aSystemImageSelected(input, "/usr/bin/sandbox-exec") {
		return invalid
	}
	measuredSandbox := false
	for _, file := range input.Files {
		if file.Path == "policy/soul-child-egress.sb" && file.Kind == "regular" &&
			file.Mode == "0444" && "sha256:"+file.SHA256 == sandbox["sha256"] &&
			file.Size != nil && *file.Size == uint64(len(soulChildProfile)) {
			measuredSandbox = true
		}
	}
	if !measuredSandbox {
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
	if rFiles != nil {
		for _, file := range rFiles {
			if file.Path == relative && file.ComponentID == "adapter" &&
				file.Path == "runtime/bin/claude-agent-acp" && file.Mode == "0550" &&
				input.ComponentDigests["adapter"] == file.SHA256 {
				measured = true
			}
		}
	} else {
		for _, file := range input.Files {
			if file.Path == relative && file.Kind == "regular" && stage2aReadOnlyMode(file.Mode) &&
				(file.Mode[2]-'0')&1 != 0 && input.ComponentDigests["adapter"] == "sha256:"+file.SHA256 {
				measured = true
			}
		}
	}
	if !measured {
		return invalid
	}
	if rFiles != nil && stage2aSelectedStockCLI(input.Files, rFiles) != nil {
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

// The stock ACP adapter invokes its adjacent Claude CLI. Count that actual
// selected executable in the external launch-input measurement and require
// the same bytes in A's sealed R inventory. This is only an omission check;
// the full selected Node/HQ/Comms import closure and child read boundary still
// need separate enforcement before protected qualification.
func stage2aSelectedStockCLI(external []Stage2aDefinitionRecord, sealed []stage2aDomainFileV3) error {
	const path = stage2aStockCLIPath
	var selected *stage2aDomainFileV3
	for i := range sealed {
		if sealed[i].Path == path {
			if selected != nil {
				return errStage2aReservationAuthority
			}
			selected = &sealed[i]
		}
	}
	if selected == nil || selected.ComponentID != "adapter" || selected.Kind != "regular" ||
		selected.Mode != "0550" || selected.SizeBytes == 0 ||
		(selected.SizeBytes > stage2aMaxFileBytes &&
			(selected.SizeBytes != stage2aStockCLISizeBytes || selected.SizeBytes > stage2aStockCLIMaxBytes ||
				selected.SHA256 != "sha256:"+stage2aStockCLISHA256)) ||
		!stage2aPrefixedDigest.MatchString(selected.SHA256) {
		return errStage2aReservationAuthority
	}
	matched := 0
	for _, file := range external {
		if file.Path == path {
			if file.Kind != "regular" || file.Mode != selected.Mode || file.Size == nil ||
				*file.Size != selected.SizeBytes || file.SHA256 != strings.TrimPrefix(selected.SHA256, "sha256:") {
				return errStage2aReservationAuthority
			}
			matched++
		}
	}
	if matched != 1 {
		return errStage2aReservationAuthority
	}
	return nil
}
