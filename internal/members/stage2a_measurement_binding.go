package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var stage2aBindingID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var stage2aDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)
var stage2aPrefixedDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Stage2aSnapshotIdentity is a host-local claim, never a substitute for a
// no-follow descriptor observation and the root-owned snapshot receipt.
type Stage2aSnapshotIdentity struct {
	RootPath    string `json:"root_path"`
	Device      string `json:"device"`
	Inode       string `json:"inode"`
	Generation  string `json:"generation"`
	BirthtimeNS string `json:"birthtime_ns"`
	OwnerUID    uint32 `json:"owner_uid"`
	OwnerGID    uint32 `json:"owner_gid"`
	Mode        string `json:"mode"`
}

type Stage2aBindingSnapshots struct {
	Definition   Stage2aSnapshotIdentity `json:"definition"`
	LaunchInputs Stage2aSnapshotIdentity `json:"launch_inputs"`
}

// Stage2aMeasurementBinding is the exact portable shared value in
// soul-contracts machine/v1. The future signed reservation, authenticated
// finalization, completed run and signed host report must all bind it.
type Stage2aMeasurementBinding struct {
	Contract            string `json:"contract"`
	Kind                string `json:"kind"`
	SchemaVersion       int    `json:"schema_version"`
	InstallationID      string `json:"installation_id"`
	SoulID              string `json:"soul_id"`
	StartID             string `json:"start_id"`
	LaunchID            string `json:"launch_id"`
	HostID              string `json:"host_id"`
	HQEpoch             string `json:"hq_epoch"`
	PlanID              string `json:"plan_id"`
	InstalledPlanDigest string `json:"installed_plan_digest"`
	PackageSHA256       string `json:"package_sha256"`
	// SoulArtifactSHA256 is the exact frozen .soul byte digest. It is distinct
	// from the legacy package field, adapter release, and Souls runtime .tgz.
	// Old machine/v1 readers may omit it; v3 host reports must require it.
	SoulArtifactSHA256      string                  `json:"soul_artifact_sha256,omitempty"`
	ProfileInForce          string                  `json:"profile_in_force"`
	ClaimedDefinitionDigest string                  `json:"claimed_definition_digest"`
	DefinitionMeasurement   string                  `json:"definition_measurement"`
	LaunchInputMeasurement  string                  `json:"launch_input_measurement"`
	Snapshots               Stage2aBindingSnapshots `json:"snapshots"`
}

func stage2aValidSnapshotClaim(s Stage2aSnapshotIdentity) bool {
	if !stage2aAbsolutePath(s.RootPath) || s.OwnerUID != 0 || !stage2aReadOnlyMode(s.Mode) {
		return false
	}
	for _, decimal := range []string{s.Device, s.Inode, s.Generation, s.BirthtimeNS} {
		if !stage2aDecimal.MatchString(decimal) {
			return false
		}
		if _, err := strconv.ParseUint(decimal, 10, 64); err != nil {
			return false
		}
	}
	return true
}

func stage2aDistinctSnapshotRoots(a, b Stage2aSnapshotIdentity) bool {
	aFolded, bFolded := strings.ToLower(a.RootPath), strings.ToLower(b.RootPath)
	return aFolded != bFolded &&
		!strings.HasPrefix(aFolded, bFolded+"/") &&
		!strings.HasPrefix(bFolded, aFolded+"/") &&
		(a.Device != b.Device || a.Inode != b.Inode)
}

// Stage2aBindingDigest validates the complete nonauthorizing binding and
// computes the plain SHA-256 of its RFC 8785 JCS bytes, as in the contract
// fixture. It does not inspect the claimed snapshots or sign anything.
func Stage2aBindingDigest(binding Stage2aMeasurementBinding) (string, []byte, error) {
	invalid := errors.New("invalid Stage 2a measurement binding")
	if binding.Contract != "machine/v1" || binding.Kind != "stage2a-measurement-binding" ||
		binding.SchemaVersion != 1 ||
		!stage2aBindingID.MatchString(binding.InstallationID) ||
		!soulIdentity.MatchString(binding.SoulID) ||
		!soulStartID.MatchString(binding.StartID) || !soulLaunchID.MatchString(binding.LaunchID) ||
		!stage2aBindingID.MatchString(binding.HostID) ||
		!soulDigest.MatchString(binding.HQEpoch) ||
		!stage2aBindingID.MatchString(binding.PlanID) ||
		!soulDigest.MatchString(binding.InstalledPlanDigest) ||
		!soulDigest.MatchString(binding.PackageSHA256) ||
		(binding.SoulArtifactSHA256 != "" && !soulDigest.MatchString(binding.SoulArtifactSHA256)) ||
		(binding.ProfileInForce != "managed-protected" && binding.ProfileInForce != "managed-cooperative") ||
		!stage2aPrefixedDigest.MatchString(binding.ClaimedDefinitionDigest) ||
		!stage2aPrefixedDigest.MatchString(binding.DefinitionMeasurement) ||
		!stage2aPrefixedDigest.MatchString(binding.LaunchInputMeasurement) ||
		!stage2aValidSnapshotClaim(binding.Snapshots.Definition) ||
		!stage2aValidSnapshotClaim(binding.Snapshots.LaunchInputs) ||
		!stage2aDistinctSnapshotRoots(binding.Snapshots.Definition, binding.Snapshots.LaunchInputs) {
		return "", nil, invalid
	}
	raw, err := json.Marshal(binding)
	if err != nil || len(raw) > 16<<10 || stage2aStrictJSON(raw) != nil {
		return "", nil, invalid
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) > 16<<10 {
		return "", nil, invalid
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("sha256:%x", sum), canonical, nil
}

// CheckStage2aMeasuredBinding compares portable measurements and identity
// fields with the selected Machine assignment and independently named host
// and SoulLock claim. The installed-plan receipt, actual opened bytes,
// frozen .soul artifact bytes, snapshot identity, owner mapping and signed
// one-use lifecycle still need separate physical checks before protected start.
func CheckStage2aMeasuredBinding(binding Stage2aMeasurementBinding,
	definition []Stage2aDefinitionRecord, launch Stage2aLaunchInputRecords,
	assignment SoulStartAssignment, hostID, claimedDefinitionDigest string) (string, error) {
	invalid := errors.New("Stage 2a binding differs from measured start")
	bindingDigest, _, err := Stage2aBindingDigest(binding)
	if err != nil {
		return "", invalid
	}
	definitionDigest, _, err := Stage2aDefinitionDigest(definition)
	if err != nil || definitionDigest != binding.DefinitionMeasurement {
		return "", invalid
	}
	launchDigest, _, err := Stage2aLaunchInputDigest(launch)
	if err != nil || launchDigest != binding.LaunchInputMeasurement ||
		launch.EffectiveConfig["profile"] != binding.ProfileInForce ||
		!stage2aSelectedCommandRecorded(binding, definition, launch) {
		return "", invalid
	}
	if assignment.Schema != "agent-bot-machine/soul-start-assignment/v2" ||
		binding.InstallationID != assignment.InstallationID || binding.SoulID != assignment.SoulID ||
		binding.StartID != assignment.StartID || binding.LaunchID != assignment.LaunchID ||
		binding.HQEpoch != assignment.HQEpoch || binding.PlanID != assignment.PlanID ||
		binding.InstalledPlanDigest != assignment.PlanDigest ||
		binding.PackageSHA256 != assignment.PackageSHA256 ||
		binding.HostID != hostID || binding.ClaimedDefinitionDigest != claimedDefinitionDigest {
		return "", invalid
	}
	return bindingDigest, nil
}

func stage2aSelectedCommandRecorded(binding Stage2aMeasurementBinding,
	definition []Stage2aDefinitionRecord, launch Stage2aLaunchInputRecords) bool {
	command := launch.SelectedCommand
	for _, candidate := range []struct {
		root    string
		records []Stage2aDefinitionRecord
	}{
		{binding.Snapshots.Definition.RootPath, definition},
		{binding.Snapshots.LaunchInputs.RootPath, launch.Files},
	} {
		if !strings.HasPrefix(command, candidate.root+"/") {
			continue
		}
		relative := strings.TrimPrefix(command, candidate.root+"/")
		if candidate.root == binding.Snapshots.Definition.RootPath &&
			!strings.HasPrefix(relative, "Contents/opt/") {
			return false
		}
		if candidate.root == binding.Snapshots.LaunchInputs.RootPath &&
			(relative == "host/adapters.json" || relative == "host/installation.json") {
			return false
		}
		for _, record := range candidate.records {
			if record.Path == relative && record.Kind == "regular" &&
				stage2aReadOnlyMode(record.Mode) && (record.Mode[2]-'0')&1 != 0 {
				return true
			}
		}
		return false
	}
	return false
}

// ParseStage2aMeasurementBinding accepts only exact canonical object bytes.
// Signed envelopes should retain these bytes; a permissive JSON reparse would
// otherwise erase duplicate or unknown fields before signature checks.
func ParseStage2aMeasurementBinding(raw []byte) (Stage2aMeasurementBinding, error) {
	var binding Stage2aMeasurementBinding
	if len(raw) == 0 || len(raw) > 16<<10 || stage2aStrictJSON(raw) != nil {
		return binding, errors.New("invalid Stage 2a binding encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return Stage2aMeasurementBinding{}, errors.New("invalid Stage 2a binding fields")
	}
	_, canonical, err := Stage2aBindingDigest(binding)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Stage2aMeasurementBinding{}, errors.New("noncanonical Stage 2a binding")
	}
	return binding, nil
}
