package qualification

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

var stage2aStartID = regexp.MustCompile(`^st_[0-9a-f]{24}$`)
var stage2aLaunchID = regexp.MustCompile(`^ln_[0-9a-f]{24}$`)
var stage2aDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)

// measurementBinding is the exact machine/v1 per-start object from
// soul-contracts. Shape validation alone does not establish physical custody,
// one-use execution, or permission to sign a host report.
type measurementBinding struct {
	Contract                string `json:"contract"`
	Kind                    string `json:"kind"`
	SchemaVersion           int    `json:"schema_version"`
	InstallationID          string `json:"installation_id"`
	SoulID                  string `json:"soul_id"`
	StartID                 string `json:"start_id"`
	LaunchID                string `json:"launch_id"`
	HostID                  string `json:"host_id"`
	HQEpoch                 string `json:"hq_epoch"`
	PlanID                  string `json:"plan_id"`
	InstalledPlanDigest     string `json:"installed_plan_digest"`
	PackageSHA256           string `json:"package_sha256"`
	ProfileInForce          string `json:"profile_in_force"`
	ClaimedDefinitionDigest string `json:"claimed_definition_digest"`
	DefinitionMeasurement   string `json:"definition_measurement"`
	LaunchInputMeasurement  string `json:"launch_input_measurement"`
	Snapshots               struct {
		Definition   snapshotIdentity `json:"definition"`
		LaunchInputs snapshotIdentity `json:"launch_inputs"`
	} `json:"snapshots"`
}

type snapshotIdentity struct {
	RootPath    string `json:"root_path"`
	Device      string `json:"device"`
	Inode       string `json:"inode"`
	Generation  string `json:"generation"`
	BirthtimeNS string `json:"birthtime_ns"`
	OwnerUID    uint32 `json:"owner_uid"`
	OwnerGID    uint32 `json:"owner_gid"`
	Mode        string `json:"mode"`
}

func validSnapshotIdentity(s snapshotIdentity) bool {
	if !reportPath(s.RootPath) || strings.ContainsRune(s.RootPath, '\\') ||
		!stage2aDecimal.MatchString(s.Device) || !stage2aDecimal.MatchString(s.Inode) ||
		!stage2aDecimal.MatchString(s.Generation) || !stage2aDecimal.MatchString(s.BirthtimeNS) ||
		s.OwnerUID != 0 || len(s.Mode) != 4 || s.Mode[0] != '0' {
		return false
	}
	for _, c := range s.Mode {
		if c < '0' || c > '7' {
			return false
		}
	}
	// The observed snapshot root cannot grant write access to a group or
	// other account, regardless of whether the enclosing directory is pinned.
	if (s.Mode[2]-'0')&2 != 0 || (s.Mode[3]-'0')&2 != 0 {
		return false
	}
	return true
}

// parseMeasurementBinding verifies the strict canonical object and its
// internal constraints. Its caller must compare the result with independently
// authenticated reservation, finalization, completed-run and report values.
func parseMeasurementBinding(raw []byte) (measurementBinding, error) {
	var binding measurementBinding
	fields, err := canonicalBytes(raw, MaxReportBytes)
	if err != nil || !hasFields(fields,
		"contract", "kind", "schema_version", "installation_id", "soul_id", "start_id",
		"launch_id", "host_id", "hq_epoch", "plan_id", "installed_plan_digest",
		"package_sha256", "profile_in_force", "claimed_definition_digest",
		"definition_measurement", "launch_input_measurement", "snapshots") {
		return measurementBinding{}, ErrUnqualified
	}
	snapshots, err := strictObject(fields["snapshots"], MaxReportBytes)
	if err != nil || !hasFields(snapshots, "definition", "launch_inputs") {
		return measurementBinding{}, ErrUnqualified
	}
	for _, name := range []string{"definition", "launch_inputs"} {
		identity, err := strictObject(snapshots[name], MaxReportBytes)
		if err != nil || !hasFields(identity, "root_path", "device", "inode", "generation",
			"birthtime_ns", "owner_uid", "owner_gid", "mode") {
			return measurementBinding{}, ErrUnqualified
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&binding) != nil || binding.Contract != "machine/v1" ||
		binding.Kind != "stage2a-measurement-binding" || binding.SchemaVersion != 1 ||
		!reportID.MatchString(binding.InstallationID) || !bridgeSoulID.MatchString(binding.SoulID) ||
		!stage2aStartID.MatchString(binding.StartID) || !stage2aLaunchID.MatchString(binding.LaunchID) ||
		!reportID.MatchString(binding.HostID) || !validHex(binding.HQEpoch, 64) ||
		!reportID.MatchString(binding.PlanID) || !validHex(binding.InstalledPlanDigest, 64) ||
		!validHex(binding.PackageSHA256, 64) ||
		(binding.ProfileInForce != "managed-protected" && binding.ProfileInForce != "managed-cooperative") ||
		!validSHA(binding.ClaimedDefinitionDigest) || !validSHA(binding.DefinitionMeasurement) ||
		!validSHA(binding.LaunchInputMeasurement) ||
		!validSnapshotIdentity(binding.Snapshots.Definition) ||
		!validSnapshotIdentity(binding.Snapshots.LaunchInputs) ||
		binding.Snapshots.Definition.RootPath == binding.Snapshots.LaunchInputs.RootPath {
		return measurementBinding{}, ErrUnqualified
	}
	return binding, nil
}
