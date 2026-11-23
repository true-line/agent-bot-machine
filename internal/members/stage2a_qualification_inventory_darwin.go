//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// stage2aInstalledInputEvidenceV3 is a compact, still unsigned A observation.
// A future physical segment publisher must put every blob in its private
// content-addressed archive and sign the inventory digest in the segment
// attestation. Building this value alone grants no T gate or launch authority.
type stage2aInstalledInputEvidenceV3 struct {
	inventory []byte
	sha256    string
	blobs     map[string][]byte
}

type stage2aInstalledInputRefV3 struct {
	Role      string `json:"role"`
	URI       string `json:"uri"`
	SHA256    string `json:"sha256"`
	SizeBytes int    `json:"size_bytes"`
	Issuer    string `json:"issuer"`
}

type stage2aInstalledInputRowV3 struct {
	Scope         string `json:"scope"`
	Path          string `json:"path"`
	SizeBytes     uint64 `json:"size_bytes"`
	Mode          string `json:"mode"`
	SHA256        string `json:"sha256"`
	OwnerUID      uint32 `json:"owner_uid"`
	OwnerGID      uint32 `json:"owner_gid"`
	Device        string `json:"device"`
	Inode         string `json:"inode"`
	Generation    string `json:"generation"`
	BirthtimeNS   string `json:"birthtime_ns"`
	LinkCount     uint32 `json:"link_count"`
	ACLAllowCount uint32 `json:"acl_allow_count"`
	ObservedAt    string `json:"observed_at"`
}

type stage2aInstalledInputInventoryV3 struct {
	SchemaVersion            int                          `json:"schema_version"`
	Kind                     string                       `json:"kind"`
	InstallationID           string                       `json:"installation_id"`
	SoulID                   string                       `json:"soul_id"`
	StartID                  string                       `json:"start_id"`
	LaunchID                 string                       `json:"launch_id"`
	HostID                   string                       `json:"host_id"`
	Profile                  string                       `json:"profile"`
	PlanID                   string                       `json:"plan_id"`
	InstalledPlanDigest      string                       `json:"installed_plan_digest"`
	MeasurementBindingSHA256 string                       `json:"measurement_binding_sha256"`
	DefinitionRecords        stage2aInstalledInputRefV3   `json:"definition_records"`
	LaunchInputRecords       stage2aInstalledInputRefV3   `json:"launch_input_records"`
	HostAdaptersJSON         stage2aInstalledInputRefV3   `json:"host_adapters_json"`
	HostInstallationJSON     stage2aInstalledInputRefV3   `json:"host_installation_json"`
	DefinitionSnapshot       Stage2aSnapshotIdentity      `json:"definition_snapshot"`
	LaunchInputsSnapshot     Stage2aSnapshotIdentity      `json:"launch_inputs_snapshot"`
	OpenedFiles              []stage2aInstalledInputRowV3 `json:"opened_files"`
	ObservedAt               string                       `json:"observed_at"`
}

func stage2aInstalledInputRef(role string, raw []byte) stage2aInstalledInputRefV3 {
	hash := stage2aQualificationSHA256(raw)
	return stage2aInstalledInputRefV3{Role: role,
		URI:    "qualification://stage2a/blob/" + strings.TrimPrefix(hash, "sha256:"),
		SHA256: hash, SizeBytes: len(raw), Issuer: "machine-a"}
}

func stage2aInstalledBirthtimeNS(st unix.Stat_t) (string, error) {
	if st.Btim.Sec <= 0 || st.Btim.Nsec < 0 || st.Btim.Nsec >= 1_000_000_000 ||
		st.Btim.Sec > (1<<63-1-st.Btim.Nsec)/1_000_000_000 {
		return "", errStage2aReservationAuthority
	}
	return strconv.FormatInt(st.Btim.Sec*1_000_000_000+st.Btim.Nsec, 10), nil
}

// stage2aObserveInstalledInputRows reopens every approved regular file under
// the held snapshot root with O_NOFOLLOW, hashes descriptor bytes and records
// the same descriptor's metadata before and after reading. The existing full
// closure observers run on both sides of these reads; R cannot write the tree.
func stage2aObserveInstalledInputRows(identity Stage2aSnapshotIdentity,
	approved []Stage2aDefinitionRecord, scope string) ([]stage2aInstalledInputRowV3, error) {
	if scope != "definition" && scope != "launch" {
		return nil, errStage2aReservationAuthority
	}
	root, err := openStage2aAdminDirectory(identity.RootPath, identity.OwnerUID)
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	defer root.Close()
	observed, beforeRoot, err := stage2aSnapshotIdentity(int(root.Fd()), identity.OwnerUID, identity.OwnerGID)
	if err != nil || observed != identity {
		return nil, errStage2aReservationAuthority
	}
	rows := make([]stage2aInstalledInputRowV3, 0, len(approved))
	for _, record := range approved {
		if record.Kind == "directory" && scope == "definition" {
			continue
		}
		if record.Kind != "regular" || record.Size == nil || *record.Size > stage2aMaxFileBytes {
			return nil, errStage2aReservationAuthority
		}
		file, before, err := stage2aOpenSourceFile(int(root.Fd()), record.Path,
			identity.OwnerUID, identity.OwnerGID, record, false)
		if err != nil {
			return nil, errStage2aReservationAuthority
		}
		if err := checkDarwinACLs([]string{filepath.Join(identity.RootPath, record.Path)}); err != nil {
			file.Close()
			return nil, errStage2aReservationAuthority
		}
		hash := sha256.New()
		_, readErr := io.CopyN(hash, file, int64(*record.Size))
		var extra [1]byte
		n, extraErr := file.Read(extra[:])
		var after unix.Stat_t
		statErr := unix.Fstat(int(file.Fd()), &after)
		closeErr := file.Close()
		if readErr != nil || n != 0 || extraErr != io.EOF || statErr != nil || closeErr != nil ||
			!stage2aSameNode(before, after) || fmt.Sprintf("%x", hash.Sum(nil)) != record.SHA256 {
			return nil, errStage2aReservationAuthority
		}
		birthtime, err := stage2aInstalledBirthtimeNS(after)
		if err != nil || after.Ino == 0 || after.Nlink != 1 {
			return nil, errStage2aReservationAuthority
		}
		rows = append(rows, stage2aInstalledInputRowV3{
			Scope: scope, Path: record.Path, SizeBytes: *record.Size, Mode: record.Mode,
			SHA256: record.SHA256, OwnerUID: after.Uid, OwnerGID: after.Gid,
			Device:      strconv.FormatUint(uint64(uint32(after.Dev)), 10),
			Inode:       strconv.FormatUint(after.Ino, 10),
			Generation:  strconv.FormatUint(uint64(after.Gen), 10),
			BirthtimeNS: birthtime, LinkCount: uint32(after.Nlink), ACLAllowCount: 0,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	var afterRoot unix.Stat_t
	if unix.Fstat(int(root.Fd()), &afterRoot) != nil || !stage2aSameNode(beforeRoot, afterRoot) {
		return nil, errStage2aReservationAuthority
	}
	return rows, nil
}

// buildStage2aInstalledInputEvidenceV3 prepares exact nested blobs and the
// compact wrapper for a completed A-owned start. The physical segment issuer
// must still prove its own A custody and sign the wrapper's digest; no caller
// may treat this unsigned return value as a protected qualification result.
func buildStage2aInstalledInputEvidenceV3(a stage2aAdminSnapshots,
	binding Stage2aMeasurementBinding, definition []Stage2aDefinitionRecord,
	launch Stage2aLaunchInputRecords) (stage2aInstalledInputEvidenceV3, error) {
	var zero stage2aInstalledInputEvidenceV3
	if a.check() != nil || binding.Snapshots.Definition.OwnerUID != a.uid ||
		binding.Snapshots.LaunchInputs.OwnerUID != a.uid ||
		binding.Snapshots.Definition.OwnerGID != a.runnerReadGID ||
		binding.Snapshots.LaunchInputs.OwnerGID != a.runnerReadGID ||
		binding.Snapshots.Definition.RootPath == binding.Snapshots.LaunchInputs.RootPath ||
		!stage2aSelectedCommandRecorded(binding, definition, launch) {
		return zero, errStage2aReservationAuthority
	}
	_, bindingRaw, err := stage2aBindingDigestForOwner(binding, a.uid)
	if err != nil || binding.SoulArtifactSHA256 == "" {
		return zero, errStage2aReservationAuthority
	}
	definitionDigest, definitionRaw, err := Stage2aDefinitionDigest(definition)
	if err != nil || definitionDigest != binding.DefinitionMeasurement {
		return zero, errStage2aReservationAuthority
	}
	launchDigest, launchRaw, err := Stage2aLaunchInputDigest(launch)
	if err != nil || launchDigest != binding.LaunchInputMeasurement ||
		launch.EffectiveConfig["profile"] != binding.ProfileInForce {
		return zero, errStage2aReservationAuthority
	}
	if observed, err := observeStage2aAdminSnapshot(a,
		filepath.Base(binding.Snapshots.Definition.RootPath), binding.Snapshots.Definition, definition); err != nil || observed != definitionDigest ||
		observeInstalledStage2aLaunchInputs(a, binding, launch) != nil {
		return zero, errStage2aReservationAuthority
	}
	definitionRows, err := stage2aObserveInstalledInputRows(binding.Snapshots.Definition, definition, "definition")
	if err != nil {
		return zero, errStage2aReservationAuthority
	}
	launchRows, err := stage2aObserveInstalledInputRows(binding.Snapshots.LaunchInputs, launch.Files, "launch")
	if err != nil {
		return zero, errStage2aReservationAuthority
	}
	if observed, err := observeStage2aAdminSnapshot(a,
		filepath.Base(binding.Snapshots.Definition.RootPath), binding.Snapshots.Definition, definition); err != nil || observed != definitionDigest ||
		observeInstalledStage2aLaunchInputs(a, binding, launch) != nil {
		return zero, errStage2aReservationAuthority
	}
	adapters, err := stage2aReadProjectedFile(binding.Snapshots.LaunchInputs, launch.Files, "host/adapters.json")
	if err != nil {
		return zero, errStage2aReservationAuthority
	}
	installation, err := stage2aReadProjectedFile(binding.Snapshots.LaunchInputs, launch.Files, "host/installation.json")
	if err != nil || CheckStage2aHostProjectionBytes(launch, adapters, installation) != nil {
		return zero, errStage2aReservationAuthority
	}
	blobs := map[string][]byte{"definition_records": definitionRaw, "launch_input_records": launchRaw,
		"host_adapters_json": adapters, "host_installation_json": installation}
	rows := append(definitionRows, launchRows...)
	slices.SortFunc(rows, func(x, y stage2aInstalledInputRowV3) int {
		return strings.Compare(x.Scope+"/"+x.Path, y.Scope+"/"+y.Path)
	})
	inventory := stage2aInstalledInputInventoryV3{
		SchemaVersion: 1, Kind: "stage2a-installed-inputs", InstallationID: binding.InstallationID,
		SoulID: binding.SoulID, StartID: binding.StartID, LaunchID: binding.LaunchID,
		HostID: binding.HostID, Profile: binding.ProfileInForce, PlanID: binding.PlanID,
		InstalledPlanDigest:      binding.InstalledPlanDigest,
		MeasurementBindingSHA256: stage2aQualificationSHA256(bindingRaw),
		DefinitionRecords:        stage2aInstalledInputRef("definition_records", definitionRaw),
		LaunchInputRecords:       stage2aInstalledInputRef("launch_input_records", launchRaw),
		HostAdaptersJSON:         stage2aInstalledInputRef("host_adapters_json", adapters),
		HostInstallationJSON:     stage2aInstalledInputRef("host_installation_json", installation),
		DefinitionSnapshot:       binding.Snapshots.Definition,
		LaunchInputsSnapshot:     binding.Snapshots.LaunchInputs,
		OpenedFiles:              rows, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	raw, err := marshalStage2aReservationJCS(inventory)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 || len(rows) == 0 || len(rows) > 576 ||
		stage2aStrictJSON(raw) != nil || !json.Valid(raw) {
		return zero, errors.New("Stage 2a installed input inventory exceeds fixed wire bounds")
	}
	return stage2aInstalledInputEvidenceV3{inventory: raw,
		sha256: stage2aQualificationSHA256(raw), blobs: blobs}, nil
}
