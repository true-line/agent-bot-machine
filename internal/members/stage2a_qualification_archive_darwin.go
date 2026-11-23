//go:build darwin

package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// stage2aQualificationArchiveDirectory opens or creates one A-private archive
// directory beneath an already pinned A store. The prefix is a single fixed
// name, never a path supplied by Q, R, HQ or an archive reference.
func stage2aQualificationArchiveDirectory(parent *os.File, name string,
	uid, gid uint32) (*os.File, error) {
	if name == "" || strings.ContainsAny(name, "/\\.") {
		return nil, errStage2aReservationAuthority
	}
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, errStage2aReservationAuthority
	}
	fd, err := unix.Openat(int(parent.Fd()), name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	child := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	var st unix.Stat_t
	path := child.Name()
	actual, pathErr := stage2aFDPath(fd)
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFDIR|0700 ||
		st.Uid != uid || st.Gid != gid || actual != path || pathErr != nil ||
		checkDarwinACLs([]string{path}) != nil {
		child.Close()
		return nil, errStage2aReservationAuthority
	}
	return child, nil
}

func stage2aPublishQualificationObject(dir *os.File, raw []byte,
	uid, gid uint32, maximum int64) (string, error) {
	if len(raw) == 0 || int64(len(raw)) > maximum {
		return "", errStage2aReservationAuthority
	}
	hash := stage2aQualificationSHA256(raw)
	name := strings.TrimPrefix(hash, "sha256:")
	if len(name) != 64 || !stage2aQualificationHex(name) {
		return "", errStage2aReservationAuthority
	}
	prefix, err := stage2aQualificationArchiveDirectory(dir, name[:2], uid, gid)
	if err != nil {
		return "", errStage2aReservationAuthority
	}
	defer prefix.Close()
	if err := commitStage2aReservation(prefix, name, raw); err != nil &&
		!errors.Is(err, errStage2aReservationSpent) {
		return "", errStage2aReservationAuthority
	}
	if stage2aExactAdminRecord(prefix, name, uid, gid, raw, maximum) != nil {
		return "", errStage2aReservationAuthority
	}
	return "qualification://stage2a/blob/" + name, nil
}

// publishStage2aInstalledInputEvidenceV3 durably publishes only the compact
// A-observed inventory and its four nested blobs in the private claim-store
// archive. A later physical-segment issuer must bind the exact inventory
// digest after the signed idle stop. This function issues no signature, Q
// verdict, release qualification or protected-launch authority.
func publishStage2aInstalledInputEvidenceV3(store stage2aAdminClaimStore,
	evidence stage2aInstalledInputEvidenceV3) (string, string, error) {
	if len(evidence.inventory) == 0 || len(evidence.inventory) > 1<<20 ||
		len(evidence.blobs) != 4 || evidence.sha256 != stage2aQualificationSHA256(evidence.inventory) ||
		stage2aStrictJSON(evidence.inventory) != nil {
		return "", "", errStage2aReservationAuthority
	}
	var inventory stage2aInstalledInputInventoryV3
	if json.Unmarshal(evidence.inventory, &inventory) != nil ||
		inventory.SchemaVersion != 1 || inventory.Kind != "stage2a-installed-inputs" ||
		inventory.MeasurementBindingSHA256 == "" || inventory.InstallationID == "" ||
		inventory.StartID == "" || inventory.LaunchID == "" || inventory.HostID == "" {
		return "", "", errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(inventory)
	if err != nil || !bytes.Equal(canonical, evidence.inventory) {
		return "", "", errStage2aReservationAuthority
	}
	for _, item := range []struct {
		role string
		ref  stage2aInstalledInputRefV3
		max  int
	}{
		{"definition_records", inventory.DefinitionRecords, 4 << 20},
		{"launch_input_records", inventory.LaunchInputRecords, 1 << 20},
		{"host_adapters_json", inventory.HostAdaptersJSON, 64 << 10},
		{"host_installation_json", inventory.HostInstallationJSON, 64 << 10},
	} {
		raw, ok := evidence.blobs[item.role]
		if !ok || len(raw) == 0 || len(raw) > item.max ||
			item.ref != stage2aInstalledInputRef(item.role, raw) {
			return "", "", errStage2aReservationAuthority
		}
	}
	root, err := store.open()
	if err != nil {
		return "", "", errStage2aReservationAuthority
	}
	defer root.Close()
	objects, err := stage2aQualificationArchiveDirectory(root, "objects", store.uid, store.gid)
	if err != nil {
		return "", "", errStage2aReservationAuthority
	}
	defer objects.Close()
	sha256Dir, err := stage2aQualificationArchiveDirectory(objects, "sha256", store.uid, store.gid)
	if err != nil {
		return "", "", errStage2aReservationAuthority
	}
	defer sha256Dir.Close()
	for _, role := range []string{"definition_records", "launch_input_records",
		"host_adapters_json", "host_installation_json"} {
		if _, err := stage2aPublishQualificationObject(sha256Dir, evidence.blobs[role],
			store.uid, store.gid, 4<<20); err != nil {
			return "", "", errStage2aReservationAuthority
		}
	}
	uri, err := stage2aPublishQualificationObject(sha256Dir, evidence.inventory,
		store.uid, store.gid, 1<<20)
	if err != nil || store.checkDirectory(root) != nil {
		return "", "", errStage2aReservationAuthority
	}
	return uri, evidence.sha256, nil
}
