//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

func (s *Stage2aService) List(hqUID int, epoch string) (Stage2aListReply, error) {
	reply := Stage2aListReply{Installations: []Stage2aInstalledAssignment{}}
	if len(s.key) != ed25519.PrivateKeySize || !soulHQEpoch.MatchString(epoch) {
		return reply, errStage2aReservationAuthority
	}
	reply.MachinePublicKey = hex.EncodeToString(s.key.Public().(ed25519.PublicKey))
	dir, err := openStage2aAdminDirectory(stage2aAuthorityDirectory, uint32(os.Getuid()))
	if errors.Is(err, unix.ENOENT) {
		// No authority directory exists before the first paired root install.
		// The public key is needed to review that exact install, and returning
		// no policies cannot authorize a launch.
		return reply, nil
	}
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	defer dir.Close()
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != uint32(os.Getuid()) || st.Gid != uint32(os.Getgid()) {
		return reply, errStage2aReservationAuthority
	}
	names, err := dir.Readdirnames(17)
	if err != nil && err != io.EOF || len(names) > 16 {
		return reply, errStage2aReservationAuthority
	}
	seenPackage := map[string]bool{}
	seenInstallation := map[string]bool{}
	for _, name := range names {
		if len(name) != 25 || !strings.HasSuffix(name, ".json") {
			return Stage2aListReply{}, errStage2aReservationAuthority
		}
		path := filepath.Join(stage2aAuthorityDirectory, name)
		raw, err := stage2aReadAdminPolicy(path, 1<<20)
		if err != nil || stage2aStrictJSON(raw) != nil {
			return Stage2aListReply{}, errStage2aReservationAuthority
		}
		var index struct {
			Binding Stage2aMeasurementBinding `json:"measurement_binding"`
		}
		if json.Unmarshal(raw, &index) != nil {
			return Stage2aListReply{}, errStage2aReservationAuthority
		}
		want, err := stage2aAuthorityPath(index.Binding.InstallationID)
		if err != nil || want != path {
			return Stage2aListReply{}, errStage2aReservationAuthority
		}
		p, checked, err := loadStage2aInstalledPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, index.Binding.InstallationID)
		if err != nil || !bytes.Equal(raw, checked) || seenPackage[p.Runner.PackageRoot] || seenInstallation[p.Binding.InstallationID] {
			return Stage2aListReply{}, errStage2aReservationAuthority
		}
		seenPackage[p.Runner.PackageRoot], seenInstallation[p.Binding.InstallationID] = true, true
		ends, err := DeriveSoulBridgeEndpoints(p.Runner, p.Bridge, p.HQUID, "st_000000000000000000000000")
		if err != nil {
			return Stage2aListReply{}, err
		}
		convert := func(e SoulEndpoint) Stage2aEndpointPolicy {
			return Stage2aEndpointPolicy{e.Directory, e.OwnerUID, e.GroupGID, e.DirMode, e.SocketMode}
		}
		_, providerSHA256, err := stage2aProviderConfig(p.BridgeQualification)
		if err != nil {
			return Stage2aListReply{}, err
		}
		reply.Installations = append(reply.Installations, Stage2aInstalledAssignment{
			InstallationID: p.Binding.InstallationID, SoulID: p.Binding.SoulID, PackageRoot: p.Runner.PackageRoot,
			PlanID: p.Binding.PlanID, PlanDigest: p.Binding.InstalledPlanDigest, HQEpoch: p.Binding.HQEpoch, HostID: p.Binding.HostID,
			MachineUID: p.MachineUID, HQUID: p.HQUID, RunnerAccount: p.Runner.Account, RunnerUID: p.Runner.UID, RunnerGID: p.Runner.GID,
			BridgeAccount: p.Bridge.Account, BridgeUID: p.Bridge.UID, BridgeGID: p.Bridge.GID,
			SoulArtifactSHA256: p.Binding.SoulArtifactSHA256, DefinitionDigest: p.Binding.DefinitionMeasurement,
			ClaimedDefinition: p.Binding.ClaimedDefinitionDigest, LaunchInputDigest: p.Binding.LaunchInputMeasurement,
			RootReceiptSHA256: stage2aReservationSHA256(p.Receipt), ProviderConfigSHA256: providerSHA256,
			Broker: convert(ends.Broker), Member: convert(ends.Member),
			Relay: convert(ends.Relay), Admission: convert(ends.Admission),
		})
	}
	slices.SortFunc(reply.Installations, func(a, b Stage2aInstalledAssignment) int { return strings.Compare(a.InstallationID, b.InstallationID) })
	return reply, nil
}
