//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// LookupCooperativeInstalled lets HQ start from the user's .soul path. A
// derives all privileged selectors from its own installed authority files;
// a duplicate path or damaged authority refuses rather than picking one.
func (s *Stage2aService) LookupCooperativeInstalled(hqUID int, epoch string,
	q Stage2aLookupRequest, paired func(string, func() error) error) (SoulCooperativeLookupReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply SoulCooperativeLookupReplyV3
	if paired == nil || len(s.key) != ed25519.PrivateKeySize || !stage2aLookupPath(q.PackagePath) ||
		hqUID < 300 || hqUID > 399 || epoch == "" {
		return reply, errSoulCooperativeAuthority
	}
	installationID, err := findSoulCooperativeInstallation(q.PackagePath)
	if err != nil {
		return reply, errSoulCooperativeAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	installed, r, err := loadSoulCooperativeInstalledV3(key, hqUID, epoch, installationID)
	if err != nil || installed.Policy.SourcePackagePath != q.PackagePath {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err = paired(installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		current, verifiedR, e := loadSoulCooperativeInstalledV3(key, hqUID, epoch, installationID)
		if e != nil || !bytes.Equal(current.RootReceipt, installed.RootReceipt) ||
			current.PairCommitment != installed.PairCommitment ||
			stage2aRecheckVerifiedDomainV3(r) != nil ||
			stage2aRecheckVerifiedDomainV3(verifiedR) != nil {
			return errSoulCooperativeAuthority
		}
		var receipt Receipt
		if json.Unmarshal(current.RootReceipt, &receipt) != nil ||
			!ValidApproval(receipt.PlanID, receipt.PlanDigest) {
			return errSoulCooperativeAuthority
		}
		admission, e := cooperativeEndpoint(current.Policy, "st_000000000000000000000000")
		if e != nil {
			return errSoulCooperativeAuthority
		}
		broker, e := cooperativeBrokerEndpoint(current.Policy)
		if e != nil {
			return errSoulCooperativeAuthority
		}
		p := current.Policy
		reply = SoulCooperativeLookupReplyV3{SourcePackagePath: p.SourcePackagePath,
			InstallationID: p.Runner.InstallationID, PlanID: receipt.PlanID,
			PlanDigest: receipt.PlanDigest, HostID: p.HostID, HQEpoch: p.HQEpoch,
			HQInstallationID: p.HQInstallationID, HOwnerPlanDigest: p.HOwnerPlanDigest,
			RunnerUID: p.Runner.UID, RunnerGID: p.Runner.GID,
			AdmissionDir: admission.Directory, BrokerSocketPath: broker.SocketPath,
			AdapterTransport: p.AdapterTransport}
		return nil
	})
	if err != nil || !ran || reply.InstallationID == "" {
		return SoulCooperativeLookupReplyV3{}, errSoulCooperativeAuthority
	}
	return reply, nil
}

func findSoulCooperativeInstallation(sourcePackagePath string) (string, error) {
	dir, err := openStage2aAdminDirectory(stage2aCooperativeAuthorityDir, uint32(os.Getuid()))
	if err != nil {
		return "", errSoulCooperativeAuthority
	}
	defer dir.Close()
	names, err := dir.Readdirnames(8193)
	if err != nil && err != io.EOF || len(names) > 8192 {
		return "", errSoulCooperativeAuthority
	}
	var found string
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") || len(name) != 25 {
			continue
		}
		fd, e := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
		if e != nil {
			return "", errSoulCooperativeAuthority
		}
		f := os.NewFile(uintptr(fd), name)
		var before, after unix.Stat_t
		if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0400 ||
			before.Uid != uint32(os.Getuid()) || before.Gid != uint32(os.Getgid()) ||
			before.Nlink != 1 || before.Size < 1 || before.Size > 2<<20 ||
			checkDarwinACLs([]string{filepath.Join(stage2aCooperativeAuthorityDir, name)}) != nil {
			f.Close()
			return "", errSoulCooperativeAuthority
		}
		raw, e := io.ReadAll(io.LimitReader(f, (2<<20)+1))
		if e != nil || len(raw) != int(before.Size) || unix.Fstat(fd, &after) != nil ||
			!stage2aSameNode(before, after) ||
			stage2aStrictJSONBounded(raw, 2<<20, stage2aV3MaxJSONNodes) != nil {
			f.Close()
			return "", errSoulCooperativeAuthority
		}
		f.Close()
		var row soulCooperativeInstalledV3
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&row) != nil || dec.Decode(new(any)) != io.EOF ||
			row.Schema != stage2aCooperativeInstalledSchemaV3 ||
			!soulInstallationID.MatchString(row.Policy.Runner.InstallationID) ||
			name != soulEndpointInstallationSlot(row.Policy.Runner.InstallationID)+".json" {
			return "", errSoulCooperativeAuthority
		}
		if row.Policy.SourcePackagePath == sourcePackagePath {
			if found != "" {
				return "", errSoulCooperativeAuthority
			}
			found = row.Policy.Runner.InstallationID
		}
	}
	if found == "" {
		return "", errSoulCooperativeAuthority
	}
	return found, nil
}
