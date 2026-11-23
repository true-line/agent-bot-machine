//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestStage2aCooperativeRSealRequestKeepsFixedCustody(t *testing.T) {
	const installationID = "cooperative-seal-test"
	namespace, err := stage2aFrozenNamespace(installationID)
	if err != nil {
		t.Fatal(err)
	}
	approved := stage2aSyntheticRecords()
	digest, _, err := Stage2aDefinitionDigest(approved)
	if err != nil {
		t.Fatal(err)
	}
	base := stage2aSharedSealRequest{
		Schema: stage2aSharedSealSchema, Purpose: stage2aCooperativeRSealPurpose,
		MachineAccount: "_abm-admin", MachineUID: 401, MachineGID: 401,
		RunnerAccount: soulRunnerName(installationID), RunnerUID: 301, RunnerGID: 301,
		InstallationID: installationID,
		Namespace: stage2aInstalledDirectory{Path: namespace, Device: 1, Inode: "123",
			BirthSeconds: 1, BirthNanoseconds: 1},
		LauncherSHA256: strings.Repeat("a", 64),
		Prepared:       stage2aPreparedSnapshot{WrapperPath: filepath.Join(namespace, ".stage2a-private"), Digest: digest},
		Approved:       approved, ApprovedDigest: digest,
	}
	if err := base.validate(); err != nil {
		t.Fatalf("reviewed cooperative R handoff refused: %v", err)
	}
	for name, change := range map[string]func(*stage2aSharedSealRequest){
		"wrong purpose":    func(r *stage2aSharedSealRequest) { r.Purpose = "agent-bot/stage2a-protected-seal/v1" },
		"wrong schema":     func(r *stage2aSharedSealRequest) { r.Schema = stage2aInstallSealSchema },
		"wrong namespace":  func(r *stage2aSharedSealRequest) { r.Namespace.Path += "-other" },
		"wrong runner":     func(r *stage2aSharedSealRequest) { r.RunnerAccount = "_abm-sr-other" },
		"wrong group":      func(r *stage2aSharedSealRequest) { r.RunnerGID++ },
		"wrong executable": func(r *stage2aSharedSealRequest) { r.LauncherSHA256 = "" },
		"wrong inventory": func(r *stage2aSharedSealRequest) {
			r.Approved = stage2aSyntheticRecords()
			r.Approved[5].SHA256 = strings.Repeat("b", 64)
		},
		"wrong digest":         func(r *stage2aSharedSealRequest) { r.ApprovedDigest = "sha256:" + strings.Repeat("b", 64) },
		"wrong staging parent": func(r *stage2aSharedSealRequest) { r.Prepared.WrapperPath = "/tmp/.stage2a-other" },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			change(&request)
			if request.validate() == nil {
				t.Fatal("unreviewed cooperative R seal accepted")
			}
		})
	}
}

func TestStage2aCooperativeInputsSealBindsRuntimeFileDigest(t *testing.T) {
	const installationID = "cooperative-inputs-test"
	namespace, err := stage2aFrozenNamespace(installationID)
	if err != nil {
		t.Fatal(err)
	}
	size := uint64(2)
	files := []Stage2aDefinitionRecord{
		{Path: "host/adapters.json", Kind: "regular", Mode: "0444", Size: &size,
			SHA256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		{Path: "host/installation.json", Kind: "regular", Mode: "0444", Size: &size,
			SHA256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
	}
	expanded, err := stage2aExpandedRuntimeRecords(files)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(expanded)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	r := stage2aSharedSealRequest{Schema: stage2aSharedSealSchema,
		Purpose: stage2aCooperativeInputsSealPurpose, Kind: "inputs",
		MachineAccount: "_abm-admin", MachineUID: 401, MachineGID: 401,
		RunnerAccount: soulRunnerName(installationID), RunnerUID: 301, RunnerGID: 301,
		InstallationID: installationID,
		Namespace: stage2aInstalledDirectory{Path: namespace, Device: 1, Inode: "123",
			BirthSeconds: 1, BirthNanoseconds: 1},
		LauncherSHA256: strings.Repeat("a", 64),
		Prepared:       stage2aPreparedSnapshot{WrapperPath: filepath.Join(namespace, ".stage2a-private"), Digest: digest},
		Approved:       files, ApprovedDigest: digest}
	if err := r.validate(); err != nil {
		t.Fatalf("reviewed input seal refused: %v", err)
	}
	r.Purpose = stage2aCooperativeDefinitionSealPurpose
	if r.validate() == nil {
		t.Fatal("definition purpose accepted input files")
	}
}
