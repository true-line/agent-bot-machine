package members

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func stage2aHQTestService(t *testing.T) (HQService, []byte) {
	t.Helper()
	root := t.TempDir()
	digest := "sha256:" + strings.Repeat("0", 64)
	svc := HQService{Archive: filepath.Join(root, "hq.tar"), ReleaseDir: filepath.Join(root, "hq"), Node: filepath.Join(root, "node"), ArtifactSHA256: digest[7:],
		Stage2a: &hqStage2aService{HostID: "test-host", RuntimeInstallationID: "test-runtime", InstallationID: "test-install", MachineAccount: "test-owner", MachineUID: 501, MachineGID: 20,
			ReaderUID: 309, ReaderGID: 309, AuthorityKeySHA256: digest, PreloaderPath: hqStage2aPreloader, InventorySource: "/fixture/release/h.jcs",
			InventoryLimits: stage2aDomainInventoryLimitsV3{MaxFiles: 10, MaxFileBytes: 100, MaxTotalBytes: 900},
			ContractsSource: hqStage2aContractsSource{Tag: "v0.10.0", Commit: strings.Repeat("a", 40),
				FullDigest: digest, FullFiles: 2, RuntimeDigest: digest, RuntimeFiles: 2},
			Components: []stage2aReleaseComponent{
				{ComponentID: "hq", SourceRepository: "fixture/hq", SourceCommit: strings.Repeat("1", 40), ArtifactSource: "/fixture/hq.tar", ArtifactSHA256: digest, ManifestSource: "/fixture/hq.jcs", ManifestSHA256: digest},
				{ComponentID: "node", SourceRepository: "fixture/node", SourceCommit: strings.Repeat("2", 40), ArtifactSource: "/fixture/node.tar", ArtifactSHA256: digest, ManifestSource: "/fixture/node.jcs", ManifestSHA256: digest},
			}}}
	rows := make([]stage2aDomainFileV3, 0, 10)
	var total uint64
	for _, relative := range []string{hqStage2aNode, hqStage2aHelper, hqStage2aEntry, svc.Stage2a.PreloaderPath, hqStage2aGuard,
		hqStage2aCooperativeMachine, hqStage2aCooperativeProof, hqStage2aCooperativeStart,
		hqStage2aCooperativeBridge, hqStage2aCooperativeInstall} {
		contents := []byte("fixture " + relative + "\n")
		hash := fmt.Sprintf("sha256:%x", sha256.Sum256(contents))
		path, component, mode := filepath.Join(svc.ReleaseDir, relative), "hq", "0440"
		if relative == hqStage2aNode {
			path, component, mode = svc.Node, "node", "0550"
			svc.NodeSHA256 = hash[7:]
		}
		if relative == hqStage2aGuard {
			svc.Stage2a.GuardModuleSHA256 = hash
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, stage2aDomainFileV3{Path: relative, ReleasePath: relative, Kind: "regular", Mode: mode, ComponentID: component, SizeBytes: uint64(len(contents)), SHA256: hash})
		total += uint64(len(contents))
	}
	slices.SortFunc(rows, func(a, b stage2aDomainFileV3) int { return cmp.Compare(a.Path, b.Path) })
	raw, err := json.Marshal(stage2aDomainInventoryV3{Contract: "machine/v3", Kind: "stage2a-domain-inventory", SchemaVersion: 3, InstallationID: svc.Stage2a.InstallationID, Domain: "H-code", Limits: svc.Stage2a.InventoryLimits, Files: rows, TotalBytes: total,
		Directories: []stage2aDomainDirectoryV3{{Path: "bin", Kind: "directory", Mode: "0550"}, {Path: "helpers", Kind: "directory", Mode: "0550"}, {Path: "hq", Kind: "directory", Mode: "0550"}}})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err = stage2aDomainInventoryDigestV3(canonical)
	if err != nil {
		t.Fatal(err)
	}
	svc.Stage2a.InventoryDigest = digest
	return svc, canonical
}

func TestStage2aHQPlanPinsExactProtectedLaunchArgv(t *testing.T) {
	svc, _ := stage2aHQTestService(t)
	if err := svc.Stage2a.validate(); err != nil {
		t.Fatal(err)
	}
	owner := "review-owner"
	launch, err := svc.Stage2a.launch(owner, svc.Stage2a.AuthorityKeySHA256)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/ruby", "--disable-gems", path.Join(launch.Root, hqStage2aHelper), "launch", path.Join(launch.Root, hqStage2aNode),
		"--no-addons", "--disallow-code-generation-from-strings", "--import", path.Join(launch.Root, svc.Stage2a.PreloaderPath),
		path.Join(launch.Root, hqStage2aEntry), "run", "--home", launchState, "--owner-account", owner}
	if !slices.Equal(launch.RuntimeArgv, want[4:]) || !slices.Equal(launch.OuterArgv, want) || launch.PublicKeyPath != SoulAuthorityPin ||
		launch.InventoryPath == launch.Root || path.Dir(launch.InventoryPath) != path.Dir(launch.Root) || launch.DescriptorPath != hqStage2aDescriptor ||
		launch.GuardModulePath != path.Join(launch.Root, hqStage2aGuard) {
		t.Fatalf("unexpected launch: %+v", launch)
	}
	base := renderLaunchPlist(svc, 501, owner, launchControlV2)
	protected := renderHQStage2aPlist(base, launch.OuterArgv)
	var plist struct {
		Args []string `xml:"dict>array>string"`
	}
	if err := xml.Unmarshal([]byte(protected), &plist); err != nil || !slices.Equal(plist.Args, want) {
		t.Fatalf("%v, plist arguments %v", err, plist.Args)
	}
	if strings.Contains(base, "--no-addons") || strings.Contains(base, launch.Root) || !strings.Contains(protected, launchRuntimeSocket) {
		t.Fatal("protected launch changed the base service or owner-control endpoint")
	}
}

func TestStage2aHQPlanRequiresReviewedContractsSourcePins(t *testing.T) {
	svc, _ := stage2aHQTestService(t)
	if err := svc.Stage2a.validate(); err != nil {
		t.Fatal(err)
	}
	withSubset := *svc.Stage2a
	withSubset.ExcludedHQReleasePaths = hqStage2aContractsFixturePathsV010[:]
	withSubset.ContractsSource.FullFiles = 438
	withSubset.ContractsSource.RuntimeFiles = 422
	if err := withSubset.validate(); err != nil {
		t.Fatalf("reviewed H subset refused: %v", err)
	}
	withSuccessor := withSubset
	withSuccessor.ExcludedHQReleasePaths = hqStage2aContractsFixturePathsV0101[:]
	withSuccessor.ContractsSource.Tag = "v0.10.1"
	withSuccessor.ContractsSource.FullFiles = 446
	withSuccessor.ContractsSource.RuntimeFiles = 418
	if err := withSuccessor.validate(); err != nil {
		t.Fatalf("reviewed v0.10.1 H subset refused: %v", err)
	}
	withQWire := withSuccessor
	withQWire.ExcludedHQReleasePaths = hqStage2aContractsFixturePathsV0102[:]
	withQWire.ContractsSource.Tag = "v0.10.2"
	withQWire.ContractsSource.FullFiles = 469
	withQWire.ContractsSource.RuntimeFiles = 417
	if err := withQWire.validate(); err != nil {
		t.Fatalf("candidate v0.10.2 H subset refused: %v", err)
	}
	for _, mismatch := range []struct {
		tag   string
		paths []string
		full  int
	}{
		{"v0.10.2", hqStage2aContractsFixturePathsV0101[:], 469},
		{"v0.10.1", hqStage2aContractsFixturePathsV0102[:], 446},
		{"v0.10.3", hqStage2aContractsFixturePathsV0102[:], 469},
	} {
		candidate := withQWire
		candidate.ContractsSource.Tag = mismatch.tag
		candidate.ExcludedHQReleasePaths = mismatch.paths
		candidate.ContractsSource.FullFiles = mismatch.full
		candidate.ContractsSource.RuntimeFiles = mismatch.full - len(mismatch.paths)
		if err := candidate.validate(); err == nil {
			t.Fatalf("accepted unreviewed Contracts tag and fixture partition: %s", candidate.ContractsSource.Tag)
		}
	}
	for _, change := range []func(*hqStage2aContractsSource){
		func(p *hqStage2aContractsSource) { p.Tag = "" },
		func(p *hqStage2aContractsSource) { p.Commit = "" },
		func(p *hqStage2aContractsSource) { p.FullDigest = "" },
		func(p *hqStage2aContractsSource) { p.RuntimeDigest = "" },
		func(p *hqStage2aContractsSource) { p.RuntimeFiles = p.FullFiles + 1 },
	} {
		candidate := *svc.Stage2a
		change(&candidate.ContractsSource)
		if err := candidate.validate(); err == nil {
			t.Fatal("accepted a Stage 2a HQ plan without coherent Contracts source pins")
		}
	}
}

func TestStage2aHQV010ExcludesOnlyReviewedSyntheticFixtures(t *testing.T) {
	final := hqStage2aContractsFixturePathsV010[:]
	if len(final) != 16 || !slices.IsSorted(final) || !hqStage2aValidExclusions(final) {
		t.Fatal("final Contracts fixture partition is not exact and ordered")
	}
	changed := slices.Clone(final)
	changed[0] = "vendor/soul-contracts/schemas/machine/v3/required.schema.json"
	if hqStage2aValidExclusions(changed) || hqStage2aValidExclusions(final[:15]) {
		t.Fatal("unreviewed or missing fixture omission accepted")
	}
}

func TestStage2aHQV0101ExcludesOnlyReviewedFixtures(t *testing.T) {
	final := hqStage2aContractsFixturePathsV0101[:]
	if len(final) != 28 || !slices.IsSorted(final) || !hqStage2aValidExclusions(final) {
		t.Fatal("v0.10.1 Contracts fixture partition is not exact and ordered")
	}
	changed := slices.Clone(final)
	changed[0] = "vendor/soul-contracts/schemas/machine/v3/required.schema.json"
	if hqStage2aValidExclusions(changed) || hqStage2aValidExclusions(final[:27]) {
		t.Fatal("unreviewed or missing v0.10.1 fixture omission accepted")
	}
}

func TestStage2aHQV0102ExcludesOnlyReviewedFixtures(t *testing.T) {
	final := hqStage2aContractsFixturePathsV0102[:]
	if len(final) != 52 || !slices.IsSorted(final) || !hqStage2aValidExclusions(final) {
		t.Fatal("v0.10.2 Contracts fixture partition is not exact and ordered")
	}
	changed := slices.Clone(final)
	changed[0] = "vendor/soul-contracts/schemas/machine/v3/stage2a-q-ready.schema.json"
	if hqStage2aValidExclusions(changed) || hqStage2aValidExclusions(final[:51]) {
		t.Fatal("unreviewed or missing v0.10.2 fixture omission accepted")
	}
}

func TestStage2aHQV0102BrokeredExcludesOnlyReviewedFixtures(t *testing.T) {
	final := hqStage2aContractsFixturePathsV0102Brokered[:]
	if len(final) != 107 || !slices.IsSorted(final) ||
		!hqStage2aValidExclusionsForTag("v0.10.2", final) || !hqStage2aValidExclusions(final) {
		t.Fatal("brokered v0.10.2 fixture partition is not exact and ordered")
	}
	changed := slices.Clone(final)
	changed[0] = "vendor/soul-contracts/schemas/machine/v3/stage2a-q-ready.schema.json"
	if hqStage2aValidExclusionsForTag("v0.10.2", changed) ||
		hqStage2aValidExclusionsForTag("v0.10.2", final[:106]) {
		t.Fatal("unreviewed or missing brokered fixture omission accepted")
	}
}

func TestStage2aHQPlanRefusesFirstInstallAndLinux(t *testing.T) {
	svc, _ := stage2aHQTestService(t)
	for _, platform := range []string{PlatformDarwin, ""} {
		if _, err := Build(Input{Platform: platform, HQAccount: DefaultHQAccountFor(platform), HQService: &svc}, bare()); err == nil || !strings.Contains(err.Error(), "paired macOS service upgrade") {
			t.Fatalf("%q: %v", platform, err)
		}
	}
}

func TestStage2aHQSelectsAuthenticatedDarwinHelper(t *testing.T) {
	svc, inventory := stage2aHQTestService(t)
	if _, err := verifyHQStage2aReleaseRows(svc, inventory); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(svc.ReleaseDir, hqStage2aHelper)
	contents, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	contents[0] ^= 1
	if err := os.WriteFile(helper, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyHQStage2aReleaseRows(svc, inventory); err == nil {
		t.Fatal("accepted changed Ruby helper bytes at the approved location")
	}
}

func TestStage2aHQRequiresEntrypointCooperativeImports(t *testing.T) {
	svc, inventory := stage2aHQTestService(t)
	for _, name := range []string{hqStage2aCooperativeMachine, hqStage2aCooperativeProof,
		hqStage2aCooperativeStart, hqStage2aCooperativeBridge, hqStage2aCooperativeInstall} {
		path := filepath.Join(svc.ReleaseDir, name)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyHQStage2aReleaseRows(svc, inventory); err == nil {
			t.Fatalf("accepted H inventory without required %s", name)
		}
		if err := os.WriteFile(path, []byte("fixture "+name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStage2aHQCandidateSkipsDirectRoleProbe(t *testing.T) {
	for _, rec := range []launchRecord{{Stage2a: &hqStage2aLaunch{}}, {Service: HQService{Stage2a: &hqStage2aService{}}}} {
		if err := probeBaseHQRole(rec, func() error {
			t.Fatal("protected candidate ran a raw H role probe outside its sealed argv")
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	want := errors.New("base probe refused")
	if err := probeBaseHQRole(launchRecord{}, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("base candidate lost its original probe: %v", err)
	}
}

func TestStage2aHQOptionalReleaseTagRejectsNullAndEmpty(t *testing.T) {
	for _, raw := range []string{`{"source_tag":null}`, `{"source_tag":""}`, `{"source_tag":42}`} {
		var component stage2aReleaseComponent
		if err := json.Unmarshal([]byte(raw), &component); err == nil {
			t.Fatalf("accepted an invalid source tag in %s", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"source_tag":"v1.2.3"}`} {
		var component stage2aReleaseComponent
		if err := json.Unmarshal([]byte(raw), &component); err != nil {
			t.Fatalf("refused optional source tag in %s: %v", raw, err)
		}
	}
}
