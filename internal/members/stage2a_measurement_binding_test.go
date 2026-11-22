package members

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func stage2aBindingFixture(t *testing.T) (Stage2aMeasurementBinding, string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/stage2a-measurement-binding.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Input           Stage2aMeasurementBinding `json:"input"`
		CanonicalSHA256 string                    `json:"canonical_sha256"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Input, fixture.CanonicalSHA256
}

func cloneStage2aBinding(t *testing.T, value Stage2aMeasurementBinding) Stage2aMeasurementBinding {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy Stage2aMeasurementBinding
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func stage2aFixtureAssignment(b Stage2aMeasurementBinding) SoulStartAssignment {
	return SoulStartAssignment{
		Schema:         "agent-bot-machine/soul-start-assignment/v2",
		InstallationID: b.InstallationID, SoulID: b.SoulID,
		StartID: b.StartID, LaunchID: b.LaunchID,
		PlanID: b.PlanID, PlanDigest: b.InstalledPlanDigest,
		HQEpoch: b.HQEpoch, PackageSHA256: b.PackageSHA256,
	}
}

func TestStage2aBindingMatchesContractAndMeasuredStart(t *testing.T) {
	binding, want := stage2aBindingFixture(t)
	got, canonical, err := Stage2aBindingDigest(binding)
	if err != nil || got != want {
		t.Fatalf("binding vector differs: %s, %v", got, err)
	}
	if parsed, err := ParseStage2aMeasurementBinding(canonical); err != nil || parsed != binding {
		t.Fatalf("canonical binding did not parse: %v", err)
	}
	if checked, err := CheckStage2aMeasuredBinding(binding, stage2aSyntheticRecords(),
		stage2aLaunchFixture(t), stage2aFixtureAssignment(binding),
		binding.HostID, binding.ClaimedDefinitionDigest); err != nil || checked != want {
		t.Fatalf("measured start did not match: %s, %v", checked, err)
	}
}

func TestStage2aBindingSeparatesFrozenSoulArtifactDigest(t *testing.T) {
	legacy, legacyDigest := stage2aBindingFixture(t)
	withArtifact := cloneStage2aBinding(t, legacy)
	withArtifact.SoulArtifactSHA256 = strings.Repeat("a", 64)
	got, canonical, err := Stage2aBindingDigest(withArtifact)
	if err != nil || got == legacyDigest || !bytes.Contains(canonical, []byte(`"soul_artifact_sha256":"`+withArtifact.SoulArtifactSHA256+`"`)) {
		t.Fatalf("typed Soul artifact digest did not change canonical binding: %s, %v", got, err)
	}
	if parsed, err := ParseStage2aMeasurementBinding(canonical); err != nil || parsed != withArtifact {
		t.Fatalf("typed binding did not round trip: %v", err)
	}
	// Legacy assignment package_sha256 is a separate field and must not be
	// inferred from the new frozen .soul digest by this nonauthorizing helper.
	if _, err := CheckStage2aMeasuredBinding(withArtifact, stage2aSyntheticRecords(),
		stage2aLaunchFixture(t), stage2aFixtureAssignment(legacy),
		withArtifact.HostID, withArtifact.ClaimedDefinitionDigest); err != nil {
		t.Fatalf("typed binding changed legacy assignment semantics: %v", err)
	}
	withArtifact.SoulArtifactSHA256 = "sha256:" + strings.Repeat("a", 64)
	if _, _, err := Stage2aBindingDigest(withArtifact); err == nil {
		t.Fatal("prefixed frozen Soul artifact digest accepted")
	}
}

func TestStage2aBindingAcceptsRunnerGroupOnlyCommand(t *testing.T) {
	binding, _ := stage2aBindingFixture(t)
	launch := cloneStage2aLaunch(t, stage2aLaunchFixture(t))
	for i := range launch.Files {
		if launch.Files[i].Path == "bin/node" {
			launch.Files[i].Mode = "0550"
		}
	}
	binding.LaunchInputMeasurement, _, _ = Stage2aLaunchInputDigest(launch)
	if _, err := CheckStage2aMeasuredBinding(binding, stage2aSyntheticRecords(), launch,
		stage2aFixtureAssignment(binding), binding.HostID, binding.ClaimedDefinitionDigest); err != nil {
		t.Fatalf("runner-group executable refused: %v", err)
	}
	for i := range launch.Files {
		if launch.Files[i].Path == "bin/node" {
			launch.Files[i].Mode = "0544"
		}
	}
	binding.LaunchInputMeasurement, _, _ = Stage2aLaunchInputDigest(launch)
	if _, err := CheckStage2aMeasuredBinding(binding, stage2aSyntheticRecords(), launch,
		stage2aFixtureAssignment(binding), binding.HostID, binding.ClaimedDefinitionDigest); err == nil {
		t.Fatal("runner-group nonexecutable command accepted")
	}
}

func TestStage2aBindingRejectsInvalidContextAndCustodyClaims(t *testing.T) {
	base, _ := stage2aBindingFixture(t)
	for name, edit := range map[string]func(*Stage2aMeasurementBinding){
		"new schema":    func(b *Stage2aMeasurementBinding) { b.SchemaVersion = 2 },
		"wrong profile": func(b *Stage2aMeasurementBinding) { b.ProfileInForce = "ordinary" },
		"bad host ID":   func(b *Stage2aMeasurementBinding) { b.HostID = "bad host" },
		"prefixed live plan": func(b *Stage2aMeasurementBinding) {
			b.InstalledPlanDigest = "sha256:" + b.InstalledPlanDigest
		},
		"missing generation": func(b *Stage2aMeasurementBinding) { b.Snapshots.Definition.Generation = "" },
		"decimal overflow": func(b *Stage2aMeasurementBinding) {
			b.Snapshots.Definition.Inode = "99999999999999999999"
		},
		"runner owned":  func(b *Stage2aMeasurementBinding) { b.Snapshots.Definition.OwnerUID = 331 },
		"writable root": func(b *Stage2aMeasurementBinding) { b.Snapshots.Definition.Mode = "0755" },
		"path traversal": func(b *Stage2aMeasurementBinding) {
			b.Snapshots.Definition.RootPath += "/../other"
		},
		"same root": func(b *Stage2aMeasurementBinding) {
			b.Snapshots.LaunchInputs = b.Snapshots.Definition
		},
		"case alias root": func(b *Stage2aMeasurementBinding) {
			b.Snapshots.LaunchInputs.RootPath = strings.ToUpper(b.Snapshots.Definition.RootPath)
		},
		"nested roots": func(b *Stage2aMeasurementBinding) {
			b.Snapshots.LaunchInputs.RootPath = b.Snapshots.Definition.RootPath + "/child"
		},
		"same inode": func(b *Stage2aMeasurementBinding) {
			b.Snapshots.LaunchInputs.Inode = b.Snapshots.Definition.Inode
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneStage2aBinding(t, base)
			edit(&changed)
			if _, _, err := Stage2aBindingDigest(changed); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
	_, canonical, _ := Stage2aBindingDigest(base)
	for name, raw := range map[string][]byte{
		"trailing newline": append(bytes.Clone(canonical), '\n'),
		"unknown key":      bytes.Replace(bytes.Clone(canonical), []byte(`"contract":`), []byte(`"extra":1,"contract":`), 1),
		"duplicate key":    bytes.Replace(bytes.Clone(canonical), []byte(`"contract":`), []byte(`"contract":"machine/v1","contract":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseStage2aMeasurementBinding(raw); err == nil {
				t.Fatal("noncanonical or ambiguous binding accepted")
			}
		})
	}
}

func TestStage2aBindingRejectsChangedMeasurementsAndCommand(t *testing.T) {
	binding, _ := stage2aBindingFixture(t)
	definition := stage2aSyntheticRecords()
	launch := stage2aLaunchFixture(t)
	assignment := stage2aFixtureAssignment(binding)
	check := func(name string, b Stage2aMeasurementBinding, d []Stage2aDefinitionRecord,
		l Stage2aLaunchInputRecords, a SoulStartAssignment, host, claim string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if _, err := CheckStage2aMeasuredBinding(b, d, l, a, host, claim); err == nil {
				t.Fatal("changed measured start accepted")
			}
		})
	}
	changedDefinition := stage2aSyntheticRecords()
	changedDefinition[5].SHA256 = strings.Repeat("a", 64)
	check("changed frozen bytes", binding, changedDefinition, launch, assignment, binding.HostID, binding.ClaimedDefinitionDigest)
	changedLaunch := cloneStage2aLaunch(t, launch)
	changedLaunch.Environment["TMPDIR"] += "-changed"
	check("changed launch environment", binding, definition, changedLaunch, assignment, binding.HostID, binding.ClaimedDefinitionDigest)
	command := cloneStage2aLaunch(t, launch)
	command.SelectedCommand = "/private/stage2a/snapshot-launch/bin/unlisted"
	command.Argv[0] = command.SelectedCommand
	bindingForCommand := cloneStage2aBinding(t, binding)
	bindingForCommand.LaunchInputMeasurement, _, _ = Stage2aLaunchInputDigest(command)
	check("unlisted command", bindingForCommand, definition, command, assignment, binding.HostID, binding.ClaimedDefinitionDigest)
	hostCommand := cloneStage2aLaunch(t, launch)
	hostCommand.SelectedCommand = "/private/stage2a/snapshot-launch/host/adapters.json"
	hostCommand.Argv[0] = hostCommand.SelectedCommand
	for i := range hostCommand.Files {
		if hostCommand.Files[i].Path == "host/adapters.json" {
			hostCommand.Files[i].Mode = "0555"
		}
	}
	bindingForHostCommand := cloneStage2aBinding(t, binding)
	bindingForHostCommand.LaunchInputMeasurement, _, _ = Stage2aLaunchInputDigest(hostCommand)
	check("host JSON as command", bindingForHostCommand, definition, hostCommand, assignment, binding.HostID, binding.ClaimedDefinitionDigest)
	check("wrong physical host", binding, definition, launch, assignment, "other-host", binding.ClaimedDefinitionDigest)
	check("wrong SoulLock claim", binding, definition, launch, assignment, binding.HostID, "sha256:"+strings.Repeat("c", 64))
	assignment.PlanDigest = strings.Repeat("d", 64)
	check("different assignment", binding, definition, launch, assignment, binding.HostID, binding.ClaimedDefinitionDigest)
}
