package qualification_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/qwts/managed-machine/internal/members"
	"github.com/qwts/managed-machine/internal/qualification"
)

func measuredDefinitionFixtureV3() []members.Stage2aDefinitionRecord {
	size2, size17 := uint64(2), uint64(17)
	return []members.Stage2aDefinitionRecord{
		{Path: "Contents", Kind: "directory", Mode: "0555"},
		{Path: "Contents/SoulInfo.json", Kind: "regular", Mode: "0444", Size: &size2, SHA256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		{Path: "Contents/SoulLock.json", Kind: "regular", Mode: "0444", Size: &size2, SHA256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		{Path: "Contents/opt", Kind: "directory", Mode: "0555"},
		{Path: "Contents/opt/quickstart-adapter.mjs", Kind: "regular", Mode: "0555", Size: &size17, SHA256: "56332e0a55734bc2b73df56a2df8635ed5c5b24b6d7a456b41de7cab9a2f3814"},
		{Path: "Contents/opt/quickstart-check.mjs", Kind: "regular", Mode: "0555", Size: &size17, SHA256: "a903ba200e1d43efd9a49f4a8f57c622efb2ca72b9a00222dacd16d6ba6f3ba0"},
		{Path: "Contents/primitives", Kind: "directory", Mode: "0555"},
		{Path: "Contents/primitives/quickstart-task.json", Kind: "regular", Mode: "0444", Size: &size2, SHA256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
	}
}

func TestOfflineMeasurementDigestsMatchMachineByteVectorsV3(t *testing.T) {
	definitionDigest, definitionRaw, err := members.Stage2aDefinitionDigest(measuredDefinitionFixtureV3())
	if err != nil {
		t.Fatal(err)
	}
	launchFixture, err := os.ReadFile("../members/testdata/stage2a-launch-inputs.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var launch struct {
		Input members.Stage2aLaunchInputRecords `json:"input"`
	}
	if err := json.Unmarshal(launchFixture, &launch); err != nil {
		t.Fatal(err)
	}
	launchDigest, launchRaw, err := members.Stage2aLaunchInputDigest(launch.Input)
	if err != nil {
		t.Fatal(err)
	}
	reportRaw, err := os.ReadFile("testdata/stage2a-report-v3-protected-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		MeasurementBinding json.RawMessage `json:"measurement_binding"`
	}
	if err := json.Unmarshal(reportRaw, &report); err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(report.MeasurementBinding, &binding); err != nil {
		t.Fatal(err)
	}
	if binding["definition_measurement"] != definitionDigest || binding["launch_input_measurement"] != launchDigest {
		t.Fatal("Machine source vectors do not match the v3 signed-report fixture")
	}
	got, err := qualification.VerifyMeasurementRecordDigestsV3(report.MeasurementBinding, definitionRaw, launchRaw)
	if err != nil || got.DefinitionMeasurementSHA256 != definitionDigest || got.LaunchInputMeasurementSHA256 != launchDigest {
		t.Fatalf("offline verifier disagrees with Machine's canonical records: %+v %v", got, err)
	}
	if _, err := qualification.VerifyMeasurementRecordDigestsV3(report.MeasurementBinding, append(bytes.Clone(definitionRaw), '\n'), launchRaw); err == nil {
		t.Fatal("noncanonical definition newline accepted")
	}
	changedLaunch := bytes.Replace(launchRaw, []byte("managed-protected"), []byte("managed-cooperative"), 1)
	if bytes.Equal(changedLaunch, launchRaw) {
		t.Fatal("fixture lacks protected profile")
	}
	if _, err := qualification.VerifyMeasurementRecordDigestsV3(report.MeasurementBinding, definitionRaw, changedLaunch); err == nil {
		t.Fatal("changed canonical launch inputs accepted against old binding")
	}
	plain := sha256.Sum256(launchRaw)
	binding["launch_input_measurement"] = "sha256:" + hex.EncodeToString(plain[:])
	wrongPurpose, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qualification.VerifyMeasurementRecordDigestsV3(wrongPurpose, definitionRaw, launchRaw); err == nil {
		t.Fatal("ordinary SHA-256 accepted without launch-input purpose")
	}
	duplicate := []byte(`{"files":[],"files":[]}`)
	sum := sha256.Sum256(append([]byte("agent-bot/stage2a-launch-inputs/v1\x00"), duplicate...))
	binding["launch_input_measurement"] = "sha256:" + hex.EncodeToString(sum[:])
	duplicateBinding, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qualification.VerifyMeasurementRecordDigestsV3(duplicateBinding, definitionRaw, duplicate); err == nil {
		t.Fatal("duplicate-key launch record accepted with matching digest")
	}
}
