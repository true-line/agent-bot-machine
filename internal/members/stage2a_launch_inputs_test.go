package members

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func stage2aLaunchFixture(t *testing.T) Stage2aLaunchInputRecords {
	t.Helper()
	raw, err := os.ReadFile("testdata/stage2a-launch-inputs.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Input Stage2aLaunchInputRecords `json:"input"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Input
}

func cloneStage2aLaunch(t *testing.T, value Stage2aLaunchInputRecords) Stage2aLaunchInputRecords {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy Stage2aLaunchInputRecords
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestStage2aLaunchInputDigestMatchesSyntheticFullObject(t *testing.T) {
	input := stage2aLaunchFixture(t)
	got, canonical, err := Stage2aLaunchInputDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:2f861779b03affdd5fdc594a5d4ebee5e7d19bef2a433377d6b9b42ea31a7712"
	if got != want || len(canonical) == 0 || canonical[0] != '{' {
		t.Fatalf("launch-input object vector differs: %s", got)
	}
	if compared, err := CheckStage2aApprovedLaunchInputs(input, stage2aLaunchFixture(t)); err != nil || compared != want {
		t.Fatalf("matching exact owner object refused: %s, %v", compared, err)
	}
}

func TestStage2aLaunchInputDigestBindsEveryNonFileInput(t *testing.T) {
	baseline := stage2aLaunchFixture(t)
	want, _, err := Stage2aLaunchInputDigest(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Stage2aLaunchInputRecords){
		"argv":            func(v *Stage2aLaunchInputRecords) { v.Argv[2] = "--changed" },
		"environment":     func(v *Stage2aLaunchInputRecords) { v.Environment["TMPDIR"] += "-changed" },
		"profile":         func(v *Stage2aLaunchInputRecords) { v.EffectiveConfig["profile"] = "managed-cooperative" },
		"OS build":        func(v *Stage2aLaunchInputRecords) { v.SystemImages.BuildVersion += "x" },
		"image CDHash":    func(v *Stage2aLaunchInputRecords) { v.SystemImages.Selected[0].CDHash = strings.Repeat("3", 40) },
		"host projection": func(v *Stage2aLaunchInputRecords) { v.HostProjection.Installation["id"] = "other-installation" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneStage2aLaunch(t, baseline)
			edit(&changed)
			got, _, err := Stage2aLaunchInputDigest(changed)
			if err != nil || got == want {
				t.Fatalf("changed full object did not change digest: %s, %v", got, err)
			}
			if _, err := CheckStage2aApprovedLaunchInputs(changed, baseline); err == nil {
				t.Fatal("changed object matched approved object")
			}
		})
	}
}

func TestStage2aLaunchInputRejectsIncompleteOrUnboundedObject(t *testing.T) {
	base := stage2aLaunchFixture(t)
	for name, edit := range map[string]func(*Stage2aLaunchInputRecords){
		"missing broker":       func(v *Stage2aLaunchInputRecords) { delete(v.ComponentDigests, "comms_broker") },
		"unmeasured component": func(v *Stage2aLaunchInputRecords) { v.ComponentDigests["bridge"] = "sha256:" + strings.Repeat("a", 64) },
		"unmeasured policy":    func(v *Stage2aLaunchInputRecords) { v.SandboxPolicyDigest = "sha256:" + strings.Repeat("a", 64) },
		"argv zero mismatch":   func(v *Stage2aLaunchInputRecords) { v.Argv[0] = "/other/node" },
		"relative command":     func(v *Stage2aLaunchInputRecords) { v.SelectedCommand = "bin/node"; v.Argv[0] = "bin/node" },
		"parent traversal command": func(v *Stage2aLaunchInputRecords) {
			v.SelectedCommand = "/private/../node"
			v.Argv[0] = v.SelectedCommand
		},
		"writable file":            func(v *Stage2aLaunchInputRecords) { v.Files[0].Mode = "0777" },
		"reordered files":          func(v *Stage2aLaunchInputRecords) { v.Files[0], v.Files[1] = v.Files[1], v.Files[0] },
		"directory case alias":     func(v *Stage2aLaunchInputRecords) { v.Files[0].Path = "Bin/adapter" },
		"file directory collision": func(v *Stage2aLaunchInputRecords) { v.Files[0].Path = "bin" },
		"oversized file":           func(v *Stage2aLaunchInputRecords) { n := uint64(stage2aMaxFileBytes + 1); v.Files[0].Size = &n },
		"oversized host file": func(v *Stage2aLaunchInputRecords) {
			for i := range v.Files {
				if v.Files[i].Path == "host/adapters.json" {
					n := uint64(64<<10 + 1)
					v.Files[i].Size = &n
				}
			}
		},
		"missing host file": func(v *Stage2aLaunchInputRecords) {
			for i := range v.Files {
				if v.Files[i].Path == "host/installation.json" {
					v.Files = append(v.Files[:i], v.Files[i+1:]...)
					break
				}
			}
		},
		"bad environment key":   func(v *Stage2aLaunchInputRecords) { v.Environment["BAD-KEY"] = "x" },
		"bridge-only proof":     func(v *Stage2aLaunchInputRecords) { v.Environment["B_ONLY_TOKEN"] = "synthetic" },
		"unsupported profile":   func(v *Stage2aLaunchInputRecords) { v.EffectiveConfig["profile"] = "ordinary" },
		"missing image signing": func(v *Stage2aLaunchInputRecords) { v.SystemImages.Selected[0].SigningRequirement = "" },
		"image path case alias": func(v *Stage2aLaunchInputRecords) {
			alias := v.SystemImages.Selected[0]
			alias.Path = strings.ToUpper(alias.Path)
			v.SystemImages.Selected = append([]Stage2aSystemImage{alias}, v.SystemImages.Selected...)
		},
		"duplicate host key": func(v *Stage2aLaunchInputRecords) {
			v.HostProjection.Installation["raw"] = json.RawMessage(`{"x":1,"x":2}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneStage2aLaunch(t, base)
			edit(&changed)
			if _, _, err := Stage2aLaunchInputDigest(changed); err == nil {
				t.Fatal("invalid full launch-input object accepted")
			}
		})
	}
	if raw := []byte(`{"x":1,"x":2}`); stage2aStrictJSON(raw) == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	tooDeep := []byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18))
	if stage2aStrictJSON(tooDeep) == nil {
		t.Fatal("deep JSON accepted")
	}
	if stage2aStrictJSON([]byte(`{"value":9007199254740993}`)) == nil {
		t.Fatal("inexact JCS number accepted")
	}
	if stage2aStrictJSON([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}) == nil {
		t.Fatal("invalid UTF-8 JSON accepted")
	}
	// The object hash is domain separated from a plain JCS SHA-256.
	_, canonical, _ := Stage2aLaunchInputDigest(base)
	plain := sha256.Sum256(canonical)
	if plain == sha256.Sum256(append([]byte(stage2aLaunchPurpose+"\x00"), canonical...)) {
		t.Fatal("launch-input domain separation failed")
	}
}

func TestStage2aHostProjectionBindsRawFilesAndParsedValues(t *testing.T) {
	input := stage2aLaunchFixture(t)
	adapters := []byte(`{"selected":"fixture-adapter"}`)
	installation := []byte(`{"id":"fixture-installation"}`)
	if err := CheckStage2aHostProjectionBytes(input, adapters, installation); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"changed raw byte":        []byte(`{ "selected":"fixture-adapter"}`),
		"different value":         []byte(`{"selected":"different"}`),
		"duplicate key":           []byte(`{"selected":"fixture-adapter","selected":"other"}`),
		"array instead of object": []byte(`[]`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckStage2aHostProjectionBytes(input, raw, installation); err == nil {
				t.Fatal("changed host projection accepted")
			}
		})
	}
	changed := cloneStage2aLaunch(t, input)
	changed.HostProjection.Adapters["selected"] = "different"
	if err := CheckStage2aHostProjectionBytes(changed, adapters, installation); err == nil {
		t.Fatal("parsed host projection changed without raw bytes")
	}
}
