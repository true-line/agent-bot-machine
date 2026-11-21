package members

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func exampleHarness() HarnessPolicyRecord {
	digest := strings.Repeat("a", 64)
	return HarnessPolicyRecord{
		Schema: "agent-bot-harness-launch/v1", Action: "install", HQUID: 311,
		Launcher: HarnessArtifact{HarnessLauncher, digest}, Sandbox: HarnessArtifact{HarnessSandbox, strings.Repeat("b", 64)},
		Adapters: []HarnessAdapter{{"adapter-one", "_lead", 321, "/Library/Example/adapter", strings.Repeat("c", 64), []string{"--stdio"}}, {"adapter-two", "_spec", 322, "/Library/Example/adapter", strings.Repeat("c", 64), []string{}}},
	}
}
func TestReviewedHarnessMappingAndRetirementAreDistinct(t *testing.T) {
	r := exampleHarness()
	p, e := r.plan()
	if e != nil {
		t.Fatal(e)
	}
	original, e := p.Digest()
	if e != nil {
		t.Fatal(e)
	}
	r.Adapters[0].Account, r.Adapters[1].Account = r.Adapters[1].Account, r.Adapters[0].Account
	r.Adapters[0].UID, r.Adapters[1].UID = r.Adapters[1].UID, r.Adapters[0].UID
	swapped, e := r.plan()
	if e != nil {
		t.Fatal(e)
	}
	sha, _ := swapped.Digest()
	if sha == original {
		t.Fatal("swapping adapters retained old approval")
	}
	prior := exampleHarness()
	prior.Action = "retire"
	prior.InstalledID = "plan-20261120T120000Z-abcd"
	prior.InstalledDigest = original
	retired, e := prior.plan()
	if e != nil {
		t.Fatal(e)
	}
	sha, _ = retired.Digest()
	if sha == original || !strings.Contains(retired.Steps[0].Content, original) {
		t.Fatal("retirement was not bound to install")
	}
	if p.Steps[1].Content != retired.Steps[1].Content {
		t.Fatal("retirement did not identify exact grant")
	}
	for _, step := range retired.Steps {
		if step.Action != ActionRemove {
			t.Fatal(step.Action)
		}
	}
	bytesBefore, _ := p.Canonical()
	var roundtrip Plan
	if json.Unmarshal(bytesBefore, &roundtrip) != nil {
		t.Fatal("not JSON")
	}
	b, _ := roundtrip.Canonical()
	if !bytes.Equal(b, bytesBefore) || b[len(b)-1] != '\n' {
		t.Fatal("noncanonical")
	}
}

func TestReviewedHarnessRetirementRecomputesInstallPlan(t *testing.T) {
	original := exampleHarness()
	original.Adapters[0].Args = []string{"--name", "λ\u2028&", ""}
	p, e := original.plan()
	if e != nil {
		t.Fatal(e)
	}
	digest, e := p.Digest()
	if e != nil {
		t.Fatal(e)
	}
	r := original
	r.Action = "retire"
	r.InstalledID = "plan-20261120T120000Z-abcd"
	r.InstalledDigest = digest
	if _, e := r.plan(); e != nil {
		t.Fatal("valid prior installation refused", e)
	}
	for _, tc := range []struct {
		name string
		edit func(*HarnessPolicyRecord)
	}{
		{"different digest", func(p *HarnessPolicyRecord) { p.InstalledDigest = strings.Repeat("f", 64) }},
		{"changed launcher", func(p *HarnessPolicyRecord) { p.Launcher.SHA256 = strings.Repeat("e", 64) }},
		{"changed arguments", func(p *HarnessPolicyRecord) { p.Adapters[0].Args = []string{"--new"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := r
			candidate.Adapters = append([]HarnessAdapter(nil), r.Adapters...)
			tc.edit(&candidate)
			if _, e := candidate.plan(); e == nil || !strings.Contains(e.Error(), "referenced installation digest") {
				t.Fatalf("expected prior installation mismatch, got %v", e)
			}
		})
	}
}
