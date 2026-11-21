package members

import (
	"strings"
	"testing"
)

func TestDarwinGrantCommitsEveryReviewedField(t *testing.T) {
	original, err := exampleHarness().plan()
	if err != nil {
		t.Fatal(err)
	}
	before, err := original.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for label, edit := range map[string]func(*HarnessPolicyRecord){
		"adapter id":        func(p *HarnessPolicyRecord) { p.Adapters[0].ID = "adapter-lead" },
		"target name":       func(p *HarnessPolicyRecord) { p.Adapters[0].Account = "_other" },
		"target uid":        func(p *HarnessPolicyRecord) { p.Adapters[0].UID += 2 },
		"executable":        func(p *HarnessPolicyRecord) { p.Adapters[0].Executable += "-new" },
		"executable digest": func(p *HarnessPolicyRecord) { p.Adapters[0].SHA256 = strings.Repeat("d", 64) },
		"argument value":    func(p *HarnessPolicyRecord) { p.Adapters[0].Args[0] = "--other" },
		"empty argument":    func(p *HarnessPolicyRecord) { p.Adapters[0].Args = append(p.Adapters[0].Args, "") },
		"launcher digest":   func(p *HarnessPolicyRecord) { p.Launcher.SHA256 = strings.Repeat("e", 64) },
		"sandbox digest":    func(p *HarnessPolicyRecord) { p.Sandbox.SHA256 = strings.Repeat("f", 64) },
		"HQ uid":            func(p *HarnessPolicyRecord) { p.HQUID++ },
	} {
		t.Run(label, func(t *testing.T) {
			r := exampleHarness()
			edit(&r)
			mutated, err := r.plan()
			if err != nil {
				t.Fatal(err)
			}
			after, err := mutated.Digest()
			if err != nil || after == before {
				t.Fatal("changed field retained its original approval digest")
			}
		})
	}
	r := exampleHarness()
	r.Adapters[0].Args = []string{"first", "second"}
	a, err := r.plan()
	if err != nil {
		t.Fatal(err)
	}
	r.Adapters[0].Args = []string{"second", "first"}
	b, err := r.plan()
	if err != nil {
		t.Fatal(err)
	}
	ad, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	bd, err := b.Digest()
	if err != nil || ad == bd {
		t.Fatal("reordered arguments retained their original approval digest")
	}
}
