//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aInstalledPolicyMustMatchReviewedTemplate(t *testing.T) {
	key := ed25519.PublicKey(strings.Repeat("k", ed25519.PublicKeySize))
	p := stage2aInstalledPolicy{
		Schema:       "agent-bot-machine/stage2a-installed-authority/v1",
		ArtifactPath: stage2aArtifactPath("install-one"),
		Binding:      Stage2aMeasurementBinding{InstallationID: "install-one"},
		LegacySpent:  []string{}, Node: "/reviewed/node",
	}
	template, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{SoulProtectedLaunch: &SoulProtectedLaunchInstall{
		Schema: stage2aInstallSchema, MachinePublicKey: hex.EncodeToString(key), Policy: template,
	}}
	p.Binding.PlanID, p.Binding.InstalledPlanDigest = "plan-one", strings.Repeat("a", 64)
	if !stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("exact reviewed template refused")
	}
	p.Node = "/unreviewed/node"
	if stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("A policy replaced reviewed runtime path")
	}
	p.Node = "/reviewed/node"
	p.Binding.Snapshots.Definition.Inode = "123"
	if !stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("installer-generated inode was treated as request mutation")
	}
	plan.SoulProtectedLaunch.MachinePublicKey = hex.EncodeToString(ed25519.PublicKey(strings.Repeat("z", ed25519.PublicKeySize)))
	if stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("wrong Machine key accepted")
	}
}
