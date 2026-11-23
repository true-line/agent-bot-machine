//go:build darwin

package members

import (
	"strings"
	"testing"
)

func TestCooperativeRuleGrantsOnlyFixedBridgeAndChildRoles(t *testing.T) {
	p, _, _, _, _ := cooperativeTwoMemberPolicyFixture(t)
	rule, err := renderSoulCooperativeBRule(p)
	if err != nil || !strings.Contains(rule, " cooperative-soul-bridge\n") ||
		!strings.Contains(rule, " cooperative-soul-child\n") ||
		strings.Contains(rule, " soul-bridge\n") || strings.Contains(rule, " soul-run\n") ||
		strings.Contains(rule, " soul-child\n") ||
		!strings.Contains(rule, "("+p.Bridge.Account+")") ||
		!strings.Contains(rule, "("+p.Runner.Account+")") ||
		!strings.Contains(rule, "sha256:"+p.LauncherSHA256) {
		t.Fatalf("cooperative B sudo rule grants the wrong role: %v", err)
	}
	p.Profile = "managed-protected"
	if _, err := renderSoulCooperativeBRule(p); err == nil {
		t.Fatal("protected policy reused the cooperative B sudo rule")
	}
}
