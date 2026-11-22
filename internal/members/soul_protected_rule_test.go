package members

import (
	"strings"
	"testing"
)

func provisionedSoulRoles() ([]SoulRunner, []SoulBridge) {
	runners, bridges := runnerFixture(), bridgeFixture()
	for i := range runners {
		runners[i].Account = soulRunnerName(runners[i].InstallationID)
	}
	return runners, bridges
}

func TestSoulProtectedRulePinsOnlyReviewedCommandsAndRunAsRoles(t *testing.T) {
	runners, bridges := provisionedSoulRoles()
	digest := strings.Repeat("a", 64)
	rule, err := RenderSoulProtectedRule(runners, bridges, 309, []HarnessAdapter{{Account: "_shared-c", UID: 330}}, digest)
	if err != nil {
		t.Fatal(err)
	}
	want := "# Managed by managed-machine protected Soul launch v1.\n"
	path := strings.ReplaceAll(SoulLauncher, " ", "\\ ")
	for i := range runners {
		want += DarwinHQAccount + " ALL = (" + runners[i].Account + ") NOPASSWD: NOSETENV: sha256:" + digest + " " + path + " soul-run\n"
		want += DarwinHQAccount + " ALL = (" + bridges[i].Account + ") NOPASSWD: NOSETENV: sha256:" + digest + " " + path + " soul-bridge\n"
	}
	if rule != want || strings.Contains(rule, "_shared-c") || strings.Contains(rule, "(root)") {
		t.Fatalf("unexpected protected rule:\n%s", rule)
	}
	for name, change := range map[string]func([]SoulRunner, []SoulBridge){
		"arbitrary runner": func(r []SoulRunner, _ []SoulBridge) { r[0].Account = "_another" },
		"shared runner":    func(r []SoulRunner, _ []SoulBridge) { r[1].UID, r[1].GID = r[0].UID, r[0].GID },
		"shared bridge":    func(_ []SoulRunner, b []SoulBridge) { b[1].UID, b[1].GID = b[0].UID, b[0].GID },
		"wrong bridge":     func(_ []SoulRunner, b []SoulBridge) { b[1].InstallationID = b[0].InstallationID },
		"runner is C":      func(r []SoulRunner, _ []SoulBridge) { r[0].UID, r[0].GID = 330, 330 },
		"bridge is C":      func(_ []SoulRunner, b []SoulBridge) { b[0].UID, b[0].GID = 330, 330 },
		"runner is HQ":     func(r []SoulRunner, _ []SoulBridge) { r[0].UID, r[0].GID = 309, 309 },
		"bridge is HQ":     func(_ []SoulRunner, b []SoulBridge) { b[0].UID, b[0].GID = 309, 309 },
	} {
		t.Run(name, func(t *testing.T) {
			r, b := provisionedSoulRoles()
			change(r, b)
			if _, err := RenderSoulProtectedRule(r, b, 309, []HarnessAdapter{{Account: "_shared-c", UID: 330}}, digest); err == nil {
				t.Fatal("unreviewed principal received a sudo rule")
			}
		})
	}
	if _, err := RenderSoulProtectedRule(runners, bridges, 309, nil, "other"); err == nil {
		t.Fatal("unverified launcher digest received a sudo rule")
	}
	changed, err := RenderSoulProtectedRule(runners, bridges, 309, nil, strings.Repeat("b", 64))
	if err != nil || changed == rule || strings.Contains(changed, "sha256:"+digest) {
		t.Fatal("changing the reviewed launcher digest did not change every allowed command")
	}
}
