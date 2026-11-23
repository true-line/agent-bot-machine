package members

import (
	"fmt"
	"strings"
)

// One reviewed cooperative installation grants HQ exactly the fixed B and
// stock child roles. The protected commands are absent from this rule.
func renderSoulCooperativeBRule(p SoulCooperativeLaunchPolicy) (string, error) {
	if p.Schema != soulCooperativeTwoMemberInstallSchemaV3 || p.validate() != nil ||
		p.Bridge == nil || p.LauncherPath != SoulLauncher ||
		p.Bridge.Account != SoulBridgeName(p.Runner.InstallationID) {
		return "", errSoulCooperativeAuthority
	}
	launcher := strings.ReplaceAll(SoulLauncher, " ", "\\ ")
	return fmt.Sprintf("# Managed by managed-machine cooperative Soul launch v3.\n%s ALL = (%s) NOPASSWD: NOSETENV: sha256:%s %s cooperative-soul-bridge\n%s ALL = (%s) NOPASSWD: NOSETENV: sha256:%s %s cooperative-soul-child\n",
		DarwinHQAccount, p.Bridge.Account, p.LauncherSHA256, launcher,
		DarwinHQAccount, p.Runner.Account, p.LauncherSHA256, launcher), nil
}
