package members

import (
	"errors"
	"fmt"
	"strings"
)

const (
	SoulLauncher      = launchRuntimeDir + "/soul-launch"
	SoulRunnerSandbox = launchRuntimeDir + "/soul-runner-egress.sb"
	SoulBridgeSandbox = launchRuntimeDir + "/soul-bridge-egress.sb"
	SoulBridgeBinary  = launchRuntimeDir + "/soul-bridge"
	SoulLaunchRule    = "/private/etc/sudoers.d/agent-bot-hq-soul-launch"
)

// RenderSoulProtectedRule prepares the fixed two-principal sudoers content.
// It grants no authority until a separate paired installer has verified the
// launcher and package closure, staged the exact root-owned bytes, checked
// visudo, and committed its receipt and rule under the owner approval guard.
func RenderSoulProtectedRule(runners []SoulRunner, bridges []SoulBridge, hqUID int, shared []HarnessAdapter, launcherSHA256 string) (string, error) {
	if !digestPattern.MatchString(launcherSHA256) || ValidateSoulBridges(runners, bridges, hqUID, shared) != nil {
		return "", errors.New("invalid reviewed Soul launch rule")
	}
	for i := range runners {
		if runners[i].Account != soulRunnerName(runners[i].InstallationID) ||
			bridges[i].Account != SoulBridgeName(runners[i].InstallationID) {
			return "", errors.New("Soul launch rule requires provisioned role names")
		}
	}
	var rule strings.Builder
	rule.WriteString("# Managed by managed-machine protected Soul launch v1.\n")
	launcher := strings.ReplaceAll(SoulLauncher, " ", "\\ ")
	for i := range runners {
		fmt.Fprintf(&rule, "%s ALL = (%s) NOPASSWD: NOSETENV: sha256:%s %s soul-run\n",
			DarwinHQAccount, runners[i].Account, launcherSHA256, launcher)
		fmt.Fprintf(&rule, "%s ALL = (%s) NOPASSWD: NOSETENV: sha256:%s %s soul-bridge\n",
			DarwinHQAccount, bridges[i].Account, launcherSHA256, launcher)
	}
	if rule.Len() > 16*1024 {
		return "", errors.New("Soul launch rule exceeds the reviewed file limit")
	}
	return rule.String(), nil
}
