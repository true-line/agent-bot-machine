// Package agentenv recognizes an agent account and an agent session. A
// command that only a human may run refuses both before it reads anything.
package agentenv

import "strings"

// Account reports whether name is an agent account: the glob *-*-agent.
func Account(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	parts := strings.Split(name, "-")
	return len(parts) >= 3 && parts[len(parts)-1] == "agent" && parts[0] != "" && parts[1] != ""
}

// Marker returns the name of the first environment variable that marks an
// agent session, or "" when there is none.
func Marker(env map[string]string) string {
	if env["CLAUDECODE"] == "1" {
		return "CLAUDECODE"
	}
	if env["QWEN_CODE"] == "1" {
		return "QWEN_CODE"
	}
	for _, key := range []string{"CLAUDE_CODE_ENTRYPOINT", "AI_AGENT", "GH_AGENT_APP"} {
		if strings.TrimSpace(env[key]) != "" {
			return key
		}
	}
	for key, val := range env {
		if strings.HasPrefix(key, "CODEX_") {
			return key
		}
		if strings.HasSuffix(key, "_AGENT") && val == "1" && key == strings.ToUpper(key) {
			return key
		}
	}
	return ""
}
