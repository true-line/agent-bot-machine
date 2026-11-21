//go:build darwin

package members

import (
	"io"
	"slices"
	"strings"
	"testing"
)

func TestHarnessRunPrivateHeader(t *testing.T) {
	digest := strings.Repeat("a", 64)
	token := strings.Repeat("b", 48)
	header := `{"plan_digest":"` + digest + `","adapter_id":"native","launch_id":"ln_01c4eabcfedcba00000000ff","soul_id":"agent_01234567-0123-4567-0123-456789abcdef","member_id":"writer","role":"agent","member_token":"` + token + `"}`
	const acp = "{\"jsonrpc\":\"2.0\"}\n"
	request, reader, err := readHarnessRunInput(strings.NewReader(header + "\n" + acp))
	if err != nil || request.PlanDigest != digest || request.MemberToken != token {
		t.Fatal("valid launch header refused")
	}
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != acp {
		t.Fatal("ACP bytes after launch header changed")
	}
	for name, line := range map[string]string{
		"duplicate":        strings.Replace(header, `"adapter_id":`, `"adapter_id":"other","adapter_id":`, 1),
		"unknown":          strings.Replace(header, "{", `{"command":[],`, 1),
		"caller socket":    strings.Replace(header, "{", `{"member_socket":"/tmp/a",`, 1),
		"missing":          strings.Replace(header, `"role":"agent",`, "", 1),
		"parent directory": strings.Replace(header, "writer", "../other", 1),
		"bad type":         strings.Replace(header, `"native"`, "null", 1),
		"extra record":     header + " {}",
		"too long":         strings.Repeat(" ", 4096) + header,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := readHarnessRunInput(strings.NewReader(line + "\n"))
			if err != errLaunchInput {
				t.Fatal("malformed input should return a redacted diagnostic")
			}
		})
	}
	if _, _, err := readHarnessRunInput(strings.NewReader(header)); err != errLaunchInput {
		t.Fatal("unterminated header accepted")
	}
}

// Expected names come from packaged HQ's Darwin launchMemberSocket. They
// cover the literal, full base-36, and shortened base-36 representations.
func TestHarnessRunSocketsMatchHQ(t *testing.T) {
	const id = "ln_01c4eabcfedcba00000000ff"
	for account, name := range map[string]string{
		"_a":                          "member-01c4eabcfedcba00000000ff.sock",
		"_agent-bot-harness":          "01wsqp7nu4pf4ae5bsv",
		"_" + strings.Repeat("x", 31): "u4pf4ae5bsv",
	} {
		broker, member, err := harnessRunSockets(account, id)
		dir := DarwinBrokerDir + "/" + account + "/"
		if err != nil || broker != dir+"broker.sock" || member != dir+name || len(member) > 103 {
			t.Fatalf("incorrect endpoints for %s", account)
		}
	}
	if _, _, err := harnessRunSockets("../sibling", id); err == nil {
		t.Fatal("invalid account accepted")
	}
	if _, _, err := harnessRunSockets("_a", "ln_invalid"); err == nil {
		t.Fatal("invalid launch ID accepted")
	}
}

func TestHarnessAdapterCommandBindsReviewedGrant(t *testing.T) {
	policy := exampleHarness()
	grant := installedHarness{Digest: strings.Repeat("d", 64), Policy: policy}
	req := harnessRunInput{
		PlanDigest: grant.Digest, AdapterID: "adapter-one", LaunchID: "ln_01c4eabcfedcba00000000ff",
		SoulID: "agent_01234567-0123-4567-0123-456789abcdef", MemberID: "writer", Role: "agent", MemberToken: strings.Repeat("b", 48),
	}
	cmd, adapter, err := harnessAdapterCommand(grant, req, 321)
	if err != nil {
		t.Fatal(err)
	}
	broker, member, err := harnessRunSockets("_lead", req.LaunchID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/sandbox-exec", "-D", "BROKER_SOCKET=" + broker, "-D", "MEMBER_SOCKET=" + member, "-f", HarnessSandbox, adapter.Executable, "--stdio"}
	if !slices.Equal(cmd.Args, want) {
		t.Fatal("command differs from reviewed executable, arguments and policy")
	}
	env := strings.Join(cmd.Env, "\n")
	if !slices.Contains(cmd.Env, "AGENT_BOT_SOULS_MEMBER_TOKEN="+req.MemberToken) || strings.Contains(strings.Join(cmd.Args, " "), req.MemberToken) || strings.Contains(env, "SUDO_") {
		t.Fatal("incorrect private child environment")
	}
	for _, uid := range []int{0, 311, 322, 501} {
		if _, _, err := harnessAdapterCommand(grant, req, uid); err == nil {
			t.Fatal("accepted another target UID")
		}
	}
	req.PlanDigest = strings.Repeat("e", 64)
	if _, _, err = harnessAdapterCommand(grant, req, 321); err == nil {
		t.Fatal("accepted stale reservation")
	}
	req.PlanDigest = grant.Digest
	grant.Policy.Action = "retire"
	if _, _, err = harnessAdapterCommand(grant, req, 321); err == nil {
		t.Fatal("accepted retired grant")
	}
}
