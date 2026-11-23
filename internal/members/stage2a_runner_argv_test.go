package members

import (
	"slices"
	"testing"
)

func TestStage2aRunnerTemplateDerivesTwoFreshStarts(t *testing.T) {
	const node = "/private/frozen/bin/node"
	const entry = "/private/frozen/bin/agent-bot-souls.mjs"
	const root = "/private/frozen/definition"
	launch := Stage2aLaunchInputRecords{SelectedCommand: node,
		Argv: stage2aRunnerArgvTemplate(node, entry, root, "managed-protected")}
	runners, bridges := runnerFixture(), bridgeFixture()
	first, firstEndpoints, err := stage2aRunnerArgvForStart(launch, node, entry, root,
		"managed-protected", runners[0], bridges[0], 309, "st_0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	second, secondEndpoints, err := stage2aRunnerArgvForStart(launch, node, entry, root,
		"managed-protected", runners[0], bridges[0], 309, "st_0123456789abcdef01234568")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(first[:6], launch.Argv[:6]) || first[6] != firstEndpoints.Admission.SocketPath ||
		first[7] != "--broker-socket" || first[8] != firstEndpoints.Relay.SocketPath ||
		!slices.Equal(first[9:], launch.Argv[9:]) ||
		second[6] != secondEndpoints.Admission.SocketPath || second[8] != secondEndpoints.Relay.SocketPath ||
		first[6] == second[6] || first[8] == second[8] ||
		!slices.Equal(first[:6], second[:6]) || !slices.Equal(first[9:], second[9:]) {
		t.Fatalf("fresh starts did not preserve measured argv and derive only their sockets: %q / %q", first, second)
	}
	changed := launch
	changed.Argv = slices.Clone(launch.Argv)
	changed.Argv[6] = firstEndpoints.Admission.SocketPath
	if _, _, err := stage2aRunnerArgvForStart(changed, node, entry, root,
		"managed-protected", runners[0], bridges[0], 309, "st_0123456789abcdef01234567"); err == nil {
		t.Fatal("installed per-start socket substituted for reviewed template")
	}
	if _, _, err := stage2aRunnerArgvForStart(launch, node, entry, root,
		"managed-protected", runners[0], bridges[1], 309, "st_0123456789abcdef01234567"); err == nil {
		t.Fatal("sibling B account supplied a socket")
	}
	if _, _, err := stage2aRunnerArgvForStart(launch, node, entry, root,
		"managed-protected", runners[0], bridges[0], 309, "st_invalid"); err == nil {
		t.Fatal("unreviewed start ID supplied a socket")
	}
}
