//go:build darwin

package members

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestStage2aTwoMemberObservationRefusesMissingDuplicateAndReplacedChild(t *testing.T) {
	const uid = 310
	proc := func(pid, parent, group int) soulKernelProcessSnapshot {
		return soulKernelProcessSnapshot{PID: pid, ParentPID: parent, ProcessGroupID: group,
			StartSeconds: int64(pid), StartMicros: 1, RealUID: uid, EffectiveUID: uid, SavedUID: uid,
			RealGID: uid, PrimaryGroupGID: uid, SavedGID: uid, Groups: []uint32{uid}}
	}
	runner, bridge := proc(100, 50, 100), proc(200, 50, 200)
	launchers := map[int]soulKernelProcessSnapshot{301: proc(301, 100, 301), 302: proc(302, 100, 302)}
	children := map[int]soulKernelProcessSnapshot{401: proc(401, 301, 401), 402: proc(402, 302, 402)}
	roles := []stage2aHelloMember{{MemberID: "m_lead"}, {MemberID: "m_spec"}}
	candidates := []stage2aMemberChildCandidate{
		{MemberID: "m_lead", LauncherPID: 301, ChildPID: 401, GrantedLauncher: launchers[301]},
		{MemberID: "m_spec", LauncherPID: 302, ChildPID: 402, GrantedLauncher: launchers[302]},
	}
	observeLauncher := func(pid int) (soulKernelProcessSnapshot, error) {
		p, ok := launchers[pid]
		if !ok {
			return p, errors.New("missing launcher")
		}
		return p, nil
	}
	observeChild := func(pid, _ int) (soulKernelProcessSnapshot, error) {
		p, ok := children[pid]
		if !ok {
			return p, errors.New("missing child")
		}
		return p, nil
	}
	collect := func(items []stage2aMemberChildCandidate, child stage2aObserveChild) error {
		_, err := collectStage2aTwoMemberChildren(roles, items, runner, bridge, uid, uid,
			"/private/var/db/agent-bot-machine/runtime/bin/claude-agent-acp", "sha256:"+strings.Repeat("a", 64),
			observeLauncher, child)
		return err
	}
	if err := collect(candidates, observeChild); err != nil {
		t.Fatalf("two distinct live children refused: %v", err)
	}
	if collect(candidates[:1], observeChild) == nil {
		t.Fatal("missing member accepted")
	}
	duplicate := append([]stage2aMemberChildCandidate(nil), candidates...)
	duplicate[1].ChildPID = duplicate[0].ChildPID
	if collect(duplicate, observeChild) == nil {
		t.Fatal("duplicate child PID accepted")
	}
	wrongMember := append([]stage2aMemberChildCandidate(nil), candidates...)
	wrongMember[1].MemberID = "m_other"
	if collect(wrongMember, observeChild) == nil {
		t.Fatal("unassigned member accepted")
	}
	reads := 0
	replaced := func(pid, parent int) (soulKernelProcessSnapshot, error) {
		p, err := observeChild(pid, parent)
		reads++
		if reads > 2 && pid == 401 {
			p.StartMicros++ // same PID, later process
		}
		return p, err
	}
	if collect(candidates, replaced) == nil {
		t.Fatal("replaced child after second member observation accepted")
	}
	wrongUID := func(pid, parent int) (soulKernelProcessSnapshot, error) {
		p, err := observeChild(pid, parent)
		if pid == 402 {
			p.EffectiveUID++
		}
		return p, err
	}
	if collect(candidates, wrongUID) == nil {
		t.Fatal("same-account child with changed effective UID accepted")
	}
}

func TestStage2aOwnerMemberSetDigestBindsExactMeasuredProjection(t *testing.T) {
	roles := []stage2aHelloMember{
		{MemberID: "m_lead", Role: "lead", AdapterID: "claude-code", AdapterVersion: "0.109.0"},
		{MemberID: "m_spec", Role: "specialist", AdapterID: "claude-code", AdapterVersion: "0.109.0"},
	}
	path := "/private/var/db/agent-bot-machine/runtime/bin/claude-agent-acp"
	sha := "sha256:" + strings.Repeat("a", 64)
	cliPath := "/private/var/db/agent-bot-machine/runtime/bin/claude"
	cliSHA := "sha256:" + strings.Repeat("c", 64)
	want, err := stage2aOwnerMemberSetDigest(roles, path, sha, cliPath, cliSHA)
	if err != nil || !stage2aPrefixedDigest.MatchString(want) {
		t.Fatalf("valid exact member set refused: %s %v", want, err)
	}
	reversed := []stage2aHelloMember{roles[1], roles[0]}
	got, err := stage2aOwnerMemberSetDigest(reversed, path, sha, cliPath, cliSHA)
	if err != nil || got != want {
		t.Fatal("member input order changed the sorted owner projection")
	}
	changed := append([]stage2aHelloMember(nil), roles...)
	changed[1].Role = "lead"
	if _, err := stage2aOwnerMemberSetDigest(changed, path, sha, cliPath, cliSHA); err == nil {
		t.Fatal("second lead accepted")
	}
	changed[1] = changed[0]
	if _, err := stage2aOwnerMemberSetDigest(changed, path, sha, cliPath, cliSHA); err == nil {
		t.Fatal("duplicate member accepted")
	}
	got, err = stage2aOwnerMemberSetDigest(roles, path+"-other", sha, cliPath, cliSHA)
	if err != nil || got == want {
		t.Fatal("changed installed command path kept owner selection")
	}
	got, err = stage2aOwnerMemberSetDigest(roles, path, "sha256:"+strings.Repeat("b", 64), cliPath, cliSHA)
	if err != nil || got == want {
		t.Fatal("changed measured command bytes kept owner selection")
	}
	got, err = stage2aOwnerMemberSetDigest(roles, path, sha, cliPath, "sha256:"+strings.Repeat("d", 64))
	if err != nil || got == want {
		t.Fatal("changed adjacent CLI bytes kept owner selection")
	}
}

func TestStage2aOwnerMemberSetMatchesContractsSyntheticVector(t *testing.T) {
	roles := []stage2aHelloMember{
		{MemberID: "m_lead", Role: "lead", AdapterID: "fixture-stock", AdapterVersion: "1.0.0"},
		{MemberID: "m_spec", Role: "specialist", AdapterID: "fixture-stock", AdapterVersion: "1.0.0"},
	}
	got, err := stage2aOwnerMemberSetDigest(roles,
		"/fixture/r/adapter/fixture-acp", "sha256:d904480689034c73d063d9a60e1a03c53df3c26bfcfb19a58f49c41b9b549242",
		"/fixture/r/adapter/fixture-cli", "sha256:4575517e516023fd0698342aec5e470a7533a94b5cf003b172af874cf773817f")
	if err != nil || got != "sha256:40758695d8a20df897316151f464059180d45739b2a018ef8d6ea097f5d2baf3" {
		t.Fatalf("owner projection differs from Contracts #85: %s %v", got, err)
	}
}

func TestStage2aStockManifestRequiresMeasuredAdjacentCLI(t *testing.T) {
	roles := []stage2aHelloMember{
		{MemberID: "m_lead", Role: "lead", AdapterID: "claude-code", AdapterVersion: "0.109.0"},
		{MemberID: "m_spec", Role: "specialist", AdapterID: "claude-code", AdapterVersion: "0.109.0"},
	}
	command := "/frozen/r/runtime/bin/claude-agent-acp"
	commandSHA := "sha256:" + strings.Repeat("a", 64)
	cliSHA := "sha256:" + strings.Repeat("b", 64)
	manifest := map[string]string{
		"adapter_id": "claude-code", "adapter_version": "0.109.0",
		"executable": "claude-agent-acp", "executable_sha256": commandSHA,
		"adjacent_cli": "claude", "adjacent_cli_sha256": cliSHA,
	}
	files := []Stage2aDefinitionRecord{{Path: "runtime/bin/claude", Kind: "regular", SHA256: strings.TrimPrefix(cliSHA, "sha256:")}}
	check := func() bool {
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		path, sha, ok := stage2aStockManifestCLI(raw, roles, command, commandSHA, files)
		return ok && path == "/frozen/r/runtime/bin/claude" && sha == cliSHA
	}
	if !check() {
		t.Fatal("measured adjacent CLI declaration refused")
	}
	manifest["adjacent_cli_sha256"] = "sha256:" + strings.Repeat("c", 64)
	if check() {
		t.Fatal("changed manifest CLI bytes accepted")
	}
	manifest["adjacent_cli_sha256"] = cliSHA
	files[0].SHA256 = strings.Repeat("c", 64)
	if check() {
		t.Fatal("external CLI record changed without refusal")
	}
	files[0].SHA256 = strings.TrimPrefix(cliSHA, "sha256:")
	manifest["adjacent_cli"] = "../sibling"
	if check() {
		t.Fatal("nonadjacent CLI path accepted")
	}
	manifest["adjacent_cli"] = "claude"
	raw := []byte(`{"adapter_id":"claude-code","adapter_id":"claude-code"}`)
	if _, _, ok := stage2aStockManifestCLI(raw, roles, command, commandSHA, files); ok {
		t.Fatal("duplicate manifest key accepted")
	}
}
