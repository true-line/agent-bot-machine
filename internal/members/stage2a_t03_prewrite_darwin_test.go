//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStage2aT03CompletionMACSharedVectorAndTampering(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-b-completion-vector.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RawFD4Hex           string                     `json:"raw_fd4_hex"`
		Completion          Stage2aT03BrokerCompletion `json:"completion"`
		CompletionKeyHex    string                     `json:"completion_key_hex"`
		CompletionOriginMAC string                     `json:"completion_origin_mac"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(vector.RawFD4Hex)
	if err != nil {
		t.Fatal(err)
	}
	body, err := vector.Completion.canonicalBody()
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(body); hex.EncodeToString(got[:]) != "7dc32def5361deb8f655b17a18272f1493910a97ee877a53398bb9e6862c3a63" {
		t.Fatalf("cross-language completion JCS differs: %x", got)
	}
	mac, err := stage2aT03CompletionOriginMAC(key, vector.Completion)
	if err != nil || hex.EncodeToString(mac) != vector.CompletionOriginMAC {
		t.Fatalf("cross-language completion MAC differs: %x %v", mac, err)
	}
	if vector.CompletionKeyHex != "adca64dffe9a14d180c9c846a1f22ba5e13418fd8f88a42b47c0738b9bbee30a" {
		t.Fatal("shared vector completion key changed")
	}
	// The shared byte vector uses a synthetic plan ID; give the source guard a
	// valid plan ID and independently compute the MAC for its strict parser.
	c := vector.Completion
	c.Selectors.PlanID = "plan-20261122T120000Z-abcd"
	c.CompletionOriginMAC = mustStage2aT03MAC(t, key, c)
	epoch := strings.Repeat("a", 64)
	if !verifyStage2aT03CompletionOrigin(key, c, epoch) {
		t.Fatal("B-authenticated full-write completion refused")
	}
	for _, change := range []func(*Stage2aT03BrokerCompletion){
		func(v *Stage2aT03BrokerCompletion) { v.ResponseWireSHA256 = "sha256:" + strings.Repeat("f", 64) },
		func(v *Stage2aT03BrokerCompletion) { v.Peer.PID++ },
		func(v *Stage2aT03BrokerCompletion) { v.PrewriteReceipt = strings.Repeat("e", 64) },
		func(v *Stage2aT03BrokerCompletion) { v.WriteCompletedAt = "2026-11-24T18:40:02.223456789Z" },
	} {
		bad := c
		change(&bad)
		if verifyStage2aT03CompletionOrigin(key, bad, epoch) {
			t.Fatal("changed B wire, peer, receipt or write time reused the old MAC")
		}
	}
	wrongKey := append([]byte(nil), key...)
	wrongKey[0] ^= 0x80
	if verifyStage2aT03CompletionOrigin(wrongKey, c, epoch) {
		t.Fatal("other reservation's proof verified the B completion")
	}
}

func mustStage2aT03MAC(t *testing.T, key []byte, c Stage2aT03BrokerCompletion) string {
	t.Helper()
	mac, err := stage2aT03CompletionOriginMAC(key, c)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(mac)
}

func TestStage2aT03CompletionJoinsPrewriteAfterNormalCLIExit(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-b-completion-vector.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Completion Stage2aT03BrokerCompletion `json:"completion"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	c := vector.Completion
	epoch := strings.Repeat("a", 64)
	start, err := time.Parse(time.RFC3339Nano, c.WriteStartedAt)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := time.Parse(time.RFC3339Nano, c.WriteCompletedAt)
	if err != nil {
		t.Fatal(err)
	}
	q := Stage2aT03ArmRequest{Stage2aStopRequest: c.Selectors.stop(epoch), BrokerCompletion: c,
		Receipt: Stage2aT03PositiveReceipt{BindReceiptSHA256: c.BindReceiptSHA256,
			Peer: c.Peer, PeerSHA256: c.PeerSHA256, RequestSHA256: c.RequestSHA256,
			PromptSHA256: c.PromptSHA256, Model: c.Model, ResponseWireSHA256: c.ResponseWireSHA256,
			ResponseWireBytes: c.ResponseWireBytes, HTTPStatus: c.HTTPStatus,
			CompletedAtMS: completed.UnixMilli()}}
	prewrite := &stage2aT03PrewriteState{Record: c.Stage2aT03BrokerPrewrite,
		Receipt: c.PrewriteReceipt, ObservedAtMS: start.UnixMilli() - 1}
	// The CLI may exit immediately after the full write. This join uses the
	// recorded live observation, not a later process-liveness check.
	if !stage2aT03CompletionMatches(q, prewrite) {
		t.Fatal("full-write completion rejected after normal CLI exit")
	}
	if stage2aT03CompletionMatches(q, nil) {
		t.Fatal("stopped or consumed prewrite accepted")
	}
	changed := q
	changed.BrokerCompletion.ResponseWireBytes++
	if stage2aT03CompletionMatches(changed, prewrite) {
		t.Fatal("other wire reused one-use prewrite")
	}
	changed = q
	changed.BrokerCompletion.Peer.PID++
	if stage2aT03CompletionMatches(changed, prewrite) {
		t.Fatal("other broker connection reused one-use prewrite")
	}
	changed = q
	changed.Receipt.PromptSHA256 = changed.Receipt.RequestSHA256
	if stage2aT03CompletionMatches(changed, prewrite) {
		t.Fatal("HQ replaced the true prompt digest")
	}
	stale := *prewrite
	stale.ObservedAtMS = start.UnixMilli() + 1
	if stage2aT03CompletionMatches(q, &stale) {
		t.Fatal("write started before A's live CLI observation")
	}
	stale.ObservedAtMS = completed.Add(-stage2aT03ReceiptLifetime - time.Millisecond).UnixMilli()
	if stage2aT03CompletionMatches(q, &stale) {
		t.Fatal("stale prewrite observation accepted")
	}
}
