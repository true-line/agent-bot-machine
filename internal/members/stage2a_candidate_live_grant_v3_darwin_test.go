package members

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

func TestStage2aCandidateGrantV3BurnAndRestart(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	selector := Stage2aReserveRequest{StartID: "first"}
	parent := soulKernelProcessSnapshot{PID: 90, StartSeconds: 100, RealUID: uint32(os.Getuid()), EffectiveUID: uint32(os.Geteuid())}
	g := stage2aCandidateGrantV3{HQUID: 309, Selector: selector, DaemonPID: parent.PID, StartedSec: parent.StartSeconds,
		Nonce: [32]byte{1}, ExpiresAt: now.Add(time.Minute), Attempt: stage2aQualificationCandidateAttemptV3{ApprovalPlanDigest: "attempt"}}
	registry := make(stage2aCandidateGrantRegistryV3)
	if err := registry.add(g, now); err != nil {
		t.Fatal(err)
	}
	changed := selector
	changed.StartID = "different"
	if wrong, err := registry.consume(309, changed, key, now); wrong != nil || err != nil {
		t.Fatal("changed selector received a grant")
	}
	signed, err := registry.consume(309, selector, key, now)
	if err != nil || verifyStage2aCandidateLiveGrantV3(signed, 309, selector, parent, pub, now) != nil {
		t.Fatal("exact live attempt was refused", err)
	}
	if _, err := registry.consume(309, selector, key, now); err == nil {
		t.Fatal("spent grant was reissued")
	}
	if err := registry.add(g, now); err == nil {
		t.Fatal("spent attempt was rearmed")
	}
	restarted := make(stage2aCandidateGrantRegistryV3)
	if got, err := restarted.consume(309, selector, key, now); got != nil || err != nil {
		t.Fatal("restart recovered a live grant")
	}
	if verifyStage2aCandidateLiveGrantV3(nil, 309, selector, parent, pub, now) == nil {
		t.Fatal("absence of an A-live grant authorized signing")
	}
	parent.StartSeconds++
	if verifyStage2aCandidateLiveGrantV3(signed, 309, selector, parent, pub, now) == nil {
		t.Fatal("grant survived daemon restart with reused PID")
	}
	parent.StartSeconds--
	signed.Grant.Attempt.AttemptReceiptSHA256 = "changed"
	if verifyStage2aCandidateLiveGrantV3(signed, 309, selector, parent, pub, now) == nil {
		t.Fatal("accepted modified spent receipt digest")
	}
}
