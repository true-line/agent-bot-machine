//go:build darwin

package members

import "testing"

func TestStage2aQualificationKernelRequiresDedicatedExactIdentity(t *testing.T) {
	good := soulKernelProcessSnapshot{PID: 721, ParentPID: 720, StartSeconds: 123,
		RealUID: 451, EffectiveUID: 451, SavedUID: 451,
		RealGID: 452, PrimaryGroupGID: 452, SavedGID: 452}
	if !stage2aQualificationKernelMatches(good, 721, 451, 452) {
		t.Fatal("matching kernel identity refused")
	}
	for _, change := range []func(*soulKernelProcessSnapshot){
		func(k *soulKernelProcessSnapshot) { k.PID++ },
		func(k *soulKernelProcessSnapshot) { k.ParentPID = 0 },
		func(k *soulKernelProcessSnapshot) { k.RealUID++ },
		func(k *soulKernelProcessSnapshot) { k.EffectiveUID++ },
		func(k *soulKernelProcessSnapshot) { k.SavedUID++ },
		func(k *soulKernelProcessSnapshot) { k.RealGID++ },
		func(k *soulKernelProcessSnapshot) { k.PrimaryGroupGID++ },
		func(k *soulKernelProcessSnapshot) { k.SavedGID++ },
	} {
		bad := good
		change(&bad)
		if stage2aQualificationKernelMatches(bad, 721, 451, 452) {
			t.Fatal("changed kernel identity accepted")
		}
	}
}
