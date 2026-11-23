//go:build darwin

package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCooperativeHSelectorUsesPrefixedOwnerDigestFromInstalledRecord(t *testing.T) {
	receipt := Receipt{PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("a", 64), Owner: "owner"}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	installed := soulCooperativeInstalledV3{RootReceipt: raw,
		Policy: SoulCooperativeLaunchPolicy{HOwnerPlanDigest: strings.Repeat("b", 64),
			HQInstallationID: "h_0123456789abcdef01234567"}}
	selector, err := cooperativeHSelectorFromInstalled(installed)
	if err != nil || selector.HOwnerPlanDigest != "sha256:"+strings.Repeat("b", 64) ||
		selector.CooperativePlanDigest != receipt.PlanDigest {
		t.Fatalf("installed H selector misbound: %+v, %v", selector, err)
	}
	installed.Policy.HOwnerPlanDigest = receipt.PlanDigest
	if _, err := cooperativeHSelectorFromInstalled(installed); err == nil {
		t.Fatal("cooperative R plan accepted itself as the separate H owner plan")
	}
}
