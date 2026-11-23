package members

import (
	"strings"
	"testing"
)

func TestStage2aMemberChildStateIsolatedBySignedSelector(t *testing.T) {
	const installationID = "soul-installation"
	const startID = "st_aaaaaaaaaaaaaaaaaaaaaaaa"
	lead := "mb_" + strings.Repeat("a", 64)
	specialist := "mb_" + strings.Repeat("b", 64)
	leadRoot, err := stage2aChildStateName(installationID, startID, lead)
	if err != nil {
		t.Fatal(err)
	}
	specialistRoot, err := stage2aChildStateName(installationID, startID, specialist)
	if err != nil {
		t.Fatal(err)
	}
	legacyRoot, err := stage2aChildStateName(installationID, startID, "")
	if err != nil {
		t.Fatal(err)
	}
	if leadRoot == specialistRoot || leadRoot == legacyRoot || specialistRoot == legacyRoot {
		t.Fatal("two members or legacy child share writable state")
	}
	if got, err := stage2aChildStateName(installationID, startID, lead); err != nil || got != leadRoot {
		t.Fatal("member state root changed for the same signed selector")
	}
	for _, bad := range []string{lead[:len(lead)-1], "mb_" + strings.Repeat("A", 64),
		"../" + lead, "mb_" + strings.Repeat("a", 63) + "/"} {
		if _, err := stage2aChildStateName(installationID, startID, bad); err == nil {
			t.Fatalf("accepted invalid member selector %q", bad)
		}
	}
}
