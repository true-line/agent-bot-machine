package members

import (
	"strings"
	"testing"
)

func stage2aSyntheticRecords() []Stage2aDefinitionRecord {
	size2, size17 := uint64(2), uint64(17)
	return []Stage2aDefinitionRecord{
		{Path: "Contents", Kind: "directory", Mode: "0555"},
		{Path: "Contents/SoulInfo.json", Kind: "regular", Mode: "0444", Size: &size2, SHA256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		{Path: "Contents/SoulLock.json", Kind: "regular", Mode: "0444", Size: &size2, SHA256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		{Path: "Contents/opt", Kind: "directory", Mode: "0555"},
		{Path: "Contents/opt/quickstart-adapter.mjs", Kind: "regular", Mode: "0555", Size: &size17, SHA256: "56332e0a55734bc2b73df56a2df8635ed5c5b24b6d7a456b41de7cab9a2f3814"},
		{Path: "Contents/opt/quickstart-check.mjs", Kind: "regular", Mode: "0555", Size: &size17, SHA256: "a903ba200e1d43efd9a49f4a8f57c622efb2ca72b9a00222dacd16d6ba6f3ba0"},
		{Path: "Contents/primitives", Kind: "directory", Mode: "0555"},
		{Path: "Contents/primitives/quickstart-task.json", Kind: "regular", Mode: "0444", Size: &size2, SHA256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
	}
}

func TestStage2aDefinitionDigestMatchesSyntheticByteVector(t *testing.T) {
	records := stage2aSyntheticRecords()
	got, canonical, err := Stage2aDefinitionDigest(records)
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:27c6f3b4c768a2f5b2fe4f5f58c829eef7d02e111517937fea100d0aa15a2ede"
	if got != want || len(canonical) == 0 || canonical[0] != '[' || canonical[len(canonical)-1] != ']' {
		t.Fatalf("definition byte vector differs: %s", got)
	}
	if compared, err := CheckStage2aApprovedDefinition(records, stage2aSyntheticRecords()); err != nil || compared != want {
		t.Fatalf("matching approved inventory refused: %s, %v", compared, err)
	}
}

func TestStage2aDefinitionRejectsChangedOrUnclosedInventory(t *testing.T) {
	for name, edit := range map[string]func([]Stage2aDefinitionRecord) []Stage2aDefinitionRecord{
		"missing checker": func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord { return append(r[:5], r[6:]...) },
		"changed checker bytes": func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord {
			r[5].SHA256 = strings.Repeat("a", 64)
			return r
		},
		"changed mode":  func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord { r[5].Mode = "0755"; return r },
		"writable mode": func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord { r[5].Mode = "0777"; return r },
		"setid mode":    func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord { r[5].Mode = "4555"; return r },
		"reordered":     func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord { r[4], r[5] = r[5], r[4]; return r },
		"case alias": func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord {
			r[5].Path = "Contents/opt/Quickstart-adapter.mjs"
			return r
		},
		"traversal": func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord {
			r[5].Path = "Contents/opt/../quickstart-check.mjs"
			return r
		},
		"backslash": func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord {
			r[5].Path = "Contents/opt\\quickstart-check.mjs"
			return r
		},
		"outside frozen scope": func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord {
			r[5].Path = "Contents/workspaces/quickstart-check.mjs"
			return r
		},
		"directory with size": func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord {
			size := uint64(0)
			r[3].Size = &size
			return r
		},
		"file too large": func(r []Stage2aDefinitionRecord) []Stage2aDefinitionRecord {
			size := uint64(stage2aMaxFileBytes + 1)
			r[5].Size = &size
			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			base := stage2aSyntheticRecords()
			changed := edit(base)
			if name == "missing checker" || name == "changed checker bytes" || name == "changed mode" {
				if _, err := CheckStage2aApprovedDefinition(changed, stage2aSyntheticRecords()); err == nil {
					t.Fatal("changed approved inventory accepted")
				}
				return
			}
			if _, _, err := Stage2aDefinitionDigest(changed); err == nil {
				t.Fatal("invalid frozen definition accepted")
			}
		})
	}
}
