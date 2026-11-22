package members

import (
	"fmt"
	"strings"
	"testing"
)

func TestStage2aInstalledGroupExactRunner(t *testing.T) {
	before := runOutput
	t.Cleanup(func() { runOutput = before })
	attributes := map[string]string{
		"/Groups/_abm_run PrimaryGroupID":  "311",
		"/Groups/_abm_run GroupMembership": "_abm_run",
		"/Groups/_abm_run GroupMembers":    "GUID-R",
		"/Groups/_abm_run NestedGroups":    "",
		"/Users/machine GeneratedUID":      "GUID-A",
		"/Users/_abm_run GeneratedUID":     "GUID-R",
	}
	search := map[string][]string{
		"/Groups PrimaryGroupID 311": {"_abm_run"},
		"/Users PrimaryGroupID 311":  {"_abm_run"},
		"/Users UniqueID 501":        {"machine"},
		"/Users UniqueID 311":        {"_abm_run"},
	}
	runOutput = func(name string, args ...string) (string, error) {
		if name != dsclPath || len(args) < 4 {
			return "", fmt.Errorf("unexpected query")
		}
		switch args[1] {
		case "-read":
			if value, ok := attributes[args[2]+" "+args[3]]; ok {
				return args[3] + ": " + value + "\n", nil
			}
			return "No such key: " + args[3], nil
		case "-search":
			var out strings.Builder
			for _, owner := range search[strings.Join(args[2:], " ")] {
				fmt.Fprintf(&out, "%s %s = (\n    %s\n)\n", owner, args[3], args[4])
			}
			return out.String(), nil
		}
		return "", fmt.Errorf("unexpected query")
	}
	check := func(want bool) {
		t.Helper()
		err := verifyStage2aInstalledGroup("_abm_run", 311, "machine", 501, "_abm_run", 311)
		if (err == nil) != want {
			t.Fatalf("group verdict %v, want %v", err, want)
		}
	}
	check(true)
	attributes["/Groups/_abm_run GroupMembership"] = "machine _abm_run"
	check(false)
	attributes["/Groups/_abm_run GroupMembership"] = "_abm_run"
	search["/Users PrimaryGroupID 311"] = []string{"_abm_run", "mallory"}
	check(false)
	search["/Users PrimaryGroupID 311"] = []string{"_abm_run"}
	attributes["/Groups/_abm_run GroupMembers"] = "GUID-A GUID-R"
	check(false)
	attributes["/Groups/_abm_run GroupMembers"] = "GUID-R"
	search["/Users UniqueID 311"] = []string{"_abm_run", "directory-alias"}
	check(false)
}
