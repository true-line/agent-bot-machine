package members

import (
	"strings"
	"testing"
)

func TestStage2aLookupAcceptsOnlyOneCanonicalInstalledPath(t *testing.T) {
	good := `{"package_path":"/Library/Application Support/Example/é.soul"}`
	got, err := ParseStage2aLookupRequest([]byte(good))
	if err != nil || got.PackagePath != "/Library/Application Support/Example/é.soul" {
		t.Fatalf("valid installed path refused: %+v %v", got, err)
	}
	for name, raw := range map[string]string{
		"duplicate": strings.Replace(good, `"}`, `","package_path":"/other"}`, 1),
		"unknown":   strings.Replace(good, `"}`, `","uid":331}`, 1),
		"relative":  `{"package_path":"relative.soul"}`,
		"parent":    `{"package_path":"/Library/../other.soul"}`,
		"newline":   `{"package_path":"/Library/a\nb.soul"}`,
		"null":      `{"package_path":null}`,
	} {
		if _, err := ParseStage2aLookupRequest([]byte(raw)); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}
