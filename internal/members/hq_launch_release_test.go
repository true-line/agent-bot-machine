package members

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRetainedArchiveMatchesCompleteInstalledTree(t *testing.T) {
	for _, tt := range []struct {
		name      string
		installed string
		mode      uint32
		extra     bool
		ok        bool
	}{
		{"matches", "installed bytes", 0644, false, true},
		{"changed bytes", "local edit", 0644, false, false},
		{"changed mode", "installed bytes", 0755, false, false},
		{"extra installed file", "installed bytes", 0644, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			content := "installed bytes"
			if err := writer.WriteHeader(&tar.Header{Name: "hq/module", Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			local := filepath.Join(t.TempDir(), "module")
			if err := os.WriteFile(local, []byte(tt.installed), 0644); err != nil {
				t.Fatal(err)
			}
			tree := map[string]installedHQEntry{"hq/module": {Entry: Entry{Regular: true, Mode: tt.mode}, path: local}}
			if tt.extra {
				tree["hq/extra"] = installedHQEntry{}
			}
			if err := matchDarwinArchive(&archive, tree); (err == nil) != tt.ok {
				t.Fatalf("validation error %v", err)
			}
		})
	}
}

func TestDarwinControlCapability(t *testing.T) {
	for _, c := range []struct{ body, want string }{
		{`{"target_platform":"darwin"}`, launchControlV1},
		{`{"target_platform":"darwin","owner_control_capability":"darwin-owner-control/v2"}`, launchControlV2},
		{`{"target_platform":"linux","owner_control_capability":"darwin-owner-control/v2"}`, ""},
		{`{"target_platform":"darwin","owner_control_capability":null}`, ""},
		{`{"target_platform":"darwin","owner_control_capability":"darwin-owner-control/v3"}`, ""},
		{`{"target_platform":"darwin","owner_control_capability":{}}`, ""},
	} {
		got, err := darwinControlCapability([]byte(c.body))
		if got != c.want || (err != nil) != (c.want == "") {
			t.Errorf("%s: %q, %v", c.body, got, err)
		}
	}
}
