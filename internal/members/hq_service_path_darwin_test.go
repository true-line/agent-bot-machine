//go:build darwin

package members

import (
	"strings"
	"testing"
)

func TestHQServiceDarwinReviewedApplicationSupportPaths(t *testing.T) {
	const base = "/Library/Application Support/TrueLine/stage2a"
	service := HQService{
		Archive: base + "/hq.tar", ReleaseDir: base + "/release/hq",
		Node:           base + "/node/bin/node",
		ArtifactSHA256: strings.Repeat("a", 64), NodeSHA256: strings.Repeat("b", 64),
	}
	// The fixed Apple directory is the only permitted whitespace. The path
	// remains a single argv element when Machine invokes the installed Node.
	if err := service.validate(); err != nil {
		t.Fatalf("reviewed Darwin H paths refused: %v", err)
	}
	for _, bad := range []string{
		base + "/node with space", base + "/../other/node", base + "/a//node",
		base + "/node\twith-tab", base + "/node\nwith-newline",
		"/private/var/db/Application Support/node", "relative/node", "/",
	} {
		if validHQServiceArgumentPath(bad) {
			t.Fatalf("unsafe HQ argument path accepted: %q", bad)
		}
	}
	service.Node = base + "/node with space"
	if err := service.validate(); err == nil {
		t.Fatal("service accepted a second space outside the reviewed Apple directory")
	}
}
