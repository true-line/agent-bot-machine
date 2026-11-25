package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHostV3RequiresIndependentChainAndCannotMixModes(t *testing.T) {
	base := []string{
		"-owner-root", "/nonexistent/owner-root", "-owner-key-id", "owner-key",
		"-policy-envelope", "/nonexistent/policy", "-trusted-root", "/nonexistent/release-root",
		"-bundle", "/nonexistent/bundle", "-bundle-sha256", "sha256:" + strings.Repeat("a", 64),
		"-qualification", "/nonexistent/qualification", "-protected-envelope", "/nonexistent/protected",
		"-cooperative-envelope", "/nonexistent/cooperative",
		"-souls-build-bundle", "/nonexistent/souls-bundle", "-souls-package", "/nonexistent/souls-package",
		"-souls-trusted-root", "/nonexistent/souls-root",
	}
	chain := []string{
		"-machine-root", "/nonexistent/machine-root", "-protected-execution", "/nonexistent/protected-execution",
		"-cooperative-execution", "/nonexistent/cooperative-execution", "-protected-commitment", "/nonexistent/protected-commitment",
		"-cooperative-commitment", "/nonexistent/cooperative-commitment",
	}
	check := func(args []string, want int) {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if got := run(args, &out, &diagnostic); got != want || out.Len() != 0 {
			t.Fatalf("run exit %d, want %d; stdout %q; stderr %q", got, want, out.String(), diagnostic.String())
		}
	}
	check(append([]string{"-host-v3"}, base...), 2)
	check(append(append([]string{"-host-v3", "-bridge-v2"}, base...), chain...), 2)
	check(append(append([]string{"-host-v3"}, base...), chain...), 1)
	check(append([]string{"-bridge-v2"}, base...), 1)
	check(append(append([]string{"-bridge-v2"}, base...), "-cooperative-commitment", "/nonexistent/commitment"), 2)
	check(append([]string{}, base[:len(base)-6]...), 1)
	check(append(append([]string{}, base[:len(base)-6]...), "-cooperative-commitment", "/nonexistent/commitment"), 2)
}
