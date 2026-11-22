package members

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSoulProtectedRuleParsesWithNativeVisudo(t *testing.T) {
	runners, bridges := provisionedSoulRoles()
	rule, err := RenderSoulProtectedRule(runners, bridges, 309, nil, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "soul-rule")
	if err := os.WriteFile(p, []byte(rule), 0440); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/usr/sbin/visudo", "-c", "-s", "-f", p).CombinedOutput()
	if err != nil {
		t.Fatalf("native visudo refused the exact proposed sudoers bytes: %s: %v", out, err)
	}
}
