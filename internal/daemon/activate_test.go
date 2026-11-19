package daemon

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyLaunchctlBootstrapNotFoundFails(t *testing.T) {
	err := classifyLaunchctl("bootstrap", "Could not find domain", errors.New("exit 5"))
	if err == nil || !strings.Contains(err.Error(), "Could not find domain") {
		t.Fatalf("bootstrap not found must fail, got %v", err)
	}
	if err := classifyLaunchctl("bootstrap", "service already loaded", errors.New("exit 5")); err != nil {
		t.Fatalf("bootstrap already loaded: %v", err)
	}
	if err := classifyLaunchctl("bootout", "", errors.New("launchctl executable not found")); err == nil {
		t.Fatal("missing launchctl must fail")
	}
}
