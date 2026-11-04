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
	if err := classifyLaunchctl("bootout", "Could not find service", errors.New("exit 3")); err != nil {
		t.Fatalf("bootout missing: %v", err)
	}
}
