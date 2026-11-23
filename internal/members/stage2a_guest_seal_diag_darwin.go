//go:build darwin && stage2a_guest

package members

import (
	"fmt"
	"os"
)

// Disposable-guest-only failure localization. The production build does not
// contain this diagnostic path and still emits a generic refusal.
func stage2aGuestSealDiagnostic(stage string, err error) {
	fmt.Fprintf(os.Stderr, "STAGE2A_GUEST_DIAG %s: %v\n", stage, err)
}
