//go:build !darwin

package members

// RunHarness is reserved for the reviewed Darwin launcher.
func RunHarness() int { return 78 }
