//go:build windows

package members

// members has no Windows runtime route. Its planner fixtures still run on
// Windows CI. FlushFileBuffers requires a writable file handle and cannot be
// used on the read-only directory handle opened by os.Open, so the macOS and
// Linux directory durability contract does not apply to those fixtures.
func syncSavedPlanDirectory(string) error { return nil }
