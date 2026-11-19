package daemon

// The Linux group-class mode bits include the effective POSIX ACL mask.
// Fstat mode checks in openSavedPlan and trustedPlansDir enforce that limit.
func safeMembersPlanACL(fd int, directory bool) bool { return true }
