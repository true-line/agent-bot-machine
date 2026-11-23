//go:build !darwin

package members

// RunHarness is reserved for the reviewed Darwin launcher.
func RunHarness() int { return 78 }

// RunStage2aRole is reserved for fixed Darwin launchers.
func RunStage2aRole(string) int { return 78 }

// RunStage2aInstallSeal is reserved for an A-owned Darwin install handoff.
func RunStage2aInstallSeal() int { return 78 }

func RunStage2aHQWithdraw() int { return 78 }
