//go:build !darwin

package members

// The protected control is a macOS Seatbelt test. Other hosts fail closed.
func RunStage2aProtectedControlProbeV1() int { return 78 }
