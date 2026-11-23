//go:build !darwin

package members

import "errors"

// Keep the daemon's portable request shape available for compilation while
// refusing the protected A-only operation on hosts without the macOS worker.
type Stage2aMemberSetAssignmentRequest = Stage2aStopRequest

func ParseStage2aMemberSetAssignmentRequest([]byte) (Stage2aMemberSetAssignmentRequest, error) {
	return Stage2aMemberSetAssignmentRequest{}, errors.New("Stage 2a member-set assignment requires macOS")
}
