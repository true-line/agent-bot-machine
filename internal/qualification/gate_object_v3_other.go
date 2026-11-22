//go:build !darwin && !linux

package qualification

// ResolveGateObjectV3 is unavailable without descriptor-relative no-follow
// opening. An unsupported host cannot infer a physical gate result.
func ResolveGateObjectV3(root, uri, sha256 string, maxBytes int64) ([]byte, error) {
	return nil, ErrUnqualified
}
