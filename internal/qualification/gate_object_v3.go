package qualification

import "strings"

const gateObjectPrefixV3 = "qualification://stage2a/"

const (
	maxGateManifestBytesV3 = 1 << 20
	maxGateBlobBytesV3     = 64 << 20
)

// gateObjectNameV3 accepts only the two content-addressed Stage 2a object
// classes. A URI is a logical identifier, never a filesystem path or URL to
// fetch. The digest in the URI must agree with the signed reference.
func gateObjectNameV3(uri, sha256 string) (string, error) {
	if !validSHA(sha256) || !strings.HasPrefix(uri, gateObjectPrefixV3) {
		return "", ErrUnqualified
	}
	rest := strings.TrimPrefix(uri, gateObjectPrefixV3)
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || (parts[0] != "gate-manifest" && parts[0] != "blob") ||
		parts[1] != strings.TrimPrefix(sha256, "sha256:") {
		return "", ErrUnqualified
	}
	return parts[1], nil
}
