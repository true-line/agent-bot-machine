package members

import _ "embed"

// The protected grant installer must pin these exact embedded profile bytes
// and verify their installed copies before any package or bridge code runs.
// Embedding alone grants no launch authority.

//go:embed darwin/soul-runner-egress.sb
var soulRunnerProfile []byte

//go:embed darwin/soul-bridge-egress.sb
var soulBridgeProfile []byte

//go:embed darwin/soul-child-egress.sb
var soulChildProfile []byte
