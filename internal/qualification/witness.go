package qualification

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"
)

// WitnessPurpose is separate from both owner policy and host report signing.
const WitnessPurpose = "agent-bot/qualification-policy-acceptance-witness/v1"

const maxWitnessPayloadBytes = 4096
const maxWitnessEnvelopeBytes = 8192

// WitnessContext contains only independently authenticated state. In
// particular, none of these values may be copied from the witness envelope or
// an HQ request. This portable check does not persist or consume a challenge
// and is not an installed protected-launch decision.
type WitnessContext struct {
	HostID         string
	MachinePub     string
	HQPub          string
	HQUid          uint32
	HQEpoch        string
	PairOwnerPub   string
	WitnessKeyID   string
	WitnessSPKIDER []byte
	// WitnessKeyActive comes from reviewed release/pairing revocation state,
	// never from the signed witness or an HQ request.
	WitnessKeyActive     bool
	OwnerKeyID           string
	OwnerRoot            ed25519.PublicKey
	AcceptedVersion      int
	AcceptedRevision     uint64
	AcceptedSHA256       string
	Challenge            []byte
	ChallengeOutstanding bool
	TrustedTime          bool
}

type acceptanceWitnessPayload struct {
	Contract           string `json:"contract"`
	Kind               string `json:"kind"`
	SchemaVersion      int    `json:"schema_version"`
	HostID             string `json:"host_id"`
	MachinePub         string `json:"machine_pub"`
	HQPub              string `json:"hq_pub"`
	HQUid              uint32 `json:"hq_uid"`
	HQEpoch            string `json:"hq_epoch"`
	PairOwnerPub       string `json:"pair_owner_pub"`
	WitnessKeyID       string `json:"witness_key_id"`
	ChallengeBase64URL string `json:"challenge_base64url"`
	PolicyVersion      int    `json:"policy_version"`
	PolicyRevision     uint64 `json:"policy_revision"`
	PolicySHA256       string `json:"policy_sha256"`
	OwnerKeyID         string `json:"owner_key_id"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
}

type acceptanceWitnessEnvelope struct {
	SchemaVersion      int    `json:"schema_version"`
	Purpose            string `json:"purpose"`
	WitnessKeyID       string `json:"witness_key_id"`
	PayloadSHA256      string `json:"payload_sha256"`
	PayloadBase64URL   string `json:"payload_base64url"`
	SignatureBase64URL string `json:"signature_base64url"`
}

func canonicalStandardKey(encoded string, size int) ([]byte, bool) {
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	return raw, err == nil && len(raw) == size && base64.StdEncoding.EncodeToString(raw) == encoded
}

func witnessContextKey(ctx WitnessContext) (*ecdsa.PublicKey, bool) {
	if !reportID.MatchString(ctx.HostID) || !reportID.MatchString(ctx.WitnessKeyID) ||
		!reportID.MatchString(ctx.OwnerKeyID) || ctx.WitnessKeyID == ctx.OwnerKeyID ||
		ctx.HQUid == 0 || ctx.AcceptedRevision == 0 || !validSHA(ctx.AcceptedSHA256) ||
		(ctx.AcceptedVersion != 1 && ctx.AcceptedVersion != 2) ||
		len(ctx.OwnerRoot) != ed25519.PublicKeySize || len(ctx.Challenge) != 32 ||
		!ctx.WitnessKeyActive || !ctx.ChallengeOutstanding || !ctx.TrustedTime || !validHex(ctx.HQEpoch, 64) {
		return nil, false
	}
	if _, ok := canonicalStandardKey(ctx.MachinePub, 32); !ok {
		return nil, false
	}
	if _, ok := canonicalStandardKey(ctx.HQPub, 32); !ok {
		return nil, false
	}
	pairOwner, ok := canonicalStandardKey(ctx.PairOwnerPub, 65)
	x, y := elliptic.Unmarshal(elliptic.P256(), pairOwner)
	if !ok || x == nil || y == nil {
		return nil, false
	}
	parsed, err := x509.ParsePKIXPublicKey(ctx.WitnessSPKIDER)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve.Params().Name != "P-256" {
		return nil, false
	}
	canonicalDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytesEqual(canonicalDER, ctx.WitnessSPKIDER) ||
		bytesEqual(elliptic.Marshal(key.Curve, key.X, key.Y), pairOwner) {
		return nil, false
	}
	return key, true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyAcceptanceWitnessPreflight verifies one signed witness against a
// release-pinned owner root, pairing-pinned distinct witness key, live pair,
// and the greatest accepted policy tuple. The caller must still atomically
// consume its durable Machine challenge and reread the ledger under the
// secure-admin admission lock; this function alone grants no launch authority.
func VerifyAcceptanceWitnessPreflight(envelope, ownerPolicyEnvelope []byte, ctx WitnessContext, now time.Time) error {
	key, ok := witnessContextKey(ctx)
	if !ok || now.IsZero() {
		return ErrUnqualified
	}
	var policy VerifiedPolicy
	var err error
	if ctx.AcceptedVersion == 2 {
		policy, err = VerifyOwnerPolicyV2(ownerPolicyEnvelope, ctx.OwnerKeyID, ctx.OwnerRoot, ctx.AcceptedRevision, ctx.AcceptedSHA256, now)
	} else {
		policy, err = VerifyOwnerPolicy(ownerPolicyEnvelope, ctx.OwnerKeyID, ctx.OwnerRoot, ctx.AcceptedRevision, ctx.AcceptedSHA256, now)
	}
	if err != nil || policy.version != ctx.AcceptedVersion || policy.value.PolicyRevision != ctx.AcceptedRevision || policy.payloadSHA256 != ctx.AcceptedSHA256 {
		return ErrUnqualified
	}
	for _, signer := range policy.value.EvidenceSigners {
		der, valid := canonicalStandardKey(signer.PublicKeySPKIDERBase64, len(ctx.WitnessSPKIDER))
		if valid && bytesEqual(der, ctx.WitnessSPKIDER) {
			return ErrUnqualified
		}
	}
	fields, err := strictObject(envelope, maxWitnessEnvelopeBytes)
	if err != nil || !hasFields(fields, "schema_version", "purpose", "witness_key_id", "payload_sha256", "payload_base64url", "signature_base64url") {
		return ErrUnqualified
	}
	var outer acceptanceWitnessEnvelope
	if json.Unmarshal(envelope, &outer) != nil || outer.SchemaVersion != 1 || outer.Purpose != WitnessPurpose ||
		outer.WitnessKeyID != ctx.WitnessKeyID || !validSHA(outer.PayloadSHA256) {
		return ErrUnqualified
	}
	raw, err := decode(outer.PayloadBase64URL, maxWitnessPayloadBytes)
	if err != nil || digest(raw) != outer.PayloadSHA256 {
		return ErrUnqualified
	}
	fields, err = canonicalBytes(raw, maxWitnessPayloadBytes)
	if err != nil || !hasFields(fields, "contract", "kind", "schema_version", "host_id", "machine_pub", "hq_pub", "hq_uid", "hq_epoch", "pair_owner_pub", "witness_key_id", "challenge_base64url", "policy_version", "policy_revision", "policy_sha256", "owner_key_id", "issued_at", "expires_at") {
		return ErrUnqualified
	}
	var payload acceptanceWitnessPayload
	if json.Unmarshal(raw, &payload) != nil || payload.Contract != "control/v1" ||
		payload.Kind != "qualification-policy-acceptance-witness" || payload.SchemaVersion != 1 ||
		payload.HostID != ctx.HostID || payload.MachinePub != ctx.MachinePub || payload.HQPub != ctx.HQPub ||
		payload.HQUid != ctx.HQUid || payload.HQEpoch != ctx.HQEpoch || payload.PairOwnerPub != ctx.PairOwnerPub ||
		payload.WitnessKeyID != ctx.WitnessKeyID || payload.WitnessKeyID != outer.WitnessKeyID ||
		payload.PolicyVersion != ctx.AcceptedVersion || payload.PolicyRevision != ctx.AcceptedRevision ||
		payload.PolicySHA256 != ctx.AcceptedSHA256 || payload.OwnerKeyID != ctx.OwnerKeyID {
		return ErrUnqualified
	}
	challenge, err := decode(payload.ChallengeBase64URL, 32)
	if err != nil || !bytesEqual(challenge, ctx.Challenge) {
		return ErrUnqualified
	}
	issued, e1 := parseTime(payload.IssuedAt)
	expires, e2 := parseTime(payload.ExpiresAt)
	if e1 != nil || e2 != nil || issued.Location() != time.UTC || expires.Location() != time.UTC ||
		payload.IssuedAt != issued.Format(time.RFC3339) || payload.ExpiresAt != expires.Format(time.RFC3339) ||
		!expires.After(issued) || expires.Sub(issued) > time.Minute || issued.After(now) || !expires.After(now) {
		return ErrUnqualified
	}
	sig, err := decode(outer.SignatureBase64URL, 64)
	if err != nil || len(sig) != 64 {
		return ErrUnqualified
	}
	sum := sha256.Sum256(preimage(WitnessPurpose, raw))
	if !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return ErrUnqualified
	}
	return nil
}
