package qualification

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"
)

const KeydWitnessRequestPurpose = "agent-bot-machine/keyd-qualification-witness-request/v1"

// KeydWitnessRequestInput must be populated from Machine's authenticated
// release anchors and live owner-approved pairing under the secure-admin
// lock. This builder has no HQ-facing route and does not grant launch.
type KeydWitnessRequestInput struct {
	Mode           string
	HostID         string
	MachinePub     string
	HQPub          string
	HQUid          uint32
	HQEpoch        string
	PairOwnerPub   string
	OwnerRootHex   string
	OwnerKeyID     string
	PolicyEnvelope []byte
	Challenge      []byte
	TrustedTime    bool
}

func standardExact(raw string, length int) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(raw)
	return err == nil && len(decoded) == length && base64.StdEncoding.EncodeToString(decoded) == raw
}

// BuildKeydWitnessRequest signs a separate Machine-to-keyd transcript. The
// keyd process rechecks every field against live pairing and its own policy
// root before using its distinct Secure Enclave witness key.
func BuildKeydWitnessRequest(input KeydWitnessRequestInput, machine ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if now.IsZero() || !input.TrustedTime || !reportID.MatchString(input.HostID) ||
		len(machine) != ed25519.PrivateKeySize || !standardExact(input.MachinePub, 32) ||
		!standardExact(input.HQPub, 32) || input.HQUid == 0 || !validHex(input.HQEpoch, 64) ||
		!standardExact(input.PairOwnerPub, 65) || !reportID.MatchString(input.OwnerKeyID) ||
		!validHex(input.OwnerRootHex, 64) || len(input.PolicyEnvelope) > 2*MaxReportBytes ||
		base64.StdEncoding.EncodeToString(machine.Public().(ed25519.PublicKey)) != input.MachinePub {
		return nil, ErrUnqualified
	}
	owner, _ := base64.StdEncoding.DecodeString(input.PairOwnerPub)
	x, y := elliptic.Unmarshal(elliptic.P256(), owner)
	if x == nil || y == nil {
		return nil, ErrUnqualified
	}
	if (input.Mode == "sign" && (len(input.Challenge) != 32 || len(input.PolicyEnvelope) == 0)) ||
		(input.Mode == "init" && (len(input.Challenge) != 0 || len(input.PolicyEnvelope) == 0)) ||
		(input.Mode == "pin" && (len(input.Challenge) != 0 || len(input.PolicyEnvelope) != 0)) ||
		(input.Mode != "init" && input.Mode != "sign" && input.Mode != "pin") {
		return nil, ErrUnqualified
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrUnqualified
	}
	value := map[string]any{
		"mode": input.Mode, "host_id": input.HostID, "machine_pub": input.MachinePub,
		"hq_pub": input.HQPub, "hq_uid": input.HQUid, "hq_epoch": input.HQEpoch,
		"pair_owner_pub": input.PairOwnerPub, "owner_root_hex": input.OwnerRootHex,
		"owner_key_id":              input.OwnerKeyID,
		"policy_envelope_base64url": base64.RawURLEncoding.EncodeToString(input.PolicyEnvelope),
		"request_nonce_base64url":   base64.RawURLEncoding.EncodeToString(nonce),
		"timestamp":                 now.Unix(), "trusted_time": true,
	}
	if input.Mode == "sign" {
		value["challenge_base64url"] = base64.RawURLEncoding.EncodeToString(input.Challenge)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrUnqualified
	}
	sig := ed25519.Sign(machine, preimage(KeydWitnessRequestPurpose, raw))
	value["signature_base64url"] = base64.RawURLEncoding.EncodeToString(sig)
	envelope, err := json.Marshal(value)
	if err != nil || len(envelope) > 3*MaxReportBytes {
		return nil, ErrUnqualified
	}
	return envelope, nil
}
