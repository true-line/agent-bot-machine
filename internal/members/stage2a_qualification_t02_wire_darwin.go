package members

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const stage2aT02OutagePurpose = "agent-bot-hq/t02-machine-outage/v1"
const stage2aT02Audience = "https://agents.true-line.ai/oauth/device_authorization"

// This is wire corroboration only. The caller must obtain commandRaw from A's
// own driver transcript, pins from the live pair under its lock, and separate
// OS/keyd observations before granting a T02 host result.
type stage2aT02WireResult struct {
	requestNonce string
	thumbprint   string
	generation   int64
	jti          string
	refusal      string
}

type stage2aT02WireCapture struct {
	commandRaw, requestRaw, responseRaw, outageSignature []byte
	hqKey, machineKey                                    ed25519.PublicKey
	epoch                                                string
	observedAt                                           time.Time
}

func (c stage2aT02WireCapture) verify() (stage2aT02WireResult, error) {
	return verifyStage2aT02Wire(c.commandRaw, c.requestRaw, c.responseRaw, c.outageSignature,
		c.hqKey, c.machineKey, c.epoch, c.observedAt)
}

// A later protected restart spends a new reservation and Q session. This
// refuses a replayed proof even when both individual Machine signatures pass.
func verifyStage2aT02Restart(before, after stage2aT02WireCapture) error {
	var first, second stage2aDriverCommand
	if json.Unmarshal(before.commandRaw, &first) != nil || json.Unmarshal(after.commandRaw, &second) != nil ||
		first.Phase != stage2aDriverLiveStart || second.Phase != stage2aDriverRestart ||
		first.Event != "paired-operation" || second.Event != first.Event ||
		first.InstallationID != second.InstallationID || first.TestPlanSHA256 != second.TestPlanSHA256 ||
		first.SessionID == second.SessionID || first.StartID == second.StartID ||
		first.ReservationSHA256 == second.ReservationSHA256 || first.Challenge == second.Challenge ||
		!after.observedAt.After(before.observedAt) || !bytes.Equal(before.hqKey, after.hqKey) ||
		!bytes.Equal(before.machineKey, after.machineKey) || before.epoch != after.epoch {
		return errStage2aReservationAuthority
	}
	initial, err := before.verify()
	if err != nil {
		return err
	}
	restarted, err := after.verify()
	if err != nil || initial.thumbprint != restarted.thumbprint || initial.generation != restarted.generation ||
		initial.jti == restarted.jti || initial.requestNonce == restarted.requestNonce {
		return errStage2aReservationAuthority
	}
	return nil
}

func verifyStage2aT02Wire(commandRaw, requestRaw, responseRaw, outageSignature []byte,
	hqKey, machineKey ed25519.PublicKey, epoch string, observedAt time.Time) (stage2aT02WireResult, error) {
	bad := stage2aT02WireResult{}
	command, nonce, err := parseStage2aT02Command(commandRaw)
	if err != nil || len(hqKey) != ed25519.PublicKeySize || len(machineKey) != ed25519.PublicKeySize ||
		bytes.Equal(hqKey, machineKey) || !stage2aQualificationHex(epoch) || len(epoch) != 64 || observedAt.IsZero() {
		return bad, errStage2aReservationAuthority
	}
	request, fields, err := stage2aT02Object(requestRaw)
	if err != nil || !stage2aT02Fields(fields, "verb", "option", "hq_epoch", "timestamp", "nonce", "public_key", "signature") {
		return bad, errStage2aReservationAuthority
	}
	var req struct {
		Verb      string `json:"verb"`
		Option    string `json:"option"`
		HQEpoch   string `json:"hq_epoch"`
		Nonce     string `json:"nonce"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
		Timestamp int64  `json:"timestamp"`
	}
	if json.Unmarshal(request, &req) != nil || req.Verb != "hq-device" || req.Option != "enrollment-proof" ||
		req.HQEpoch != epoch || req.Nonce != nonce || !stage2aT02Near(req.Timestamp, observedAt) ||
		!stage2aT02StandardKey(req.PublicKey, hqKey) ||
		!stage2aT02VerifyEd25519(hqKey, strings.Join([]string{
			"hq-device", "", "enrollment-proof", "", "", "", "", "", stage2aT02Int(req.Timestamp),
			nonce, "hq_epoch", epoch,
		}, "\n"), req.Signature) {
		return bad, errStage2aReservationAuthority
	}
	result := stage2aT02WireResult{requestNonce: nonce}
	if command.Event == "machine-outage-refused" {
		if len(responseRaw) != 0 {
			return bad, errStage2aReservationAuthority
		}
		hash := sha256.Sum256(requestRaw)
		if !stage2aT02VerifyEd25519(hqKey, strings.Join([]string{stage2aT02OutagePurpose,
			hex.EncodeToString(hash[:]), "machine-unreachable"}, "\n"), string(outageSignature)) {
			return bad, errStage2aReservationAuthority
		}
		result.refusal = "machine-unreachable"
		return result, nil
	}
	if len(outageSignature) != 0 {
		return bad, errStage2aReservationAuthority
	}
	response, replyFields, err := stage2aT02Object(responseRaw)
	if err != nil {
		return bad, errStage2aReservationAuthority
	}
	var reply struct {
		OK           bool            `json:"ok"`
		State        string          `json:"state"`
		Diagnostic   string          `json:"diagnostic"`
		Message      string          `json:"message"`
		Nonce        string          `json:"nonce"`
		RequestNonce string          `json:"request_nonce"`
		Signature    string          `json:"signature"`
		Timestamp    int64           `json:"timestamp"`
		Body         json.RawMessage `json:"body"`
	}
	if json.Unmarshal(response, &reply) != nil || reply.RequestNonce != nonce ||
		!stage2aT02Near(reply.Timestamp, observedAt) || reply.Timestamp < req.Timestamp ||
		len(reply.Nonce) < 1 || len(reply.Nonce) > 128 || !stage2aT02Token(reply.Nonce) {
		return bad, errStage2aReservationAuthority
	}
	if command.Event == "pairing-revoked-refused" {
		if !stage2aT02Fields(replyFields, "ok", "diagnostic", "message", "timestamp", "nonce", "request_nonce", "signature") ||
			reply.OK || (reply.Diagnostic != "MM_DAEMON_PEER_REFUSED" && reply.Diagnostic != "MM_DAEMON_UNKNOWN_KEY") ||
			strings.ContainsAny(reply.Message, "\r\n") ||
			!stage2aT02VerifyEd25519(machineKey, strings.Join([]string{"false", reply.Diagnostic,
				reply.Message, "", "", stage2aT02Int(reply.Timestamp), reply.Nonce, nonce}, "\n"), reply.Signature) {
			return bad, errStage2aReservationAuthority
		}
		result.refusal = reply.Diagnostic
		return result, nil
	}
	if !stage2aT02Fields(replyFields, "ok", "state", "body", "timestamp", "nonce", "request_nonce", "signature") ||
		!reply.OK || reply.State != "proved" ||
		!stage2aT02VerifyEd25519(machineKey, strings.Join([]string{"true", "", "", "proved",
			string(reply.Body), stage2aT02Int(reply.Timestamp), reply.Nonce, nonce}, "\n"), reply.Signature) {
		return bad, errStage2aReservationAuthority
	}
	thumb, generation, jti, err := stage2aT02Proof(reply.Body, epoch, reply.Timestamp)
	if err != nil {
		return bad, err
	}
	result.thumbprint, result.generation, result.jti = thumb, generation, jti
	return result, nil
}

// Stage2aT02PairedOperationNonce derives the released HQ request nonce from
// the exact A command payload. The daemon may arm only this positive purpose.
func Stage2aT02PairedOperationNonce(raw []byte) (string, error) {
	command, nonce, err := parseStage2aT02Command(raw)
	if err != nil || command.Event != "paired-operation" {
		return "", errStage2aReservationAuthority
	}
	return nonce, nil
}

// Stage2aT02RevokedRefusalNonce is for a disposable pairing-revocation
// rehearsal. It cannot arm the signing provider.
func Stage2aT02RevokedRefusalNonce(raw []byte) (string, error) {
	command, nonce, err := parseStage2aT02Command(raw)
	if err != nil || command.Event != "pairing-revoked-refused" {
		return "", errStage2aReservationAuthority
	}
	return nonce, nil
}

func parseStage2aT02Command(commandRaw []byte) (stage2aDriverCommand, string, error) {
	var command stage2aDriverCommand
	if len(commandRaw) == 0 || len(commandRaw) > 8192 ||
		stage2aQualificationKeysV1OnlyT02(commandRaw, stage2aDriverCommandFields) != nil ||
		json.Unmarshal(commandRaw, &command) != nil ||
		command.Schema != stage2aDriverCaseSchema || command.Kind != "capture" ||
		command.Profile != "managed-protected" || command.Gate != "T02" ||
		len(command.SessionID) != 32 || !stage2aQualificationHex(command.SessionID) ||
		!soulInstallationID.MatchString(command.InstallationID) || !soulStartID.MatchString(command.StartID) ||
		!stage2aQualificationDigest(command.ReservationSHA256) || !stage2aQualificationDigest(command.TestPlanSHA256) ||
		command.Sequence < 1 || command.Sequence > 1024 || !stage2aT02Base64URL(command.Challenge, 32) ||
		!stage2aT02Case(command.Phase, command.Event) {
		return stage2aDriverCommand{}, "", errStage2aReservationAuthority
	}
	commandHash := sha256.Sum256(append([]byte("soul-conformance/T02/paired-operation/v1\x00"), commandRaw...))
	nonce := base64.RawURLEncoding.EncodeToString(commandHash[:16])
	return command, nonce, nil
}

func stage2aQualificationKeysV1OnlyT02(raw []byte, fields []string) error {
	_, err := stage2aQualificationKeysV1(raw, fields, "")
	return err
}

func stage2aT02Case(phase stage2aDriverRunPhase, event string) bool {
	switch event {
	case "paired-operation":
		return phase == stage2aDriverLiveStart || phase == stage2aDriverRestart
	case "machine-outage-refused":
		return phase == "machine-outage"
	case "pairing-revoked-refused":
		return phase == "pairing-revoked"
	}
	return false
}

func stage2aT02Object(raw []byte) ([]byte, map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > 8192 || rejectDuplicateJSONKeys(raw) != nil {
		return nil, nil, errStage2aReservationAuthority
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil || !bytes.Equal(raw, compact.Bytes()) {
		return nil, nil, errStage2aReservationAuthority
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, nil, errStage2aReservationAuthority
	}
	return raw, fields, nil
}

func stage2aT02Fields(fields map[string]json.RawMessage, keys ...string) bool {
	if len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if len(fields[key]) == 0 || bytes.Equal(fields[key], []byte("null")) {
			return false
		}
	}
	return true
}

func stage2aT02Base64URL(value string, size int) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == size && base64.RawURLEncoding.EncodeToString(raw) == value
}

func stage2aT02StandardKey(value string, key ed25519.PublicKey) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && bytes.Equal(raw, key) && base64.StdEncoding.EncodeToString(raw) == value
}

func stage2aT02VerifyEd25519(key ed25519.PublicKey, message, encoded string) bool {
	sig, err := base64.StdEncoding.Strict().DecodeString(encoded)
	return err == nil && len(sig) == ed25519.SignatureSize &&
		base64.StdEncoding.EncodeToString(sig) == encoded && ed25519.Verify(key, []byte(message), sig)
}

func stage2aT02Near(timestamp int64, observed time.Time) bool {
	when := time.Unix(timestamp, 0)
	return !when.Before(observed.Add(-120*time.Second)) && !when.After(observed.Add(120*time.Second))
}

func stage2aT02Int(value int64) string { return strconv.FormatInt(value, 10) }

func stage2aT02Proof(raw []byte, epoch string, timestamp int64) (string, int64, string, error) {
	_, fields, err := stage2aT02Object(raw)
	if err != nil || !stage2aT02Fields(fields, "hq_epoch", "jwk", "thumbprint", "generation", "key_storage", "proof") {
		return "", 0, "", errStage2aReservationAuthority
	}
	var body struct {
		HQEpoch    string                          `json:"hq_epoch"`
		Thumbprint string                          `json:"thumbprint"`
		KeyStorage string                          `json:"key_storage"`
		Proof      string                          `json:"proof"`
		Generation int64                           `json:"generation"`
		JWK        struct{ Kty, Crv, X, Y string } `json:"jwk"`
	}
	if json.Unmarshal(raw, &body) != nil || body.HQEpoch != epoch || body.KeyStorage != "hardware" ||
		body.Generation < 1 || body.Generation > (1<<53)-1 || body.JWK.Kty != "EC" || body.JWK.Crv != "P-256" ||
		!stage2aT02Base64URL(body.JWK.X, 32) || !stage2aT02Base64URL(body.JWK.Y, 32) {
		return "", 0, "", errStage2aReservationAuthority
	}
	var jwkFields map[string]json.RawMessage
	if json.Unmarshal(fields["jwk"], &jwkFields) != nil || !stage2aT02Fields(jwkFields, "kty", "crv", "x", "y") {
		return "", 0, "", errStage2aReservationAuthority
	}
	x, _ := base64.RawURLEncoding.DecodeString(body.JWK.X)
	y, _ := base64.RawURLEncoding.DecodeString(body.JWK.Y)
	point := append(append([]byte{4}, x...), y...)
	px, py := elliptic.Unmarshal(elliptic.P256(), point)
	if px == nil || py == nil {
		return "", 0, "", errStage2aReservationAuthority
	}
	thumbRaw := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + body.JWK.X + `","y":"` + body.JWK.Y + `"}`))
	thumb := base64.RawURLEncoding.EncodeToString(thumbRaw[:])
	if body.Thumbprint != thumb {
		return "", 0, "", errStage2aReservationAuthority
	}
	parts := strings.Split(body.Proof, ".")
	if len(parts) != 3 || !stage2aT02Base64URL(parts[2], 64) {
		return "", 0, "", errStage2aReservationAuthority
	}
	headerRaw, headerErr := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	claimsRaw, claimsErr := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	_, header, hErr := stage2aT02Object(headerRaw)
	_, claims, cErr := stage2aT02Object(claimsRaw)
	if headerErr != nil || claimsErr != nil || hErr != nil || cErr != nil ||
		!stage2aT02Fields(header, "alg", "typ", "jwk") || !stage2aT02Fields(claims, "aud", "iat", "jti") {
		return "", 0, "", errStage2aReservationAuthority
	}
	var h struct{ Alg, Typ string }
	var c struct {
		Aud, Jti string
		Iat      int64
	}
	var headerJWK struct{ Kty, Crv, X, Y string }
	if json.Unmarshal(header["jwk"], &headerJWK) != nil ||
		headerJWK.Kty != body.JWK.Kty || headerJWK.Crv != body.JWK.Crv ||
		headerJWK.X != body.JWK.X || headerJWK.Y != body.JWK.Y ||
		json.Unmarshal(headerRaw, &h) != nil || json.Unmarshal(claimsRaw, &c) != nil ||
		h.Alg != "ES256" || h.Typ != "ab-enroll+jwt" || c.Aud != stage2aT02Audience ||
		c.Iat < timestamp-120 || c.Iat > timestamp+120 || len(c.Jti) < 16 || len(c.Jti) > 128 ||
		!stage2aT02Token(c.Jti) {
		return "", 0, "", errStage2aReservationAuthority
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: px, Y: py}
	if !ecdsa.Verify(&pub, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return "", 0, "", errStage2aReservationAuthority
	}
	return thumb, body.Generation, c.Jti, nil
}

func stage2aT02Token(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, c := range []byte(value) {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
