package daemon

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/qwts/managed-machine/internal/diag"
)

const deviceVerb = "hq-device"
const deviceDomain = "agent-bot-machine/keyd-hq-device/v1"

var errHQDevice = errors.New("HQ device custody is unavailable")
var deviceNonce = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var receiptNonce = regexp.MustCompile(`^enroll-v1:[0-9a-f]{64}$`)
var receiptKID = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`)
var deviceID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// Parse the exact field names once, including explicit null and duplicates.
// Machine and keyd must interpret canonically signed fields identically.
func deviceObject(raw []byte) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false
		}
		fields[name] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return nil, false
	}
	return fields, true
}

func deviceKeys(fields map[string]json.RawMessage, keys ...string) bool {
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

func deviceFields(r Request, raw []byte) (string, string) {
	if r.Verb != deviceVerb {
		if r.DeviceSession != "" || r.HQEpoch != "" || r.ReceiptBody != "" || r.ReceiptJTI != "" || r.ReceiptKID != "" || r.ReceiptSignature != "" || hasRawField(raw, "session", "hq_epoch", "receipt_body", "receipt_jti", "receipt_kid", "receipt_signature") {
			return diag.DaemonUndeclared, "HQ device fields are not declared on this verb"
		}
		return "", ""
	}
	fields, ok := deviceObject(raw)
	keys := []string{"verb", "option", "nonce", "timestamp", "public_key", "signature"}
	if r.Option != "identity" {
		keys = append(keys, "hq_epoch")
		ok = ok && (r.HQEpoch == "legacy" || exactKey(r.HQEpoch))
	}
	if ok && deviceNonce.MatchString(r.Nonce) {
		switch r.Option {
		case "identity", "enrollment-proof", "access-assertion":
			ok = deviceKeys(fields, keys...)
		case "whoami":
			selector, valid := deviceSegment(r.DeviceSession)
			ok = deviceKeys(fields, append(keys, "session")...) && valid && len(selector) == sha256.Size
		case "bind-enrollment", "bind-access":
			keys = append(keys, "receipt_body", "receipt_jti", "receipt_kid", "receipt_signature")
			body, bodyOK := deviceSegment(r.ReceiptBody)
			sig, sigOK := deviceSegment(r.ReceiptSignature)
			ok = deviceKeys(fields, keys...) && bodyOK && len(body) > 0 && len(body) <= 8192 && json.Valid(body) &&
				validReceiptJTI(r.Option, r.ReceiptJTI) && receiptKID.MatchString(r.ReceiptKID) && sigOK && len(sig) == ed25519.SignatureSize
		default:
			ok = false
		}
		if ok {
			return "", ""
		}
	}
	return diag.DaemonUndeclared, "invalid HQ device purpose or request fields"
}

func validReceiptJTI(option, jti string) bool {
	if option == "bind-enrollment" {
		return receiptNonce.MatchString(jti)
	}
	raw, ok := deviceSegment(jti)
	return option == "bind-access" && ok && len(raw) == 16
}

type deviceJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func validDevicePoint(x, y string) bool {
	encoded := []byte{4}
	for _, v := range []string{x, y} {
		coordinate, err := base64.RawURLEncoding.Strict().DecodeString(v)
		if err != nil || len(coordinate) != 32 || len(v) != 43 {
			return false
		}
		encoded = append(encoded, coordinate...)
	}
	_, err := ecdh.P256().NewPublicKey(encoded)
	return err == nil
}

func (j deviceJWK) thumbprint() string {
	// RFC 7638 requires lexicographic member ordering and only public fields.
	digest := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

type deviceDelegation struct {
	Session          string `json:"session,omitempty"`
	Epoch            string `json:"hq_epoch"`
	Machine          string `json:"machine_pub"`
	HQ               string `json:"hq_pub"`
	UID              int    `json:"hq_uid"`
	Nonce            string `json:"req_nonce"`
	Timestamp        int64  `json:"timestamp"`
	Option           string `json:"option"`
	ReceiptBody      string `json:"receipt_body,omitempty"`
	ReceiptJTI       string `json:"receipt_jti,omitempty"`
	ReceiptKID       string `json:"receipt_kid,omitempty"`
	ReceiptSignature string `json:"receipt_signature,omitempty"`
	Signature        string `json:"signature"`
}

func (d deviceDelegation) transcript() []byte {
	parts := []string{deviceDomain, d.Machine, d.HQ, strconv.Itoa(d.UID), d.Nonce, strconv.FormatInt(d.Timestamp, 10), d.Option, "", "", "", "hq_epoch", d.Epoch}
	if d.Option == "whoami" {
		parts = append(parts, "session", d.Session)
	}
	if d.Option == "bind-enrollment" || d.Option == "bind-access" {
		parts = append(parts, "receipt_body", d.ReceiptBody, "receipt_jti", d.ReceiptJTI, "receipt_kid", d.ReceiptKID, "receipt_signature", d.ReceiptSignature)
	}
	return []byte(strings.Join(parts, "\n"))
}

func deviceUnavailable() Response {
	return refused(diag.DaemonUnimplemented, "HQ device operation unavailable from administrative custody")
}

// Only the explicitly approved, live HQ principal can use device custody.
func currentDevicePairing(dir string) (Pairing, error) {
	s, err := readOwnerPairState(dir)
	if err != nil || s == nil {
		return Pairing{}, errHQDevice
	}
	return approvedHQPairing(dir, s)
}

func devicePairAllows(p Pairing, peerUID int, pub ed25519.PublicKey) bool {
	return p.OwnerPresenceRequired && p.AgentDaemonBound && peerUID > 0 && peerUID != ownerPeerID() &&
		p.AgentDaemonUID == peerUID && len(pub) == ed25519.PublicKeySize && p.AgentDaemon.Equal(pub) &&
		p.allows(pub) && !p.isTerminal(pub)
}

// A successful response can wait for the peer's receive buffer. Hold the
// pairing lock across the actual bounded write so a completed local revoke
// cannot be followed by delivery of an earlier authorized provider response.
func lockDeviceDelivery(dir string, req Request, body []byte) (func() error, error) {
	unlock, err := lockDevicePairing(dir)
	if err != nil {
		return nil, errHQDevice
	}
	p, err := currentDevicePairing(dir)
	pub, decodeErr := base64.StdEncoding.Strict().DecodeString(req.PublicKey)
	var result struct {
		Epoch string `json:"hq_epoch"`
	}
	if err != nil || decodeErr != nil || !devicePairAllows(p, req.peerUID, pub) || json.Unmarshal(body, &result) != nil || result.Epoch != deviceEpoch(p) {
		_ = unlock()
		return nil, errHQDevice
	}
	return unlock, nil
}

func deviceEpoch(p Pairing) string {
	if p.HQEpoch == "" {
		return "legacy"
	}
	return p.HQEpoch
}

type deviceProvider func(context.Context, string, deviceDelegation) ([]byte, error)

func requestHQDevice(ctx context.Context, root string, machine ed25519.PrivateKey, req Request, now func() time.Time, provider deviceProvider) Response {
	switch req.Option {
	case "identity", "enrollment-proof", "bind-enrollment", "access-assertion", "bind-access", "whoami":
	default:
		return deviceUnavailable()
	}
	dir := stateDir(root)
	// Hold the same lock as protected enrollment/revocation until the
	// bounded custody call finishes. Recheck the live role, not cached state.
	unlock, err := lockDevicePairing(dir)
	if err != nil {
		return deviceUnavailable()
	}
	defer unlock()
	p, err := currentDevicePairing(dir)
	pub, decodeErr := base64.StdEncoding.Strict().DecodeString(req.PublicKey)
	if err != nil || decodeErr != nil || !devicePairAllows(p, req.peerUID, ed25519.PublicKey(pub)) ||
		base64.StdEncoding.EncodeToString(pub) != req.PublicKey || len(machine) != ed25519.PrivateKeySize {
		return deviceUnavailable()
	}
	epoch := deviceEpoch(p)
	if req.Option != "identity" && req.HQEpoch != epoch {
		return deviceUnavailable()
	}
	pinnedMachine, err := loadPublic(filepath.Join(dir, "daemon.pub"))
	if err != nil || !pinnedMachine.Equal(machine.Public()) {
		return deviceUnavailable()
	}
	t := now()
	if t.Sub(time.Unix(req.Timestamp, 0)).Abs() > timestampSkew {
		return deviceUnavailable()
	}
	d := deviceDelegation{Epoch: epoch, Machine: base64.StdEncoding.EncodeToString(machine.Public().(ed25519.PublicKey)), HQ: req.PublicKey, UID: req.peerUID, Nonce: req.Nonce,
		Timestamp: t.Unix(), Option: req.Option, Session: req.DeviceSession, ReceiptBody: req.ReceiptBody, ReceiptJTI: req.ReceiptJTI, ReceiptKID: req.ReceiptKID, ReceiptSignature: req.ReceiptSignature}
	d.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(machine, d.transcript()))
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := provider(ctx, root, d)
	if err != nil {
		return deviceUnavailable()
	}
	// Local administrative revocation does not wait for keyd. A completed
	// signature must not be delivered if the role was cut off in flight.
	current, err := currentDevicePairing(dir)
	if err != nil || !devicePairAllows(current, req.peerUID, ed25519.PublicKey(pub)) || current.HQEpoch != p.HQEpoch {
		return deviceUnavailable()
	}
	body, state, err := deviceResult(req, raw, t, epoch)
	if err != nil {
		return deviceUnavailable()
	}
	return Response{OK: true, State: state, Body: body}
}
