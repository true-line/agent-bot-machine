package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"time"
)

// This is the release's enrollment audience. No Machine request supplies it.
const deviceEnrollmentAudience = "https://agents.true-line.ai/oauth/device_authorization"

type keydIdentity struct {
	Epoch      string    `json:"hq_epoch,omitempty"`
	JWK        deviceJWK `json:"jwk"`
	Thumbprint string    `json:"thumbprint"`
	Generation int64     `json:"generation"`
	Storage    string    `json:"key_storage"`
	DeviceID   string    `json:"device_id,omitempty"`
	ReceiptJTI string    `json:"receipt_jti,omitempty"`
	ReceiptSHA string    `json:"receipt_sha256,omitempty"`
	Assertion  string    `json:"assertion,omitempty"`
	Proof      string    `json:"proof,omitempty"`
}

func deviceResult(r Request, raw []byte, now time.Time, epoch string) ([]byte, string, error) {
	if len(raw) > 8192 {
		return nil, "", errHQDevice
	}
	if r.Option == "bind-access" {
		fields, ok := deviceObject(raw)
		var data struct {
			Session   string `json:"session"`
			ExpiresAt int64  `json:"expires_at"`
			Epoch     string `json:"hq_epoch,omitempty"`
		}
		if !ok || !deviceKeys(fields, "session", "expires_at") || json.Unmarshal(raw, &data) != nil || data.ExpiresAt <= now.Unix() || data.ExpiresAt > now.Unix()+900 {
			return nil, "", errHQDevice
		}
		thumb, ok := deviceSegment(data.Session)
		if !ok || len(thumb) != 32 {
			return nil, "", errHQDevice
		}
		data.Epoch = epoch
		body, err := json.Marshal(data)
		return body, "access-bound", err
	}
	var id keydIdentity
	fs, ok := deviceObject(raw)
	jwk, okJWK := deviceObject(fs["jwk"])
	keys := []string{"jwk", "thumbprint", "generation", "key_storage"}
	state := "identity"
	binding := []string{"device_id", "receipt_jti", "receipt_sha256"}
	switch r.Option {
	case "identity":
		if len(fs) != len(keys) {
			keys = append(keys, binding...)
		}
	case "bind-enrollment":
		keys = append(keys, binding...)
		state = "bound"
	case "access-assertion":
		keys = append(keys, "assertion")
		state = "asserted"
	case "enrollment-proof":
		keys = append(keys, "proof")
		state = "proved"
	default:
		return nil, "", errHQDevice
	}
	if !ok || !okJWK || !deviceKeys(fs, keys...) || !deviceKeys(jwk, "kty", "crv", "x", "y") || json.Unmarshal(raw, &id) != nil ||
		id.Storage != "hardware" || id.Generation < 1 || id.Generation > (1<<53)-1 || id.JWK.Kty != "EC" || id.JWK.Crv != "P-256" ||
		!validDevicePoint(id.JWK.X, id.JWK.Y) || id.JWK.thumbprint() != id.Thumbprint {
		return nil, "", errHQDevice
	}
	if _, bound := fs["device_id"]; bound {
		if !deviceID.MatchString(id.DeviceID) || !receiptNonce.MatchString(id.ReceiptJTI) || !exactKey(id.ReceiptSHA) {
			return nil, "", errHQDevice
		}
		if r.Option == "bind-enrollment" {
			raw, _ := deviceSegment(r.ReceiptBody)
			sum := sha256.Sum256(raw)
			var receipt struct {
				DeviceID string `json:"device_id"`
				JKT      string `json:"jkt"`
			}
			if json.Unmarshal(raw, &receipt) != nil || receipt.DeviceID != id.DeviceID || receipt.JKT != id.Thumbprint ||
				id.ReceiptSHA != hex.EncodeToString(sum[:]) || id.ReceiptJTI != r.ReceiptJTI {
				return nil, "", errHQDevice
			}
		}
	}
	if r.Option == "enrollment-proof" && !validDeviceJWS(id.Proof, id, now, true) || r.Option == "access-assertion" && !validDeviceJWS(id.Assertion, id, now, false) {
		return nil, "", errHQDevice
	}
	id.Epoch = epoch
	body, err := json.Marshal(id)
	return body, state, err
}

func deviceSegment(s string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil && base64.RawURLEncoding.EncodeToString(b) == s
}

func validDeviceJWS(value string, id keydIdentity, now time.Time, enrollment bool) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	header, okHeader := deviceSegment(parts[0])
	claims, okClaims := deviceSegment(parts[1])
	signature, okSig := deviceSegment(parts[2])
	if !okHeader || !okClaims || !okSig || len(signature) != 64 {
		return false
	}
	h, ok := deviceObject(header)
	c, okC := deviceObject(claims)
	var hdr struct {
		Alg string
		Typ string
		JWK deviceJWK
	}
	var payload struct {
		Aud string
		Iat int64
		Exp int64
		Jti string
		Iss string
		Sub string
		Cnf struct{ JWK deviceJWK }
	}
	if !ok || !okC || json.Unmarshal(header, &hdr) != nil || hdr.Alg != "ES256" || json.Unmarshal(claims, &payload) != nil ||
		payload.Iat < now.Unix()-30 || payload.Iat > now.Unix()+30 {
		return false
	}
	jti, ok := deviceSegment(payload.Jti)
	if !ok || len(jti) != 16 {
		return false
	}
	if enrollment {
		key, ok := deviceObject(h["jwk"])
		if !ok || !deviceKeys(h, "alg", "typ", "jwk") || !deviceKeys(key, "kty", "crv", "x", "y") || hdr.Typ != "ab-enroll+jwt" || hdr.JWK != id.JWK ||
			!deviceKeys(c, "aud", "iat", "jti") || payload.Aud != deviceEnrollmentAudience {
			return false
		}
	} else {
		cnf, ok := deviceObject(c["cnf"])
		key, keyOK := deviceObject(cnf["jwk"])
		j := payload.Cnf.JWK
		if !ok || !keyOK || !deviceKeys(cnf, "jwk") || !deviceKeys(key, "kty", "crv", "x", "y") || !deviceKeys(h, "alg", "typ") || hdr.Typ != "JWT" ||
			!deviceKeys(c, "iss", "sub", "aud", "iat", "exp", "jti", "cnf") || !deviceID.MatchString(payload.Iss) || payload.Iss != payload.Sub ||
			payload.Aud != "https://agents.true-line.ai/oauth/token" || payload.Exp != payload.Iat+120 || j.Kty != "EC" || j.Crv != "P-256" || !validDevicePoint(j.X, j.Y) || j == id.JWK {
			return false
		}
	}
	x, _ := deviceSegment(id.JWK.X)
	y, _ := deviceSegment(id.JWK.Y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
}
