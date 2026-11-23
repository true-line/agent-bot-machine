package qualification

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// These exact envelopes are copied from soul-contracts draft PR #83 at the
// pinned source head. They are fixture keys and grant no host or gate authority.
func TestVerifyQPreSignCurrentProfilesV3(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-q-v3-profile-join-contracts-draft.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		SourceHead string `json:"source_head"`
		Profiles   map[string]struct {
			Reservation string `json:"reservation_envelope_jcs"`
			Wire        string `json:"q_wire_jcs"`
			Index       string `json:"q_index_envelope_jcs"`
			EOF         string `json:"q_eof_envelope_jcs"`
			Issuer      string `json:"issuer_public_key_base64url"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil ||
		vectors.SourceHead != "1ba4af13895f2b046ce904e7dd4ff739b7af350a" ||
		len(vectors.Profiles) != 3 {
		t.Fatal("pinned contract vectors unavailable")
	}
	now := time.Date(2026, 11, 22, 14, 15, 30, 0, time.UTC)
	for name, vector := range vectors.Profiles {
		t.Run(name, func(t *testing.T) {
			key, err := base64.RawURLEncoding.Strict().DecodeString(vector.Issuer)
			if err != nil || len(key) != ed25519.PublicKeySize {
				t.Fatal("invalid fixture issuer")
			}
			verify := VerifyQPreSignV3
			if name == "direct" {
				verify = VerifyQPreSignDirectCooperativeV3
			}
			got, err := verify([]byte(vector.Wire), []byte(vector.Index), []byte(vector.EOF),
				[]byte(vector.Reservation), ed25519.PublicKey(key), now)
			if err != nil || !got.verified || got.ReservationSHA256 != digest([]byte(vector.Reservation)) ||
				got.IndexSHA256 != digest([]byte(vector.Index)) || got.EOFReceiptSHA256 != digest([]byte(vector.EOF)) {
				t.Fatalf("current signed %s Q chain refused: %+v %v", name, got, err)
			}
			wantProfile := "managed-" + name
			if name == "direct" {
				wantProfile = "managed-cooperative"
			}
			if got.Profile != wantProfile {
				t.Fatalf("profile = %q, want %q", got.Profile, wantProfile)
			}
			changed := append([]byte(nil), vector.Reservation...)
			changed[len(changed)-2] ^= 1
			wantTransport := ""
			if name == "cooperative" {
				wantTransport = "brokered-b"
			} else if name == "direct" {
				wantTransport = "direct-comms"
			}
			if got.AdapterTransport != wantTransport {
				t.Fatalf("transport = %q, want %q", got.AdapterTransport, wantTransport)
			}
			if _, err := verify([]byte(vector.Wire), []byte(vector.Index), []byte(vector.EOF),
				changed, ed25519.PublicKey(key), now); err == nil {
				t.Fatal("changed signed reservation accepted")
			}
			if name == "cooperative" || name == "direct" {
				other := VerifyQPreSignDirectCooperativeV3
				if name == "direct" {
					other = VerifyQPreSignV3
				}
				if _, err := other([]byte(vector.Wire), []byte(vector.Index), []byte(vector.EOF),
					[]byte(vector.Reservation), ed25519.PublicKey(key), now); err == nil {
					t.Fatal("other cooperative transport branch accepted signed reservation")
				}
				reservation, err := qSignedRecordV3([]byte(vector.Reservation),
					cooperativeReservationPurposeV3, 3, ed25519.PublicKey(key))
				if err != nil {
					t.Fatal(err)
				}
				index, err := qSignedRecordV3([]byte(vector.Index), QFrameIndexPurposeV3, 1,
					ed25519.PublicKey(key))
				if err != nil {
					t.Fatal(err)
				}
				var payload map[string]any
				var idx qIndexV3
				if json.Unmarshal(reservation, &payload) != nil || json.Unmarshal(index, &idx) != nil {
					t.Fatal("invalid pinned fixture payload")
				}
				payload["adapter_transport"] = "wrong-transport"
				changedPayload, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if qReservationJoinCurrentV3(changedPayload, idx, "soul-cooperative-reservation", wantTransport) == nil {
					t.Fatal("cooperative Q joined wrong transport")
				}
			}
		})
	}
	cooperative := vectors.Profiles["cooperative"]
	protected := vectors.Profiles["protected"]
	protectedKey, err := base64.RawURLEncoding.Strict().DecodeString(protected.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyQPreSignDirectCooperativeV3([]byte(protected.Wire), []byte(protected.Index),
		[]byte(protected.EOF), []byte(protected.Reservation), ed25519.PublicKey(protectedKey), now); err == nil {
		t.Fatal("direct cooperative entry point accepted protected run")
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(cooperative.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyQPreSignV3([]byte(cooperative.Wire), []byte(cooperative.Index), []byte(cooperative.EOF),
		[]byte(protected.Reservation), ed25519.PublicKey(key), now); err == nil {
		t.Fatal("cross-profile signed reservation accepted")
	}
}
