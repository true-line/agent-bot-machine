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
		vectors.SourceHead != "424b831c02a9486c5ad8489165c8727ab7c70341" ||
		len(vectors.Profiles) != 2 {
		t.Fatal("pinned contract vectors unavailable")
	}
	now := time.Date(2026, 11, 22, 14, 15, 30, 0, time.UTC)
	for name, vector := range vectors.Profiles {
		t.Run(name, func(t *testing.T) {
			key, err := base64.RawURLEncoding.Strict().DecodeString(vector.Issuer)
			if err != nil || len(key) != ed25519.PublicKeySize {
				t.Fatal("invalid fixture issuer")
			}
			got, err := VerifyQPreSignV3([]byte(vector.Wire), []byte(vector.Index), []byte(vector.EOF),
				[]byte(vector.Reservation), ed25519.PublicKey(key), now)
			if err != nil || !got.verified || got.ReservationSHA256 != digest([]byte(vector.Reservation)) ||
				got.IndexSHA256 != digest([]byte(vector.Index)) || got.EOFReceiptSHA256 != digest([]byte(vector.EOF)) {
				t.Fatalf("current signed %s Q chain refused: %+v %v", name, got, err)
			}
			wantProfile := "managed-" + name
			if got.Profile != wantProfile {
				t.Fatalf("profile = %q, want %q", got.Profile, wantProfile)
			}
			changed := append([]byte(nil), vector.Reservation...)
			changed[len(changed)-2] ^= 1
			if _, err := VerifyQPreSignV3([]byte(vector.Wire), []byte(vector.Index), []byte(vector.EOF),
				changed, ed25519.PublicKey(key), now); err == nil {
				t.Fatal("changed signed reservation accepted")
			}
			if name == "cooperative" {
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
				payload["adapter_transport"] = "direct"
				changedPayload, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if qReservationJoinCurrentV3(changedPayload, idx, "soul-cooperative-reservation", true) == nil {
					t.Fatal("cooperative Q joined non-B transport")
				}
			}
		})
	}
	cooperative := vectors.Profiles["cooperative"]
	protected := vectors.Profiles["protected"]
	key, err := base64.RawURLEncoding.Strict().DecodeString(cooperative.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyQPreSignV3([]byte(cooperative.Wire), []byte(cooperative.Index), []byte(cooperative.EOF),
		[]byte(protected.Reservation), ed25519.PublicKey(key), now); err == nil {
		t.Fatal("cross-profile signed reservation accepted")
	}
}
