//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestStage2aInnerACPCaptureSelectorRequiresExactSignedOneUseShape(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	q := stage2aInnerACPCaptureSelectorV1{
		Schema: stage2aInnerACPCaptureSelectorSchemaV1,
		Stage2aStopRequest: Stage2aStopRequest{
			ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
			InstallationID:    "soul-one", StartID: "st_0123456789abcdef01234567",
			LaunchID: "ln_0123456789abcdef01234567",
			PlanID:   "plan-20261122T120000Z-abcd", PlanDigest: strings.Repeat("b", 64),
			HQEpoch: strings.Repeat("c", 64),
		},
		SessionID: strings.Repeat("d", 32), Sequence: 4,
		TestPlanSHA256:     "sha256:" + strings.Repeat("e", 64),
		ChallengeBase64URL: base64.RawURLEncoding.EncodeToString(bytesOf(32, 7)),
		ExpiresAtMS:        now.Add(time.Minute).UnixMilli(),
	}
	sign := func(message []byte) ([]byte, error) { return ed25519.Sign(private, message), nil }
	wire, digest, err := signStage2aInnerACPCaptureSelectorV1(q, now, public, sign)
	if err != nil {
		t.Fatal(err)
	}
	got, gotDigest, err := verifyStage2aInnerACPCaptureSelectorV1(wire, public, now)
	if err != nil || got != q || gotDigest != digest {
		t.Fatalf("signed selector round trip failed: %v", err)
	}
	bad := q
	bad.ChallengeBase64URL = base64.RawURLEncoding.EncodeToString(bytesOf(31, 7))
	if _, _, err := signStage2aInnerACPCaptureSelectorV1(bad, now, public, sign); err == nil {
		t.Fatal("short challenge accepted")
	}
	bad = q
	bad.ExpiresAtMS = now.Add(121 * time.Second).UnixMilli()
	if _, _, err := signStage2aInnerACPCaptureSelectorV1(bad, now, public, sign); err == nil {
		t.Fatal("overlong selector lease accepted")
	}
	bad = q
	bad.Sequence = 0
	if _, _, err := signStage2aInnerACPCaptureSelectorV1(bad, now, public, sign); err == nil {
		t.Fatal("missing Q sequence accepted")
	}
	if _, _, err := verifyStage2aInnerACPCaptureSelectorV1(wire, public, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired selector accepted")
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyStage2aInnerACPCaptureSelectorV1(wire, otherPublic, now); err == nil {
		t.Fatal("foreign Machine key accepted")
	}
	if _, _, err := verifyStage2aInnerACPCaptureSelectorV1(append([]byte(" "), wire...), public, now); err == nil {
		t.Fatal("noncanonical selector envelope accepted")
	}
}

func bytesOf(n int, value byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = value
	}
	return b
}
