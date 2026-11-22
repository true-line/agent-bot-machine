//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStage2aRoleGrantBindsLiveChallengeAndInvocation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expires := now.Add(20 * time.Second).Format(time.RFC3339Nano)
	request := SoulRunRequest{
		PlanDigest: strings.Repeat("a", 64), InstallationID: "soul-one",
		StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("b", 64),
	}
	launchID := "ln_0123456789abcdef01234567"
	challenge := stage2aExecChallenge{
		Role: "runner", Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), PID: 1234,
	}
	invocation := Stage2aRoleInvocation{
		Request: request,
		Start: SoulStartAssignment{
			InstallationID: request.InstallationID, StartID: request.StartID,
			HQEpoch: request.HQEpoch, LaunchID: launchID, ExpiresAt: expires,
		},
		RunnerExec: &Stage2aRunnerExec{},
	}
	invocationRaw, err := marshalStage2aReservationJCS(invocation)
	if err != nil {
		t.Fatal(err)
	}
	grant := Stage2aRoleGrant{
		ReservationSHA256: "sha256:" + strings.Repeat("c", 64),
		Role:              challenge.Role, Nonce: challenge.Nonce, PID: challenge.PID,
		LaunchID: launchID, InstallationID: request.InstallationID,
		StartID: request.StartID, HQEpoch: request.HQEpoch, ExpiresAt: expires,
		InvocationSHA256: stage2aReservationSHA256(invocationRaw),
	}
	envelope, err := signStage2aEnvelope(grant, 1, Stage2aRoleExecPurpose, pub,
		func(raw []byte) ([]byte, error) { return ed25519.Sign(priv, raw), nil })
	if err != nil {
		t.Fatal(err)
	}
	reply := Stage2aExecReply{
		EnvelopeBase64URL:   base64.RawURLEncoding.EncodeToString(envelope),
		SHA256:              stage2aReservationSHA256(envelope),
		InvocationBase64URL: base64.RawURLEncoding.EncodeToString(invocationRaw),
	}
	frame, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStage2aRoleGrant(frame, challenge, pub, now); err != nil {
		t.Fatalf("signed grant refused: %v", err)
	}
	wrongNonce := challenge
	wrongNonce.Nonce = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	if _, err := verifyStage2aRoleGrant(frame, wrongNonce, pub, now); err == nil {
		t.Fatal("grant replayed against another role nonce")
	}
	wrongPID := challenge
	wrongPID.PID++
	if _, err := verifyStage2aRoleGrant(frame, wrongPID, pub, now); err == nil {
		t.Fatal("grant replayed against another process")
	}
	if _, err := verifyStage2aRoleGrant(frame, challenge, pub, now.Add(21*time.Second)); err == nil {
		t.Fatal("expired grant accepted")
	}
	reply.InvocationBase64URL = base64.RawURLEncoding.EncodeToString(append(invocationRaw, ' '))
	frame, _ = json.Marshal(reply)
	if _, err := verifyStage2aRoleGrant(frame, challenge, pub, now); err == nil {
		t.Fatal("tampered invocation accepted")
	}
}

func TestStage2aExecRefusesUninstalledBridgeGrant(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := NewStage2aService(priv)
	if _, err := service.Exec(501, strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64),
		"bridge", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), 1234); err == nil {
		t.Fatal("bridge grant issued without installed B proof authority")
	}
}

func TestStage2aInstalledAuthorityIsPerSoul(t *testing.T) {
	one, err := stage2aAuthorityPath("soul-one")
	if err != nil {
		t.Fatal(err)
	}
	two, err := stage2aAuthorityPath("soul-two")
	if err != nil || two == one {
		t.Fatalf("sibling Soul selected the same authority file: %q %q, %v", one, two, err)
	}
	if _, err := stage2aAuthorityPath("../soul-one"); err == nil {
		t.Fatal("path component accepted as installation ID")
	}
}
