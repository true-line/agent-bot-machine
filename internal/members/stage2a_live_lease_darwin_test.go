package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStage2aSignedLiveLeaseBindsChallengeAndKernelStarts(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	sign := func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }
	q := Stage2aStopRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID:    "soul-one", StartID: "st_0123456789abcdef01234567",
		LaunchID: "ln_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64),
	}
	finalization, err := signStage2aEnvelope(Stage2aFinalizationPayload{
		Schema: "agent-bot-machine/stage2a-finalization/v1", Stage2aStopRequest: q,
		BindReceiptSHA256: "sha256:" + strings.Repeat("d", 64),
		RelaySocket: Stage2aRelayClaim{Path: "/private/example/relay.sock",
			Socket: Stage2aKernelNodeClaim{UID: 312, GID: 311, Device: "1", Inode: "2", Mode: 0660}},
		BridgePID: 4243, FinalizedAt: "2026-11-22T14:15:16Z",
	}, 1, Stage2aFinalizationPurpose, pub, sign)
	if err != nil {
		t.Fatal(err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	r := &stage2aLiveReservation{
		digest: q.ReservationSHA256, finalizationEnvelope: finalization,
		bindReceiptSHA256: "sha256:" + strings.Repeat("d", 64),
		runnerPID:         4242, bridgePID: 4243,
		runnerProcess: soulKernelProcessSnapshot{PID: 4242, EffectiveUID: 311, PrimaryGroupGID: 311,
			StartSeconds: 1795356916, StartMicros: 123456},
		bridgeProcess: soulKernelProcessSnapshot{PID: 4243, EffectiveUID: 312, PrimaryGroupGID: 312,
			StartSeconds: 1795356917, StartMicros: 654321},
	}
	issued := time.Date(2026, 11, 22, 14, 15, 17, 0, time.UTC)
	envelope, err := signStage2aLiveLease(q, challenge, r, 1, issued, issued.Add(5*time.Second), pub, sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 8192 {
		t.Fatalf("signed lease did not fit bounded relay: %d %v", len(envelope), err)
	}
	var signed stage2aSignedReservation
	if decodeStage2aRoleJSON(envelope, &signed) != nil || signed.SchemaVersion != 1 ||
		signed.Purpose != Stage2aLiveLeasePurpose ||
		signed.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(pub) {
		t.Fatal("lease envelope purpose, issuer or schema differs")
	}
	payloadRaw, err := decodeStage2aRoleBase64(signed.PayloadBase64URL, 4096)
	if err != nil || signed.PayloadSHA256 != stage2aReservationSHA256(payloadRaw) {
		t.Fatal("lease payload digest differs")
	}
	signature, err := decodeStage2aRoleBase64(signed.SignatureBase64URL, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(pub, append([]byte(Stage2aLiveLeasePurpose+"\x00"), payloadRaw...), signature) ||
		ed25519.Verify(pub, append([]byte(Stage2aFinalizationPurpose+"\x00"), payloadRaw...), signature) {
		t.Fatal("lease signature lacks its own A purpose")
	}
	var payload Stage2aLiveLeasePayload
	if json.Unmarshal(payloadRaw, &payload) != nil {
		t.Fatal("lease payload cannot be decoded")
	}
	canonical, err := marshalStage2aReservationJCS(payload)
	if err != nil || !bytes.Equal(payloadRaw, canonical) || payload.Schema != "agent-bot-machine/stage2a-live-lease/v1" ||
		payload.Stage2aStopRequest != q || payload.Challenge != challenge || payload.Sequence != 1 ||
		payload.FinalizationSHA256 != stage2aReservationSHA256(finalization) ||
		payload.BindReceiptSHA256 != r.bindReceiptSHA256 ||
		payload.Runner.PID != 4242 || payload.Runner.StartMicros != 123456 ||
		payload.Bridge.PID != 4243 || payload.Bridge.StartMicros != 654321 ||
		payload.IssuedAtMS != issued.UnixMilli() || payload.ExpiresAtMS != issued.Add(5*time.Second).UnixMilli() {
		t.Fatalf("signed lease did not bind exact run: %+v %v", payload, err)
	}
	for name, change := range map[string]func(*stage2aLiveReservation, *uint64, *time.Time){
		"replayed sequence":   func(r *stage2aLiveReservation, n *uint64, _ *time.Time) { r.liveSequence = 1 },
		"changed wrapper PID": func(r *stage2aLiveReservation, _ *uint64, _ *time.Time) { r.runnerProcess.PID++ },
		"late expiry":         func(_ *stage2aLiveReservation, _ *uint64, expires *time.Time) { *expires = issued.Add(6 * time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *r
			next, expiry := uint64(1), issued.Add(5*time.Second)
			change(&changed, &next, &expiry)
			if _, err := signStage2aLiveLease(q, challenge, &changed, next, issued, expiry, pub, sign); err == nil {
				t.Fatal("invalid lease was signed")
			}
		})
	}
}
