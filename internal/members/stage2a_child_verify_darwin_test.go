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

func signedStage2aChildTest(t *testing.T, payload any, purpose string,
	pub ed25519.PublicKey, priv ed25519.PrivateKey) (string, string) {
	t.Helper()
	envelope, err := signStage2aEnvelope(payload, 1, purpose, pub,
		func(raw []byte) ([]byte, error) { return ed25519.Sign(priv, raw), nil })
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(envelope), stage2aReservationSHA256(envelope)
}

func TestStage2aChildReceiptAndLiveBindKernelStarts(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	selectors := Stage2aStopRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64), InstallationID: "soul-one",
		StartID: "st_0123456789abcdef01234567", LaunchID: "ln_0123456789abcdef01234567",
		PlanID: "plan-20261122T120000Z-abcd", PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64),
	}
	launcher := soulKernelProcessSnapshot{PID: 4201, ParentPID: 4000, ProcessGroupID: 4000,
		StartSeconds: now.Unix(), StartMicros: 1000, RealUID: 310, EffectiveUID: 310, SavedUID: 310,
		RealGID: 310, PrimaryGroupGID: 310, SavedGID: 310, Groups: []uint32{310}}
	child := soulKernelProcessSnapshot{PID: 4202, ParentPID: 4201, ProcessGroupID: 4202,
		StartSeconds: now.Unix(), StartMicros: 2000, RealUID: 310, EffectiveUID: 310, SavedUID: 310,
		RealGID: 310, PrimaryGroupGID: 310, SavedGID: 310, Groups: []uint32{310}}
	role := Stage2aLiveRoleIdentity{PID: 4101, UID: 310, GID: 310, StartSeconds: now.Unix(), StartMicros: 3000}
	bridge := Stage2aLiveRoleIdentity{PID: 4102, UID: 311, GID: 311, StartSeconds: now.Unix(), StartMicros: 4000}
	env := map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/private/tmp/one"}
	envRaw, err := marshalStage2aReservationJCS(env)
	if err != nil {
		t.Fatal(err)
	}
	in := Stage2aRoleInvocation{Request: SoulRunRequest{PlanDigest: selectors.PlanDigest,
		InstallationID: selectors.InstallationID, StartID: selectors.StartID, HQEpoch: selectors.HQEpoch},
		Start: SoulStartAssignment{PlanID: selectors.PlanID, PlanDigest: selectors.PlanDigest, LaunchID: selectors.LaunchID},
		ChildExec: &Stage2aChildExec{ReservationSHA256: selectors.ReservationSHA256,
			FinalizationSHA256: "sha256:" + strings.Repeat("d", 64), BindReceiptSHA256: "sha256:" + strings.Repeat("e", 64),
			Runner: role, Bridge: bridge, Executable: "/private/tmp/claude-agent-acp",
			ExecutableSHA256: "sha256:" + strings.Repeat("f", 64), SandboxPath: SoulChildSandbox,
			SandboxSHA256: "sha256:" + strings.Repeat("1", 64), RelaySocket: "/private/tmp/relay.sock", Environment: env}}
	grant := "sha256:" + strings.Repeat("2", 64)
	receipt := Stage2aChildStartPayload{Schema: "agent-bot-machine/stage2a-child-start/v1",
		Stage2aStopRequest: selectors, FinalizationSHA256: in.ChildExec.FinalizationSHA256,
		BindReceiptSHA256: in.ChildExec.BindReceiptSHA256, GrantSHA256: grant, Runner: role, Bridge: bridge,
		ChildLauncher: stage2aLiveRoleIdentity(launcher), Child: stage2aLiveRoleIdentity(child),
		Executable: in.ChildExec.Executable, ExecutableSHA256: in.ChildExec.ExecutableSHA256,
		SandboxPath: SoulChildSandbox, SandboxSHA256: in.ChildExec.SandboxSHA256,
		RelaySocket: in.ChildExec.RelaySocket, EnvironmentSHA256: stage2aReservationSHA256(envRaw),
		StartedAtMS: now.UnixMilli(), ExpiresAtMS: now.Add(4 * time.Second).UnixMilli()}
	b64, sha := signedStage2aChildTest(t, receipt, Stage2aChildStartPurpose, pub, priv)
	reply := Stage2aChildReadyReply{EnvelopeBase64URL: b64, SHA256: sha, ExpiresAtMS: receipt.ExpiresAtMS}
	if _, err := verifyStage2aChildStartReceipt(reply, in, grant, launcher, child, pub, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reused := child
	reused.StartMicros++
	if _, err := verifyStage2aChildStartReceipt(reply, in, grant, launcher, reused, pub, now.Add(time.Second)); err == nil {
		t.Fatal("reused child PID accepted")
	}
	if _, err := verifyStage2aChildStartReceipt(reply, in, grant, launcher, child, pub, now.Add(5*time.Second)); err == nil {
		t.Fatal("expired child receipt accepted")
	}
	reply.SHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err := verifyStage2aChildStartReceipt(reply, in, grant, launcher, child, pub, now.Add(time.Second)); err == nil {
		t.Fatal("tampered receipt accepted")
	}
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	lease := Stage2aLiveLeasePayload{Schema: "agent-bot-machine/stage2a-live-lease/v1",
		Stage2aStopRequest: selectors, FinalizationSHA256: in.ChildExec.FinalizationSHA256,
		BindReceiptSHA256: in.ChildExec.BindReceiptSHA256, Challenge: challenge, Runner: role, Bridge: bridge,
		ChildLauncher: ptrStage2aLiveRole(stage2aLiveRoleIdentity(launcher)),
		Child:         ptrStage2aLiveRole(stage2aLiveRoleIdentity(child)), ChildReceiptSHA256: sha,
		Sequence: 7, IssuedAtMS: now.UnixMilli(), ExpiresAtMS: now.Add(4 * time.Second).UnixMilli()}
	liveB64, liveSHA := signedStage2aChildTest(t, lease, Stage2aLiveLeasePurpose, pub, priv)
	liveReply := Stage2aLiveReply{LeaseEnvelopeBase64URL: liveB64, LeaseSHA256: liveSHA, LeaseSequence: 7}
	if _, err := verifyStage2aChildLiveLease(liveReply, challenge, in, sha, launcher, child, pub, 6, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStage2aChildLiveLease(liveReply, challenge, in, sha, launcher, child, pub, 7, now.Add(time.Second)); err == nil {
		t.Fatal("replayed lease sequence accepted")
	}
	if _, err := verifyStage2aChildLiveLease(liveReply, challenge, in, sha, launcher, child, pub, 6, now.Add(5*time.Second)); err == nil {
		t.Fatal("expired lease accepted")
	}
}

func ptrStage2aLiveRole(v Stage2aLiveRoleIdentity) *Stage2aLiveRoleIdentity { return &v }
