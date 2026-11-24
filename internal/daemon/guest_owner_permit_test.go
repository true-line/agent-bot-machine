package daemon

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/members"
)

func TestGuestOwnerPermitActionIncludesHQUpgradeAndSafeRetirement(t *testing.T) {
	if !guestOwnerPermitAction(members.SoulProtectedLaunchRetirePurpose) ||
		!guestOwnerPermitAction(members.UpgradePurpose) ||
		guestOwnerPermitAction("hq-service-recovery") ||
		guestOwnerPermitAction("arbitrary") {
		t.Fatal("guest permit action scope changed")
	}
}

func guestPermitFixture(t *testing.T, now time.Time) (ed25519.PrivateKey, string, []byte, GuestTartObservation) {
	return guestPermitFixtureForAction(t, now, members.SoulRunnerAccountsPurpose)
}

func guestPermitFixtureForAction(t *testing.T, now time.Time, action string) (ed25519.PrivateKey, string, []byte, GuestTartObservation) {
	t.Helper()
	guestPub, guestPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ownerPublic := base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), owner.X, owner.Y))
	plan := "{\"purpose\":\"" + action + "\",\"version\":3}\n"
	digest := sha256.Sum256([]byte(plan))
	body, err := json.Marshal(map[string]any{
		"action": action, "machine_key": hex.EncodeToString(guestPub),
		"hq_key": "1" + hex.EncodeToString(make([]byte, 31)) + "1", "owner_key": ownerPublic,
		"plan_id": "plan-20260101T000000Z-abcd", "plan_digest": hex.EncodeToString(digest[:]),
		"nonce": hex.EncodeToString(make([]byte, 32)), "expires_at": now.Unix() + 90,
		"plan_canonical": plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := Response{OK: true, State: "challenged", Body: body,
		Timestamp: now.Unix(), Nonce: "response-nonce", RequestNonce: "request-nonce"}
	signResponse(guestPrivate, &frame)
	line, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	line = append(line, '\n')
	return guestPrivate, ownerPublic, line,
		GuestTartObservation{VMName: "stage2a-rehearsal", MAC: "02:00:00:00:00:01", Build: "25G83",
			WrapperSHA: hex.EncodeToString(make([]byte, 32)), AppSHA: hex.EncodeToString(make([]byte, 32)), Machine: guestPub}
}

func TestGuestOwnerPermitIssuesExactHQUpgradeButRefusesRecovery(t *testing.T) {
	now := time.Unix(1795503600, 0)
	_, owner, challenge, observed := guestPermitFixtureForAction(t, now, members.UpgradePurpose)
	_, host, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := issueGuestOwnerPermit(host, owner, challenge, observed, now)
	if err != nil || permit.Action != members.UpgradePurpose {
		t.Fatalf("exact HQ upgrade permit refused: %v", err)
	}
	_, owner, challenge, observed = guestPermitFixtureForAction(t, now, "hq-service-recovery")
	if _, err := issueGuestOwnerPermit(host, owner, challenge, observed, now); err == nil {
		t.Fatal("HQ recovery acquired a guest permit")
	}
}

func TestGuestOwnerPermitAcceptsOnlyDedicatedHQUpgradeWithoutPurpose(t *testing.T) {
	now := time.Unix(1795503600, 0)
	guest, owner, original, observed := guestPermitFixtureForAction(t, now, members.UpgradePurpose)
	_, host, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := members.Plan{Version: members.PlanVersion, HQAccount: members.DarwinHQAccount,
		Dir: members.DarwinDir, Members: []string{}, Steps: []members.Step{
			{Kind: members.KindHQAccount, Target: members.DarwinHQAccount,
				Action: members.ActionNone, Group: members.DarwinHQAccount, Mode: "0700"},
			{Kind: members.KindService, Target: "ai.true-line.agent-bot-hq",
				Action: "upgrade", Owner: "admin", Content: "{}"},
		}}
	challengeFor := func(plan members.Plan) []byte {
		t.Helper()
		canonical, err := plan.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		var frame Response
		if err := json.Unmarshal(original, &frame); err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(frame.Body, &body); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(canonical)
		body["plan_canonical"] = string(canonical)
		body["plan_digest"] = hex.EncodeToString(digest[:])
		frame.Body, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		signResponse(guest, &frame)
		line, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		return append(line, '\n')
	}
	if permit, err := issueGuestOwnerPermit(host, owner, challengeFor(plan), observed, now); err != nil ||
		permit.Action != members.UpgradePurpose {
		t.Fatalf("dedicated HQ upgrade plan refused: %v", err)
	}
	wrong := plan
	wrong.Steps = append([]members.Step(nil), plan.Steps...)
	wrong.Steps[1].Target = "other-service"
	if _, err := issueGuestOwnerPermit(host, owner, challengeFor(wrong), observed, now); err == nil {
		t.Fatal("different service acquired an HQ upgrade permit")
	}
	wrong = plan
	wrong.Members = []string{"_other"}
	if _, err := issueGuestOwnerPermit(host, owner, challengeFor(wrong), observed, now); err == nil {
		t.Fatal("account-bearing plan acquired an HQ upgrade permit")
	}
}

func TestGuestOwnerPermitBindsIndependentTartKeyAndExactChallenge(t *testing.T) {
	now := time.Unix(1795503600, 0)
	_, owner, challenge, observed := guestPermitFixture(t, now)
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := issueGuestOwnerPermit(hostPrivate, owner, challenge, observed, now)
	if err != nil {
		t.Fatal(err)
	}
	if permit.HostMachineKey != hex.EncodeToString(hostPublic) || permit.GuestMachineKey != hex.EncodeToString(observed.Machine) ||
		permit.Action != "soul-runner-provision" || permit.PlanID != "plan-20260101T000000Z-abcd" ||
		permit.ExpiresAt != now.Unix()+90 || permit.GuestVMMAC != observed.MAC {
		t.Fatalf("permit lost exact binding: %+v", permit)
	}
	sig, err := base64.StdEncoding.DecodeString(permit.Signature)
	if err != nil || !ed25519.Verify(hostPublic, permit.signedBytes(), sig) {
		t.Fatal("host permit signature failed")
	}
	challengeHash := sha256.Sum256(challenge[:len(challenge)-1])
	if permit.ChallengeSHA256 != hex.EncodeToString(challengeHash[:]) {
		t.Fatal("permit omitted exact signed frame digest")
	}
	changed := permit
	changed.PlanDigest = hex.EncodeToString(make([]byte, 32))
	if ed25519.Verify(hostPublic, changed.signedBytes(), sig) {
		t.Fatal("changed plan retained host signature")
	}
	changed = permit
	changed.TartWrapperSHA = hex.EncodeToString(make([]byte, 32))
	changed.TartWrapperSHA = "1" + changed.TartWrapperSHA[1:]
	if ed25519.Verify(hostPublic, changed.signedBytes(), sig) {
		t.Fatal("changed Tart wrapper retained host signature")
	}
}

func TestGuestOwnerPermitRefusesUnobservedOrChangedGuest(t *testing.T) {
	now := time.Unix(1795503600, 0)
	_, owner, challenge, observed := guestPermitFixture(t, now)
	_, host, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := observed
	wrong.Machine = ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	if _, err := issueGuestOwnerPermit(host, owner, challenge, wrong, now); err == nil {
		t.Fatal("unobserved guest key accepted")
	}
	if _, err := issueGuestOwnerPermit(host, "different-owner", challenge, observed, now); err == nil {
		t.Fatal("other owner accepted")
	}
	if _, err := issueGuestOwnerPermit(host, owner, challenge, observed, now.Add(91*time.Second)); err == nil {
		t.Fatal("expired challenge accepted")
	}
	changed := append([]byte(nil), challenge...)
	for i := range changed {
		if changed[i] == '1' {
			changed[i] = '2'
			break
		}
	}
	if _, err := issueGuestOwnerPermit(host, owner, changed, observed, now); err == nil {
		t.Fatal("changed signed challenge accepted")
	}
	wrong = observed
	wrong.MAC = "invalid"
	if _, err := issueGuestOwnerPermit(host, owner, challenge, wrong, now); err == nil {
		t.Fatal("malformed VM MAC accepted")
	}
}
