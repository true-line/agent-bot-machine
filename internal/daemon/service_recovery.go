package daemon

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
)

const recoveryVerb = "hq-service-recovery"
const upgradeVerb = "hq-service-upgrade"

const harnessAccountsVerb = members.HarnessAccountsPurpose
const soulRunnerAccountsVerb = members.SoulRunnerAccountsPurpose
const harnessInstallVerb = members.HarnessInstall
const harnessRetireVerb = members.HarnessRetire

func pairedServiceVerb(verb string) bool {
	return verb == harnessAccountsVerb || verb == soulRunnerAccountsVerb || verb == recoveryVerb || verb == upgradeVerb || verb == members.HarnessInstall || verb == members.HarnessRetire
}

// This record never contains plan contents. UID is a local pairing property.
type recoveryChallenge struct {
	Action  string `json:"action"`
	Machine string `json:"machine_key"`
	HQ      string `json:"hq_key"`
	Owner   string `json:"owner_key"`
	ID      string `json:"plan_id"`
	Digest  string `json:"plan_digest"`
	Nonce   string `json:"nonce"`
	Expires int64  `json:"expires_at"`
	UID     int    `json:"uid"`
}

func (c recoveryChallenge) valid() bool {
	_, err := ownerKey(c.Owner)
	return err == nil && pairedServiceVerb(c.Action) && exactKey(c.Machine) && exactKey(c.HQ) && members.ValidApproval(c.ID, c.Digest) && exactKey(c.Nonce) && c.Expires > 0 && c.UID > 0
}

func (c recoveryChallenge) message() []byte {
	return []byte(strings.Join([]string{"agent-bot-machine-owner/v1", c.Action, c.Machine, c.HQ, c.Owner, c.ID, c.Digest, c.Nonce, strconv.FormatInt(c.Expires, 10), ""}, "\n"))
}

func validRecoveryRequest(req Request, raw []byte) bool {
	if !members.ValidApproval(req.PlanID, req.PlanDigest) || req.Nonce == "" || len(req.Nonce) > 128 || strings.ContainsAny(req.Nonce, "\r\n") {
		return false
	}
	var allowed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &allowed); err != nil {
		return false
	}
	for field := range allowed {
		switch field {
		case "verb", "option", "plan_id", "plan_digest", "timestamp", "nonce", "public_key", "signature":
		case "challenge_nonce":
			if req.Option != "approve" && req.Option != "cancel" {
				return false
			}
		case "owner_signature":
			if req.Option != "approve" {
				return false
			}
		default:
			return false
		}
	}
	switch req.Option {
	case "challenge":
		return true
	case "cancel":
		return exactKey(req.ChallengeNonce)
	case "approve":
		if !exactKey(req.ChallengeNonce) || len(req.OwnerSignature) > 96 {
			return false
		}
		sig, err := base64.StdEncoding.Strict().DecodeString(req.OwnerSignature)
		return err == nil && len(sig) > 0 && base64.StdEncoding.EncodeToString(sig) == req.OwnerSignature
	}
	return false
}

type recoveryPlanCheck func(id, digest string, uid int) (string, error)

func recoverHQService(dir string, machine ed25519.PublicKey, req Request, now func() time.Time, check recoveryPlanCheck) Response {
	deny := func() Response {
		return refused(diag.DaemonPeerRefused, "service challenge, pairing, plan or owner proof is invalid")
	}
	unlock, err := lockOwnerPairing(dir)
	if err != nil {
		return deny()
	}
	defer unlock()
	p, err := readOwnerPairState(dir)
	if err != nil || p == nil || (p.Pending != nil && p.Pending.Expires > now().Unix()) || p.HQ == "" || p.UID != req.peerUID || p.Machine != hex.EncodeToString(machine) {
		return deny()
	}
	peers := filepath.Join(dir, "peers")
	live, err := p.liveKey(peers)
	if err != nil || len(live) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(live) != req.PublicKey {
		return deny()
	}
	c := p.Recovery
	if !pairedServiceVerb(req.Verb) || (req.Option != "challenge" && (c == nil || c.Action != req.Verb || c.ID != req.PlanID || c.Digest != req.PlanDigest || c.Nonce != req.ChallengeNonce)) {
		return deny()
	}
	if req.Option == "cancel" {
		p.Recovery = nil
		if err := p.save(dir); err != nil {
			return deny()
		}
		body, _ := json.Marshal(map[string]string{"plan_id": req.PlanID, "plan_digest": req.PlanDigest})
		return Response{OK: true, State: "cancelled", Body: body}
	}
	if req.Option != "challenge" && req.Option != "approve" {
		return deny()
	}
	if req.Option == "approve" {
		t := now().Unix()
		if c.Expires <= t || c.Expires > t+ownerChallengeTTL {
			return deny()
		}
		key, err := ownerKey(p.Owner)
		sig, errSig := base64.StdEncoding.Strict().DecodeString(req.OwnerSignature)
		hash := sha256.Sum256(c.message())
		if err != nil || errSig != nil || !ecdsa.VerifyASN1(key, hash[:], sig) {
			return deny()
		}
	}
	canonical, err := check(req.PlanID, req.PlanDigest, req.peerUID)
	if err != nil {
		return refused(diag.DaemonPlanFailed, "saved plan is not eligible for the requested paired operation")
	}
	// Revocation by legacy admin tooling and Machine key replacement do not
	// take the pairing lock. Recheck after the potentially slow artifact scan.
	stillPaired := func() bool {
		if !dedicatedMembersPlanPeer(req.peerUID) {
			return false
		}
		current, err := p.liveKey(peers)
		return err == nil && live.Equal(current)
	}
	if !stillPaired() {
		return deny()
	}
	t := now()
	if req.Option == "challenge" {
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return deny()
		}
		c = &recoveryChallenge{req.Verb, p.Machine, p.HQ, p.Owner, req.PlanID, req.PlanDigest, hex.EncodeToString(nonce[:]), t.Unix() + ownerChallengeTTL, p.UID}
		body, err := json.Marshal(map[string]any{"action": c.Action, "machine_key": c.Machine, "hq_key": c.HQ, "owner_key": c.Owner, "plan_id": c.ID, "plan_digest": c.Digest, "nonce": c.Nonce, "expires_at": c.Expires, "plan_canonical": canonical})
		if err != nil || len(body) > maxMessage-1024 {
			return deny()
		}
		p.Recovery = c
		if err := p.save(dir); err != nil {
			return deny()
		}
		if req.Verb != recoveryVerb && !stillPaired() {
			return deny()
		}
		return Response{OK: true, State: "challenged", Body: body}
	}
	if c.Expires <= t.Unix() || c.Expires > t.Unix()+ownerChallengeTTL {
		return deny()
	}
	// Consume and fsync under the pairing lock before exposing any approval.
	p.Recovery = nil
	if err := p.save(dir); err != nil {
		return deny()
	}
	var a members.Approval
	if req.Verb != recoveryVerb {
		fp := sha256.Sum256(machine)
		a, err = members.RecordPairedPlanApproval(req.Verb, dir, req.PlanID, req.PlanDigest, hex.EncodeToString(fp[:]), pairCommitment(p), t)
	} else {
		a, err = members.RecordApproval(dir, req.PlanID, req.PlanDigest, t)
	}
	if err != nil {
		return refused(diag.DaemonPlanFailed, "paired owner approval could not be recorded")
	}
	// Revocation publishes its marker before waiting for the pairing lock.
	// A persisted harness approval remains bound to the retired pairing.
	if req.Verb != recoveryVerb && !stillPaired() {
		return deny()
	}
	a.MachineFingerprint = ""
	a.PairCommitment = ""
	a.Purpose = "" // The public acknowledgment retains the established four-field shape.
	body, _ := json.Marshal(a)
	return Response{OK: true, State: "approved", Body: body}
}

var errRecoveryPlan = errors.New("saved plan is not eligible for the requested paired operation")

// Keep the existing paired-plan commitment transcript used by service upgrades.
func pairCommitment(p *ownerPairState) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"hq-service-upgrade/pair/v1", p.Owner, p.Machine, p.HQ, strconv.Itoa(p.UID), p.HQEpoch, ""}, "\n")))
	return hex.EncodeToString(sum[:])
}
