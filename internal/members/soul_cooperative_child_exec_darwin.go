//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type soulCooperativeChildStateV3 struct {
	memberID          string
	memberLaunchID    string
	memberSelector    string
	grantEnvelope     []byte
	grantSHA          string
	launcherPID       int
	launcher          soulKernelProcessSnapshot
	childPID          int
	child             soulKernelProcessSnapshot
	hObservationSHA   string
	lastSequence      uint64
	lastExpiry        time.Time
	lastNonce         string
	lastLeaseEnvelope []byte
	lastLeaseSHA      string
}

// CooperativeChildExec is the only A grant entry for a cooperative R wrapper.
// The four signed inputs are read from A's current reservation, not from H.
func (s *Stage2aService) CooperativeChildExec(hqUID int, epoch string,
	q SoulCooperativeChildExecRequestV3,
	paired func(string, func() error) error) (Stage2aExecReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aExecReply
	raw, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeChildExecRequestV3(raw); err != nil ||
		paired == nil || len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || !live.bridgeBindVerified ||
		len(live.bridgeObservedEnvelope) == 0 || len(live.memberBAuthorityEnvelope) == 0 ||
		len(live.provisionalHQMap) == 0 ||
		live.installed.Policy.HQUID != hqUID || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest ||
		live.request.HQEpoch != epoch || live.digest != q.ReservationSHA256 ||
		stage2aReservationSHA256(live.memberEnvelope) != live.memberSHA ||
		stage2aReservationSHA256(live.bridgeEnvelope) != live.bridgeSHA {
		return reply, errSoulCooperativeAuthority
	}
	if live.childGrants != nil && live.childGrants[q.MemberID] != nil {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		pub := s.key.Public().(ed25519.PublicKey)
		installed, r, err := loadSoulCooperativeInstalledV3(pub, hqUID, epoch, q.InstallationID)
		if err != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
			stage2aRecheckVerifiedDomainV3(r) != nil ||
			stage2aRecheckVerifiedDomainV3(live.h) != nil ||
			!cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		paths, err := cooperativeLaunchPaths(q.InstallationID)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		pid, err := observeSoulCooperativeLaunchdPID(paths, q.InstallationID)
		if err != nil || pid != live.dispatcherPID {
			return errSoulCooperativeAuthority
		}
		dispatcher, e1 := observeSoulKernelProcess(live.dispatcherPID)
		runner, e2 := observeSoulKernelProcess(live.runnerPID)
		if e1 != nil || e2 != nil || !sameSoulKernelProcess(live.dispatcher, dispatcher) ||
			!sameSoulKernelProcess(live.runner, runner) ||
			!cooperativeProcessPair(installed.Policy, dispatcher, runner) {
			return errSoulCooperativeAuthority
		}
		store := installed.claimStore()
		dir, err := store.open()
		if err != nil {
			return errSoulCooperativeAuthority
		}
		defer dir.Close()
		lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		defer lock.Close()
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			stage2aCheckSpentClaim(dir, cooperativeAttachedName(q.InstallationID, q.StartID),
				store.uid, store.gid) != nil {
			return errSoulCooperativeAuthority
		}
		var receipt Receipt
		if json.Unmarshal(installed.RootReceipt, &receipt) != nil ||
			receipt.PlanID != q.PlanID || receipt.PlanDigest != q.PlanDigest {
			return errSoulCooperativeAuthority
		}
		checked := SoulCooperativeInstalledAuthority{Policy: installed.Policy,
			InstallationOwner: receipt.Owner, PlanID: receipt.PlanID,
			PlanDigest:    receipt.PlanDigest,
			ReceiptSHA256: fmt.Sprintf("%x", sha256.Sum256(installed.RootReceipt)),
			CanonicalPlan: installed.CanonicalPlan, RootReceipt: installed.RootReceipt,
			ObservedRInventorySHA256: installed.RuntimeV3.InventoryDigest}
		var observed soulKernelProcessSnapshot
		observed, err = observeStage2aRoleProcess(q.PID, installed.Policy.Runner.UID,
			installed.Policy.Runner.GID, "child")
		if err != nil {
			return errSoulCooperativeAuthority
		}
		name := ".stage2a-cooperative-child-exec-" +
			soulStartClaimName(q.InstallationID, q.StartID) + "-" + q.MemberSelector
		reply, err = prepareStage2aCooperativeChildGrant(checked, live.envelope,
			live.bridgeEnvelope, live.memberEnvelope, live.memberBAuthorityEnvelope,
			q.MemberID, q.MemberLaunchID, q.MemberSelector, q.Nonce, q.PID,
			time.Now().UTC(), pub, s.sign, func(got string) error {
				if got != name || requireUnspentStage2aReservation(dir, got) != nil {
					return errSoulCooperativeAuthority
				}
				return spendStage2aAdminName(dir, got, store.uid, store.gid)
			})
		if err != nil || reply.SHA256 == "" {
			return errSoulCooperativeAuthority
		}
		if live.childGrants == nil {
			live.childGrants = make(map[string]*soulCooperativeChildStateV3, 2)
		}
		grantEnvelope, err := base64.RawURLEncoding.Strict().DecodeString(reply.EnvelopeBase64URL)
		if err != nil || stage2aReservationSHA256(grantEnvelope) != reply.SHA256 {
			return errSoulCooperativeAuthority
		}
		live.childGrants[q.MemberID] = &soulCooperativeChildStateV3{
			memberID: q.MemberID, memberLaunchID: q.MemberLaunchID,
			memberSelector: q.MemberSelector, grantEnvelope: grantEnvelope,
			grantSHA: reply.SHA256, launcherPID: q.PID, launcher: observed}
		return nil
	})
	if err != nil || !ran || reply.SHA256 == "" {
		return Stage2aExecReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
