//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type soulCooperativeRelayIngressPayloadV3 struct {
	Contract             string `json:"contract"`
	Kind                 string `json:"kind"`
	SchemaVersion        int    `json:"schema_version"`
	ProfileInForce       string `json:"profile_in_force"`
	InstallationID       string `json:"installation_id"`
	StartID              string `json:"start_id"`
	LaunchID             string `json:"launch_id"`
	HQEpoch              string `json:"hq_epoch"`
	ReservationSHA256    string `json:"reservation_sha256"`
	AttachSHA256         string `json:"attach_sha256"`
	MemberID             string `json:"member_id"`
	MemberLaunchID       string `json:"member_launch_id"`
	MemberSelector       string `json:"member_selector"`
	ReadySHA256          string `json:"ready_sha256"`
	BLeaseSHA256         string `json:"b_lease_sha256"`
	BLeaseSequence       uint64 `json:"b_lease_sequence"`
	MemberLeaseSHA256    string `json:"member_lease_sha256"`
	MemberLeaseSequence  uint64 `json:"member_lease_sequence"`
	PeerSHA256           string `json:"peer_sha256"`
	Model                string `json:"model"`
	RequestSHA256        string `json:"request_sha256"`
	ResponseSHA256       string `json:"response_sha256"`
	ProviderConfigSHA256 string `json:"provider_config_sha256"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

// CooperativeRelayIngress authorizes one reviewed local response after the
// exact B socket peer has a current A warrant and both five-second leases.
func (s *Stage2aService) CooperativeRelayIngress(hqUID int, epoch string,
	q SoulCooperativeRelayIngressRequestV3,
	paired func(string, func() error) error) (SoulCooperativeRelayIngressReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply SoulCooperativeRelayIngressReplyV3
	fail := func() (SoulCooperativeRelayIngressReplyV3, error) {
		return SoulCooperativeRelayIngressReplyV3{}, errSoulCooperativeAuthority
	}
	rawQ, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeRelayIngressRequestV3(rawQ); err != nil || paired == nil ||
		len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch {
		return fail()
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || live.installed.Policy.HQUID != hqUID ||
		live.request.InstallationID != q.InstallationID || live.request.StartID != q.StartID ||
		live.request.LaunchID != q.LaunchID || live.request.PlanDigest != q.PlanDigest ||
		live.request.HQEpoch != epoch || live.attachSHA256 != q.AttachSHA256 ||
		q.ReadySHA256 != stage2aReservationSHA256(live.memberReadyEnvelope) ||
		q.BLeaseSHA256 != live.bridgeLiveSHA || q.BLeaseSequence != live.bridgeLiveSequence ||
		len(live.peerWarrants[q.PeerSHA256]) == 0 {
		return fail()
	}
	state := live.childGrants[q.MemberID]
	if state == nil || state.memberLaunchID != q.MemberLaunchID ||
		state.memberSelector != q.MemberSelector || state.lastLeaseSHA != q.MemberLeaseSHA256 ||
		state.lastSequence != q.MemberLeaseSequence {
		return fail()
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		pub := s.key.Public().(ed25519.PublicKey)
		installed, r, e := loadSoulCooperativeInstalledV3(pub, hqUID, epoch, q.InstallationID)
		if e != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
			stage2aRecheckVerifiedDomainV3(r) != nil || stage2aRecheckVerifiedDomainV3(live.h) != nil ||
			!cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		peerRaw, e := verifyStage2aStoredARecordV3(live.peerWarrants[q.PeerSHA256],
			SoulCooperativeRelayPeerPurposeV3, 3, pub)
		var peer soulCooperativeRelayPeerPayloadV3
		if e != nil || stage2aDecodeExact(peerRaw, &peer) != nil ||
			peer.ProfileInForce != "managed-cooperative" || peer.ReservationSHA256 != q.ReservationSHA256 ||
			peer.MemberID != q.MemberID || peer.MemberLaunchID != q.MemberLaunchID ||
			peer.MemberSelector != q.MemberSelector || peer.ReadySHA256 != q.ReadySHA256 ||
			peer.BLeaseSHA256 != q.BLeaseSHA256 || peer.BLeaseSequence != q.BLeaseSequence ||
			peer.MemberLeaseSHA256 != q.MemberLeaseSHA256 || peer.MemberLeaseSequence != q.MemberLeaseSequence {
			return errSoulCooperativeAuthority
		}
		now := time.Now().UTC()
		peerUntil, e := time.Parse(time.RFC3339Nano, peer.ExpiresAt)
		if e != nil || !now.Before(peerUntil) || !now.Before(live.bridgeLiveExpires) ||
			!now.Before(state.lastExpiry) || !now.Before(live.memberReadyExpires) ||
			!soulCooperativeCLIInSealedR(installed.RuntimeV3, peer.CLIPath, peer.CLISHA256) {
			return errSoulCooperativeAuthority
		}
		peerNow, e := observeStage2aQualificationProcess(peer.Peer.PID, peer.CLIPath, nil, true)
		parentNow, parentErr := observeStage2aChildProcess(state.childPID, state.launcherPID,
			installed.Policy.Runner, *installed.Policy.LaunchInputs)
		if e != nil || parentErr != nil || peerNow.Kernel.PID != peer.Peer.PID ||
			peerNow.Kernel.ParentPID != state.childPID ||
			peerNow.Kernel.StartSeconds != peer.Peer.StartSeconds ||
			peerNow.Kernel.StartMicros != peer.Peer.StartMicros ||
			!sameSoulKernelProcess(parentNow, state.child) {
			return errSoulCooperativeAuthority
		}
		var selected *Stage2aBridgeQualification
		for i := range installed.Policy.MemberBridgeQualifications {
			row := &installed.Policy.MemberBridgeQualifications[i]
			if row.MemberID == q.MemberID {
				selected = &row.Qualification
			}
		}
		if selected == nil || selected.Model != q.Model || selected.RequestSHA256 != q.PromptSHA256 {
			return errSoulCooperativeAuthority
		}
		config, configDigest, e := stage2aProviderConfig(*selected)
		if e != nil {
			return errSoulCooperativeAuthority
		}
		configSHA := stage2aReservationSHA256(config)
		until := minStage2aTime(now.Add(5*time.Second), peerUntil)
		until = minStage2aTime(until, live.bridgeLiveExpires)
		until = minStage2aTime(until, state.lastExpiry)
		until = minStage2aTime(until, live.memberReadyExpires)
		if !until.After(now) {
			return errSoulCooperativeAuthority
		}
		payload := soulCooperativeRelayIngressPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-relay-ingress",
			SchemaVersion: 3, ProfileInForce: "managed-cooperative", InstallationID: q.InstallationID,
			StartID: q.StartID, LaunchID: q.LaunchID, HQEpoch: epoch, ReservationSHA256: q.ReservationSHA256,
			AttachSHA256: q.AttachSHA256, MemberID: q.MemberID, MemberLaunchID: q.MemberLaunchID,
			MemberSelector: q.MemberSelector, ReadySHA256: q.ReadySHA256, BLeaseSHA256: q.BLeaseSHA256,
			BLeaseSequence: q.BLeaseSequence, MemberLeaseSHA256: q.MemberLeaseSHA256,
			MemberLeaseSequence: q.MemberLeaseSequence, PeerSHA256: q.PeerSHA256, Model: q.Model,
			RequestSHA256: q.PromptSHA256, ResponseSHA256: stage2aReservationSHA256([]byte(selected.ResponseText)),
			ProviderConfigSHA256: configSHA,
			IssuedAt:             now.Format(time.RFC3339Nano), ExpiresAt: until.Format(time.RFC3339Nano)}
		envelope, e := signStage2aEnvelope(payload, 3, SoulCooperativeRelayIngressPurposeV3, pub, s.sign)
		if e != nil || !time.Now().Before(until) || !cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		store := installed.claimStore()
		dir, e := store.open()
		if e != nil {
			return e
		}
		defer dir.Close()
		lock, e := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
		if e != nil {
			return e
		}
		defer lock.Close()
		name := ".cooperative-provider-" + soulStartClaimName(q.InstallationID, q.StartID)
		if store.checkDirectory(dir) != nil ||
			checkSoulCooperativeActiveForIngress(dir, store, q.InstallationID, q.StartID) != nil ||
			requireUnspentStage2aReservation(dir, name) != nil || !time.Now().Before(until) {
			return errSoulCooperativeAuthority
		}
		if e := spendStage2aAdminName(dir, name, store.uid, store.gid); e != nil {
			return e
		}
		reply = SoulCooperativeRelayIngressReplyV3{ReceiptEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			ReceiptSHA256: stage2aReservationSHA256(envelope), Model: q.Model, RequestSHA256: q.PromptSHA256,
			ConfigBase64URL: base64.RawURLEncoding.EncodeToString(config), ResponseText: selected.ResponseText,
			ProviderConfigSHA256: configDigest, ExpiresAtMS: until.UnixMilli()}
		return nil
	})
	if err != nil || !ran || reply.ReceiptSHA256 == "" {
		return fail()
	}
	return reply, nil
}

func checkSoulCooperativeActiveForIngress(dir *os.File, store stage2aAdminClaimStore, installationID, startID string) error {
	name := cooperativeActiveName(installationID)
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_RDONLY, 0)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if checkStage2aReservationFile(fd, store.uid, store.gid, unix.S_IFREG|0600) != nil {
		return errSoulCooperativeAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil || string(raw) != startID+"\n" {
		return errSoulCooperativeAuthority
	}
	return nil
}
