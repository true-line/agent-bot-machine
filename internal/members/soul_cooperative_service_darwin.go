//go:build darwin

package members

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// A live cooperative run is kept separate from the protected B reservation
// table. A restart loses this cache and refuses a positive attach/stop until
// the durable spent claim is explicitly reconciled through the owner-signed
// cooperative recovery command.
type soulCooperativeLiveV3 struct {
	request           SoulCooperativeReserveRequest
	installed         soulCooperativeInstalledV3
	h                 stage2aVerifiedDomainRefV3
	hDescriptorDigest string
	envelope          []byte
	digest            string
	challengeSHA      string
	issuedAt          time.Time
	dispatcherPID     int
	runnerPID         int
	dispatcher        soulKernelProcessSnapshot
	runner            soulKernelProcessSnapshot
	attached          bool
	attachSHA256      string
	directQ           *stage2aDirectQRunV3
}

// ReserveCooperativeV3 reconstructs the candidate solely from current
// installed R authority and the daemon-selected, independently applied H plan.
func (s *Stage2aService) ReserveCooperativeV3(hqUID int, epoch string,
	start SoulCooperativeStartRequestV3, findHPlan func(string) (Saved, error),
	paired func(string, func() error) error) (Stage2aReserveReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aReserveReply
	q := start.SoulCooperativeReserveRequest
	if findHPlan == nil || paired == nil || len(s.key) != ed25519.PrivateKeySize ||
		!q.valid() || q.HQEpoch != epoch || len(s.cooperativeActive) >= 128 {
		return reply, errSoulCooperativeAuthority
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(start.AdmissionChallengeBase64URL)
	if err != nil || len(challenge) != 32 || !soulLaunchID.MatchString(q.LaunchID) ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(challenge)) != q.AdmissionChallengeSHA256 {
		return reply, errSoulCooperativeAuthority
	}
	for _, live := range s.cooperativeActive {
		if live.request.InstallationID == q.InstallationID {
			return reply, errSoulCooperativeAuthority
		}
	}
	key := s.key.Public().(ed25519.PublicKey)
	installed, _, err := loadSoulCooperativeInstalledV3(key, hqUID, epoch, q.InstallationID)
	if err != nil || installed.Policy.ReviewedStartID != q.StartID {
		return reply, errSoulCooperativeAuthority
	}
	selector, err := cooperativeHSelectorFromInstalled(installed)
	if err != nil || selector.CooperativePlanDigest != q.PlanDigest {
		return reply, errSoulCooperativeAuthority
	}
	saved, err := findHPlan(selector.HOwnerPlanDigest)
	if err != nil || "sha256:"+saved.PlanDigest != selector.HOwnerPlanDigest {
		return reply, errSoulCooperativeAuthority
	}
	var proof soulCooperativeVerifiedStartV3
	var issued time.Time
	var ran bool
	err = paired(installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		current, r, err := loadSoulCooperativeInstalledV3(key, hqUID, epoch, q.InstallationID)
		if err != nil || !bytes.Equal(current.RootReceipt, installed.RootReceipt) ||
			current.PairCommitment != installed.PairCommitment {
			return errSoulCooperativeAuthority
		}
		h, err := loadInstalledCooperativeHV3(saved, selector.Owner, selector.CooperativePlanID,
			selector.CooperativePlanDigest, time.Now().Add(30*time.Second), key, paired)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		descriptor, digest, err := stage2aDecodeHDescriptorV3(h.envelope, key)
		if err != nil || digest != h.descriptorDigest || descriptor.HostID != current.Policy.HostID ||
			descriptor.HQInstallationID != selector.HQInstallationID {
			return errSoulCooperativeAuthority
		}
		proof = soulCooperativeVerifiedStartV3{installed: current, r: r, h: h.verifiedH,
			hDescriptorDigest: digest, hEntryPath: descriptor.Runtime.EntryPath,
			hEntrySHA256: descriptor.Runtime.EntrySHA256}
		for _, c := range descriptor.Components {
			proof.hComponents = append(proof.hComponents, soulCooperativeComponentV3(c))
		}
		if current.Policy.QualificationProvider != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			install, request, err := loadStage2aQualificationQAuthority(ctx)
			if err != nil {
				return errSoulCooperativeAuthority
			}
			proof.qualificationHarnessSHA256, err = cooperativeQualificationHarnessV3(
				install, request, current.Policy, selector.Owner, selector.CooperativePlanDigest, r.ref.InventoryDigest)
			if err != nil {
				return err
			}
			proof.qualificationCodeInputs = request.Adapter.Launch.CodeInputs
		}
		issued = time.Now().UTC()
		reply, err = publishSoulCooperativeStartV3(proof, q, challenge, issued, key, s.sign)
		return err
	})
	if err != nil {
		return Stage2aReserveReply{}, err
	}
	if !ran || !stage2aPrefixedDigest.MatchString(reply.SHA256) {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	s.cooperativeActive[reply.SHA256] = &soulCooperativeLiveV3{
		request: q, installed: proof.installed, h: proof.h,
		hDescriptorDigest: proof.hDescriptorDigest, digest: reply.SHA256,
		challengeSHA: fmt.Sprintf("sha256:%x", sha256.Sum256(challenge)),
		issuedAt:     issued,
	}
	envelope, _ := base64.RawURLEncoding.Strict().DecodeString(reply.EnvelopeBase64URL)
	s.cooperativeActive[reply.SHA256].envelope = envelope
	return reply, nil
}

type soulCooperativeAttachPayloadV3 struct {
	Contract            string `json:"contract"`
	Kind                string `json:"kind"`
	SchemaVersion       int    `json:"schema_version"`
	ReservationSHA256   string `json:"reservation_sha256"`
	HDescriptorDigest   string `json:"h_service_descriptor_digest"`
	InstallationID      string `json:"installation_id"`
	StartID             string `json:"start_id"`
	LaunchID            string `json:"launch_id"`
	ChallengeSHA256     string `json:"challenge_sha256"`
	RunnerUID           int    `json:"runner_uid"`
	DispatcherPID       int    `json:"dispatcher_pid"`
	DispatcherStartSec  int64  `json:"dispatcher_start_sec"`
	DispatcherStartUsec int32  `json:"dispatcher_start_usec"`
	RunnerPID           int    `json:"runner_pid"`
	RunnerStartSec      int64  `json:"runner_start_sec"`
	RunnerStartUsec     int32  `json:"runner_start_usec"`
	AttachedAt          string `json:"attached_at"`
}

const soulCooperativeAttachPurposeV3 = "agent-bot/soul-cooperative-attach/v3"

// AttachCooperativeVerified is invoked only by paired HQ after HQ has checked
// the kernel peer on the signed H admission socket. A independently matches
// the live R Node PID to the fixed loaded launchd dispatcher and its kernel
// parent/start identity before durably consuming the attach claim.
func (s *Stage2aService) AttachCooperativeVerified(hqUID int, epoch string,
	q SoulCooperativeAttachRequestV3, paired func(string, func() error) error) (Stage2aReserveReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aReserveReply
	if paired == nil || len(s.key) != ed25519.PrivateKeySize ||
		!stage2aPrefixedDigest.MatchString(q.ReservationSHA256) ||
		q.RunnerPID <= 1 || !soulInstallationID.MatchString(q.InstallationID) ||
		!soulStartID.MatchString(q.StartID) || !soulLaunchID.MatchString(q.LaunchID) {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || live.attached || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.HQEpoch != epoch || live.installed.Policy.HQUID != hqUID {
		return reply, errSoulCooperativeAuthority
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(q.AdmissionChallengeBase64URL)
	if err != nil || len(challenge) != 32 ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(challenge)) != live.challengeSHA {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err = paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		p := live.installed.Policy
		if time.Since(live.issuedAt) > 30*time.Second ||
			stage2aRecheckVerifiedDomainV3(live.h) != nil {
			return errSoulCooperativeAuthority
		}
		installed, _, loadErr := loadSoulCooperativeInstalledV3(
			s.key.Public().(ed25519.PublicKey), hqUID, epoch, q.InstallationID)
		if loadErr != nil || installed.PairCommitment != live.installed.PairCommitment ||
			!bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) {
			return errSoulCooperativeAuthority
		}
		paths, pathErr := cooperativeLaunchPaths(q.InstallationID)
		if pathErr != nil {
			return errSoulCooperativeAuthority
		}
		dispatchPID, observeErr := observeSoulCooperativeLaunchdPID(paths, q.InstallationID)
		if observeErr != nil {
			return errSoulCooperativeAuthority
		}
		dispatcher, observeErr := observeSoulKernelProcess(dispatchPID)
		if observeErr != nil {
			return errSoulCooperativeAuthority
		}
		runner, observeErr := observeSoulKernelProcess(q.RunnerPID)
		if observeErr != nil || !cooperativeProcessPair(p, dispatcher, runner) {
			return errSoulCooperativeAuthority
		}
		if dispatcher2, e := observeSoulKernelProcess(dispatchPID); e != nil || !sameSoulKernelProcess(dispatcher, dispatcher2) {
			return errSoulCooperativeAuthority
		}
		if runner2, e := observeSoulKernelProcess(q.RunnerPID); e != nil || !sameSoulKernelProcess(runner, runner2) {
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
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			requireUnspentStage2aReservation(dir, cooperativeAttachedName(q.InstallationID, q.StartID)) != nil {
			return errSoulCooperativeAuthority
		}
		payload := soulCooperativeAttachPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-attach",
			SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256,
			HDescriptorDigest: live.hDescriptorDigest, InstallationID: q.InstallationID,
			StartID: q.StartID, LaunchID: q.LaunchID, ChallengeSHA256: live.challengeSHA,
			RunnerUID: p.Runner.UID, DispatcherPID: dispatcher.PID,
			DispatcherStartSec: dispatcher.StartSeconds, DispatcherStartUsec: dispatcher.StartMicros,
			RunnerPID: runner.PID, RunnerStartSec: runner.StartSeconds,
			RunnerStartUsec: runner.StartMicros, AttachedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		envelope, e := signStage2aEnvelope(payload, 3, soulCooperativeAttachPurposeV3,
			s.key.Public().(ed25519.PublicKey), s.sign)
		if e != nil {
			return e
		}
		// Once H has authenticated the live R peer, retire the WatchPaths
		// trigger before any later cancel leaf can wake another dispatcher.
		if e := unix.RenamexNp(paths.request, paths.activeRequest, unix.RENAME_EXCL); e != nil {
			return errSoulCooperativeAuthority
		}
		if e := syncUpgradeDir(paths.requestDir); e != nil {
			return e
		}
		if e := spendStage2aAdminName(dir, cooperativeAttachedName(q.InstallationID, q.StartID), store.uid, store.gid); e != nil {
			return e
		}
		live.dispatcherPID, live.runnerPID = dispatchPID, q.RunnerPID
		live.dispatcher, live.runner, live.attached = dispatcher, runner, true
		reply = Stage2aReserveReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			SHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(envelope))}
		live.attachSHA256 = reply.SHA256
		return nil
	})
	if err != nil {
		return Stage2aReserveReply{}, err
	}
	if !ran || reply.SHA256 == "" {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}

func cooperativeAttachedName(installationID, startID string) string {
	return ".cooperative-attach-" + soulStartClaimName(installationID, startID)
}

func cooperativeActiveClaimMatches(dir *os.File, store stage2aAdminClaimStore,
	installationID, startID string) error {
	fd, err := unix.Openat(int(dir.Fd()), cooperativeActiveName(installationID), stage2aFileOpenFlags, 0)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), installationID)
	defer f.Close()
	if checkStage2aReservationFile(fd, store.uid, store.gid, unix.S_IFREG|0600) != nil {
		return errSoulCooperativeAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil || string(raw) != startID+"\n" {
		return errSoulCooperativeAuthority
	}
	return nil
}

func cooperativeProcessPair(p SoulCooperativeLaunchPolicy,
	dispatcher, runner soulKernelProcessSnapshot) bool {
	uid, gid := uint32(p.Runner.UID), uint32(p.Runner.GID)
	for _, row := range []soulKernelProcessSnapshot{dispatcher, runner} {
		if row.RealUID != uid || row.EffectiveUID != uid || row.SavedUID != uid ||
			row.RealGID != gid || row.PrimaryGroupGID != gid || row.SavedGID != gid {
			return false
		}
	}
	return dispatcher.PID > 1 && dispatcher.ParentPID == 1 && runner.ParentPID == dispatcher.PID &&
		runner.ProcessGroupID == runner.PID &&
		time.Unix(runner.StartSeconds, int64(runner.StartMicros)*1000).After(
			time.Unix(dispatcher.StartSeconds, int64(dispatcher.StartMicros)*1000))
}

func observeSoulCooperativeLaunchdPID(paths soulCooperativeLaunchPaths, installationID string) (int, error) {
	out, err := hqProgramOutput(launchctl, "print", "system/"+paths.label)
	if err != nil {
		return 0, errSoulCooperativeAuthority
	}
	return parseSoulCooperativeLaunchdPID(out, paths, installationID)
}

func parseSoulCooperativeLaunchdPID(out []byte, paths soulCooperativeLaunchPaths, installationID string) (int, error) {
	if !strings.HasPrefix(string(out), "system/"+paths.label+" = {\n") {
		return 0, errSoulCooperativeAuthority
	}
	var source, program, pid string
	var argv []string
	inArgs := false
	var repeated bool
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if inArgs {
			if line == "}" {
				inArgs = false
			} else {
				argv = append(argv, line)
			}
			continue
		}
		switch {
		case line == "arguments = {":
			inArgs = true
		case strings.HasPrefix(line, "path = "):
			if source != "" {
				repeated = true
			} else {
				source = strings.TrimPrefix(line, "path = ")
			}
		case strings.HasPrefix(line, "program = "):
			if program != "" {
				repeated = true
			} else {
				program = strings.TrimPrefix(line, "program = ")
			}
		case strings.HasPrefix(line, "pid = "):
			if pid != "" {
				repeated = true
			} else {
				pid = strings.TrimPrefix(line, "pid = ")
			}
		}
	}
	if repeated || inArgs || source != paths.plist || program != SoulLauncher || len(argv) != 3 ||
		argv[0] != SoulLauncher || argv[1] != "cooperative-dispatch" || argv[2] != installationID {
		return 0, errSoulCooperativeAuthority
	}
	n, e := strconv.Atoi(pid)
	if e != nil || n <= 1 {
		return 0, errSoulCooperativeAuthority
	}
	return n, nil
}
