//go:build darwin

package members

import (
	"crypto/ed25519"
	"os"
	"strconv"
	"time"
)

type stage2aT03SiblingWitnessReceipt struct {
	Witness         Stage2aT03SiblingCredentialWitness
	LeaseIssuedAtMS int64
	ReceivedAtMS    int64
}

type stage2aT03SiblingWitnessState struct {
	PrimaryReservationSHA256 string
	ChallengeBase64URL       string
	Path                     string
	ExpectedDigest           string
	IssuedSequence           uint64
	IssuedAtMS               int64
	ExpiresAtMS              int64
	First, Latest            *stage2aT03SiblingWitnessReceipt
}

func (s *Stage2aService) prepareStage2aT03SiblingWitness(hqUID int, epoch string,
	primary Stage2aStopRequest, review stage2aT03Review, challenge string) error {
	if !validStage2aLiveChallenge(challenge) || !stage2aPrefixedDigest.MatchString(review.SiblingCredentialMetadataSHA256) {
		return errStage2aReservationAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withStage2aT03Start(hqUID, epoch, primary,
		func(r *stage2aLiveReservation, p stage2aInstalledPolicy, _ stage2aAdminClaimStore, _ *os.File) error {
			sibling, err := s.findStage2aT03Sibling(review, p.Runner, hqUID, epoch)
			if err != nil || sibling.t03SiblingWitness != nil {
				return errStage2aReservationAuthority
			}
			sibling.t03SiblingWitness = &stage2aT03SiblingWitnessState{
				PrimaryReservationSHA256: primary.ReservationSHA256, ChallengeBase64URL: challenge,
				Path: review.SiblingPath, ExpectedDigest: review.SiblingCredentialMetadataSHA256,
			}
			return nil
		})
}

func (s *Stage2aService) clearStage2aT03SiblingWitness(primary string, review stage2aT03Review, challenge string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.active {
		w := r.t03SiblingWitness
		if r.payload.Assignment.InstallationID == review.SiblingInstallationID &&
			r.payload.Assignment.StartID == review.SiblingStartID && w != nil &&
			w.PrimaryReservationSHA256 == primary && w.ChallengeBase64URL == challenge {
			r.t03SiblingWitness = nil
		}
	}
}

func (s *Stage2aService) stage2aT03SiblingFirstWitness(hqUID int, epoch string,
	primary Stage2aStopRequest, review stage2aT03Review, challenge string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.active[primary.ReservationSHA256]
	if !stage2aMatchesStopSelectors(r, primary, hqUID) {
		return false
	}
	p, _, err := loadStage2aActiveExecutionPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, r)
	if err != nil {
		return false
	}
	sibling, err := s.findStage2aT03Sibling(review, p.Runner, hqUID, epoch)
	if err != nil || sibling.t03SiblingWitness == nil {
		return false
	}
	w := sibling.t03SiblingWitness
	return w.PrimaryReservationSHA256 == primary.ReservationSHA256 && w.ChallengeBase64URL == challenge &&
		w.Path == review.SiblingPath && w.ExpectedDigest == review.SiblingCredentialMetadataSHA256 &&
		w.First != nil && time.Now().UnixMilli()-w.First.ReceivedAtMS <= 30_000
}

// Caller holds s.mu. A receipt accepted before the primary attempted the
// credential open cannot substitute for the required later reobservation.
func (s *Stage2aService) stage2aT03SiblingSecondWitness(review stage2aT03Review,
	primary SoulRunner, hqUID int, epoch, primaryReservation, challenge string, attemptedAtMS int64) bool {
	sibling, err := s.findStage2aT03Sibling(review, primary, hqUID, epoch)
	if err != nil || sibling.t03SiblingWitness == nil {
		return false
	}
	return stage2aT03SecondWitnessMatches(sibling.t03SiblingWitness, review,
		primaryReservation, challenge, attemptedAtMS, time.Now().UnixMilli())
}

func stage2aT03SecondWitnessMatches(state *stage2aT03SiblingWitnessState,
	review stage2aT03Review, primaryReservation, challenge string, attemptedAtMS, now int64) bool {
	if state == nil {
		return false
	}
	return state.PrimaryReservationSHA256 == primaryReservation && state.ChallengeBase64URL == challenge &&
		state.Path == review.SiblingPath && state.ExpectedDigest == review.SiblingCredentialMetadataSHA256 &&
		state.First != nil && state.Latest != nil &&
		state.Latest.Witness.LeaseSequence > state.First.Witness.LeaseSequence &&
		state.Latest.LeaseIssuedAtMS > attemptedAtMS &&
		state.Latest.Witness.ObservedAtMS >= attemptedAtMS &&
		state.Latest.ReceivedAtMS >= attemptedAtMS &&
		state.Latest.ReceivedAtMS <= now && now-state.Latest.ReceivedAtMS <= 5_000
}

func validStage2aT03CredentialMetadata(m Stage2aT03CredentialMetadata, path string, uid uint32) bool {
	if m.Schema != "agent-bot-machine/stage2a-t03-credential-metadata/v1" || m.Path != path ||
		m.UID != uid || m.GID != uid || m.Mode != "0400" && m.Mode != "0600" {
		return false
	}
	for _, field := range []string{m.Device, m.Inode, m.Generation, m.SizeBytes, m.BirthSeconds,
		m.BirthNanos, m.ModifySeconds, m.ModifyNanos, m.ChangeSeconds, m.ChangeNanos} {
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != field {
			return false
		}
	}
	size, _ := strconv.ParseUint(m.SizeBytes, 10, 64)
	ino, _ := strconv.ParseUint(m.Inode, 10, 64)
	birth, _ := strconv.ParseUint(m.BirthSeconds, 10, 64)
	for _, nanos := range []string{m.BirthNanos, m.ModifyNanos, m.ChangeNanos} {
		n, _ := strconv.ParseUint(nanos, 10, 64)
		if n >= 1_000_000_000 {
			return false
		}
	}
	return size > 0 && size <= 1<<20 && ino > 0 && birth > 0
}

func stage2aT03WitnessMatchesIssued(state *stage2aT03SiblingWitnessState,
	w Stage2aT03SiblingCredentialWitness, sibling Stage2aStopRequest, childReceipt string,
	uid uint32, now int64) bool {
	if state == nil || w.Schema != "agent-bot-machine/stage2a-t03-sibling-credential-witness/v1" ||
		w.ChallengeBase64URL != state.ChallengeBase64URL ||
		w.PrimaryReservationSHA256 != state.PrimaryReservationSHA256 ||
		w.SiblingReservationSHA256 != sibling.ReservationSHA256 ||
		w.SiblingInstallationID != sibling.InstallationID || w.SiblingStartID != sibling.StartID ||
		w.ChildReceiptSHA256 != childReceipt ||
		w.LeaseSequence != state.IssuedSequence || w.LeaseSequence == 0 ||
		w.CredentialPath != state.Path || w.Metadata.Path != state.Path ||
		!validStage2aT03CredentialMetadata(w.Metadata, state.Path, uid) ||
		w.MetadataSHA256 != state.ExpectedDigest ||
		w.ObservedAtMS < state.IssuedAtMS || w.ObservedAtMS > now ||
		now > state.ExpiresAtMS || now-w.ObservedAtMS > 5_000 ||
		state.Latest != nil && w.LeaseSequence <= state.Latest.Witness.LeaseSequence {
		return false
	}
	metadata, err := marshalStage2aReservationJCS(w.Metadata)
	return err == nil && stage2aReservationSHA256(metadata) == w.MetadataSHA256
}

func (s *Stage2aService) Stage2aT03AcceptSiblingWitness(hqUID int, epoch string,
	q Stage2aT03SiblingCredentialWitnessRequest) (string, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.active[q.ReservationSHA256]
	w := q.Witness
	if !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) || q.HQEpoch != epoch ||
		r.t03SiblingWitness == nil || r.childPID <= 1 || len(r.childReceiptEnvelope) == 0 {
		return "", 0, errStage2aReservationAuthority
	}
	state := r.t03SiblingWitness
	now := time.Now().UnixMilli()
	if !stage2aT03WitnessMatchesIssued(state, w, q.Stage2aStopRequest,
		stage2aReservationSHA256(r.childReceiptEnvelope), uint32(r.payload.Assignment.RunnerUID), now) {
		return "", 0, errStage2aReservationAuthority
	}
	p, raw, err := loadStage2aActiveExecutionPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, r)
	if err != nil || stage2aReservationSHA256(raw) != r.policyDigest ||
		checkStage2aGrantedRoleProcess(r.childLauncherPID, p.Runner.UID, p.Runner.GID, "child", r.childLauncherProcess) != nil ||
		checkStage2aChildProcess(r.childPID, r.childLauncherPID, p.Runner, p.LaunchInputs, r.childProcess) != nil {
		return "", 0, errStage2aReservationAuthority
	}
	receipt := &stage2aT03SiblingWitnessReceipt{Witness: w, LeaseIssuedAtMS: state.IssuedAtMS, ReceivedAtMS: now}
	if state.First == nil {
		state.First = receipt
	}
	state.Latest = receipt
	return w.MetadataSHA256, w.LeaseSequence, nil
}
