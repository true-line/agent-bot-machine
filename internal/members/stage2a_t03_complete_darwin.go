package members

import (
	"encoding/json"
	"os"
	"time"
)

type stage2aT03Completion struct {
	Schema          string                   `json:"schema"`
	Positive        json.RawMessage          `json:"positive"`
	Result          Stage2aT03ProbeResult    `json:"result"`
	Network         Stage2aT03NetworkReceipt `json:"network"`
	OSWitnessSHA256 string                   `json:"os_witness_sha256"`
}

func (s *Stage2aService) Stage2aT03AcceptComplete(hqUID int, epoch string, q Stage2aT03CompleteRequest) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var digest string
	err := s.withStage2aT03Start(hqUID, epoch, q.Stage2aStopRequest,
		func(r *stage2aLiveReservation, policy stage2aInstalledPolicy, store stage2aAdminClaimStore, dir *os.File) error {
			p := r.t03Pending
			if p == nil || p.issuedLease == "" || len(p.complete) != 0 || !stage2aT03ResultMatches(q.Result, p) ||
				!stage2aT03NetworkMatches(q.Network, q.Result, p, time.Now()) ||
				s.checkStage2aT03Sibling(p.review, policy.Runner, hqUID, epoch) != nil {
				return errStage2aReservationAuthority
			}
			witness, err := marshalStage2aReservationJCS(struct {
				Attempts                        []stage2aT03ObservedAttempt `json:"attempts"`
				SiblingInstallationID           string                      `json:"sibling_installation_id"`
				SiblingStartID                  string                      `json:"sibling_start_id"`
				SiblingUID                      int                         `json:"sibling_uid"`
				SiblingHomeMode                 string                      `json:"sibling_home_mode"`
				SiblingCredentialMetadataSHA256 string                      `json:"sibling_credential_metadata_sha256"`
			}{p.attempts, p.review.SiblingInstallationID, p.review.SiblingStartID, p.review.SiblingUID,
				"0700", p.review.SiblingCredentialMetadataSHA256})
			if err != nil {
				return err
			}
			record, err := marshalStage2aReservationJCS(stage2aT03Completion{
				Schema: "agent-bot-machine/stage2a-t03-capture/v1", Positive: p.positiveBytes, Result: q.Result,
				Network: q.Network, OSWitnessSHA256: stage2aReservationSHA256(witness),
			})
			if err != nil || len(record) > stage2aQualificationFrameMax {
				return errStage2aReservationAuthority
			}
			name := ".stage2a-t03-complete-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
			if err := commitStage2aReservation(dir, name, record); err != nil {
				return err
			}
			p.complete, p.osWitness = record, witness
			digest = stage2aReservationSHA256(record)
			return nil
		})
	return digest, err
}

func stage2aT03ResultMatches(result Stage2aT03ProbeResult, p *stage2aT03Pending) bool {
	d := p.directive
	if result.Schema != "agent-bot-machine/stage2a-t03-probe-result/v1" ||
		result.ChallengeBase64URL != d.ChallengeBase64URL || result.SessionID != d.SessionID ||
		result.TestPlanSHA256 != d.TestPlanSHA256 || result.ReservationSHA256 != d.ReservationSHA256 ||
		result.InstallationID != d.InstallationID || result.StartID != d.StartID || result.ChildReceiptSHA256 != d.ChildReceiptSHA256 ||
		result.LeaseSequence != d.LeaseSequence || result.CLIExecutableSHA256 != d.CLIExecutableSHA256 ||
		result.SandboxSHA256 != "sha256:"+harnessSHA(soulChildProfile) ||
		len(p.attempts) != 3 || len(result.Attempts) != len(p.attempts) ||
		result.CredentialPath != d.SiblingCredentialPath ||
		(result.CredentialDenialErrno != "EACCES" && result.CredentialDenialErrno != "EPERM") ||
		result.CredentialAttemptedAtMS < result.Attempts[len(result.Attempts)-1].FinishedAtMS ||
		result.CredentialAttemptedAtMS > d.ExpiresAtMS {
		return false
	}
	for i, attempt := range result.Attempts {
		witness := p.attempts[i]
		ready := witness.Ready
		if attempt.Kind != ready.Kind || attempt.Target != ready.Target || result.CLIExecutable != ready.CLIExecutable ||
			attempt.PID != ready.PID || attempt.UID != ready.UID || attempt.GID != ready.GID ||
			attempt.StartSeconds != ready.StartSeconds || attempt.StartMicros != ready.StartMicros ||
			attempt.ArgvSHA256 != ready.ArgvSHA256 || attempt.EnvSHA256 != ready.EnvSHA256 ||
			witness.GoLeaseSHA256 == "" || attempt.StartedAtMS < p.issuedAt.UnixMilli() ||
			attempt.StartedAtMS > witness.ObservedAtMS || attempt.FinishedAtMS < witness.GoIssuedAtMS ||
			attempt.FinishedAtMS > d.ExpiresAtMS || attempt.ExitCode <= 0 || attempt.OutputCapped ||
			attempt.ErrorClass != "connect_denied" || !attempt.DenialTargetObserved ||
			attempt.DenialErrno != "EPERM" && attempt.DenialErrno != "EACCES" ||
			attempt.StdoutBytes < 0 || attempt.StdoutBytes > 64<<10 || attempt.StderrBytes < 0 || attempt.StderrBytes > 64<<10 ||
			attempt.StdoutBytes+attempt.StderrBytes == 0 || !stage2aPrefixedDigest.MatchString(attempt.StdoutSHA256) ||
			!stage2aPrefixedDigest.MatchString(attempt.StderrSHA256) {
			return false
		}
	}
	return true
}

func stage2aT03NetworkMatches(n Stage2aT03NetworkReceipt, result Stage2aT03ProbeResult, p *stage2aT03Pending, now time.Time) bool {
	var positive Stage2aT03ArmRequest
	if json.Unmarshal(p.positiveBytes, &positive) != nil {
		return false
	}
	age := now.Sub(time.UnixMilli(n.ObservedAtMS))
	return n.Schema == "agent-bot/stage2a-t03-network-receipt/v1" &&
		n.ChallengeBase64URL == p.directive.ChallengeBase64URL &&
		n.ChildReceiptSHA256 == p.directive.ChildReceiptSHA256 && n.ProbeLeaseSequence == p.directive.LeaseSequence &&
		n.PositiveReceiptSHA256 == stage2aReservationSHA256(p.positiveBytes) &&
		n.ObservedAtMS >= result.CredentialAttemptedAtMS &&
		age >= 0 && age <= stage2aT03ReceiptLifetime &&
		stage2aPrefixedDigest.MatchString(n.ReachabilityIPv4SHA256) && stage2aPrefixedDigest.MatchString(n.ReachabilityIPv6SHA256) &&
		n.IPv4RequestsBefore == positive.Receipt.IPv4RequestCount && n.IPv4RequestsAfter == n.IPv4RequestsBefore &&
		n.IPv6RequestsBefore == positive.Receipt.IPv6RequestCount && n.IPv6RequestsAfter == n.IPv6RequestsBefore
}
