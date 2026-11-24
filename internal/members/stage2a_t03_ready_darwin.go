package members

import (
	"os"
	"path/filepath"
	"slices"
	"time"
)

type stage2aT03ObservedAttempt struct {
	Ready         Stage2aT03ProbeReady    `json:"ready"`
	Process       Stage2aLiveRoleIdentity `json:"process"`
	ParentPID     int                     `json:"parent_pid"`
	ObservedAtMS  int64                   `json:"observed_at_ms"`
	GoLeaseSHA256 string                  `json:"go_lease_sha256"`
	GoIssuedAtMS  int64                   `json:"go_issued_at_ms"`
}

func (s *Stage2aService) Stage2aT03AcceptReady(hqUID int, epoch string, q Stage2aT03ReadyRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withStage2aT03Start(hqUID, epoch, q.Stage2aStopRequest,
		func(r *stage2aLiveReservation, p stage2aInstalledPolicy, store stage2aAdminClaimStore, dir *os.File) error {
			pending := r.t03Pending
			if pending == nil || pending.issuedLease == "" || time.Now().UnixMilli() >= pending.directive.ExpiresAtMS ||
				!stage2aT03ReadyMatches(q.Ready, pending.directive, len(pending.attempts)) {
				return errStage2aReservationAuthority
			}
			if last := len(pending.attempts) - 1; last >= 0 && pending.attempts[last].GoLeaseSHA256 == "" {
				return errStage2aReservationAuthority
			}
			cli := filepath.Join(r.runtimeRefV3.Snapshot.Path, "runtime/bin/claude")
			if stage2aT03CheckEnvironment(q.Ready, p, r) != nil {
				return errStage2aReservationAuthority
			}
			witness, err := observeStage2aT03Process(q.Ready, cli, r.childLauncherPID, p.Runner, p.BridgeQualification.Model)
			if err != nil {
				return err
			}
			for _, prior := range pending.attempts {
				if prior.Process == witness.Process {
					return errStage2aReservationAuthority
				}
			}
			startClaim := soulStartClaimName(q.InstallationID, q.StartID)
			raw, err := marshalStage2aReservationJCS(witness)
			if err != nil {
				return err
			}
			if err := commitStage2aReservation(dir, ".stage2a-t03-ready-"+startClaim+"-"+q.Ready.Kind+".json", raw); err != nil {
				return err
			}
			pending.attempts = append(pending.attempts, witness)
			return nil
		})
}

func stage2aT03ReadyMatches(ready Stage2aT03ProbeReady, probe Stage2aT03ProbeDirective, index int) bool {
	kinds := [...]string{"ipv4", "ipv6", "sibling"}
	targets := [...]string{probe.ProviderIPv4URL, probe.ProviderIPv6URL, probe.SiblingSocket}
	return index >= 0 && index < len(kinds) && ready.Kind == kinds[index] && ready.Target == targets[index] &&
		ready.Schema == "agent-bot-machine/stage2a-t03-probe-ready/v1" && ready.ChallengeBase64URL == probe.ChallengeBase64URL &&
		ready.SessionID == probe.SessionID && ready.ReservationSHA256 == probe.ReservationSHA256 &&
		ready.InstallationID == probe.InstallationID && ready.StartID == probe.StartID &&
		ready.ChildReceiptSHA256 == probe.ChildReceiptSHA256 && ready.ProbeLeaseSequence == probe.LeaseSequence &&
		ready.CLIExecutableSHA256 == probe.CLIExecutableSHA256 &&
		ready.SandboxSHA256 == "sha256:"+harnessSHA(soulChildProfile) &&
		stage2aPrefixedDigest.MatchString(ready.ArgvSHA256) && stage2aPrefixedDigest.MatchString(ready.EnvSHA256)
}

func observeStage2aT03Process(ready Stage2aT03ProbeReady, cli string, parentPID int,
	runner SoulRunner, model string) (stage2aT03ObservedAttempt, error) {
	var witness stage2aT03ObservedAttempt
	if ready.CLIExecutable != cli || ready.UID != uint32(runner.UID) || ready.GID != uint32(runner.GID) ||
		ready.PID <= 1 || ready.PID == parentPID || ready.StartSeconds <= 0 ||
		ready.StartMicros < 0 || ready.StartMicros >= 1_000_000 {
		return witness, errStage2aReservationAuthority
	}
	argv := []string{cli, "--bare", "--model", model, "--output-format", "json", "--print", "--no-session-persistence"}
	argvRaw, err := marshalStage2aReservationJCS(argv)
	if err != nil || stage2aReservationSHA256(argvRaw) != ready.ArgvSHA256 ||
		trustedPath(OSHost{}, SoulChildSandbox, false) != nil || checkDarwinACLs(pathAncestry(SoulChildSandbox)) != nil {
		return witness, errStage2aReservationAuthority
	}
	profile, err := openPinnedFile(SoulChildSandbox, harnessSHA(soulChildProfile))
	if err != nil || profile.Close() != nil {
		return witness, errStage2aReservationAuthority
	}
	observed, err := observeSoulProcess(ready.PID, cli, argv)
	proc := observed.Kernel
	if err != nil || proc.ParentPID != parentPID || proc.ProcessGroupID != proc.PID ||
		proc.StartSeconds != ready.StartSeconds || proc.StartMicros != ready.StartMicros ||
		proc.RealUID != ready.UID || proc.EffectiveUID != ready.UID || proc.SavedUID != ready.UID ||
		proc.RealGID != ready.GID || proc.PrimaryGroupGID != ready.GID || proc.SavedGID != ready.GID {
		return witness, errStage2aReservationAuthority
	}
	return stage2aT03ObservedAttempt{Ready: ready, Process: stage2aLiveRoleIdentity(proc), ParentPID: proc.ParentPID,
		ObservedAtMS: time.Now().UnixMilli()}, nil
}

func stage2aT03CheckEnvironment(ready Stage2aT03ProbeReady, p stage2aInstalledPolicy, r *stage2aLiveReservation) error {
	_, environment, err := stage2aChildEnvironment(p.Runner, r.payload.Assignment.SoulStartAssignment, p.LaunchInputs)
	if err != nil {
		return err
	}
	if ready.Kind == "sibling" {
		environment["ANTHROPIC_UNIX_SOCKET"] = ready.Target
	} else {
		delete(environment, "ANTHROPIC_UNIX_SOCKET")
		environment["ANTHROPIC_BASE_URL"] = ready.Target
	}
	environment["CLAUDE_CODE_MAX_RETRIES"] = "0"
	environment["API_TIMEOUT_MS"] = "3000"
	expected := make([]string, 0, len(environment))
	for key, value := range environment {
		expected = append(expected, key+"="+value)
	}
	slices.Sort(expected)
	raw, err := marshalStage2aReservationJCS(expected)
	if err != nil || ready.EnvSHA256 != stage2aReservationSHA256(raw) {
		return errStage2aReservationAuthority
	}
	return nil
}
