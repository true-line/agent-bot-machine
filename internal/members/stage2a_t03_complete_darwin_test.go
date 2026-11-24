package members

import (
	"strings"
	"testing"
	"time"
)

func TestStage2aT03CompletionRequiresObservedTargetAndNoProviderArrival(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	now := time.UnixMilli(20_000)
	p := stage2aT03Pending{issuedAt: time.UnixMilli(10_000), directive: Stage2aT03ProbeDirective{
		LeaseSequence: 10, CLIExecutableSHA256: digest, ExpiresAtMS: 30_000,
		SiblingCredentialPath: "/private/fixture/sibling/credential",
	}}
	r := Stage2aT03ProbeResult{Schema: "agent-bot-machine/stage2a-t03-probe-result/v1",
		CLIExecutable: "/private/fixture/bin/claude", CLIExecutableSHA256: digest, LeaseSequence: 10,
		SandboxSHA256: "sha256:" + harnessSHA(soulChildProfile), CredentialPath: p.directive.SiblingCredentialPath,
		CredentialDenialErrno: "EACCES", CredentialAttemptedAtMS: 18_000,
	}
	for i, kind := range []string{"ipv4", "ipv6", "sibling"} {
		ready := Stage2aT03ProbeReady{Kind: kind, Target: kind + "-target", CLIExecutable: r.CLIExecutable,
			PID: 100 + i, UID: 301, GID: 301, StartSeconds: 1, StartMicros: int32(i), ArgvSHA256: digest, EnvSHA256: digest}
		p.attempts = append(p.attempts, stage2aT03ObservedAttempt{Ready: ready,
			ObservedAtMS: 12_000, GoLeaseSHA256: digest, GoIssuedAtMS: 13_000})
		r.Attempts = append(r.Attempts, Stage2aT03ProbeAttempt{Kind: kind, Target: ready.Target,
			PID: ready.PID, UID: ready.UID, GID: ready.GID, StartSeconds: ready.StartSeconds, StartMicros: ready.StartMicros,
			ArgvSHA256: digest, EnvSHA256: digest, ExitCode: 1, StdoutSHA256: digest, StderrSHA256: digest,
			StderrBytes: 10, StartedAtMS: 11_000, FinishedAtMS: 15_000, DenialErrno: "EPERM",
			DenialTargetObserved: true, ErrorClass: "connect_denied",
		})
	}
	positive := Stage2aT03ArmRequest{Receipt: Stage2aT03PositiveReceipt{IPv4RequestCount: 1}}
	var err error
	p.positiveBytes, err = marshalStage2aReservationJCS(positive)
	if err != nil {
		t.Fatal(err)
	}
	n := Stage2aT03NetworkReceipt{Schema: "agent-bot/stage2a-t03-network-receipt/v1",
		ProbeLeaseSequence: 10, PositiveReceiptSHA256: stage2aReservationSHA256(p.positiveBytes),
		ReachabilityIPv4SHA256: digest, ReachabilityIPv6SHA256: digest,
		IPv4RequestsBefore: 1, IPv4RequestsAfter: 1, ObservedAtMS: 19_000,
	}
	if !stage2aT03ResultMatches(r, &p) || !stage2aT03NetworkMatches(n, r, &p, now) {
		t.Fatal("bound process and network evidence refused")
	}
	n.IPv6RequestsAfter++
	if stage2aT03NetworkMatches(n, r, &p, now) {
		t.Fatal("provider arrival was ignored")
	}
	r.Attempts[1].DenialErrno = "ECONNREFUSED"
	if stage2aT03ResultMatches(r, &p) {
		t.Fatal("connection refused counted as sandbox denial")
	}
	r.Attempts[1].DenialErrno = "EPERM"
	r.Attempts[1].DenialTargetObserved = false
	if stage2aT03ResultMatches(r, &p) {
		t.Fatal("an unrelated permission error counted as target denial")
	}
}
