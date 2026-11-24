package members

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"time"
)

var stage2aDriverCommandFields = []string{
	"schema", "kind", "session_id", "installation_id", "start_id", "reservation_sha256", "test_plan_sha256",
	"challenge_base64url", "sequence", "profile", "phase", "gate", "event",
}

// The owner executable dispatches only its compiled cases. It uses the
// authenticated command to bind its capture to the real fixture operation.
// capture returns the digest of out-of-band evidence, never its payload.
func serveStage2aQualificationDriverCases(ctx context.Context, conn net.Conn, begin stage2aQualificationBeginV1,
	phase stage2aDriverRunPhase, capture func(context.Context, stage2aDriverCommand) (string, error)) error {
	return serveStage2aQualificationDriverCasesFrom(ctx, conn, begin, phase, nil, capture)
}

func serveStage2aQualificationDriverCasesFrom(ctx context.Context, conn net.Conn, begin stage2aQualificationBeginV1,
	phase stage2aDriverRunPhase, first []byte, capture func(context.Context, stage2aDriverCommand) (string, error)) error {
	schedule := stage2aDriverSchedule(begin.Profile, phase)
	if ctx == nil || len(schedule) == 0 || capture == nil || ctx.Err() != nil {
		return errStage2aReservationAuthority
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	challenges := make(map[string]bool, len(schedule))
	for i, want := range schedule {
		deadline := time.Now().Add(60 * time.Second)
		if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
			deadline = bound
		}
		if ctx.Err() != nil || conn.SetDeadline(deadline) != nil || ctx.Err() != nil {
			return errStage2aReservationAuthority
		}
		raw := first
		if i != 0 || raw == nil {
			var err error
			raw, err = readStage2aQualificationFrame(conn)
			if err != nil {
				return err
			}
		}
		command, err := parseStage2aDriverCommand(raw, begin, phase, i+1, want)
		if err != nil || challenges[command.Challenge] {
			return errStage2aReservationAuthority
		}
		challenges[command.Challenge] = true
		digest, err := capture(ctx, command)
		if err != nil || ctx.Err() != nil || !stage2aQualificationDigest(digest) {
			return errStage2aReservationAuthority
		}
		_, err = writeStage2aQualificationFrame(conn, stage2aDriverResponse{
			Schema: stage2aDriverCaseSchema, Kind: "captured",
			RequestSHA: stage2aQualificationSHA256(raw), ArtifactSHA: digest,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func parseStage2aDriverCommand(raw []byte, begin stage2aQualificationBeginV1,
	phase stage2aDriverRunPhase, sequence int, step stage2aDriverCase) (stage2aDriverCommand, error) {
	if _, err := stage2aQualificationKeysV1(raw, stage2aDriverCommandFields, ""); err != nil {
		return stage2aDriverCommand{}, err
	}
	var command stage2aDriverCommand
	if json.Unmarshal(raw, &command) != nil || command.Schema != stage2aDriverCaseSchema || command.Kind != "capture" ||
		command.SessionID != begin.SessionID || command.InstallationID != begin.InstallationID ||
		command.StartID != begin.StartID || command.ReservationSHA256 != begin.ReservationSHA256 ||
		command.TestPlanSHA256 != begin.TestPlanSHA256 || command.Profile != begin.Profile ||
		command.Phase != phase || command.Sequence != sequence || command.Gate != step.Gate || command.Event != step.Event {
		return stage2aDriverCommand{}, errStage2aReservationAuthority
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(command.Challenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != command.Challenge {
		return stage2aDriverCommand{}, errStage2aReservationAuthority
	}
	return command, nil
}
