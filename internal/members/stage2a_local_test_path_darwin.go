//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"time"
)

type stage2aLocalTestPathPair struct {
	Lexical string `json:"lexical"`
	Emitted string `json:"emitted"`
}

// A signs these per-start bytes only after deriving the child slot from the
// installed runner account. The neutral vector exercises this source seam;
// the daemon producer and role readers are still separate integration work.
type stage2aLocalTestPathBinding struct {
	Schema            string                   `json:"schema"`
	Kind              string                   `json:"kind"`
	SchemaVersion     int                      `json:"schema_version"`
	InstallationID    string                   `json:"installation_id"`
	StartID           string                   `json:"start_id"`
	RunnerAccount     string                   `json:"runner_account"`
	RunnerHomeLexical string                   `json:"runner_home_lexical"`
	StartSlot         string                   `json:"start_slot"`
	CWD               stage2aLocalTestPathPair `json:"cwd"`
	Home              stage2aLocalTestPathPair `json:"home"`
	Memory            stage2aLocalTestPathPair `json:"memory"`
	AncillaryOrder    []string                 `json:"ancillary_order"`
	TargetAfter       []string                 `json:"target_after"`
	IssuedAt          string                   `json:"issued_at"`
	ExpiresAt         string                   `json:"expires_at"`
}

func stage2aLocalTestPathBindingForStart(p stage2aLocalTestOwnerPlan,
	runnerAccount, installationID, startID string, issued, expires time.Time,
) (stage2aLocalTestPathBinding, []byte, error) {
	var empty stage2aLocalTestPathBinding
	planExpiry, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil || !p.Enabled || !p.AncillaryProfile.valid(p.HTTPHost) ||
		!slices.Equal(p.AncillaryProfile.Order, []string{"first", "second"}) ||
		!slices.Equal(p.AncillaryProfile.TargetAfter, []string{"first"}) ||
		!issued.Before(expires) || !expires.After(time.Time{}) ||
		expires.After(planExpiry) || expires.Sub(issued) > 30*time.Second {
		return empty, nil, errStage2aReservationAuthority
	}
	paths, err := stage2aLocalTestPathsForStart(p, runnerAccount, installationID, startID)
	if err != nil {
		return empty, nil, err
	}
	binding := stage2aLocalTestPathBinding{
		Schema: "agent-bot-machine/stage2a-child-path-binding-local-test/v1",
		Kind:   "stage2a-child-path-binding-local-test", SchemaVersion: 1,
		InstallationID: installationID, StartID: startID,
		RunnerAccount: runnerAccount, RunnerHomeLexical: p.RunnerHomeLexical,
		StartSlot:      soulEndpointStartSlot(installationID, startID),
		CWD:            stage2aLocalTestPathPair{paths.CWDLexical, paths.CWDEmitted},
		Home:           stage2aLocalTestPathPair{paths.HomeLexical, paths.HomeEmitted},
		Memory:         stage2aLocalTestPathPair{paths.MemoryLexical, paths.MemoryEmitted},
		AncillaryOrder: []string{"first", "second"}, TargetAfter: []string{"first"},
		IssuedAt:  issued.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expires.UTC().Format(time.RFC3339Nano),
	}
	raw, err := marshalStage2aReservationJCS(binding)
	if err != nil || stage2aLocalTestCanonicalPayload(raw, stage2aLocalTestPathPurpose) != nil {
		return empty, nil, errStage2aReservationAuthority
	}
	return binding, raw, nil
}

func verifyStage2aLocalTestPathBinding(envelope []byte, key ed25519.PublicKey,
	p stage2aLocalTestOwnerPlan, runnerAccount, installationID, startID string,
	now time.Time) (stage2aLocalTestPathBinding, error) {
	var empty stage2aLocalTestPathBinding
	raw, err := verifyStage2aLocalTestEnvelope(envelope, stage2aLocalTestPathPurpose, key)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	var got stage2aLocalTestPathBinding
	if stage2aDecodeExact(raw, &got) != nil {
		return empty, errStage2aReservationAuthority
	}
	issued, e1 := time.Parse(time.RFC3339Nano, got.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, got.ExpiresAt)
	if e1 != nil || e2 != nil || now.Before(issued) || !now.Before(expires) {
		return empty, errStage2aReservationAuthority
	}
	_, expected, err := stage2aLocalTestPathBindingForStart(p, runnerAccount,
		installationID, startID, issued, expires)
	if err != nil || !bytes.Equal(raw, expected) {
		return empty, errStage2aReservationAuthority
	}
	return got, nil
}
