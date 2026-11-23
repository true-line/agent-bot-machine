//go:build darwin

package members

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestStage2aQualificationBeginPinsOneUseIdentity(t *testing.T) {
	now := time.Date(2026, 11, 22, 20, 0, 0, 0, time.UTC)
	b := stage2aQualificationBeginV1{
		Schema: stage2aQualificationSchemaV1, Kind: "begin",
		SessionID: strings.Repeat("a", 32), ChallengeBase64URL: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		CohortID: "cohort-1", InstallationID: "install-1", SoulID: "agent_11111111-1111-1111-1111-111111111111",
		StartID: "st_111111111111111111111111", HostID: "host-1", Profile: "managed-protected",
		ReservationSHA256: "sha256:" + strings.Repeat("b", 64), TestPlanSHA256: "sha256:" + strings.Repeat("c", 64),
		SuiteRevision: strings.Repeat("d", 40), PSSHA256: "sha256:" + strings.Repeat("e", 64),
		PathRoots: []string{"/private/approved"}, QUID: 450, QGID: 451,
		DeadlineAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	if !validStage2aQualificationBeginV1(b, now) {
		t.Fatal("reviewed begin refused")
	}
	b.DeadlineAt = "2026-11-22T20:01:00.120Z"
	if !validStage2aQualificationBeginV1(b, now) {
		t.Fatal("Q-compatible millisecond deadline refused")
	}
	b.DeadlineAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	for _, alter := range []func(*stage2aQualificationBeginV1){
		func(v *stage2aQualificationBeginV1) { v.Profile = "unknown" },
		func(v *stage2aQualificationBeginV1) { v.ReservationSHA256 = "sha256:" + strings.Repeat("A", 64) },
		func(v *stage2aQualificationBeginV1) { v.PathRoots = []string{"/private/approved/../other"} },
		func(v *stage2aQualificationBeginV1) { v.PathRoots = []string{"/private/approved", "/private/approved"} },
		func(v *stage2aQualificationBeginV1) { v.QUID = 0 },
		func(v *stage2aQualificationBeginV1) {
			v.DeadlineAt = now.Add(time.Hour + time.Second).Format(time.RFC3339Nano)
		},
		func(v *stage2aQualificationBeginV1) {
			v.DeadlineAt = now.Add(time.Minute).Format("2006-01-02T15:04:05+00:00")
		},
	} {
		bad := b
		alter(&bad)
		if validStage2aQualificationBeginV1(bad, now) {
			t.Fatal("changed begin accepted")
		}
	}
}
