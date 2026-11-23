package members

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestSoulCooperativeHChildReceiptBindsCommittedRow(t *testing.T) {
	now := time.Now().UTC()
	selector := "mb_" + strings.Repeat("a", 64)
	row := soulCooperativeHChildReceiptV3{
		Plugin: "hq", Kind: "hq.soul.member.observed",
		Schema:                   "agent-bot-hq/stage2a-cooperative-member-observed/v1",
		ReservationSHA256:        "sha256:" + strings.Repeat("b", 64),
		AssignmentEnvelopeSHA256: "sha256:" + strings.Repeat("c", 64),
		InstallationID:           "install_1", StartID: "st_" + strings.Repeat("d", 24),
		LaunchID: "launch_1", HQEpoch: "epoch_1", MemberID: "m_lead",
		MemberLaunchID: "launch_2", MemberSelector: selector,
		GrantSHA256: "sha256:" + strings.Repeat("e", 64),
		LauncherProcess: soulCooperativeHProcessV3{UID: 309, GID: 309, PID: 410,
			StartSeconds: now.Unix(), StartMicros: 1},
		ChildProcess: soulCooperativeHProcessV3{UID: 309, GID: 309, PID: 411,
			StartSeconds: now.Unix(), StartMicros: 2},
		At: now.UnixMilli(), Profile: "managed-cooperative", Seq: 7,
	}
	raw, err := marshalStage2aReservationJCS(row)
	if err != nil {
		t.Fatal(err)
	}
	in := SoulCooperativeChildObserveInputV3{MemberID: row.MemberID,
		MemberLaunchID: row.MemberLaunchID, MemberSelector: selector,
		ChildLauncherPID: 410, ChildPID: 411, GrantSHA256: row.GrantSHA256,
		HObservationBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		HObservationSHA256:    stage2aReservationSHA256(raw)}
	if _, _, err := decodeSoulCooperativeHChildReceipt(in); err != nil {
		t.Fatalf("committed H row refused: %v", err)
	}
	in.ChildPID++
	if _, _, err := decodeSoulCooperativeHChildReceipt(in); err == nil {
		t.Fatal("different child PID accepted with committed H row")
	}
}
