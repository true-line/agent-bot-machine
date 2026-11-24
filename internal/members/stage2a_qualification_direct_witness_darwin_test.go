//go:build darwin

package members

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestStage2aDirectQStartReceiptRequiresExplicitCooperativeProtectedFlag(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pre := stage2aDirectQPreV3{
		InstallationID: "inst_0000000000000001", StartID: "st_0123456789abcdef01234567",
		HQEpoch: "epoch", ReservationSHA256: "sha256:reservation",
	}
	live := &soulCooperativeLiveV3{runnerPID: 1234}
	live.installed.Policy.Runner.UID = 451
	live.installed.Policy.Runner.GID = 451
	base := map[string]any{
		"plugin": "hq", "kind": "hq.soul.started", "seq": 4, "at": now.UnixMilli(),
		"profile": "managed-cooperative", "installation_id": pre.InstallationID,
		"start_id": pre.StartID, "hq_epoch": pre.HQEpoch,
		"reservation_sha256": pre.ReservationSHA256, "pid": live.runnerPID,
		"runner_uid": live.installed.Policy.Runner.UID,
		"runner_gid": live.installed.Policy.Runner.GID, "state": "running",
	}
	for _, tc := range []struct {
		name    string
		present bool
		value   any
		wantOK  bool
	}{
		{name: "explicit false", present: true, value: false, wantOK: true},
		{name: "missing", present: false},
		{name: "null", present: true, value: nil},
		{name: "true", present: true, value: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := make(map[string]any, len(base)+1)
			for k, v := range base {
				row[k] = v
			}
			if tc.present {
				row["protected"] = tc.value
			}
			raw, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			raw, err = jsoncanonicalizer.Transform(raw)
			if err != nil {
				t.Fatal(err)
			}
			q := Stage2aDirectQWitnessFinishRequestV3{
				CooperativeStartReceiptBase64URL: base64.RawURLEncoding.EncodeToString(raw),
				CooperativeStartReceiptSHA256:    stage2aQualificationSHA256(raw),
			}
			_, err = stage2aDirectQStartReceiptV3(q, live, pre, now)
			if (err == nil) != tc.wantOK {
				t.Fatalf("start receipt acceptance = %t, want %t: %v", err == nil, tc.wantOK, err)
			}
		})
	}
}
