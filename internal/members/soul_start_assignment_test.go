package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPreparedSoulStartBindsReviewedPrincipalsAndExactEndpoints(t *testing.T) {
	runners, bridges := runnerFixture(), bridgeFixture()
	now := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	prepare := func(i int) (SoulStartAssignment, error) {
		return PrepareSoulStartAssignment(runners[i], bridges[i], 309, 501,
			"plan-20261121T140000Z-abcd", strings.Repeat("c", 64),
			"st_0123456789abcdef01234567", "ln_0123456789abcdef01234567", strings.Repeat("d", 64),
			now, now.Add(30*time.Second))
	}
	first, err := prepare(0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepare(1)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunnerUID != 331 || first.BridgeUID != 333 || first.HQUID != 309 || first.MachineUID != 501 ||
		first.PlanDigest != strings.Repeat("c", 64) ||
		first.RunnerGID != 331 || first.BridgeGID != 333 || first.PackageSHA256 != runners[0].PackageSHA256 ||
		first.Member.OwnerUID != first.RunnerUID || first.Member.GroupGID != first.BridgeGID ||
		!slices.Equal(first.Member.PeerUIDs, []int{first.RunnerUID, first.BridgeUID}) ||
		first.Relay.OwnerUID != first.BridgeUID || !slices.Equal(first.Relay.PeerUIDs, []int{first.RunnerUID}) ||
		first.Broker.OwnerUID != first.HQUID || !slices.Equal(first.Broker.PeerUIDs, []int{first.BridgeUID}) ||
		first.Admission.OwnerUID != first.HQUID || !slices.Equal(first.Admission.PeerUIDs, []int{first.RunnerUID}) ||
		first.Member.SocketPath == second.Member.SocketPath || first.Relay.SocketPath == second.Relay.SocketPath {
		t.Fatalf("prepared start crossed an installation or principal: %+v %+v", first, second)
	}
	raw, err := json.Marshal(first)
	if err != nil || first.Schema != "agent-bot-machine/soul-start-assignment/v2" ||
		!strings.Contains(string(raw), `"member":{"directory":`) ||
		strings.Contains(string(raw), "runtime_id") || strings.Contains(string(raw), "installation_epoch") ||
		strings.Contains(string(raw), "broker_binding_b") || strings.Contains(string(raw), "member_bridge_token") {
		t.Fatalf("unsafe or changed assignment wire: %s: %v", raw, err)
	}
	for _, endpoint := range []SoulStartEndpoint{first.Broker, first.Member, first.Relay, first.Admission} {
		if endpoint.DirMode != 02750 || endpoint.SocketMode != 0660 || len(endpoint.SocketPath) > 103 {
			t.Fatalf("invalid endpoint in assignment: %+v", endpoint)
		}
	}
}

func TestPreparedSoulStartRefusesChangedAuthority(t *testing.T) {
	r, b := runnerFixture()[0], bridgeFixture()[0]
	now := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	base := func(r SoulRunner, b SoulBridge, machineUID int, id, digest, start, launch, epoch string, expiry time.Time) error {
		_, err := PrepareSoulStartAssignment(r, b, 309, machineUID, id, digest, start, launch, epoch, now, expiry)
		return err
	}
	good := func(r SoulRunner, b SoulBridge, machineUID int, id, digest, start, launch, epoch string, expiry time.Time) {
		t.Helper()
		if err := base(r, b, machineUID, id, digest, start, launch, epoch, expiry); err == nil {
			t.Fatal("unreviewed start assignment accepted")
		}
	}
	id, digest := "plan-20261121T140000Z-abcd", strings.Repeat("c", 64)
	start, launch, epoch := "st_0123456789abcdef01234567", "ln_0123456789abcdef01234567", strings.Repeat("d", 64)
	good(r, bridgeFixture()[1], 501, id, digest, start, launch, epoch, now.Add(time.Second))
	good(r, b, 309, id, digest, start, launch, epoch, now.Add(time.Second))
	good(r, b, 335, id, digest, start, launch, epoch, now.Add(time.Second))
	good(r, b, 501, "other", digest, start, launch, epoch, now.Add(time.Second))
	good(r, b, 501, id, "other", start, launch, epoch, now.Add(time.Second))
	good(r, b, 501, id, "sha256:"+digest, start, launch, epoch, now.Add(time.Second))
	good(r, b, 501, id, digest, "other", launch, epoch, now.Add(time.Second))
	good(r, b, 501, id, digest, start, "other", epoch, now.Add(time.Second))
	good(r, b, 501, id, digest, start, launch, "other", now.Add(time.Second))
	good(r, b, 501, id, digest, start, launch, epoch, now.Add(-time.Second))
	good(r, b, 501, id, digest, start, launch, epoch, now.Add(31*time.Second))
	r.PackageSHA256 = "other"
	good(r, b, 501, id, digest, start, launch, epoch, now.Add(time.Second))
}

func TestSoulReportPlanDigestRequiresExactInstalledPlan(t *testing.T) {
	now := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	canonical := []byte(`{"installed":"reviewed Soul launch plan"}`)
	planID, digest := "plan-20261121T140000Z-abcd", fmt.Sprintf("%x", sha256.Sum256(canonical))
	assignment, err := PrepareSoulStartAssignment(runnerFixture()[0], bridgeFixture()[0], 309, 501,
		planID, digest, "st_0123456789abcdef01234567", "ln_0123456789abcdef01234567",
		strings.Repeat("d", 64), now, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := SoulReportPlanDigest(assignment, planID, canonical); err != nil || got != "sha256:"+digest {
		t.Fatalf("exact installed plan digest: %q, %v", got, err)
	}
	for _, tc := range []struct {
		id        string
		canonical []byte
	}{
		{"plan-20261121T140001Z-abcd", canonical},
		{planID, []byte(`{"installed":"different Soul launch plan"}`)},
		{planID, nil},
	} {
		if got, err := SoulReportPlanDigest(assignment, tc.id, tc.canonical); err == nil || got != "" {
			t.Fatalf("mismatched installed plan accepted: %+v: %q, %v", tc, got, err)
		}
	}
	assignment.PlanDigest = "sha256:" + digest
	if got, err := SoulReportPlanDigest(assignment, planID, canonical); err == nil || got != "" {
		t.Fatalf("prefixed assignment accepted: %q, %v", got, err)
	}
}

func TestSoulStartAssignmentMatchesInstalledPlanAndLiveStart(t *testing.T) {
	now := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	canonical := []byte(`{"installed":"reviewed R and B grant"}`)
	planID := "plan-20261121T140000Z-abcd"
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	runner, bridge := runnerFixture()[0], bridgeFixture()[0]
	live := SoulRunRequest{PlanDigest: digest, InstallationID: runner.InstallationID,
		StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("d", 64)}
	launchID := "ln_0123456789abcdef01234567"
	assignment, err := PrepareSoulStartAssignment(runner, bridge, 309, 501, planID, digest,
		live.StartID, launchID, live.HQEpoch, now, now.Add(20*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	check := func(a SoulStartAssignment, id string, bytes []byte, r SoulRunner, b SoulBridge,
		request SoulRunRequest, launch string, at time.Time) error {
		return CheckSoulStartAssignment(a, id, bytes, r, b, 309, 501, request, launch, at)
	}
	if err := check(assignment, planID, canonical, runner, bridge, live, launchID, now); err != nil {
		t.Fatalf("exact installed and live start refused: %v", err)
	}
	for name, change := range map[string]func(*SoulStartAssignment){
		"package digest":  func(a *SoulStartAssignment) { a.PackageSHA256 = strings.Repeat("e", 64) },
		"bridge UID":      func(a *SoulStartAssignment) { a.BridgeUID = 334 },
		"broker path":     func(a *SoulStartAssignment) { a.Broker.SocketPath += ".sibling" },
		"member peers":    func(a *SoulStartAssignment) { a.Member.PeerUIDs = []int{331, 334} },
		"HQ epoch":        func(a *SoulStartAssignment) { a.HQEpoch = strings.Repeat("e", 64) },
		"start ID":        func(a *SoulStartAssignment) { a.StartID = "st_0123456789abcdef01234568" },
		"launch ID":       func(a *SoulStartAssignment) { a.LaunchID = "ln_0123456789abcdef01234568" },
		"expiry text":     func(a *SoulStartAssignment) { a.ExpiresAt = "2026-11-21T14:00:20-00:00" },
		"wrong schema":    func(a *SoulStartAssignment) { a.Schema = "legacy" },
		"prefixed digest": func(a *SoulStartAssignment) { a.PlanDigest = "sha256:" + digest },
	} {
		t.Run(name, func(t *testing.T) {
			changed := assignment
			change(&changed)
			if err := check(changed, planID, canonical, runner, bridge, live, launchID, now); err == nil {
				t.Fatal("changed assignment matched installed and live authority")
			}
		})
	}
	for name, change := range map[string]func(*SoulRunRequest){
		"live sibling installation": func(r *SoulRunRequest) { r.InstallationID = "inst_0000000000000002" },
		"live new start":            func(r *SoulRunRequest) { r.StartID = "st_0123456789abcdef01234568" },
		"live new epoch":            func(r *SoulRunRequest) { r.HQEpoch = strings.Repeat("e", 64) },
		"live new plan":             func(r *SoulRunRequest) { r.PlanDigest = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := live
			change(&changed)
			if err := check(assignment, planID, canonical, runner, bridge, changed, launchID, now); err == nil {
				t.Fatal("changed live start accepted")
			}
		})
	}
	if err := check(assignment, planID, canonical, runner, bridge, live, "ln_0123456789abcdef01234568", now); err == nil {
		t.Fatal("changed live launch ID accepted")
	}
	if err := check(assignment, planID, []byte(`{"installed":"changed"}`), runner, bridge, live, launchID, now); err == nil {
		t.Fatal("changed installed plan accepted")
	}
	if err := check(assignment, "plan-20261121T140001Z-abcd", canonical, runner, bridge, live, launchID, now); err == nil {
		t.Fatal("different installed plan ID accepted")
	}
	if err := check(assignment, planID, canonical, runner, bridgeFixture()[1], live, launchID, now); err == nil {
		t.Fatal("sibling bridge accepted")
	}
	if err := check(assignment, planID, canonical, runner, bridge, live, launchID, now.Add(20*time.Second)); err == nil {
		t.Fatal("expired assignment accepted")
	}
}
