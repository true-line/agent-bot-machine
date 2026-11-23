package members

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStage2aQualificationQDisposableComponent(t *testing.T) {
	mode := os.Getenv("STAGE2A_Q_COMPONENT")
	if mode == "" {
		t.Skip("requires a dedicated disposable macOS guest")
	}
	model, err := unix.Sysctl("hw.model")
	if err != nil || !strings.HasPrefix(model, "VirtualMac") {
		t.Fatal("qualification component requires VirtualMac")
	}
	if mode == "install" {
		if os.Geteuid() != 0 {
			t.Fatal("component installation requires guest root")
		}
		adminName := os.Getenv("STAGE2A_Q_ADMIN")
		admin, exists, err := (OSHost{}).Account(adminName)
		if err != nil || !exists {
			t.Fatal("guest A account absent")
		}
		node := os.Getenv("STAGE2A_Q_NODE")
		source, err := os.ReadFile(os.Getenv("STAGE2A_Q_SOURCE"))
		if err != nil {
			t.Fatal(err)
		}
		observer, err := os.ReadFile(os.Getenv("STAGE2A_Q_OBSERVER"))
		if err != nil {
			t.Fatal(err)
		}
		digestFile := func(path string) string {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			return strings.TrimPrefix(stage2aQualificationSHA256(raw), "sha256:")
		}
		users, err := dsclList("/Users", "UniqueID")
		if err != nil {
			t.Fatal(err)
		}
		groups, err := dsclList("/Groups", "PrimaryGroupID")
		if err != nil {
			t.Fatal(err)
		}
		uid, err := freeStage2aQualificationQID(users, groups, protectedDarwinIDUsed)
		if err != nil {
			t.Fatal(err)
		}
		q := stage2aQualificationQInstall{
			AdminGID: admin.GID, SupplementalGIDs: []int{12, 61, 100, 701},
			HQGID: 621, RunnerGID: 622, BridgeGID: 623,
			LauncherSHA256: digestFile(SoulLauncher),
			AdminUID:       admin.UID, UID: uid, GID: uid,
			Node:   qualificationFile{node, digestFile(node)},
			Source: qualificationFile{filepath.Join(stage2aQualificationQHome, "qualification-runner.mjs"), strings.TrimPrefix(stage2aQualificationSHA256(source), "sha256:")},
			PS:     qualificationFile{filepath.Join(stage2aQualificationQHome, "process-observer"), strings.TrimPrefix(stage2aQualificationSHA256(observer), "sha256:")}, Roots: []string{"/private/tmp"},
			Review: stage2aQualificationQReview{
				Owner: adminName, PlanID: "plan-20261122T141516Z-abcd", PlanDigest: strings.Repeat("a", 64),
				HostUUID: "A0000000-0000-0000-0000-000000000001", HostID: "disposable-test-only",
				InstallationID: "inst_0000000000000001", InstalledPlanDigest: strings.Repeat("a", 64),
				TestPlan: qualificationFile{"/private/tmp/synthetic-plan", strings.Repeat("a", 64)},
				Provider: qualificationFile{"/private/tmp/synthetic-provider", strings.Repeat("b", 64)},
			},
		}
		q.ProfileSHA256 = stage2aQualificationProfileSHA256(q)
		config, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		if err := provisionStage2aQualificationQ(adminName, digestFile(SoulLauncher), q.Review.PlanID, config, source, observer, []byte("{}"), q); err != nil {
			t.Fatal(err)
		}
		t.Logf("component-only installed A uid %d, Q uid/gid %d", admin.UID, uid)
		return
	}
	q, err := loadStage2aQualificationQInstall()
	if err != nil || mode != "observe" || os.Getuid() != q.AdminUID || os.Geteuid() != q.AdminUID || q.AdminUID == 0 {
		t.Fatalf("component observer requires installed disposable input and guest A: %v", err)
	}
	caller, _ := user.Current()
	listener, err := newStage2aQualificationListenerV1(stage2aQualificationQSocket, q.GID)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	begin := stage2aQualificationBeginV1{
		CohortID: "disposable-component", InstallationID: q.Review.InstallationID,
		SoulID: "agent_01234567-0123-4567-8123-0123456789ab", StartID: "st_0123456789abcdef01234567",
		HostID: q.Review.HostID, Profile: "managed-protected",
		ReservationSHA256: "sha256:" + strings.Repeat("c", 64), TestPlanSHA256: "sha256:" + q.Review.TestPlan.SHA256,
		SuiteRevision: strings.Repeat("d", 40), PSSHA256: "sha256:" + q.PS.SHA256,
		QUID: q.UID, QGID: q.GID, PathRoots: q.Roots, DeadlineAt: time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339),
	}
	session, wait, err := spawnStage2aQualificationQWithArgvProof(ctx, q, listener, begin, os.Getenv("STAGE2A_Q_ARGV_PROOF") == "1")
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()
	_, err = session.observe(stage2aQualificationObserveV1{
		Gate: "T01", Phase: "component", EventID: "q-identity",
		Processes: []stage2aQualificationProcessRequestV1{{Role: "q", PID: session.peer.pid}},
		Paths:     []stage2aQualificationPathRequestV1{{Role: "absent", Path: "/private/tmp/stage2a-q-test-absent"}},
	})
	if err != nil {
		_ = wait()
		t.Fatal(err)
	}
	result, err := session.finish()
	if waitErr := wait(); err == nil {
		err = waitErr
	}
	if err != nil || verifyStage2aQualificationPairedFramesV1(result) != nil {
		t.Fatalf("Q component did not close a valid observation: %v", err)
	}
	t.Logf("component-only caller=%s Q pid=%d uid=%d gid=%d parent=%d path_observations=%d clean_eof=%t",
		caller.Username, session.peer.pid, session.peer.uid, session.peer.gid, session.peer.kernel.ParentPID, result.count, result.cleanEOFObserved)
}
