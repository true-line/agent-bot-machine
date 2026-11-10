package members

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	testPlanID = "plan-20261110T050000Z-0a1b"
	testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestRecordApprovalWritesAPrivateFile(t *testing.T) {
	state := t.TempDir()
	now := time.Date(2026, 11, 10, 5, 0, 0, 0, time.UTC)
	a, err := RecordApproval(state, testPlanID, testDigest, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.ApprovedAt != "2026-11-10T05:00:00Z" || a.ExpiresAt != "2026-11-10T05:10:00Z" {
		t.Fatalf("times %+v", a)
	}
	path := ApprovalPath(state, testPlanID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Approval
	if err := json.Unmarshal(raw, &got); err != nil || got != a {
		t.Fatalf("file %s %v", raw, err)
	}
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{path: 0o600, ApprovalsDir(state): 0o700} {
			info, err := os.Stat(p)
			if err != nil || info.Mode().Perm() != want {
				t.Fatalf("%s mode %v %v", p, info.Mode().Perm(), err)
			}
		}
	}
}

func TestRecordApprovalRefusesMalformedIdentifiers(t *testing.T) {
	state := t.TempDir()
	now := time.Now()
	cases := [][2]string{
		{"../../etc/passwd", testDigest},
		{"plan-20261110T050000Z-0a1b/..", testDigest},
		{"", testDigest},
		{testPlanID, ""},
		{testPlanID, strings.ToUpper(testDigest)},
		{testPlanID, testDigest[:63]},
		{testPlanID, testDigest + "0"},
	}
	for _, c := range cases {
		if _, err := RecordApproval(state, c[0], c[1], now); !errors.Is(err, ErrApprovalMalformed) {
			t.Fatalf("%q %q: %v", c[0], c[1], err)
		}
	}
	if _, err := os.Stat(ApprovalsDir(state)); !os.IsNotExist(err) {
		t.Fatalf("a refused approval created the directory: %v", err)
	}
}

func TestRecordApprovalReplacesAndPrunes(t *testing.T) {
	state := t.TempDir()
	start := time.Date(2026, 11, 10, 5, 0, 0, 0, time.UTC)
	if _, err := RecordApproval(state, testPlanID, testDigest, start); err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("f", 64)
	again, err := RecordApproval(state, testPlanID, other, start.Add(time.Minute))
	if err != nil || again.PlanDigest != other {
		t.Fatalf("replace %+v %v", again, err)
	}
	if err := os.WriteFile(ApprovalPath(state, "plan-20261110T040000Z-ffff"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := "plan-20261110T052000Z-0001"
	if _, err := RecordApproval(state, later, testDigest, start.Add(20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(ApprovalsDir(state))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != later+".json" {
		t.Fatalf("expired or unreadable approvals were kept: %v", entries)
	}
}
