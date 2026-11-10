package daemon

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
)

const (
	approvePlanID = "plan-20261110T050000Z-0a1b"
	approveDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func approveRequest(now time.Time, nonce string) Request {
	return Request{Verb: approveMembersVerb, PlanID: approvePlanID, PlanDigest: approveDigest, Timestamp: now.Unix(), Nonce: nonce}
}

func TestGateAcceptsApproveMembers(t *testing.T) {
	pub, priv := keyPair(t)
	now := time.Unix(1_700_000_000, 0)
	g := &Gate{Pairing: Pairing{Live: pub}, PeerUID: 501, Now: func() time.Time { return now }}
	req, id, msg := g.verify(501, signed(t, priv, approveRequest(now, "a1")))
	if id != "" || req.PlanID != approvePlanID || req.PlanDigest != approveDigest {
		t.Fatalf("%s %s %#v", id, msg, req)
	}
}

func TestGateRefusesApproveMembersShapes(t *testing.T) {
	pub, priv := keyPair(t)
	now := time.Unix(1_700_000_000, 0)
	g := &Gate{Pairing: Pairing{Live: pub}, PeerUID: 501, Now: func() time.Time { return now }}
	edit := func(nonce string, f func(*Request)) []byte {
		r := approveRequest(now, nonce)
		f(&r)
		return signed(t, priv, r)
	}
	_, key := testCatalogKey(t)
	nullDigest := signed(t, priv, Request{Verb: "status", Timestamp: now.Unix(), Nonce: "s3"})
	nullDigest = []byte(`{"verb":"status","plan_digest":null,` + string(nullDigest[len(`{"verb":"status",`):]))
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"name", edit("r1", func(r *Request) { r.Name = "jq" }), diag.DaemonUndeclared},
		{"option", edit("r2", func(r *Request) { r.Option = "stable" }), diag.DaemonUndeclared},
		{"target", edit("r3", func(r *Request) { r.Target = "local" }), diag.DaemonUndeclared},
		{"soul", edit("r4", func(r *Request) { r.Soul = "iron" }), diag.DaemonUndeclared},
		{"harness", edit("r5", func(r *Request) { r.Harness = "cursor" }), diag.DaemonUndeclared},
		{"session", edit("r6", func(r *Request) { r.SessionID = "s" }), diag.DaemonUndeclared},
		{"catalog key", edit("r7", func(r *Request) { r.CatalogKey = &key }), diag.DaemonUndeclared},
		{"no plan id", edit("r8", func(r *Request) { r.PlanID = "" }), diag.DaemonUndeclared},
		{"path plan id", edit("r9", func(r *Request) { r.PlanID = "../../peers/terminal" }), diag.DaemonUndeclared},
		{"no digest", edit("r10", func(r *Request) { r.PlanDigest = "" }), diag.DaemonUndeclared},
		{"short digest", edit("r11", func(r *Request) { r.PlanDigest = approveDigest[:40] }), diag.DaemonUndeclared},
		{"upper digest", edit("r12", func(r *Request) { r.PlanDigest = strings.ToUpper(approveDigest) }), diag.DaemonUndeclared},
		{"digest on status", signed(t, priv, Request{Verb: "status", PlanDigest: approveDigest, Timestamp: now.Unix(), Nonce: "s1"}), diag.DaemonUndeclared},
		{"digest on apply", signed(t, priv, Request{Verb: "apply", PlanID: approvePlanID, PlanDigest: approveDigest, Timestamp: now.Unix(), Nonce: "s2"}), diag.DaemonUndeclared},
		{"null digest on status", nullDigest, diag.DaemonUndeclared},
		{"unknown field", []byte(`{"verb":"approve-members","plan_id":"` + approvePlanID + `","plan_digest":"` + approveDigest + `","command":"id","timestamp":1700000000,"nonce":"u1","public_key":"aa","signature":"bb"}`), diag.DaemonTampered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, id, _ := g.verify(501, tc.raw); id != tc.want {
				t.Fatalf("got %s want %s", id, tc.want)
			}
		})
	}
}

func TestApproveMembersSignatureCoversTheDigest(t *testing.T) {
	pub, priv := keyPair(t)
	now := time.Unix(1_700_000_000, 0)
	g := &Gate{Pairing: Pairing{Live: pub}, PeerUID: 501, Now: func() time.Time { return now }}
	req := approveRequest(now, "t1")
	if err := Sign(priv, &req); err != nil {
		t.Fatal(err)
	}
	req.PlanDigest = strings.Repeat("f", 64)
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, id, _ := g.verify(501, raw); id != diag.DaemonTampered {
		t.Fatalf("a swapped digest was accepted: %s", id)
	}
}

func TestApproveMembersRefusesTheTerminalKey(t *testing.T) {
	terminalPub, terminalPriv := keyPair(t)
	now := time.Unix(1_700_000_000, 0)
	g := &Gate{Pairing: Pairing{Live: terminalPub, Terminal: terminalPub}, PeerUID: 501, Now: func() time.Time { return now }}
	if _, id, _ := g.verify(501, signed(t, terminalPriv, approveRequest(now, "k1"))); id != diag.DaemonUnknownKey {
		t.Fatalf("terminal key: %s", id)
	}
}

func TestApproveMembersRecordsOnLinuxOnly(t *testing.T) {
	now := time.Date(2026, 11, 10, 5, 0, 0, 0, time.UTC)
	for _, goos := range []string{"darwin", "windows"} {
		dir := t.TempDir()
		body, id, _ := approveMembers(goos, dir, approvePlanID, approveDigest, now)
		if id != diag.MembersUnsupported || body != nil {
			t.Fatalf("%s: %s %s", goos, id, body)
		}
		if _, err := os.Stat(members.ApprovalsDir(dir)); !os.IsNotExist(err) {
			t.Fatalf("%s wrote state: %v", goos, err)
		}
	}
	dir := t.TempDir()
	body, id, msg := approveMembers("linux", dir, approvePlanID, approveDigest, now)
	if id != "" {
		t.Fatalf("%s %s", id, msg)
	}
	var got members.Approval
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	want := members.Approval{PlanID: approvePlanID, PlanDigest: approveDigest, ApprovedAt: "2026-11-10T05:00:00Z", ExpiresAt: "2026-11-10T05:10:00Z"}
	if got != want {
		t.Fatalf("body %+v", got)
	}
	raw, err := os.ReadFile(members.ApprovalPath(dir, approvePlanID))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk members.Approval
	if err := json.Unmarshal(raw, &onDisk); err != nil || onDisk != want {
		t.Fatalf("file %s %v", raw, err)
	}
	if _, id, _ := approveMembers("linux", dir, "plan-bad", approveDigest, now); id != diag.DaemonUndeclared {
		t.Fatalf("malformed id: %s", id)
	}
}

func TestHooksReplyApproveMembers(t *testing.T) {
	req := Request{Verb: approveMembersVerb, PlanID: approvePlanID, PlanDigest: approveDigest}
	if res := (Hooks{}).reply(req); res.OK || res.Diagnostic != diag.DaemonUnimplemented {
		t.Fatalf("no hook: %+v", res)
	}
	var gotID, gotDigest string
	hooks := Hooks{
		ApproveMembers: func(planID, digest string) ([]byte, string, string) {
			gotID, gotDigest = planID, digest
			return []byte(`{"plan_id":"x"}`), "", ""
		},
		Apply:     func(string, string, string, string, string, string, string) string { t.Fatal("apply ran"); return "" },
		OnReceipt: func() { t.Fatal("approve-members wrote a receipt") },
	}
	res := hooks.reply(req)
	if !res.OK || res.State != "approved" || res.Message != approvePlanID || string(res.Body) != `{"plan_id":"x"}` {
		t.Fatalf("%+v", res)
	}
	if gotID != approvePlanID || gotDigest != approveDigest {
		t.Fatalf("hook saw %s %s", gotID, gotDigest)
	}
	refuse := Hooks{ApproveMembers: func(string, string) ([]byte, string, string) {
		return nil, diag.MembersUnsupported, "member accounts are Linux only"
	}}
	if res := refuse.reply(req); res.OK || res.Diagnostic != diag.MembersUnsupported {
		t.Fatalf("%+v", res)
	}
}
