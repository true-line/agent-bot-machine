//go:build darwin

package members

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStage2aLiveIntakeRetainsExactBytesAndRefusesReplay(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claims := filepath.Join(base, "claims")
	if err := os.Mkdir(claims, 0700); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(claims, &st); err != nil {
		t.Fatal(err)
	}
	store := stage2aAdminClaimStore{path: claims, uid: st.Uid, gid: st.Gid,
		device: st.Dev, inode: st.Ino, birthtime: st.Btim,
		legacyUnspent: func(string, string) error { return nil }}
	reservation := []byte(`{"signed":"synthetic-only"}`)
	qChallenge := bytes.Repeat([]byte{0xbb}, 32)
	begin := stage2aQualificationBeginV1{
		InstallationID: "inst_0123456789abcdef", StartID: "st_0123456789abcdef01234567",
		SessionID: strings.Repeat("a", 32), Profile: "managed-protected",
		ReservationSHA256:  stage2aQualificationSHA256(reservation),
		TestPlanSHA256:     "sha256:" + strings.Repeat("3", 64),
		ChallengeBase64URL: base64.RawURLEncoding.EncodeToString(qChallenge),
		QUID:               650, QGID: 651,
	}
	qPeer := stage2aQualificationPeerV1{
		pid: 42, uid: 650, gid: 651, executable: "/usr/local/bin/node",
		argv:       []string{"/usr/local/bin/node", "/opt/q/qualification-runner.mjs", "--once"},
		socketPath: "/private/tmp/q-session.sock", socketDev: 1, socketInode: 4242,
		socketBirthSeconds: 1795327200,
		kernel: soulKernelProcessSnapshot{PID: 42, ParentPID: 40, StartSeconds: 1795327200,
			RealUID: 650, EffectiveUID: 650, SavedUID: 650,
			RealGID: 651, PrimaryGroupGID: 651, SavedGID: 651},
	}
	dir, err := store.open()
	if err != nil {
		t.Fatal(err)
	}
	slot := soulStartClaimName(begin.InstallationID, begin.StartID)
	if err := commitStage2aReservation(dir, ".stage2a-admin-envelope-"+slot, reservation); err != nil {
		t.Fatal(err)
	}
	if err := spendStage2aAdminName(dir, stage2aActiveClaimName(begin.InstallationID), store.uid, store.gid); err != nil {
		t.Fatal(err)
	}
	dir.Close()
	if err := claimStage2aQualificationSessionV3(store, begin, reservation); err != nil {
		t.Fatal(err)
	}
	qHash := stage2aQualificationSHA256(qChallenge)
	if err := bindStage2aQualificationSessionV3(store, begin, qHash, qPeer, reservation); err != nil {
		t.Fatal(err)
	}
	session := &stage2aQualificationSessionV1{begin: begin, peer: qPeer, challengeSHA256: qHash}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	observed, err := observeSoulProcess(os.Getpid(), self, os.Args)
	if err != nil {
		t.Fatal(err)
	}
	peer := stage2aQualificationDriverPeer{pid: os.Getpid(), kernel: observed.Kernel,
		execPath: self, argv: append([]string(nil), os.Args...)}
	command := stage2aDriverCommand{
		Schema: stage2aDriverCaseSchema, Kind: "capture", SessionID: begin.SessionID,
		InstallationID: begin.InstallationID, StartID: begin.StartID,
		ReservationSHA256: begin.ReservationSHA256, TestPlanSHA256: begin.TestPlanSHA256,
		Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xcc}, 32)),
		Sequence:  6, Profile: begin.Profile, Phase: stage2aDriverLiveStart,
		Gate: "T03", Event: "direct-route-refused",
	}
	var request bytes.Buffer
	requestFrame, err := writeStage2aQualificationFrame(&request, command)
	if err != nil {
		t.Fatal(err)
	}
	blob := []byte("synthetic ACP bytes from the verified transfer")
	blobHash := stage2aQualificationSHA256(blob)
	rangeRef := stage2aLiveRange{BlobSHA256: blobHash, OffsetBytes: 0, LengthBytes: len(blob)}
	process := func(ref, role string, pid int) map[string]any {
		return map[string]any{
			"process_ref": ref, "role": role, "pid": pid, "uid": 310, "gid": 310,
			"ppid": 20, "pgid": 21, "start_identity": "synthetic-start",
			"executable_sha256": blobHash, "argv_sha256": blobHash,
			"loaded_profile_sha256": blobHash,
		}
	}
	artifact, err := marshalStage2aReservationJCS(map[string]any{
		"schema":         "agent-bot-adapters/t03-stock-claude-direct-attempts/v1",
		"driver_command": command, "driver_request_sha256": stage2aQualificationSHA256(requestFrame[4:]),
		"processes": []any{process("acp-1", "acp", 301), process("cli-1", "claude-cli", 302)},
		"raw_refs":  []any{stage2aLiveRawRef{SHA256: blobHash, SizeBytes: len(blob), Purpose: "acp-in"}},
		"attempts": []any{map[string]any{
			"attempt_id": "attempt-1", "sequence": 1, "process_ref": "cli-1",
			"destination_class": "ipv4", "destination_sha256": blobHash,
			"request_range": rangeRef, "response_range": nil, "result": "refused", "errno": 13,
			"canary_before": 0, "canary_after": 0,
			"started_monotonic_ns": 100, "ended_monotonic_ns": 200, "timeout_limit_ms": 1,
		}},
		"allowed_turn": map[string]any{
			"relay_socket_identity_ref": blobHash, "b_bind_receipt_sha256": blobHash,
			"hq_provider_receipt_ref": blobHash,
			"http_request_range":      rangeRef, "http_response_range": rangeRef,
			"acp_request_range": rangeRef, "acp_response_range": rangeRef,
			"soul_result_range": rangeRef,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, remove := range map[string]func(map[string]any){
		"process identity": func(v map[string]any) {
			delete(v["processes"].([]any)[1].(map[string]any), "loaded_profile_sha256")
		},
		"attempt result": func(v map[string]any) {
			delete(v["attempts"].([]any)[0].(map[string]any), "errno")
		},
		"allowed turn join": func(v map[string]any) {
			delete(v["allowed_turn"].(map[string]any), "hq_provider_receipt_ref")
		},
	} {
		var changed map[string]any
		if json.Unmarshal(artifact, &changed) != nil {
			t.Fatal("fixture artifact is not JSON")
		}
		remove(changed)
		raw, err := marshalStage2aReservationJCS(changed)
		if err != nil || stage2aLiveArtifactShape(raw) == nil {
			t.Fatalf("%s omission accepted: %v", name, err)
		}
	}
	manifest := stage2aLiveTransfer{Schema: stage2aLiveIntakeSchema, Kind: "raw-transfer",
		RequestSHA256: stage2aQualificationSHA256(requestFrame[4:]), ArtifactSize: len(artifact)}
	manifest.Blobs = append(manifest.Blobs, struct {
		Purpose   string `json:"purpose"`
		SizeBytes int    `json:"size_bytes"`
	}{Purpose: "acp-in", SizeBytes: len(blob)})
	var transfer bytes.Buffer
	if _, err := writeStage2aQualificationFrame(&transfer, manifest); err != nil {
		t.Fatal(err)
	}
	transfer.Write(blob)
	transfer.Write(artifact)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(shortStage2aDriverTestDir(t), "capture.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for attempt := 0; attempt < 2; attempt++ {
		client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
		if err != nil {
			t.Fatal(err)
		}
		server, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(transfer.Bytes()); err != nil {
			t.Fatal(err)
		}
		got, err := receiveStage2aLiveCapture(context.Background(), server, store, session, command,
			requestFrame, peer, func() error { return nil },
			func() ([]byte, error) { return []byte(`{"a_launch":"synthetic-only"}`), nil })
		client.Close()
		server.Close()
		if attempt == 0 {
			if err != nil || !bytes.Equal(got.artifact, artifact) || len(got.refs) != 1 || got.refs[0].SHA256 != blobHash {
				t.Fatalf("exact transfer rejected: %v", err)
			}
		} else if err == nil {
			t.Fatal("same challenge replaced A's immutable capture")
		}
	}
}
