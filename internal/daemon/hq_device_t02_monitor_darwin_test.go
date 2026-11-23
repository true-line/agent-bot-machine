package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/members"
)

func TestStage2aT02KeydMonitorSpendsArmedNonceOnce(t *testing.T) {
	var monitor stage2aT02KeydMonitor
	now := time.Now()
	nonce := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	epoch := strings.Repeat("a", 64)
	command := "sha256:" + strings.Repeat("b", 64)
	d := deviceDelegation{Option: "enrollment-proof", Nonce: nonce, Epoch: epoch, UID: 309}
	if armed, err := monitor.begin(d, now); err != nil || armed {
		t.Fatalf("unarmed request: %v %v", armed, err)
	}
	if err := monitor.arm(nonce, command, epoch, d.UID, now); err != nil {
		t.Fatal(err)
	}
	if err := monitor.arm(nonce, command, epoch, d.UID, now); err == nil {
		t.Fatal("accepted duplicate arm")
	}
	wrong := d
	wrong.UID++
	if armed, err := monitor.begin(wrong, now); err == nil || !armed {
		t.Fatal("accepted wrong paired UID")
	}
	if armed, err := monitor.begin(d, now); err != nil || !armed {
		t.Fatalf("valid begin: %v %v", armed, err)
	}
	if armed, err := monitor.begin(d, now); err == nil || !armed {
		t.Fatal("accepted second provider call")
	}
	if _, err := monitor.take(nonce, command, now); err == nil {
		t.Fatal("accepted incomplete keyd observation")
	}
	w := stage2aT02KeydObservation{Schema: stage2aT02KeydObservationSchema, RequestNonce: nonce,
		HQEpoch: epoch, HQUid: d.UID, MachinePID: 123, MachineUID: 501, MachineGID: 20,
		HQPublicKeyBase64:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
		MachinePublicKeyBase64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", 32))),
		KeydProcess:            members.Stage2aT02ProcessWitness{PID: 124, ParentPID: 123, UID: 501, GID: 20},
		OutputSHA256:           "sha256:" + strings.Repeat("c", 64)}
	if err := monitor.finish(w, now); err != nil {
		t.Fatal(err)
	}
	if err := monitor.finish(w, now); err == nil {
		t.Fatal("accepted repeated completion")
	}
	if _, err := monitor.take(nonce, "sha256:"+strings.Repeat("d", 64), now); err == nil {
		t.Fatal("accepted wrong command")
	}
	got, err := monitor.take(nonce, command, now)
	if err != nil || got.KeydProcess.PID != 124 {
		t.Fatalf("missing keyd observation: %+v %v", got, err)
	}
	if _, err := monitor.take(nonce, command, now); err == nil {
		t.Fatal("accepted replay")
	}
}

func TestStage2aT02KeydMonitorExpiresAndCancels(t *testing.T) {
	var monitor stage2aT02KeydMonitor
	now := time.Now()
	nonce := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	epoch := strings.Repeat("a", 64)
	command := "sha256:" + strings.Repeat("b", 64)
	if err := monitor.arm(nonce, command, epoch, 309, now); err != nil {
		t.Fatal(err)
	}
	if armed, err := monitor.begin(deviceDelegation{Option: "enrollment-proof", Nonce: nonce, Epoch: epoch, UID: 309}, now.Add(31*time.Second)); err == nil || !armed {
		t.Fatal("accepted expired arm")
	}
	if err := monitor.cancel(nonce, command); err != nil {
		t.Fatal(err)
	}
	if err := monitor.cancel(nonce, command); err == nil {
		t.Fatal("accepted repeated cancel")
	}
}

func TestStage2aT02MonitorArmsOnlyExactPairedCommand(t *testing.T) {
	command := map[string]any{
		"schema": "agent-bot-machine/qualification-owner-driver/v1", "kind": "capture",
		"session_id": strings.Repeat("a", 32), "installation_id": "inst_0000000000000001",
		"start_id":            "st_" + strings.Repeat("b", 24),
		"reservation_sha256":  "sha256:" + strings.Repeat("c", 64),
		"test_plan_sha256":    "sha256:" + strings.Repeat("d", 64),
		"challenge_base64url": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"sequence":            1, "profile": "managed-protected", "phase": "live-start", "gate": "T02", "event": "paired-operation",
	}
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var monitor stage2aT02KeydMonitor
	nonce, hash, err := monitor.armCommand(raw, strings.Repeat("e", 64), 309, time.Now())
	if err != nil || len(nonce) != 22 || hash != stage2aT02Digest(raw) {
		t.Fatalf("arm exact command: %q %q %v", nonce, hash, err)
	}
	if err := monitor.cancel(nonce, hash); err != nil {
		t.Fatal(err)
	}
	command["event"] = "direct-route-refused"
	raw, _ = json.Marshal(command)
	if _, _, err := monitor.armCommand(raw, strings.Repeat("e", 64), 309, time.Now()); err == nil {
		t.Fatal("armed non-T02 case")
	}
}

func TestStage2aT02RefusalArmCannotCallKeyd(t *testing.T) {
	command := map[string]any{
		"schema": "agent-bot-machine/qualification-owner-driver/v1", "kind": "capture",
		"session_id": strings.Repeat("a", 32), "installation_id": "inst_0000000000000001",
		"start_id":            "st_" + strings.Repeat("b", 24),
		"reservation_sha256":  "sha256:" + strings.Repeat("c", 64),
		"test_plan_sha256":    "sha256:" + strings.Repeat("d", 64),
		"challenge_base64url": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"sequence":            2, "profile": "managed-protected", "phase": "pairing-revoked", "gate": "T02", "event": "pairing-revoked-refused",
	}
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var monitor stage2aT02KeydMonitor
	now := time.Now()
	epoch := strings.Repeat("e", 64)
	nonce, hash, err := monitor.armRefusalCommand(raw, epoch, 309, now)
	if err != nil {
		t.Fatal(err)
	}
	d := deviceDelegation{Option: "enrollment-proof", Nonce: nonce, Epoch: epoch, UID: 309}
	if armed, err := monitor.begin(d, now); !armed || err == nil {
		t.Fatal("refusal arm permitted a keyd provider call")
	}
	if _, err := monitor.provider(context.Background(), "/missing-keyd-home", d); err == nil {
		t.Fatal("refusal arm let provider start keyd")
	}
	if _, err := monitor.take(nonce, hash, now); err == nil {
		t.Fatal("refusal arm produced a positive observation")
	}
	got, err := monitor.takeNoCall(nonce, hash, now)
	if err != nil || got.RequestNonce != nonce || got.KeydStarts != 0 || got.MachinePID <= 1 {
		t.Fatalf("no-call observation: %+v %v", got, err)
	}
	if _, err := monitor.takeNoCall(nonce, hash, now); err == nil {
		t.Fatal("accepted repeated no-call observation")
	}
	command["event"] = "paired-operation"
	raw, _ = json.Marshal(command)
	if _, _, err := monitor.armRefusalCommand(raw, epoch, 309, now); err == nil {
		t.Fatal("refusal monitor accepted positive purpose")
	}
}
