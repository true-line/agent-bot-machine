package members

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

type t02Fixture struct {
	command     []byte
	request     []byte
	response    []byte
	outage      []byte
	hq          ed25519.PublicKey
	machine     ed25519.PublicKey
	hqPriv      ed25519.PrivateKey
	machinePriv ed25519.PrivateKey
	device      *ecdsa.PrivateKey
	epoch       string
	now         time.Time
}

func newT02Fixture(t *testing.T, event string, phase stage2aDriverRunPhase) t02Fixture {
	t.Helper()
	hq, hqPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine, machinePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := t02Fixture{hq: hq, machine: machine, hqPriv: hqPriv, machinePriv: machinePriv,
		epoch: strings.Repeat("a", 64), now: time.Unix(1_795_440_000, 0)}
	command := stage2aDriverCommand{
		Schema: stage2aDriverCaseSchema, Kind: "capture", SessionID: strings.Repeat("b", 32),
		InstallationID: "inst_0000000000000001", StartID: "st_" + strings.Repeat("c", 24),
		ReservationSHA256: "sha256:" + strings.Repeat("d", 64), TestPlanSHA256: "sha256:" + strings.Repeat("e", 64),
		Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Sequence: 2,
		Profile: "managed-protected", Phase: phase, Gate: "T02", Event: event,
	}
	f.command, err = marshalStage2aReservationJCS(command)
	if err != nil {
		t.Fatal(err)
	}
	caseHash := sha256.Sum256(append([]byte("soul-conformance/T02/paired-operation/v1\x00"), f.command...))
	nonce := base64.RawURLEncoding.EncodeToString(caseHash[:16])
	request := map[string]any{
		"verb": "hq-device", "option": "enrollment-proof", "hq_epoch": f.epoch,
		"timestamp": f.now.Unix(), "nonce": nonce, "public_key": base64.StdEncoding.EncodeToString(hq),
	}
	reqSig := strings.Join([]string{"hq-device", "", "enrollment-proof", "", "", "", "", "",
		stage2aT02Int(f.now.Unix()), nonce, "hq_epoch", f.epoch}, "\n")
	request["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(hqPriv, []byte(reqSig)))
	f.request, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	switch event {
	case "machine-outage-refused":
		hash := sha256.Sum256(f.request)
		preimage := strings.Join([]string{stage2aT02OutagePurpose, hex.EncodeToString(hash[:]), "machine-unreachable"}, "\n")
		f.outage = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(hqPriv, []byte(preimage))))
	case "pairing-revoked-refused":
		reply := map[string]any{"ok": false, "diagnostic": "MM_DAEMON_PEER_REFUSED", "message": "pairing revoked",
			"timestamp": f.now.Unix(), "nonce": "reply-nonce", "request_nonce": nonce}
		preimage := strings.Join([]string{"false", "MM_DAEMON_PEER_REFUSED", "pairing revoked", "", "",
			stage2aT02Int(f.now.Unix()), "reply-nonce", nonce}, "\n")
		reply["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(machinePriv, []byte(preimage)))
		f.response, err = json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
	case "paired-operation":
		device, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		f.device = device
		coordinate := func(v *big.Int) string {
			return base64.RawURLEncoding.EncodeToString(v.FillBytes(make([]byte, 32)))
		}
		jwk := map[string]string{"kty": "EC", "crv": "P-256", "x": coordinate(device.X), "y": coordinate(device.Y)}
		thumbRaw := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + jwk["x"] + `","y":"` + jwk["y"] + `"}`))
		header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "ab-enroll+jwt", "jwk": jwk})
		claims, _ := json.Marshal(map[string]any{"aud": stage2aT02Audience, "iat": f.now.Unix(), "jti": "fresh-proof-123456"})
		input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
		hash := sha256.Sum256([]byte(input))
		r, s, signErr := ecdsa.Sign(rand.Reader, device, hash[:])
		if signErr != nil {
			t.Fatal(signErr)
		}
		sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		proof := input + "." + base64.RawURLEncoding.EncodeToString(sig)
		body := map[string]any{"hq_epoch": f.epoch, "jwk": jwk,
			"thumbprint": base64.RawURLEncoding.EncodeToString(thumbRaw[:]),
			"generation": 1, "key_storage": "hardware", "proof": proof}
		bodyRaw, _ := json.Marshal(body)
		reply := map[string]any{"ok": true, "state": "proved", "body": body,
			"timestamp": f.now.Unix(), "nonce": "reply-nonce", "request_nonce": nonce}
		preimage := strings.Join([]string{"true", "", "", "proved", string(bodyRaw),
			stage2aT02Int(f.now.Unix()), "reply-nonce", nonce}, "\n")
		reply["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(machinePriv, []byte(preimage)))
		f.response, err = json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f t02Fixture) verify() (stage2aT02WireResult, error) {
	return verifyStage2aT02Wire(f.command, f.request, f.response, f.outage, f.hq, f.machine, f.epoch, f.now)
}

func (f t02Fixture) capture() stage2aT02WireCapture {
	return stage2aT02WireCapture{commandRaw: f.command, requestRaw: f.request, responseRaw: f.response,
		outageSignature: f.outage, hqKey: f.hq, machineKey: f.machine, epoch: f.epoch, observedAt: f.now}
}

func restartT02Fixture(t *testing.T, before t02Fixture) t02Fixture {
	t.Helper()
	after := before
	after.now = before.now.Add(time.Second)
	var command stage2aDriverCommand
	if json.Unmarshal(before.command, &command) != nil {
		t.Fatal("bad test command")
	}
	command.Phase = stage2aDriverRestart
	command.SessionID = strings.Repeat("f", 32)
	command.StartID = "st_" + strings.Repeat("1", 24)
	command.ReservationSHA256 = "sha256:" + strings.Repeat("2", 64)
	command.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	after.command, _ = marshalStage2aReservationJCS(command)
	caseHash := sha256.Sum256(append([]byte("soul-conformance/T02/paired-operation/v1\x00"), after.command...))
	nonce := base64.RawURLEncoding.EncodeToString(caseHash[:16])
	var request map[string]any
	if json.Unmarshal(before.request, &request) != nil {
		t.Fatal("bad test request")
	}
	request["nonce"], request["timestamp"] = nonce, after.now.Unix()
	preimage := strings.Join([]string{"hq-device", "", "enrollment-proof", "", "", "", "", "",
		stage2aT02Int(after.now.Unix()), nonce, "hq_epoch", after.epoch}, "\n")
	request["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(after.hqPriv, []byte(preimage)))
	after.request, _ = json.Marshal(request)
	var response map[string]any
	if json.Unmarshal(before.response, &response) != nil {
		t.Fatal("bad test response")
	}
	body := response["body"].(map[string]any)
	proofParts := strings.Split(body["proof"].(string), ".")
	var claims map[string]any
	claimsBytes, _ := base64.RawURLEncoding.DecodeString(proofParts[1])
	if json.Unmarshal(claimsBytes, &claims) != nil {
		t.Fatal("bad test claims")
	}
	claims["jti"] = "fresh-restart-123456"
	claims["iat"] = after.now.Unix()
	claimsBytes, _ = json.Marshal(claims)
	input := proofParts[0] + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	hash := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, after.device, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	body["proof"] = input + "." + base64.RawURLEncoding.EncodeToString(signature)
	bodyRaw, _ := json.Marshal(body)
	response["body"] = body
	response["request_nonce"], response["timestamp"] = nonce, after.now.Unix()
	preimage = strings.Join([]string{"true", "", "", "proved", string(bodyRaw),
		stage2aT02Int(after.now.Unix()), "reply-nonce", nonce}, "\n")
	response["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(after.machinePriv, []byte(preimage)))
	after.response, _ = json.Marshal(response)
	return after
}

func TestStage2aT02WireRequiresExactPairedProof(t *testing.T) {
	f := newT02Fixture(t, "paired-operation", stage2aDriverLiveStart)
	result, err := f.verify()
	if err != nil || result.generation != 1 || result.jti != "fresh-proof-123456" || result.thumbprint == "" {
		t.Fatalf("proof result = %+v, %v", result, err)
	}
	for name, change := range map[string]func(*t02Fixture){
		"different A command": func(f *t02Fixture) { f.command = append([]byte(nil), f.command...); f.command[20] ^= 1 },
		"other HQ pin":        func(f *t02Fixture) { f.hq = append(ed25519.PublicKey(nil), f.machine...) },
		"late observation":    func(f *t02Fixture) { f.now = f.now.Add(3 * time.Minute) },
		"altered response": func(f *t02Fixture) {
			f.response = append([]byte(nil), f.response...)
			f.response[len(f.response)-4] ^= 1
		},
		"spurious outage": func(f *t02Fixture) { f.outage = []byte("signature") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := f
			change(&changed)
			if _, err := changed.verify(); err == nil {
				t.Fatal("accepted altered proof")
			}
		})
	}
}

func TestStage2aT02WireDistinguishesRefusalFromOutage(t *testing.T) {
	for _, run := range []struct {
		event   string
		phase   stage2aDriverRunPhase
		refusal string
	}{
		{"machine-outage-refused", "machine-outage", "machine-unreachable"},
		{"pairing-revoked-refused", "pairing-revoked", "MM_DAEMON_PEER_REFUSED"},
	} {
		f := newT02Fixture(t, run.event, run.phase)
		result, err := f.verify()
		if err != nil || result.refusal != run.refusal {
			t.Fatalf("%s: %+v, %v", run.event, result, err)
		}
		f.response, f.outage = f.outage, f.response
		if _, err := f.verify(); err == nil {
			t.Fatalf("%s accepted wrong refusal channel", run.event)
		}
	}
}

func TestStage2aT02RestartRequiresNewReservationSessionAndProof(t *testing.T) {
	before := newT02Fixture(t, "paired-operation", stage2aDriverLiveStart)
	after := restartT02Fixture(t, before)
	if err := verifyStage2aT02Restart(before.capture(), after.capture()); err != nil {
		t.Fatal(err)
	}
	if err := verifyStage2aT02Restart(before.capture(), before.capture()); err == nil {
		t.Fatal("accepted same session as restart")
	}
	stale := after.capture()
	stale.responseRaw = before.response
	if err := verifyStage2aT02Restart(before.capture(), stale); err == nil {
		t.Fatal("accepted stale proof")
	}
}
