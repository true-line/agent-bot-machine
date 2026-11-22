package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func stage2aReservationFixture() (stage2aReservationRequest, stage2aReservationInputs, ed25519.PrivateKey, time.Time) {
	issued := time.Date(2026, 11, 22, 14, 15, 16, 0, time.UTC)
	seed := bytes.Repeat([]byte{0xab}, ed25519.SeedSize)
	signer := ed25519.NewKeyFromSeed(seed)
	runner, bridge := runnerFixture()[0], bridgeFixture()[0]
	const planID = "plan-20261122T141516Z-abcd"
	plan := []byte(`{"plan":"synthetic only"}`)
	planDigest := strings.TrimPrefix(stage2aReservationSHA256(plan), "sha256:")
	start := SoulRunRequest{PlanDigest: planDigest, InstallationID: runner.InstallationID,
		StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("a", 64)}
	req := stage2aReservationRequest{start: start, launchID: "ln_0123456789abcdef01234567"}
	in := stage2aReservationInputs{
		hostID: "synthetic-host", planID: planID, installedPlan: plan,
		installedReceipt: []byte("{\"installed\":true}\n"), runner: runner, bridge: bridge,
		hqUID: 309, machineUID: 501, enrolledAdminKey: signer.Public().(ed25519.PublicKey), expires: issued.Add(20 * time.Second),
		approvedArtifact:   stage2aSoulArtifactSHA256(strings.Repeat("b", 64)),
		installedArtifact:  stage2aSoulArtifactSHA256(strings.Repeat("b", 64)),
		admissionChallenge: [32]byte{0xde, 0xad, 0xbe, 0xef, 0xab, 0xcd},
		binding: stage2aMeasurementBinding{
			Contract: "machine/v1", Kind: "stage2a-measurement-binding", SchemaVersion: 1,
			InstallationID: start.InstallationID, SoulID: runner.SoulID, StartID: start.StartID,
			LaunchID: req.launchID, HostID: "synthetic-host", HQEpoch: start.HQEpoch, PlanID: planID,
			InstalledPlanDigest: planDigest, PackageSHA256: runner.PackageSHA256,
			SoulArtifactSHA256: stage2aSoulArtifactSHA256(strings.Repeat("b", 64)),
			ProfileInForce:     "managed-protected", ClaimedDefinitionDigest: "sha256:" + strings.Repeat("b", 64),
			DefinitionMeasurement: "sha256:" + strings.Repeat("c", 64), LaunchInputMeasurement: "sha256:" + strings.Repeat("d", 64),
			Snapshots: stage2aSnapshots{
				Definition:   stage2aSnapshotIdentity{RootPath: "/private/stage2a/definition", Device: "1", Inode: "12345", Generation: "4", BirthtimeNS: "1795356916000000000", Mode: "0555"},
				LaunchInputs: stage2aSnapshotIdentity{RootPath: "/private/stage2a/inputs", Device: "1", Inode: "12346", Generation: "4", BirthtimeNS: "1795356916000000000", Mode: "0555"},
			},
		},
	}
	return req, in, signer, issued
}

func stage2aReservationFixtureAuthority(req stage2aReservationRequest, in stage2aReservationInputs, key ed25519.PrivateKey) stage2aReservationAuthority {
	return stage2aReservationAuthority{
		load: func(got stage2aReservationRequest) (stage2aReservationInputs, error) {
			if got != req {
				return stage2aReservationInputs{}, errStage2aReservationAuthority
			}
			return in, nil
		},
		sign: func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil },
	}
}

func stage2aReservationTestDir(t *testing.T) (*os.File, uint32) {
	t.Helper()
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	if err := dir.Chmod(0700); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	return dir, st.Gid
}

func TestStage2aReservationStrictPreHelloEnvelope(t *testing.T) {
	req, in, key, at := stage2aReservationFixture()
	dir, gid := stage2aReservationTestDir(t)
	auth := stage2aReservationFixtureAuthority(req, in, key)
	got, err := reserveStage2aStartIn(dir, uint32(os.Geteuid()), gid, req, auth, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	claim := filepath.Join(dir.Name(), soulStartClaimName(req.start.InstallationID, req.start.StartID))
	stored, err := os.ReadFile(claim)
	if err != nil || !bytes.Equal(stored, got.envelope) || got.sha256 != stage2aReservationSHA256(stored) {
		t.Fatalf("returned envelope differs from durable record: %v", err)
	}
	f, err := os.Open(claim)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := checkStage2aReservationFile(int(f.Fd()), uint32(os.Geteuid()), gid, unix.S_IFREG|0600); err != nil {
		t.Fatal(err)
	}
	var envelope stage2aSignedReservation
	if err := json.Unmarshal(stored, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != 1 || envelope.Purpose != "agent-bot/stage2a-reservation/v1" ||
		envelope.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(in.enrolledAdminKey) {
		t.Fatal("wrong envelope purpose, schema version or issuer")
	}
	payloadBytes, err := base64.RawURLEncoding.Strict().DecodeString(envelope.PayloadBase64URL)
	if err != nil || envelope.PayloadSHA256 != stage2aReservationSHA256(payloadBytes) {
		t.Fatalf("invalid base64url payload or payload digest: %v", err)
	}
	var payload stage2aReservationPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	canonical, err := marshalStage2aReservationJCS(payload)
	if err != nil || !bytes.Equal(payloadBytes, canonical) {
		t.Fatalf("noncanonical payload: %v", err)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64URL)
	preimage := append([]byte("agent-bot/stage2a-reservation/v1\x00"), payloadBytes...)
	if err != nil || !ed25519.Verify(in.enrolledAdminKey, preimage, sig) || ed25519.Verify(in.enrolledAdminKey, payloadBytes, sig) {
		t.Fatalf("signature must use the reservation domain: %v", err)
	}
	endpoints, err := DeriveSoulBridgeEndpoints(in.runner, in.bridge, in.hqUID, req.start.StartID)
	if err != nil {
		t.Fatal(err)
	}
	if payload.HostID != in.hostID || payload.AdmissionChallengeSHA256 != stage2aReservationSHA256(in.admissionChallenge[:]) ||
		payload.InstalledPlanReceiptSHA256 != stage2aReservationSHA256(in.installedReceipt) ||
		payload.MeasurementBinding != in.binding || payload.ExpiresAt != in.expires.Format(time.RFC3339Nano) ||
		payload.Assignment.SoulArtifactSHA256 != in.installedArtifact ||
		payload.Assignment.SoulArtifactSHA256 != payload.MeasurementBinding.SoulArtifactSHA256 ||
		payload.Assignment.PackageSHA256 == string(payload.Assignment.SoulArtifactSHA256) ||
		!reflect.DeepEqual(payload.MemberEndpoint, endpoints.MemberLaunchAssignment()) ||
		payload.MemberEndpoint.MemberSocket != payload.Assignment.Member.SocketPath ||
		!reflect.DeepEqual(payload.MemberEndpoint.MemberEndpoint.PeerUIDs, []int{in.runner.UID, in.bridge.UID}) ||
		payload.MemberEndpoint.MemberEndpoint.DirMode != 02750 || payload.MemberEndpoint.MemberEndpoint.SocketMode != 0660 {
		t.Fatal("reservation did not bind exact installed authority and member endpoint")
	}
	for _, key := range []string{`"runtime_id"`, `"peer_pid"`, `"peer_uid"`, `"socket_inode"`, `"broker_binding_b"`, `"admission_challenge"`} {
		if bytes.Contains(payloadBytes, []byte(key)) {
			t.Fatalf("unexpected field before Hello: %s", key)
		}
	}
	// Independent RFC 8785 fixture: ASCII fixture object keys sorted recursively,
	// then Node's JSON.stringify, crypto.sign and crypto.createHash.
	const want = "sha256:5447b4e31c9e7e7c1cbb434c2fd1f45de0d507f66f25076f3ab2da3bfb94f882"
	if got.sha256 != want {
		t.Fatalf("exact signed envelope digest = %s, want %s", got.sha256, want)
	}
}

func TestStage2aReservationRefusesMissingOrMismatchedAuthority(t *testing.T) {
	req, in, key, at := stage2aReservationFixture()
	if got, err := reserveStage2aStart(req, stage2aReservationAuthority{}); !errors.Is(err, errStage2aReservationAuthority) || len(got.envelope) != 0 {
		t.Fatal("missing production authority issued a reservation")
	}
	mutations := map[string]func(*stage2aReservationInputs){
		"missing installed receipt": func(in *stage2aReservationInputs) { in.installedReceipt = nil },
		"wrong installed plan":      func(in *stage2aReservationInputs) { in.installedPlan = []byte(`{"changed":true}`) },
		"missing owner mapping":     func(in *stage2aReservationInputs) { in.approvedArtifact = "" },
		"missing frozen artifact":   func(in *stage2aReservationInputs) { in.installedArtifact = "" },
		"different frozen artifact": func(in *stage2aReservationInputs) {
			in.installedArtifact = stage2aSoulArtifactSHA256(strings.Repeat("0", 64))
		},
		"missing artifact binding": func(in *stage2aReservationInputs) { in.binding.SoulArtifactSHA256 = "" },
		"legacy package in frozen binding": func(in *stage2aReservationInputs) {
			in.binding.SoulArtifactSHA256 = stage2aSoulArtifactSHA256(in.binding.PackageSHA256)
		},
		"wrong legacy package":   func(in *stage2aReservationInputs) { in.binding.PackageSHA256 = string(in.installedArtifact) },
		"wrong installed host":   func(in *stage2aReservationInputs) { in.binding.HostID = "other-host" },
		"wrong HQ epoch":         func(in *stage2aReservationInputs) { in.binding.HQEpoch = strings.Repeat("0", 64) },
		"wrong launch":           func(in *stage2aReservationInputs) { in.binding.LaunchID = "ln_" + strings.Repeat("f", 24) },
		"bare definition digest": func(in *stage2aReservationInputs) { in.binding.DefinitionMeasurement = strings.Repeat("c", 64) },
		"snapshot inode alias": func(in *stage2aReservationInputs) {
			in.binding.Snapshots.LaunchInputs.Inode = in.binding.Snapshots.Definition.Inode
		},
		"nonroot measured snapshot": func(in *stage2aReservationInputs) { in.binding.Snapshots.Definition.OwnerUID = uint32(in.runner.UID) },
		"missing challenge":         func(in *stage2aReservationInputs) { in.admissionChallenge = [32]byte{} },
	}
	dir, gid := stage2aReservationTestDir(t)
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			invalid := in
			mutate(&invalid)
			auth := stage2aReservationFixtureAuthority(req, invalid, key)
			auth.sign = func([]byte) ([]byte, error) { t.Fatal("invalid input reached signer"); return nil, nil }
			got, err := reserveStage2aStartIn(dir, uint32(os.Geteuid()), gid, req, auth, func() time.Time { return at })
			if !errors.Is(err, errStage2aReservationAuthority) || len(got.envelope) > 0 {
				t.Fatalf("invalid authority could produce bytes: %v", err)
			}
		})
	}
	wrongKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	auth := stage2aReservationFixtureAuthority(req, in, wrongKey)
	got, err := reserveStage2aStartIn(dir, uint32(os.Geteuid()), gid, req, auth, func() time.Time { return at })
	if !errors.Is(err, errStage2aReservationAuthority) || len(got.envelope) > 0 {
		t.Fatalf("different administrator key could sign: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir.Name(), soulStartClaimName(req.start.InstallationID, req.start.StartID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unverified input produced a start claim: %v", err)
	}
}

func TestStage2aReservationSpendsBeforeReturnAcrossConcurrentCalls(t *testing.T) {
	req, in, key, at := stage2aReservationFixture()
	dir, gid := stage2aReservationTestDir(t)
	auth := stage2aReservationFixtureAuthority(req, in, key)
	var calls atomic.Int32
	sign := auth.sign
	auth.sign = func(raw []byte) ([]byte, error) { calls.Add(1); return sign(raw) }
	const attempts = 12
	results := make(chan error, attempts)
	var pending sync.WaitGroup
	for range attempts {
		pending.Go(func() {
			_, err := reserveStage2aStartIn(dir, uint32(os.Geteuid()), gid, req, auth, func() time.Time { return at })
			results <- err
		})
	}
	pending.Wait()
	close(results)
	var succeeded int
	for err := range results {
		if err == nil {
			succeeded++
		} else if !errors.Is(err, errStage2aReservationSpent) {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || calls.Load() != 1 {
		t.Fatalf("successful responses = %d, signer calls = %d", succeeded, calls.Load())
	}
	rebound := req
	rebound.start.HQEpoch = strings.Repeat("0", 64)
	rebound.launchID = "ln_" + strings.Repeat("f", 24)
	if _, err := reserveStage2aStartIn(dir, uint32(os.Geteuid()), gid, rebound, auth, func() time.Time { return at }); !errors.Is(err, errStage2aReservationSpent) {
		t.Fatalf("changed launch/epoch reopened the one-use start: %v", err)
	}
}

func TestStage2aReservationLostResponseLeavesStartSpent(t *testing.T) {
	req, in, key, at := stage2aReservationFixture()
	dir, gid := stage2aReservationTestDir(t)
	auth := stage2aReservationFixtureAuthority(req, in, key)
	var calls int
	clock := func() time.Time {
		calls++
		if calls > 1 {
			return in.expires
		}
		return at
	}
	got, err := reserveStage2aStartIn(dir, uint32(os.Geteuid()), gid, req, auth, clock)
	if !errors.Is(err, errStage2aReservationExpired) || len(got.envelope) > 0 || got.sha256 != "" {
		t.Fatalf("reservation should stay private when it expires before delivery: %v", err)
	}
	// Open the directory separately, like a replacement producer after the
	// original exited without delivering its response. No in-memory flag helps.
	reopened, err := os.Open(dir.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reserveStage2aStartIn(reopened, uint32(os.Geteuid()), gid, req, auth, func() time.Time { return at }); !errors.Is(err, errStage2aReservationSpent) {
		t.Fatalf("restart reopened a start with no returned reservation: %v", err)
	}
}

func TestStage2aReservationRefusesUntrustedStorageAndOccupiedClaims(t *testing.T) {
	req, in, key, at := stage2aReservationFixture()
	dir, gid := stage2aReservationTestDir(t)
	auth := stage2aReservationFixtureAuthority(req, in, key)
	reserve := func() error {
		_, err := reserveStage2aStartIn(dir, uint32(os.Geteuid()), gid, req, auth, func() time.Time { return at })
		return err
	}
	if err := dir.Chmod(0750); err != nil {
		t.Fatal(err)
	}
	if err := reserve(); err == nil {
		t.Fatal("shared claims directory was trusted")
	}
	if err := dir.Chmod(0700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir.Name(), ".stage2a-"+soulEndpointInstallationSlot(req.start.InstallationID)+".lock")
	if err := os.Symlink("not-a-lock", lock); err != nil {
		t.Fatal(err)
	}
	if err := reserve(); !errors.Is(err, unix.ELOOP) {
		t.Fatalf("did not refuse a lock symlink: %v", err)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	claim := filepath.Join(dir.Name(), soulStartClaimName(req.start.InstallationID, req.start.StartID))
	legacy := []byte("existing or interrupted started claim\n")
	if err := os.WriteFile(claim, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	if err := reserve(); !errors.Is(err, errStage2aReservationSpent) {
		t.Fatalf("did not refuse an existing claim: %v", err)
	}
	got, err := os.ReadFile(claim)
	if err != nil || !bytes.Equal(got, legacy) {
		t.Fatalf("existing claim was overwritten: %v", err)
	}
}
