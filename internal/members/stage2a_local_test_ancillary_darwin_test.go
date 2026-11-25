//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStage2aLocalTestAncillaryFinalRefusals(t *testing.T) {
	plan, _, _ := stage2aLocalTestOwnerPlanFixture(t)
	_, _, _, prewrite, now := stage2aLocalTestPrewriteFixture(t)
	completed := "sha256:" + strings.Repeat("c", 64)
	secret := bytes.Repeat([]byte{0x44}, 32)
	profile := plan.AncillaryProfile
	firstShape, err := marshalStage2aReservationJCS(profile.FirstHeaderShape)
	if err != nil {
		t.Fatal(err)
	}
	secondShape, err := marshalStage2aReservationJCS(profile.SecondHeaderShape)
	if err != nil {
		t.Fatal(err)
	}
	observation := func(sequence int, when time.Time, shape, headers string) stage2aLocalTestAncillaryObservation {
		return stage2aLocalTestAncillaryObservation{
			Sequence: sequence, ReceivedAt: when.Format(time.RFC3339Nano), HTTPStatus: 422,
			HeaderShapeSHA256: shape, ObservedHeadersSHA256: headers,
			NormalizedBodySHA256: profile.NormalizedBodySHA256,
			ProviderCountBefore:  1, ProviderCountAfter: 1,
		}
	}
	core := stage2aLocalTestAncillaryFinalWitness{
		Schema: "agent-bot-machine/stage2a-observed-body-local-test-ancillary-final-witness/v1",
		Kind:   "observed-body-local-test-ancillary-final-witness", SchemaVersion: 1,
		Selectors: prewrite.Selectors, CompletedRunSHA256: completed,
		Peer: prewrite.Peer, PeerSHA256: prewrite.PeerSHA256,
		First:     observation(1, now.Add(-time.Second), stage2aReservationSHA256(firstShape), profile.FirstHeadersSHA256),
		Second:    observation(2, now.Add(time.Second), stage2aReservationSHA256(secondShape), profile.SecondHeadersSHA256),
		IssuedAt:  now.Add(2 * time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano),
	}
	sign := func(c stage2aLocalTestAncillaryFinalWitness) stage2aLocalTestAncillarySubmission {
		raw, err := marshalStage2aReservationJCS(c)
		if err != nil {
			t.Fatal(err)
		}
		return stage2aLocalTestAncillarySubmission{Core: c,
			OriginMAC: hex.EncodeToString(stage2aLocalTestAncillaryMAC(secret, c.Selectors.ReservationDigest, raw))}
	}
	check := func(s stage2aLocalTestAncillarySubmission, peer Stage2aT03RelayPeer, at time.Time) error {
		_, err := verifyStage2aLocalTestAncillarySubmission(s, secret, prewrite.Selectors, completed,
			peer, profile, now, now.Add(30*time.Second), at)
		return err
	}
	if err := check(sign(core), core.Peer, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	beforeTarget := core
	beforeTarget.Second.ReceivedAt = now.Add(-500 * time.Millisecond).Format(time.RFC3339Nano)
	if err := check(sign(beforeTarget), core.Peer, now.Add(3*time.Second)); err != nil {
		t.Fatalf("A,B,T stock order refused: %v", err)
	}
	for name, edit := range map[string]func(*stage2aLocalTestAncillaryFinalWitness){
		"target first": func(c *stage2aLocalTestAncillaryFinalWitness) {
			c.First.ReceivedAt = now.Add(time.Second).Format(time.RFC3339Nano)
		},
		"missing second":   func(c *stage2aLocalTestAncillaryFinalWitness) { c.Second = stage2aLocalTestAncillaryObservation{} },
		"reordered second": func(c *stage2aLocalTestAncillaryFinalWitness) { c.Second.Sequence = 1 },
		"changed body": func(c *stage2aLocalTestAncillaryFinalWitness) {
			c.Second.NormalizedBodySHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		"Provider reached": func(c *stage2aLocalTestAncillaryFinalWitness) { c.First.ProviderCountAfter++ },
		"different completed run": func(c *stage2aLocalTestAncillaryFinalWitness) {
			c.CompletedRunSHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		"different peer": func(c *stage2aLocalTestAncillaryFinalWitness) { c.Peer.PID++ },
	} {
		t.Run(name, func(t *testing.T) {
			mutant := core
			edit(&mutant)
			if err := check(sign(mutant), core.Peer, now.Add(3*time.Second)); err == nil {
				t.Fatal("invalid ancillary final witness accepted")
			}
		})
	}
	if err := check(sign(core), core.Peer, now.Add(30*time.Second)); err == nil {
		t.Fatal("late ancillary final witness accepted")
	}
	peer := core.Peer
	peer.PID++
	if err := check(sign(core), peer, now.Add(3*time.Second)); err == nil {
		t.Fatal("different live stock peer accepted")
	}
	forged := sign(core)
	forged.OriginMAC = strings.Repeat("0", 64)
	if err := check(forged, core.Peer, now.Add(3*time.Second)); err == nil {
		t.Fatal("forged B ancillary MAC accepted")
	}
}

func TestStage2aLocalTestAncillaryDurableReplay(t *testing.T) {
	plan, _, _ := stage2aLocalTestOwnerPlanFixture(t)
	_, _, _, prewrite, now := stage2aLocalTestPrewriteFixture(t)
	profile := plan.AncillaryProfile
	header, err := marshalStage2aReservationJCS(profile.FirstHeaderShape)
	if err != nil {
		t.Fatal(err)
	}
	observation := func(sequence int, at time.Time) stage2aLocalTestAncillaryObservation {
		return stage2aLocalTestAncillaryObservation{
			Sequence: sequence, ReceivedAt: at.Format(time.RFC3339Nano), HTTPStatus: 422,
			HeaderShapeSHA256:     stage2aReservationSHA256(header),
			ObservedHeadersSHA256: profile.FirstHeadersSHA256,
			NormalizedBodySHA256:  profile.NormalizedBodySHA256,
			ProviderCountBefore:   1, ProviderCountAfter: 1,
		}
	}
	completed := "sha256:" + strings.Repeat("c", 64)
	core := stage2aLocalTestAncillaryFinalWitness{
		Schema: "agent-bot-machine/stage2a-observed-body-local-test-ancillary-final-witness/v1",
		Kind:   "observed-body-local-test-ancillary-final-witness", SchemaVersion: 1,
		Selectors: prewrite.Selectors, CompletedRunSHA256: completed,
		Peer: prewrite.Peer, PeerSHA256: prewrite.PeerSHA256,
		First: observation(1, now.Add(-time.Second)), Second: observation(2, now.Add(time.Second)),
		IssuedAt:  now.Add(2 * time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano),
	}
	secret := bytes.Repeat([]byte{0x44}, 32)
	raw, err := marshalStage2aReservationJCS(core)
	if err != nil {
		t.Fatal(err)
	}
	sub := stage2aLocalTestAncillarySubmission{Core: core,
		OriginMAC: hex.EncodeToString(stage2aLocalTestAncillaryMAC(secret, core.Selectors.ReservationDigest, raw))}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	sign := func(preimage []byte) ([]byte, error) { return ed25519.Sign(key, preimage), nil }
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := os.Chmod(dir.Name(), 0700); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	store := stage2aAdminClaimStore{uid: uint32(os.Getuid()), gid: uint32(os.Getgid()),
		device: stat.Dev, inode: stat.Ino, birthtime: stat.Btim}
	accept := func() ([]byte, error) {
		return commitAndSignStage2aLocalTestAncillary(store, dir, sub, secret,
			prewrite.Selectors, completed, core.Peer, profile, now, now.Add(30*time.Second),
			now.Add(3*time.Second), key.Public().(ed25519.PublicKey), sign)
	}
	envelope, err := accept()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := verifyStage2aLocalTestEnvelope(envelope, stage2aLocalTestAncillaryPurpose,
		key.Public().(ed25519.PublicKey)); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("durable ancillary witness signature differs from accepted core")
	}
	if _, err := accept(); err == nil {
		t.Fatal("replayed ancillary witness accepted after durable claim")
	}
}
