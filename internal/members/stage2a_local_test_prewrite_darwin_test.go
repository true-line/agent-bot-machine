//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func stage2aLocalTestSignedForTest(t *testing.T, key ed25519.PrivateKey, purpose string, payload any) []byte {
	t.Helper()
	raw, err := marshalStage2aReservationJCS(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := marshalStage2aReservationJCS(stage2aSignedReservation{
		SchemaVersion: 1, Purpose: purpose,
		IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		PayloadSHA256:            stage2aReservationSHA256(raw),
		PayloadBase64URL:         base64.RawURLEncoding.EncodeToString(raw),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key,
			append([]byte(purpose+"\x00"), raw...))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func stage2aLocalTestPrewriteFixture(t *testing.T) (ed25519.PrivateKey, []byte, []byte,
	stage2aLocalTestPrewriteCore, time.Time) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	digest := "sha256:" + strings.Repeat("a", 64)
	selectors := stage2aLocalTestSelectors{
		AssignmentEnvelopeSHA256: digest, AuthorityEnvelopeSHA256: digest,
		InstallationID: "inst.fixture", LaunchID: "ln_" + strings.Repeat("2", 24),
		MemberSelectorsSHA256: digest, PlanDigest: strings.Repeat("3", 64),
		PlanID: "plan.fixture", ReservationDigest: digest, StartID: "st_" + strings.Repeat("1", 24),
	}
	now := time.Date(2026, 11, 24, 12, 0, 11, 0, time.UTC)
	peer := Stage2aT03RelayPeer{UID: 331, PID: 4101, PIDVersion: 1,
		StartSeconds: 1795500002, ParentPID: 4001, ParentUID: 331, ParentStartSeconds: 1795500001}
	peerRaw, err := stage2aT03PeerCanonical(peer)
	if err != nil {
		t.Fatal(err)
	}
	ingress := stage2aLocalTestIngressCore{
		Schema: "stage2a-observed-body-local-test-ingress/v1", Kind: "observed-body-local-test-ingress",
		Selectors: selectors, AttemptID: "attempt.fixture", BindReceiptSHA256: digest,
		BodyProfile: "stage2a-stock-observed-local-test/v1", DigestKind: "observed-stock-body/v1",
		ObservedBodySHA256: digest, ObservedBriefSHA256: digest,
		ObservedHeadersSHA256: digest, OwnerPromptSHA256: digest,
		Peer: peer, PeerSHA256: stage2aReservationSHA256(peerRaw),
		StaticProjectionSHA256: digest, TargetReceivedAt: now.Add(-2 * time.Second).Format(time.RFC3339Nano),
	}
	ingressRaw, err := marshalStage2aReservationJCS(ingress)
	if err != nil {
		t.Fatal(err)
	}
	authorization := stage2aLocalTestIngressAuthorization{
		Schema: "agent-bot-machine/stage2a-observed-body-local-test-ingress-authorization/v1",
		Kind:   "observed-body-local-test-ingress-authorization", Selectors: selectors,
		IngressCoreSHA256: stage2aReservationSHA256(ingressRaw), ProviderClaimSHA256: digest,
		IssuedAt:  now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339Nano),
	}
	authEnvelope := stage2aLocalTestSignedForTest(t, key, stage2aLocalTestIngressPurpose, authorization)
	core := stage2aLocalTestPrewriteCore{
		Schema: "stage2a-observed-body-local-test-prewrite/v1", Selectors: selectors,
		BindReceiptSHA256: digest, AuthorizationEnvelopeSHA256: stage2aReservationSHA256(authEnvelope),
		IngressCoreSHA256: stage2aReservationSHA256(ingressRaw), ObservedBodySHA256: digest, ObservedHeadersSHA256: digest,
		StaticProjectionSHA256: digest, OwnerPromptSHA256: digest, Peer: peer,
		PeerSHA256: stage2aReservationSHA256(peerRaw), ResponseWireSHA256: digest,
		ResponseWireBytes: 897, HTTPStatus: 200,
	}
	return key, ingressRaw, authEnvelope, core, now
}

func TestStage2aLocalTestPrewriteProofWriteGate(t *testing.T) {
	key, ingress, auth, core, now := stage2aLocalTestPrewriteFixture(t)
	epoch := strings.Repeat("2", 64)
	receipt := strings.Repeat("f", 64)
	payload, err := prepareStage2aLocalTestPrewriteProof(core, ingress, auth,
		key.Public().(ed25519.PublicKey), epoch, receipt, now.Add(9*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	var proof stage2aLocalTestPrewriteProof
	if err := json.Unmarshal(payload, &proof); err != nil {
		t.Fatal(err)
	}
	envelope := stage2aLocalTestSignedForTest(t, key, stage2aLocalTestPrewritePurpose, proof)
	if got, err := verifyStage2aLocalTestPrewriteProof(envelope,
		key.Public().(ed25519.PublicKey), core, stage2aReservationSHA256(auth), epoch,
		now.Add(-time.Second), now.Add(5*time.Second), now); err != nil || got != receipt {
		t.Fatalf("valid Machine proof refused: receipt %q, error %v", got, err)
	}
	if got, err := verifyStage2aLocalTestPrewriteProofWithIngress(envelope,
		key.Public().(ed25519.PublicKey), core, ingress, auth, epoch,
		now.Add(9*time.Second), now); err != nil || got != receipt {
		t.Fatalf("full ingress/prewrite join refused: receipt %q, error %v", got, err)
	}
	for name, edit := range map[string]func(*stage2aLocalTestPrewriteCore){
		"changed response wire":       func(c *stage2aLocalTestPrewriteCore) { c.ResponseWireSHA256 = "sha256:" + strings.Repeat("b", 64) },
		"changed response byte count": func(c *stage2aLocalTestPrewriteCore) { c.ResponseWireBytes++ },
		"changed observed body":       func(c *stage2aLocalTestPrewriteCore) { c.ObservedBodySHA256 = "sha256:" + strings.Repeat("b", 64) },
		"changed outer launch":        func(c *stage2aLocalTestPrewriteCore) { c.Selectors.LaunchID = "ln_" + strings.Repeat("4", 24) },
		"changed peer":                func(c *stage2aLocalTestPrewriteCore) { c.Peer.PID++ },
	} {
		t.Run(name, func(t *testing.T) {
			mutant := core
			edit(&mutant)
			if _, err := verifyStage2aLocalTestPrewriteProof(envelope,
				key.Public().(ed25519.PublicKey), mutant, stage2aReservationSHA256(auth), epoch,
				now.Add(-time.Second), now.Add(5*time.Second), now); err == nil {
				t.Fatal("mutated prepared wire accepted for write")
			}
		})
	}
	for name, candidate := range map[string][]byte{
		"bare HQ receipt": []byte(receipt),
		"forged HQ signature": stage2aLocalTestSignedForTest(t,
			ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize)),
			stage2aLocalTestPrewritePurpose, proof),
		"wrong purpose": stage2aLocalTestSignedForTest(t, key, stage2aLocalTestIngressPurpose, proof),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyStage2aLocalTestPrewriteProof(candidate,
				key.Public().(ed25519.PublicKey), core, stage2aReservationSHA256(auth), epoch,
				now.Add(-time.Second), now.Add(5*time.Second), now); err == nil {
				t.Fatal("unauthenticated prewrite accepted for write")
			}
		})
	}
	if _, err := verifyStage2aLocalTestPrewriteProof(envelope,
		key.Public().(ed25519.PublicKey), core, stage2aReservationSHA256(auth), epoch,
		now.Add(-time.Second),
		now.Add(5*time.Second),
		now.Add(5*time.Second)); err == nil {
		t.Fatal("expired proof accepted for write")
	}
	if _, err := verifyStage2aLocalTestPrewriteProof(envelope,
		key.Public().(ed25519.PublicKey), core, "sha256:"+strings.Repeat("b", 64), epoch,
		now.Add(-time.Second), now.Add(5*time.Second), now); err == nil {
		t.Fatal("different ingress authorization accepted for write")
	}
	if _, err := verifyStage2aLocalTestPrewriteProof(envelope,
		key.Public().(ed25519.PublicKey), core, stage2aReservationSHA256(auth), strings.Repeat("3", 64),
		now.Add(-time.Second), now.Add(5*time.Second), now); err == nil {
		t.Fatal("different HQ epoch accepted for write")
	}
	if _, err := verifyStage2aLocalTestPrewriteProof(envelope,
		key.Public().(ed25519.PublicKey), core, stage2aReservationSHA256(auth), epoch,
		now.Add(-time.Second), now.Add(4*time.Second), now); err == nil {
		t.Fatal("proof outliving signed authority accepted for write")
	}
	if _, err := verifyStage2aLocalTestPrewriteProof(envelope,
		key.Public().(ed25519.PublicKey), core, stage2aReservationSHA256(auth), epoch,
		now.Add(time.Second), now.Add(5*time.Second), now); err == nil {
		t.Fatal("proof issued before ingress authorization accepted for write")
	}
}

func TestStage2aLocalTestPrewriteConsumerRejectsResignedCoreMismatch(t *testing.T) {
	key, ingress, auth, core, now := stage2aLocalTestPrewriteFixture(t)
	epoch := strings.Repeat("2", 64)
	mutant := core
	mutant.ObservedHeadersSHA256 = "sha256:" + strings.Repeat("b", 64)
	mutantRaw, err := mutant.canonical()
	if err != nil {
		t.Fatal(err)
	}
	// This proof is signed by the test A key over the mismatched B core.
	// The lower-level hash check can accept it, so the full consumer must
	// independently join B's ingress record before the first response byte.
	proof := stage2aLocalTestPrewriteProof{
		Schema: "agent-bot-machine/stage2a-observed-body-local-test-prewrite-acceptance/v1",
		Kind:   "observed-body-local-test-prewrite-acceptance", SchemaVersion: 1,
		Selectors: mutant.Selectors, HQEpoch: epoch,
		AuthorizationEnvelopeSHA256: stage2aReservationSHA256(auth),
		PrewriteCoreSHA256:          stage2aReservationSHA256(mutantRaw),
		PrewriteReceipt:             strings.Repeat("f", 64),
		IssuedAt:                    now.Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Second).Format(time.RFC3339Nano),
	}
	envelope := stage2aLocalTestSignedForTest(t, key, stage2aLocalTestPrewritePurpose, proof)
	public := key.Public().(ed25519.PublicKey)
	if _, err := verifyStage2aLocalTestPrewriteProof(envelope, public, mutant,
		stage2aReservationSHA256(auth), epoch, now.Add(-time.Second),
		now.Add(5*time.Second), now); err != nil {
		t.Fatalf("test setup must isolate ingress join: %v", err)
	}
	if _, err := verifyStage2aLocalTestPrewriteProofWithIngress(envelope,
		public, mutant, ingress, auth, epoch, now.Add(9*time.Second), now); err == nil {
		t.Fatal("consumer accepted signed proof over headers differing from ingress")
	}
}

func TestStage2aLocalTestPrewriteResignedIngressMismatch(t *testing.T) {
	key, ingressRaw, authEnvelope, core, now := stage2aLocalTestPrewriteFixture(t)
	public := key.Public().(ed25519.PublicKey)
	var ingress stage2aLocalTestIngressCore
	if stage2aDecodeExact(ingressRaw, &ingress) != nil {
		t.Fatal("fixture ingress did not decode")
	}
	authRaw, err := verifyStage2aLocalTestEnvelope(authEnvelope, stage2aLocalTestIngressPurpose, public)
	if err != nil {
		t.Fatal(err)
	}
	var authorization stage2aLocalTestIngressAuthorization
	if stage2aDecodeExact(authRaw, &authorization) != nil {
		t.Fatal("fixture authorization did not decode")
	}
	changed := "sha256:" + strings.Repeat("b", 64)
	for name, edit := range map[string]func(*stage2aLocalTestIngressCore){
		"bind receipt":      func(c *stage2aLocalTestIngressCore) { c.BindReceiptSHA256 = changed },
		"body":              func(c *stage2aLocalTestIngressCore) { c.ObservedBodySHA256 = changed },
		"headers":           func(c *stage2aLocalTestIngressCore) { c.ObservedHeadersSHA256 = changed },
		"owner prompt":      func(c *stage2aLocalTestIngressCore) { c.OwnerPromptSHA256 = changed },
		"static projection": func(c *stage2aLocalTestIngressCore) { c.StaticProjectionSHA256 = changed },
		"outer start":       func(c *stage2aLocalTestIngressCore) { c.Selectors.StartID = "st_" + strings.Repeat("9", 24) },
		"peer": func(c *stage2aLocalTestIngressCore) {
			c.Peer.PID++
			peer, err := stage2aT03PeerCanonical(c.Peer)
			if err != nil {
				t.Fatal(err)
			}
			c.PeerSHA256 = stage2aReservationSHA256(peer)
		},
		"future target": func(c *stage2aLocalTestIngressCore) {
			c.TargetReceivedAt = now.Add(time.Second).Format(time.RFC3339Nano)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutant := ingress
			edit(&mutant)
			mutantRaw, err := marshalStage2aReservationJCS(mutant)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseStage2aLocalTestIngressCore(mutantRaw); err != nil {
				t.Fatalf("mutant must be a valid canonical ingress core: %v", err)
			}
			resigned := authorization
			resigned.IngressCoreSHA256 = stage2aReservationSHA256(mutantRaw)
			newAuth := stage2aLocalTestSignedForTest(t, key, stage2aLocalTestIngressPurpose, resigned)
			prepared := core
			prepared.IngressCoreSHA256 = stage2aReservationSHA256(mutantRaw)
			prepared.AuthorizationEnvelopeSHA256 = stage2aReservationSHA256(newAuth)
			if _, err := prepareStage2aLocalTestPrewriteProof(prepared, mutantRaw, newAuth,
				public, strings.Repeat("2", 64), strings.Repeat("f", 64),
				now.Add(9*time.Second), now); err == nil {
				t.Fatal("re-signed ingress mismatch accepted for prewrite")
			}
		})
	}
}

func TestStage2aLocalTestPrewriteDurableBeforeSignature(t *testing.T) {
	key, ingress, auth, core, now := stage2aLocalTestPrewriteFixture(t)
	epoch := strings.Repeat("2", 64)
	receipt := strings.Repeat("f", 64)
	sign := func(preimage []byte) ([]byte, error) { return ed25519.Sign(key, preimage), nil }
	for _, failSign := range []bool{false, true} {
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
		if err := store.checkDirectory(dir); err != nil {
			t.Fatalf("test claim store: %v; mode %o uid %d gid %d", err, stat.Mode, stat.Uid, stat.Gid)
		}
		prepared, err := prepareStage2aLocalTestPrewriteProof(core, ingress, auth,
			key.Public().(ed25519.PublicKey), epoch, receipt, now.Add(9*time.Second), now)
		if err != nil || stage2aLocalTestCanonicalPayload(prepared, stage2aLocalTestPrewritePurpose) != nil {
			t.Fatalf("test prewrite payload: %v", err)
		}
		actualSign := sign
		if failSign {
			actualSign = func([]byte) ([]byte, error) { return nil, errors.New("test signer unavailable") }
		}
		reply, err := commitAndSignStage2aLocalTestPrewrite(store, dir, core, ingress, auth,
			key.Public().(ed25519.PublicKey), epoch, receipt, now.Add(9*time.Second), now, actualSign)
		if failSign {
			if err == nil {
				t.Fatal("failed signer returned authorization")
			}
		} else if err != nil {
			t.Fatal(err)
		} else {
			proof, err := base64.RawURLEncoding.Strict().DecodeString(reply.PrewriteProofEnvelopeBase64URL)
			if err != nil || reply.PrewriteProofEnvelopeSHA256 != stage2aReservationSHA256(proof) {
				t.Fatal("Machine reply digest does not bind the signed proof")
			}
			if _, err := verifyStage2aLocalTestPrewriteProof(proof, key.Public().(ed25519.PublicKey),
				core, stage2aReservationSHA256(auth), epoch, now.Add(-time.Second), now.Add(5*time.Second), now); err != nil {
				t.Fatal(err)
			}
		}
		name := ".stage2a-local-test-prewrite-" + soulStartClaimName(
			core.Selectors.InstallationID, core.Selectors.StartID) + ".json"
		stored, err := os.ReadFile(dir.Name() + "/" + name)
		if err != nil || len(stored) == 0 {
			t.Fatal("prewrite acceptance was not durably recorded before signing")
		}
		if _, err := commitAndSignStage2aLocalTestPrewrite(store, dir, core, ingress, auth,
			key.Public().(ed25519.PublicKey), epoch, receipt, now.Add(9*time.Second), now, sign); err == nil {
			t.Fatal("replayed prewrite returned a second proof")
		}
	}
}

// The private candidate tuple is injected only in source review. Its vendor
// literals and host claims are never copied into this public repository.
func TestStage2aLocalTestPrivateCandidate4Envelope(t *testing.T) {
	path := os.Getenv("STAGE2A_CANDIDATE4_TUPLE")
	if path == "" {
		t.Skip("private source-review tuple not supplied")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Keys        map[string]string `json:"keys"`
		Reservation struct {
			EnvelopeBase64URL string `json:"envelope_base64url"`
		} `json:"reservation"`
		MemberAssignment struct {
			EnvelopeBase64URL string `json:"envelope_base64url"`
		} `json:"member_assignment"`
		BPolicy struct {
			EnvelopeBase64URL string `json:"envelope_base64url"`
		} `json:"b_policy"`
		Authorization struct {
			EnvelopeBase64URL string `json:"envelope_base64url"`
		} `json:"authorization"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid private candidate tuple")
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(fixture.Keys["A"])
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatal("invalid private candidate public key")
	}
	for name, value := range map[string]struct{ purpose, encoded string }{
		"reservation":   {stage2aLocalTestReservationPurpose, fixture.Reservation.EnvelopeBase64URL},
		"assignment":    {stage2aLocalTestAssignmentPurpose, fixture.MemberAssignment.EnvelopeBase64URL},
		"B policy":      {stage2aLocalTestBPolicyPurpose, fixture.BPolicy.EnvelopeBase64URL},
		"authorization": {stage2aLocalTestIngressPurpose, fixture.Authorization.EnvelopeBase64URL},
	} {
		t.Run(name, func(t *testing.T) {
			envelope, err := base64.RawURLEncoding.Strict().DecodeString(value.encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyStage2aLocalTestEnvelope(envelope, value.purpose, public); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStage2aLocalTestPrewriteContractVector(t *testing.T) {
	path := os.Getenv("STAGE2A_LOCAL_TEST_PREWRITE_VECTOR")
	if path == "" {
		t.Skip("neutral source contract vector not supplied")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PrewriteCore stage2aLocalTestPrewriteCore `json:"prewrite_core"`
		Proof        struct {
			EnvelopeBase64URL string                        `json:"envelope_base64url"`
			Payload           stage2aLocalTestPrewriteProof `json:"payload"`
		} `json:"proof"`
		PrewriteReply stage2aLocalTestPrewriteReply `json:"prewrite_reply"`
	}
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("invalid neutral contract vector")
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(vector.Proof.EnvelopeBase64URL)
	if err != nil || stage2aReservationSHA256(envelope) != vector.PrewriteReply.PrewriteProofEnvelopeSHA256 ||
		vector.PrewriteReply.PrewriteProofEnvelopeBase64URL != vector.Proof.EnvelopeBase64URL ||
		vector.PrewriteReply.PrewriteReceipt != vector.Proof.Payload.PrewriteReceipt {
		t.Fatal("contract vector reply does not bind its proof")
	}
	var signed stage2aSignedReservation
	if json.Unmarshal(envelope, &signed) != nil {
		t.Fatal("invalid signed vector envelope")
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(signed.IssuerPublicKeyBase64URL)
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatal("invalid signed vector public key")
	}
	issued, err := time.Parse(time.RFC3339Nano, vector.Proof.Payload.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339Nano, vector.Proof.Payload.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStage2aLocalTestPrewriteProof(envelope, public, vector.PrewriteCore,
		vector.Proof.Payload.AuthorizationEnvelopeSHA256, vector.Proof.Payload.HQEpoch,
		issued.Add(-time.Second), expires, issued); err != nil {
		t.Fatal(err)
	}
}
