package qualification

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func witnessFixture(t *testing.T, now time.Time) (WitnessContext, []byte, map[string]any, *ecdsa.PrivateKey) {
	t.Helper()
	_, ownerEnvelope, ownerRoot := fixturePolicy(t, now)
	var outer Envelope
	if err := json.Unmarshal(ownerEnvelope, &outer); err != nil {
		t.Fatal(err)
	}
	witnessKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&witnessKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pairOwner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}
	ctx := WitnessContext{
		HostID: "fixture-host", MachinePub: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", 32))),
		HQPub: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("h", 32))), HQUid: 504,
		HQEpoch: strings.Repeat("e", 64), PairOwnerPub: base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), pairOwner.X, pairOwner.Y)),
		WitnessKeyID: "fixture-witness", WitnessSPKIDER: spki, WitnessKeyActive: true, OwnerKeyID: "fixture-root", OwnerRoot: ownerRoot,
		AcceptedVersion: 1, AcceptedRevision: 2, AcceptedSHA256: outer.PolicySHA256,
		Challenge: challenge, ChallengeOutstanding: true, TrustedTime: true,
	}
	payload := map[string]any{
		"contract": "control/v1", "kind": "qualification-policy-acceptance-witness", "schema_version": 1,
		"host_id": ctx.HostID, "machine_pub": ctx.MachinePub, "hq_pub": ctx.HQPub,
		"hq_uid": ctx.HQUid, "hq_epoch": ctx.HQEpoch, "pair_owner_pub": ctx.PairOwnerPub,
		"witness_key_id": ctx.WitnessKeyID, "challenge_base64url": base64.RawURLEncoding.EncodeToString(challenge),
		"policy_version": ctx.AcceptedVersion, "policy_revision": ctx.AcceptedRevision,
		"policy_sha256": ctx.AcceptedSHA256, "owner_key_id": ctx.OwnerKeyID,
		"issued_at":  now.Add(-10 * time.Second).Format(time.RFC3339),
		"expires_at": now.Add(30 * time.Second).Format(time.RFC3339),
	}
	return ctx, ownerEnvelope, payload, witnessKey
}

func signedAcceptanceWitness(t *testing.T, payload map[string]any, key *ecdsa.PrivateKey, keyID string) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(preimage(WitnessPurpose, raw))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	outer := acceptanceWitnessEnvelope{SchemaVersion: 1, Purpose: WitnessPurpose, WitnessKeyID: keyID,
		PayloadSHA256: digest(raw), PayloadBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(sig)}
	envelope, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestAcceptanceWitnessSignatureAndIndependentState(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	ctx, owner, payload, key := witnessFixture(t, now)
	witness := signedAcceptanceWitness(t, payload, key, ctx.WitnessKeyID)
	if err := VerifyAcceptanceWitnessPreflight(witness, owner, ctx, now); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		change func(*WitnessContext)
	}{
		{"missing ledger", func(c *WitnessContext) { c.AcceptedRevision = 0 }},
		{"stale accepted revision", func(c *WitnessContext) { c.AcceptedRevision++ }},
		{"changed accepted digest", func(c *WitnessContext) { c.AcceptedSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"wrong policy version", func(c *WitnessContext) { c.AcceptedVersion = 2 }},
		{"changed host", func(c *WitnessContext) { c.HostID = "other-host" }},
		{"changed Machine", func(c *WitnessContext) {
			c.MachinePub = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
		}},
		{"changed HQ", func(c *WitnessContext) { c.HQPub = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))) }},
		{"changed HQ UID", func(c *WitnessContext) { c.HQUid++ }},
		{"changed HQ epoch", func(c *WitnessContext) { c.HQEpoch = strings.Repeat("f", 64) }},
		{"missing challenge", func(c *WitnessContext) { c.ChallengeOutstanding = false }},
		{"different challenge", func(c *WitnessContext) { c.Challenge[0] ^= 1 }},
		{"untrusted elapsed time", func(c *WitnessContext) { c.TrustedTime = false }},
		{"wrong witness key", func(c *WitnessContext) { c.WitnessSPKIDER = []byte("invalid") }},
		{"revoked witness key", func(c *WitnessContext) { c.WitnessKeyActive = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := ctx
			changed.Challenge = append([]byte(nil), ctx.Challenge...)
			tc.change(&changed)
			if VerifyAcceptanceWitnessPreflight(witness, owner, changed, now) == nil {
				t.Fatal("accepted changed independent state")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"wrong purpose payload", func(p map[string]any) { p["kind"] = "qualification-host-report" }},
		{"wrong host payload", func(p map[string]any) { p["host_id"] = "other-host" }},
		{"wrong owner key", func(p map[string]any) { p["owner_key_id"] = "other-root" }},
		{"wrong challenge", func(p map[string]any) {
			p["challenge_base64url"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		}},
		{"long witness", func(p map[string]any) {
			p["expires_at"] = now.Add(61 * time.Second).Format(time.RFC3339)
			p["issued_at"] = now.Format(time.RFC3339)
		}},
		{"extra field", func(p map[string]any) { p["public_key"] = "attacker" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := make(map[string]any, len(payload)+1)
			for k, v := range payload {
				copy[k] = v
			}
			tc.change(copy)
			if VerifyAcceptanceWitnessPreflight(signedAcceptanceWitness(t, copy, key, ctx.WitnessKeyID), owner, ctx, now) == nil {
				t.Fatal("accepted signed invalid payload")
			}
		})
	}
	var outer acceptanceWitnessEnvelope
	if err := json.Unmarshal(witness, &outer); err != nil {
		t.Fatal(err)
	}
	outer.Purpose = HostPurposeV2
	wrong, _ := json.Marshal(outer)
	if VerifyAcceptanceWitnessPreflight(wrong, owner, ctx, now) == nil {
		t.Fatal("accepted host-report purpose")
	}
	outer.Purpose = WitnessPurpose
	outer.SignatureBase64URL = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	wrong, _ = json.Marshal(outer)
	if VerifyAcceptanceWitnessPreflight(wrong, owner, ctx, now) == nil {
		t.Fatal("accepted forged signature")
	}
	if VerifyAcceptanceWitnessPreflight(witness, []byte("{}"), ctx, now) == nil {
		t.Fatal("accepted unsigned owner policy")
	}
}

func TestAcceptanceWitnessRevocationFreshnessBoundary(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	ctx, owner, payload, key := witnessFixture(t, now)
	payload["issued_at"] = now.Format(time.RFC3339)
	payload["expires_at"] = now.Add(60 * time.Second).Format(time.RFC3339)
	witness := signedAcceptanceWitness(t, payload, key, ctx.WitnessKeyID)
	if err := VerifyAcceptanceWitnessPreflight(witness, owner, ctx, now); err != nil {
		t.Fatal("3600-second boundary refused: ", err)
	}
	if VerifyAcceptanceWitnessPreflight(witness, owner, ctx, now.Add(time.Second)) == nil {
		t.Fatal("3601-second snapshot accepted")
	}
}

func TestAcceptanceWitnessV2AndVersionRegression(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	ctx, _, payload, key := witnessFixture(t, now)
	policy, _, _ := fixturePolicy(t, now)
	policy.Contract = "control/v2"
	policy.SoulsBuildWorkflow = &struct {
		ID                   string `json:"id"`
		Repository           string `json:"repository"`
		WorkflowPath         string `json:"workflow_path"`
		SourceCommit         string `json:"source_commit"`
		SourceTree           string `json:"source_tree"`
		OIDCIssuer           string `json:"oidc_issuer"`
		CertificateIdentity  string `json:"certificate_identity"`
		TrustRootSHA256      string `json:"trust_root_sha256"`
		BuilderSHA256        string `json:"builder_sha256"`
		ToolchainSHA256      string `json:"toolchain_sha256"`
		ReceiptPredicateType string `json:"receipt_predicate_type"`
		BundleMediaType      string `json:"bundle_media_type"`
		DSSEPayloadType      string `json:"dsse_payload_type"`
	}{
		ID: "fixture-souls-build", Repository: "true-line/agent-bot-souls", WorkflowPath: ".github/workflows/release.yml",
		SourceCommit: strings.Repeat("1", 40), SourceTree: strings.Repeat("2", 40),
		OIDCIssuer:          "https://token.actions.githubusercontent.com",
		CertificateIdentity: "https://github.com/true-line/agent-bot-souls/.github/workflows/release.yml@refs/heads/main",
		TrustRootSHA256:     "sha256:" + strings.Repeat("3", 64), BuilderSHA256: "sha256:" + strings.Repeat("4", 64),
		ToolchainSHA256:      "sha256:" + strings.Repeat("5", 64),
		ReceiptPredicateType: "https://true-line.ai/soul-contracts/adapter/v2/souls-build",
		BundleMediaType:      bundleMediaType, DSSEPayloadType: DSSEPayloadType,
	}
	policy.RevocationSnapshot.RevokedSoulsBuildWorkflowIDs = []string{}
	policy.RevocationSnapshot.RevokedSoulsBuildReceiptSHA256 = []string{}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var policyObject map[string]any
	if err := json.Unmarshal(raw, &policyObject); err != nil {
		t.Fatal(err)
	}
	snapshot := policyObject["revocation_snapshot"].(map[string]any)
	snapshot["revoked_souls_build_workflow_ids"] = []any{}
	snapshot["revoked_souls_build_receipt_sha256"] = []any{}
	raw, err = json.Marshal(policyObject)
	if err != nil {
		t.Fatal(err)
	}
	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ownerSignature := ed25519.Sign(private, preimage(PolicyPurposeV2, raw))
	owner, err := json.Marshal(Envelope{SchemaVersion: 2, Purpose: PolicyPurposeV2, OwnerKeyID: policy.OwnerKeyID,
		PolicySHA256: digest(raw), PolicyBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(ownerSignature)})
	if err != nil {
		t.Fatal(err)
	}
	ctx.OwnerRoot = root
	ctx.AcceptedVersion = 2
	ctx.AcceptedSHA256 = digest(raw)
	payload["policy_version"] = 2
	payload["policy_sha256"] = ctx.AcceptedSHA256
	witness := signedAcceptanceWitness(t, payload, key, ctx.WitnessKeyID)
	if err := VerifyAcceptanceWitnessPreflight(witness, owner, ctx, now); err != nil {
		t.Fatal("signed v2 owner policy and witness refused: ", err)
	}
	ctx.AcceptedVersion = 1
	if VerifyAcceptanceWitnessPreflight(witness, owner, ctx, now) == nil {
		t.Fatal("v2 witness accepted as v1")
	}
	ctx.AcceptedVersion = 2
	ctx.AcceptedSHA256 = "sha256:" + strings.Repeat("a", 64)
	if VerifyAcceptanceWitnessPreflight(witness, owner, ctx, now) == nil {
		t.Fatal("v2 witness accepted against prior digest")
	}
}
