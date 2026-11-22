package qualification

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOwnerPolicyV2PinsSoulsBuildAndFreshness(t *testing.T) {
	// The owner policy and revocation snapshot are local signed inputs. An
	// unavailable evidence store must not become a policy-verification lookup.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	p, _, _ := fixturePolicy(t, now)
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if err := json.Unmarshal(encoded, &policy); err != nil {
		t.Fatal(err)
	}
	policy["contract"] = "control/v2"
	policy["souls_build_workflow"] = map[string]any{
		"id": "souls-build-fixture", "repository": "true-line/agent-bot-souls",
		"workflow_path": ".github/workflows/release.yml",
		"source_commit": strings.Repeat("1", 40), "source_tree": strings.Repeat("2", 40),
		"oidc_issuer":            "https://token.actions.githubusercontent.com",
		"certificate_identity":   "https://github.com/true-line/agent-bot-souls/.github/workflows/release.yml@refs/heads/main",
		"trust_root_sha256":      "sha256:" + strings.Repeat("3", 64),
		"builder_sha256":         "sha256:" + strings.Repeat("4", 64),
		"toolchain_sha256":       "sha256:" + strings.Repeat("5", 64),
		"receipt_predicate_type": "https://true-line.ai/soul-contracts/adapter/v2/souls-build",
		"bundle_media_type":      bundleMediaType, "dsse_payload_type": DSSEPayloadType,
	}
	snapshot := policy["revocation_snapshot"].(map[string]any)
	snapshot["revoked_souls_build_workflow_ids"] = []any{}
	snapshot["revoked_souls_build_receipt_sha256"] = []any{}
	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := func(value map[string]any) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(private, preimage(PolicyPurposeV2, raw))
		envelope, err := json.Marshal(Envelope{SchemaVersion: 2, Purpose: PolicyPurposeV2, OwnerKeyID: p.OwnerKeyID, PolicySHA256: digest(raw), PolicyBase64URL: base64.RawURLEncoding.EncodeToString(raw), SignatureBase64URL: base64.RawURLEncoding.EncodeToString(sig)})
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	envelope := signed(policy)
	priorDigest := "sha256:" + strings.Repeat("0", 64)
	verified, err := VerifyOwnerPolicyV2(envelope, p.OwnerKeyID, root, 1, priorDigest, now)
	if err != nil {
		t.Fatal("v2 policy refused at exact 3600-second boundary", err)
	}
	revision, payloadSHA, err := verified.RevisionDigest()
	if err != nil || revision != p.PolicyRevision || !validSHA(payloadSHA) {
		t.Fatal("verified v2 policy did not expose its rollback checkpoint", err)
	}
	if _, _, err := (VerifiedPolicy{}).RevisionDigest(); err == nil {
		t.Fatal("unverified policy exposed a rollback checkpoint")
	}
	if _, err := VerifyOwnerPolicyV2(envelope, p.OwnerKeyID, root, 1, "", now); err == nil {
		t.Fatal("missing persisted digest accepted")
	}
	if _, err := VerifyOwnerPolicyV2(envelope, p.OwnerKeyID, root, 0, priorDigest, now); err == nil {
		t.Fatal("orphaned persisted digest accepted")
	}
	if _, err := VerifyOwnerPolicyV2(envelope, p.OwnerKeyID, root, revision, payloadSHA, now); err != nil {
		t.Fatal("same owner-signed policy revision and digest refused", err)
	}
	if _, err := VerifyOwnerPolicyV2(envelope, p.OwnerKeyID, root, revision, "sha256:"+strings.Repeat("0", 64), now); err == nil {
		t.Fatal("same revision with a different accepted digest was allowed")
	}
	if _, err := VerifyOwnerPolicyV2(envelope, p.OwnerKeyID, root, 1, priorDigest, now.Add(time.Second)); err == nil {
		t.Fatal("stale v2 snapshot accepted")
	}
	if _, err := VerifyOwnerPolicy(envelope, p.OwnerKeyID, root, 1, priorDigest, now); err == nil {
		t.Fatal("v2 policy accepted as v1")
	}
	policy["issued_at"] = now.Add(-30 * time.Minute).Format(time.RFC3339)
	if _, err := VerifyOwnerPolicyV2(signed(policy), p.OwnerKeyID, root, 1, priorDigest, now); err == nil {
		t.Fatal("revocation snapshot older than policy issue time accepted")
	}
	policy["issued_at"] = p.IssuedAt
	policy["souls_build_workflow"].(map[string]any)["source_tree"] = strings.Repeat("9", 40)
	if _, err := VerifyOwnerPolicyV2(signed(policy), p.OwnerKeyID, root, 1, priorDigest, now); err != nil {
		t.Fatal("a new owner-signed source tree should be parseable", err)
	}
	delete(policy["souls_build_workflow"].(map[string]any), "source_tree")
	if _, err := VerifyOwnerPolicyV2(signed(policy), p.OwnerKeyID, root, 1, priorDigest, now); err == nil {
		t.Fatal("missing approved tree accepted")
	}
	policy["souls_build_workflow"].(map[string]any)["source_tree"] = strings.Repeat("2", 40)
	snapshot["revoked_souls_build_workflow_ids"] = []any{"souls-build-fixture"}
	if _, err := VerifyOwnerPolicyV2(signed(policy), p.OwnerKeyID, root, 1, priorDigest, now); err == nil {
		t.Fatal("revoked Souls workflow accepted")
	}
}
