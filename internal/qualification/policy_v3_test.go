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

func TestOwnerPolicyV3AuthenticatesFrozenAuthorityOffline(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	p, _, _ := fixturePolicy(t, now)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if json.Unmarshal(raw, &policy) != nil {
		t.Fatal("fixture decode")
	}
	policy["contract"] = "control/v3"
	policy["souls_build_workflow"] = map[string]any{
		"id": "fixture-souls-build", "repository": "true-line/agent-bot-souls",
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
	policy["frozen_soul_build_workflow"] = map[string]any{
		"id": "fixture-frozen-build", "repository": "true-line/soul-package",
		"workflow_path": ".github/workflows/stage2a-frozen-soul-receipt.yml",
		"source_commit": strings.Repeat("6", 40), "source_tree": strings.Repeat("7", 40),
		"oidc_issuer":            "https://token.actions.githubusercontent.com",
		"certificate_identity":   "https://github.com/true-line/soul-package/.github/workflows/stage2a-frozen-soul-receipt.yml@refs/heads/main",
		"trust_root_sha256":      "sha256:" + strings.Repeat("8", 64),
		"builder_sha256":         "sha256:" + strings.Repeat("9", 64),
		"toolchain_sha256":       "sha256:" + strings.Repeat("a", 64),
		"receipt_predicate_type": "https://true-line.ai/soul-contracts/package/v1/frozen-soul-build",
		"bundle_media_type":      bundleMediaType, "dsse_payload_type": DSSEPayloadType,
		"artifact_format":       "stage2a-frozen-hello-ustar/v1",
		"subject_name_template": "sha256-{artifact_sha256}.soul",
		"rekor_entry_kind":      "dsse", "rekor_entry_version": "0.0.1",
		"transparency_log_id": strings.Repeat("b", 64),
		"template": map[string]any{
			"repository":    "true-line/soul-conformance",
			"source_commit": "8e82f47781e583e4b09352cbfef5ca3bfefe45aa",
			"source_tree":   "5f3ab3acee16de02a38a51204fb9401c3566a6d0",
			"path":          "templates/hello.soul",
			"template_tree": "e944d40e5f495f6de395619b254ed890e36b53ee",
		},
	}
	policy["frozen_soul_mapping"] = map[string]any{
		"soul_id":                   "agent_00000000-0000-0000-0000-000000000000",
		"artifact_sha256":           strings.Repeat("c", 64),
		"receipt_sha256":            "sha256:" + strings.Repeat("f", 64),
		"claimed_definition_digest": "sha256:" + strings.Repeat("d", 64),
		"definition_measurement":    "sha256:" + strings.Repeat("e", 64),
	}
	snapshot := policy["revocation_snapshot"].(map[string]any)
	for _, key := range []string{
		"revoked_souls_build_workflow_ids", "revoked_souls_build_receipt_sha256",
		"revoked_frozen_soul_build_workflow_ids", "revoked_frozen_soul_receipt_sha256",
		"revoked_frozen_soul_artifact_sha256",
	} {
		snapshot[key] = []any{}
	}
	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := func(value map[string]any) []byte {
		t.Helper()
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(private, preimage(PolicyPurposeV3, payload))
		envelope, err := json.Marshal(Envelope{SchemaVersion: 3, Purpose: PolicyPurposeV3,
			OwnerKeyID: p.OwnerKeyID, PolicySHA256: digest(payload),
			PolicyBase64URL:    base64.RawURLEncoding.EncodeToString(payload),
			SignatureBase64URL: base64.RawURLEncoding.EncodeToString(sig)})
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	prior := "sha256:" + strings.Repeat("0", 64)
	envelope := signed(policy)
	verified, err := VerifyOwnerPolicyV3(envelope, p.OwnerKeyID, root, 1, prior, now)
	if err != nil {
		t.Fatal("owner signed v3 policy refused at 3600-second boundary", err)
	}
	if verified.value.FrozenSoulMapping.ArtifactSHA256 != strings.Repeat("c", 64) ||
		verified.value.FrozenSoulMapping.ReceiptSHA256 != "sha256:"+strings.Repeat("f", 64) ||
		verified.value.FrozenSoulBuildWorkflow.Template.Path != "templates/hello.soul" {
		t.Fatal("authenticated frozen authority was not retained")
	}
	if _, err := VerifyOwnerPolicyV2(envelope, p.OwnerKeyID, root, 1, prior, now); err == nil {
		t.Fatal("v3 substituted for v2")
	}
	if _, err := VerifyOwnerPolicyV3(envelope, p.OwnerKeyID, root, 1, prior, now.Add(time.Second)); err == nil {
		t.Fatal("stale revocation snapshot")
	}
	if _, err := VerifyOwnerPolicyV3(envelope, p.OwnerKeyID, make([]byte, ed25519.PublicKeySize), 1, prior, now); err == nil {
		t.Fatal("wrong owner root")
	}
	revision, payloadSHA, err := verified.RevisionDigest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerPolicyV3(envelope, p.OwnerKeyID, root, revision, payloadSHA, now); err != nil {
		t.Fatal("exact checkpoint replay", err)
	}
	if _, err := VerifyOwnerPolicyV3(envelope, p.OwnerKeyID, root, revision, prior, now); err == nil {
		t.Fatal("same revision equivocation")
	}
	delete(policy, "frozen_soul_mapping")
	if _, err := VerifyOwnerPolicyV3(signed(policy), p.OwnerKeyID, root, 1, prior, now); err == nil {
		t.Fatal("missing frozen mapping")
	}
	policy["frozen_soul_mapping"] = map[string]any{
		"soul_id": "agent_00000000-0000-0000-0000-000000000000", "artifact_sha256": strings.Repeat("c", 64),
		"receipt_sha256":            "sha256:" + strings.Repeat("f", 64),
		"claimed_definition_digest": "sha256:" + strings.Repeat("d", 64), "definition_measurement": "sha256:" + strings.Repeat("e", 64),
	}
	mapping := policy["frozen_soul_mapping"].(map[string]any)
	delete(mapping, "receipt_sha256")
	if _, err := VerifyOwnerPolicyV3(signed(policy), p.OwnerKeyID, root, 1, prior, now); err == nil {
		t.Fatal("missing exact frozen receipt digest")
	}
	mapping["receipt_sha256"] = "sha256:" + strings.Repeat("f", 64)
	workflow := policy["frozen_soul_build_workflow"].(map[string]any)
	workflow["rekor_entry_version"] = "0.0.2"
	if _, err := VerifyOwnerPolicyV3(signed(policy), p.OwnerKeyID, root, 1, prior, now); err == nil {
		t.Fatal("wrong Rekor kind/version")
	}
	workflow["rekor_entry_version"] = "0.0.1"
	snapshot["revoked_frozen_soul_receipt_sha256"] = []any{"sha256:" + strings.Repeat("f", 64)}
	if _, err := VerifyOwnerPolicyV3(signed(policy), p.OwnerKeyID, root, 1, prior, now); err == nil {
		t.Fatal("revoked frozen receipt")
	}
	snapshot["revoked_frozen_soul_receipt_sha256"] = []any{}
	snapshot["revoked_frozen_soul_artifact_sha256"] = []any{strings.Repeat("c", 64)}
	if _, err := VerifyOwnerPolicyV3(signed(policy), p.OwnerKeyID, root, 1, prior, now); err == nil {
		t.Fatal("revoked frozen artifact")
	}
}
