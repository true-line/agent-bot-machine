//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStage2aLocalTestC5PathBinding(t *testing.T) {
	p, _, _ := stage2aLocalTestOwnerPlanFixture(t)
	installation := "inst.fixture"
	start := "st_" + strings.Repeat("1", 24)
	runner := soulRunnerName(installation)
	issued := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	expires := issued.Add(20 * time.Second)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize))
	binding, raw, err := stage2aLocalTestPathBindingForStart(p, runner,
		installation, start, issued, expires)
	if err != nil || stage2aLocalTestCanonicalPayload(raw, stage2aLocalTestPathPurpose) != nil {
		t.Fatal(err)
	}
	if binding.StartSlot != "70799e6441e7d13e10b2" ||
		binding.CWD.Lexical != p.RunnerHomeLexical+"/state/child-70799e6441e7d13e10b2/work" ||
		binding.CWD.Emitted != "/private"+binding.CWD.Lexical ||
		binding.Home.Emitted != "/private"+binding.Home.Lexical ||
		binding.Memory.Emitted != "/private"+binding.Memory.Lexical {
		t.Fatalf("per-start path serialization changed: %+v", binding)
	}
	if stage2aLocalTestProjectSlug("/private/var/hqm_a/work") != "-private-var-hqm-a-work" ||
		strings.Contains(strings.Split(binding.Memory.Lexical, "/projects/")[1], "_abm-sr-") ||
		!strings.Contains(strings.Split(binding.Memory.Lexical, "/projects/")[1], "-abm-sr-") {
		t.Fatal("stock project slug must replace underscores and every non-alphanumeric byte")
	}
	envelope := stage2aLocalTestSignedForTest(t, key, stage2aLocalTestPathPurpose, binding)
	if _, err := verifyStage2aLocalTestPathBinding(envelope, key.Public().(ed25519.PublicKey),
		p, runner, installation, start, issued.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*stage2aLocalTestPathBinding){
		"stale c4 shared path": func(b *stage2aLocalTestPathBinding) {
			b.CWD.Lexical = p.RunnerHomeLexical + "/work"
			b.CWD.Emitted = "/private" + b.CWD.Lexical
		},
		"target first": func(b *stage2aLocalTestPathBinding) { b.TargetAfter = []string{} },
		"sibling home": func(b *stage2aLocalTestPathBinding) { b.Home.Lexical = "/var/sibling/home" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			mutate(&changed)
			signed := stage2aLocalTestSignedForTest(t, key, stage2aLocalTestPathPurpose, changed)
			if _, err := verifyStage2aLocalTestPathBinding(signed,
				key.Public().(ed25519.PublicKey), p, runner, installation, start,
				issued.Add(time.Second)); err == nil {
				t.Fatal("signed mismatched path or order accepted")
			}
		})
	}
	if _, err := verifyStage2aLocalTestPathBinding(envelope, key.Public().(ed25519.PublicKey),
		p, runner, installation, start, expires); err == nil {
		t.Fatal("expired path binding accepted")
	}
}

// The neutral vector is generated outside the public repository. It contains
// a test key, synthetic paths and two signed semantic refusals, never the
// private selected stock client or any credential.
func TestStage2aLocalTestC5NeutralVector(t *testing.T) {
	file := os.Getenv("STAGE2A_LOCAL_TEST_C5_VECTOR")
	if file == "" {
		t.Skip("neutral c5 vector not supplied")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Schema             string `json:"schema"`
		PublicKeyBase64URL string `json:"public_key_base64url"`
		InstallationID     string `json:"installation_id"`
		StartID            string `json:"start_id"`
		RunnerAccount      string `json:"runner_account"`
		StartSlot          string `json:"start_slot"`
		SlotPreimageUTF8   string `json:"slot_preimage_utf8"`
		SlotPreimageHex    string `json:"slot_preimage_hex"`
		Positive           string `json:"positive_envelope_base64url"`
		StaleC4            string `json:"stale_c4_envelope_base64url"`
		TargetFirst        string `json:"target_first_envelope_base64url"`
	}
	if stage2aStrictJSON(raw) != nil || json.Unmarshal(raw, &vector) != nil ||
		vector.Schema != "agent-bot-machine/stage2a-c5-neutral-path-order-vector/v1" {
		t.Fatal("invalid c5 vector")
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(vector.PublicKeyBase64URL)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatal("invalid test public key")
	}
	preimage := []byte("agent-bot-soul-endpoint-start/v1\x00" + vector.InstallationID + "\x00" + vector.StartID)
	decoded, err := hex.DecodeString(vector.SlotPreimageHex)
	if err != nil || !bytes.Equal(decoded, preimage) || vector.SlotPreimageUTF8 != string(preimage) {
		t.Fatal("c5 slot preimage metadata differs from exact NUL-separated bytes")
	}
	slotDigest := sha256.Sum256(preimage)
	if vector.StartSlot != fmt.Sprintf("%x", slotDigest[:10]) ||
		vector.StartSlot != soulEndpointStartSlot(vector.InstallationID, vector.StartID) {
		t.Fatal("c5 vector start slot differs from Machine serialization")
	}
	p, _, _ := stage2aLocalTestOwnerPlanFixture(t)
	now := time.Date(2026, 11, 24, 12, 0, 1, 0, time.UTC)
	for name, item := range map[string]struct {
		encoded string
		allow   bool
	}{
		"positive":     {vector.Positive, true},
		"stale c4":     {vector.StaleC4, false},
		"target first": {vector.TargetFirst, false},
	} {
		t.Run(name, func(t *testing.T) {
			envelope, err := base64.RawURLEncoding.Strict().DecodeString(item.encoded)
			if err != nil {
				t.Fatal(err)
			}
			if item.allow {
				payload, err := verifyStage2aLocalTestEnvelope(envelope, stage2aLocalTestPathPurpose, key)
				if err != nil {
					t.Fatal(err)
				}
				var binding stage2aLocalTestPathBinding
				if stage2aDecodeExact(payload, &binding) != nil ||
					!strings.Contains(binding.Memory.Lexical, "/projects/") ||
					strings.Contains(strings.Split(binding.Memory.Lexical, "/projects/")[1], "_abm-sr-") ||
					!strings.Contains(strings.Split(binding.Memory.Lexical, "/projects/")[1], "-abm-sr-") {
					t.Fatal("neutral vector memory slug differs from observed stock rule")
				}
			}
			_, err = verifyStage2aLocalTestPathBinding(envelope, key, p,
				vector.RunnerAccount, vector.InstallationID, vector.StartID, now)
			if (err == nil) != item.allow {
				t.Fatalf("unexpected c5 vector result: %v", err)
			}
		})
	}
}
