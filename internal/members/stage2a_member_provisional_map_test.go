package members

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestStage2aProvisionalMemberMapRequiresExactWithheldCanonicalBytes(t *testing.T) {
	mapValue := map[string]any{
		"contract": "hq/v1", "kind": "stage2a-provisional-member-map", "schema_version": 1,
		"profile_in_force": "managed-protected", "host_id": "host-one",
		"installation_id": "soul-one", "soul_id": "agent_01234567-0123-0123-0123-0123456789ab",
		"start_id": "st_0123456789abcdef01234567", "hq_epoch": strings.Repeat("c", 64),
		"assignment_envelope_sha256": "sha256:" + strings.Repeat("a", 64),
		"runtime_state":              "provisional", "acp_authority": "withheld",
		"members": []any{
			map[string]any{"member_id": "m_lead", "member_selector": "mb_" + strings.Repeat("a", 64),
				"runtime_id": "rt_lead", "channel_binding": "LeadBinding123456"},
			map[string]any{"member_id": "m_spec", "member_selector": "mb_" + strings.Repeat("b", 64),
				"runtime_id": "rt_spec", "channel_binding": "SpecBinding123456"},
		},
		"issued_at": "2026-11-23T18:00:00Z", "expires_at": "2026-11-23T18:00:20Z",
	}
	encode := func(value map[string]any, canonical bool) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if canonical {
			raw, err = jsoncanonicalizer.Transform(raw)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			raw = append([]byte{' '}, raw...)
		}
		q := Stage2aMemberProvisionalMapRequest{Stage2aStopRequest: stage2aHelloTestSelectors(),
			ProvisionalHQMappingBase64URL: base64.RawURLEncoding.EncodeToString(raw),
			ProvisionalHQMappingSHA256:    fmt.Sprintf("sha256:%x", sha256.Sum256(raw))}
		request, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		return request
	}
	if _, err := ParseStage2aMemberProvisionalMapRequest(encode(mapValue, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStage2aMemberProvisionalMapRequest(encode(mapValue, false)); err == nil {
		t.Fatal("noncanonical H map was accepted")
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"ACP already released", func(v map[string]any) { v["acp_authority"] = "released" }},
		{"runtime already live", func(v map[string]any) { v["runtime_state"] = "live" }},
		{"reused channel", func(v map[string]any) {
			v["members"].([]any)[1].(map[string]any)["channel_binding"] = "LeadBinding123456"
		}},
		{"reused runtime", func(v map[string]any) {
			v["members"].([]any)[1].(map[string]any)["runtime_id"] = "rt_lead"
		}},
		{"malformed selector", func(v map[string]any) {
			v["members"].([]any)[1].(map[string]any)["member_selector"] = "mb_short"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cloneBytes, _ := json.Marshal(mapValue)
			var clone map[string]any
			if err := json.Unmarshal(cloneBytes, &clone); err != nil {
				t.Fatal(err)
			}
			test.change(clone)
			if _, err := ParseStage2aMemberProvisionalMapRequest(encode(clone, true)); err == nil {
				t.Fatal("invalid provisional H map was accepted")
			}
		})
	}
	q := Stage2aMemberProvisionalMapRequest{}
	if err := json.Unmarshal(encode(mapValue, true), &q); err != nil {
		t.Fatal(err)
	}
	q.ProvisionalHQMappingSHA256 = "sha256:" + strings.Repeat("0", 64)
	tampered, _ := json.Marshal(q)
	if _, err := ParseStage2aMemberProvisionalMapRequest(tampered); err == nil {
		t.Fatal("changed digest was accepted")
	}
}
