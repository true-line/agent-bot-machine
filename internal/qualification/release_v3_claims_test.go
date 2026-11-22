package qualification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestV3ReportPairClaimsBindReleasedBytesAndDistinctRuns(t *testing.T) {
	now := time.Date(2026, 11, 22, 7, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p, _, _ := fixturePolicy(t, now)
	p.EvidenceSigners[0].HostID = "fixture-physical-mac"
	p.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	p.FrozenSoulMapping = &FrozenSoulMapping{
		SoulID:                  "agent_11111111-1111-1111-1111-111111111111",
		ArtifactSHA256:          strings.Repeat("b", 64),
		ClaimedDefinitionDigest: "sha256:" + strings.Repeat("b", 64),
		DefinitionMeasurement:   "sha256:27c6f3b4c768a2f5b2fe4f5f58c829eef7d02e111517937fea100d0aa15a2ede",
	}
	verified := VerifiedPolicy{value: p, verified: true, at: now, version: 3}
	read := func(t *testing.T, name string) map[string]any {
		t.Helper()
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	encode := func(t *testing.T, value map[string]any) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	check := func(t *testing.T, edit func(map[string]any, map[string]any, map[string]any), want bool) {
		t.Helper()
		qualification := read(t, "measurement-v3-qualification.json")
		protected := read(t, "stage2a-report-v3-protected-synthetic.json")
		cooperative := read(t, "stage2a-report-v3-cooperative-synthetic.json")
		if edit != nil {
			edit(qualification, protected, cooperative)
		}
		conformance := qualification["conformance"].(map[string]any)
		pRaw, cRaw := encode(t, protected), encode(t, cooperative)
		pEnvelope, cEnvelope := signedReportV3(t, pRaw, key), signedReportV3(t, cRaw, key)
		for _, entry := range []struct {
			name     string
			report   []byte
			envelope []byte
		}{
			{"protected_report", pRaw, pEnvelope},
			{"cooperative_report", cRaw, cEnvelope},
		} {
			ref := conformance[entry.name].(map[string]any)
			ref["payload"].(map[string]any)["sha256"] = digest(entry.report)
			ref["signature"].(map[string]any)["sha256"] = digest(entry.envelope)
		}
		err := verifyV3ReportPairClaims(verified, encode(t, qualification), pEnvelope, cEnvelope, now)
		if (err == nil) != want {
			t.Fatalf("accepted=%v, want %v: %v", err == nil, want, err)
		}
	}
	check(t, nil, true)
	verified.value.FrozenSoulMapping.ArtifactSHA256 = strings.Repeat("f", 64)
	check(t, nil, false)
	verified.value.FrozenSoulMapping.ArtifactSHA256 = strings.Repeat("b", 64)
	verified.value.FrozenSoulMapping.DefinitionMeasurement = "sha256:" + strings.Repeat("f", 64)
	check(t, nil, false)
	verified.value.FrozenSoulMapping.DefinitionMeasurement = "sha256:27c6f3b4c768a2f5b2fe4f5f58c829eef7d02e111517937fea100d0aa15a2ede"
	verified.version = 2
	check(t, nil, false)
	verified.version = 3
	fixture := read(t, "measurement-v3-qualification.json")
	if fixture["adapter"].(map[string]any)["package_sha256"] == "sha256:"+fixture["soul_artifact_sha256"].(string) ||
		fixture["souls_build"].(map[string]any)["package_sha256"] == "sha256:"+fixture["soul_artifact_sha256"].(string) {
		t.Fatal("synthetic adapter, runtime tgz and frozen Soul artifact digests must be distinct")
	}
	check(t, func(_, _, cooperative map[string]any) {
		binding := cooperative["measurement_binding"].(map[string]any)
		binding["hq_epoch"] = strings.Repeat("e", 64)
		binding["plan_id"] = "separate-cooperative-plan"
		binding["installed_plan_digest"] = strings.Repeat("e", 64)
	}, true)
	for _, tc := range []struct {
		name string
		edit func(map[string]any, map[string]any, map[string]any)
	}{
		{"qualification host", func(q, _, _ map[string]any) { q["host"].(map[string]any)["id"] = "other-host" }},
		{"qualification runner", func(q, _, _ map[string]any) { q["runner"].(map[string]any)["binary_path"] = "/fixture/other-runner" }},
		{"qualification Soul artifact", func(q, _, _ map[string]any) { q["soul_artifact_sha256"] = strings.Repeat("f", 64) }},
		{"adapter digest substituted for Soul artifact", func(q, _, _ map[string]any) {
			q["soul_artifact_sha256"] = strings.TrimPrefix(q["adapter"].(map[string]any)["package_sha256"].(string), "sha256:")
		}},
		{"runtime tgz digest substituted for Soul artifact", func(q, _, _ map[string]any) {
			q["soul_artifact_sha256"] = strings.TrimPrefix(q["souls_build"].(map[string]any)["package_sha256"].(string), "sha256:")
		}},
		{"cooperative Soul artifact", func(_, _, c map[string]any) {
			c["measurement_binding"].(map[string]any)["soul_artifact_sha256"] = strings.Repeat("f", 64)
		}},
		{"cooperative reservation replay", func(_, p, c map[string]any) {
			c["run_evidence"].(map[string]any)["reservation"] = p["run_evidence"].(map[string]any)["reservation"]
		}},
		{"cooperative launch input replay", func(_, p, c map[string]any) {
			c["measurement_binding"].(map[string]any)["launch_input_measurement"] = p["measurement_binding"].(map[string]any)["launch_input_measurement"]
		}},
		{"qualification before cooperative report", func(q, _, _ map[string]any) {
			q["recorded_at"] = "2026-11-22T06:00:30Z"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, tc.edit, false) })
	}
}
