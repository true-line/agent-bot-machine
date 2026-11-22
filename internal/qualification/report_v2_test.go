package qualification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func signedV2(t *testing.T, raw []byte, key *ecdsa.PrivateKey, purpose string) []byte {
	t.Helper()
	hash := sha256.Sum256(preimage(purpose, raw))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	version := 2
	if purpose == HostPurpose {
		version = 1
	}
	e := Envelope{SchemaVersion: version, Purpose: purpose, HostID: "fixture-qualification-mac", SignerID: "fixture-signer", ReportSHA256: digest(raw), ReportBase64URL: base64.RawURLEncoding.EncodeToString(raw), SignatureBase64URL: base64.RawURLEncoding.EncodeToString(sig)}
	envelope, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestBridgeV2SignatureAndCustody(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	raw, err := os.ReadFile("testdata/bridge-v2-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalBytes(raw, MaxReportBytes); err != nil {
		t.Fatal("contract fixture is not canonical", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, _, _ := fixturePolicy(t, now)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p.EvidenceSigners[0].HostID = "fixture-qualification-mac"
	p.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	verified := VerifiedPolicy{value: p, verified: true, at: now, version: 2}
	envelope := signedV2(t, raw, key, HostPurposeV2)
	legacyPolicy := verified
	legacyPolicy.version = 1
	if _, err := VerifyHostReportV2(envelope, legacyPolicy, now); err == nil {
		t.Fatal("v1 owner policy accepted for v2")
	}
	if _, err := VerifyHostReportV2(envelope, verified, now); err != nil {
		t.Fatal("valid synthetic v2 report refused", err)
	}
	if _, err := VerifyHostReport(envelope, verified, now); err == nil {
		t.Fatal("v2 report accepted as v1")
	}
	wrongPurpose := signedV2(t, raw, key, HostPurpose)
	if _, err := VerifyHostReportV2(wrongPurpose, verified, now); err == nil {
		t.Fatal("v1 purpose accepted for v2")
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"missing bridge", func(r map[string]any) { delete(r, "bridge") }},
		{"different Machine observation", func(r map[string]any) {
			r["bridge"].(map[string]any)["assignment"].(map[string]any)["machine_observation"].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("d", 64)
		}},
		{"shared credential UID", func(r map[string]any) {
			r["bridge"].(map[string]any)["principals"].(map[string]any)["credential_uid"] = float64(502)
		}},
		{"credential UID equals HQ", func(r map[string]any) {
			r["bridge"].(map[string]any)["principals"].(map[string]any)["credential_uid"] = float64(504)
		}},
		{"runner UID is root", func(r map[string]any) {
			r["bridge"].(map[string]any)["principals"].(map[string]any)["runner_uid"] = float64(0)
		}},
		{"zero private group", func(r map[string]any) {
			r["bridge"].(map[string]any)["principals"].(map[string]any)["bridge_private_gid"] = float64(0)
		}},
		{"wrong broker mode", func(r map[string]any) {
			r["bridge"].(map[string]any)["endpoints"].(map[string]any)["hq_broker"].(map[string]any)["socket_mode"] = "0666"
		}},
		{"aliased endpoint parent", func(r map[string]any) {
			r["bridge"].(map[string]any)["endpoints"].(map[string]any)["http_relay"].(map[string]any)["parent_inode"] = float64(1001)
		}},
		{"runner receives bootstrap", func(r map[string]any) {
			r["bridge"].(map[string]any)["handoff"].(map[string]any)["recipient_uid"] = float64(501)
		}},
		{"bare plan digest", func(r map[string]any) {
			r["bridge"].(map[string]any)["assignment"].(map[string]any)["plan_digest"] = strings.Repeat("1", 64)
		}},
		{"missing Machine UID", func(r map[string]any) {
			delete(r["bridge"].(map[string]any)["principals"].(map[string]any), "machine_uid")
		}},
		{"failed HMAC bind", func(r map[string]any) {
			r["bridge"].(map[string]any)["admission"].(map[string]any)["hq_broker_hmac_bind"].(map[string]any)["outcome"] = "fail"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var altered map[string]any
			if err := json.Unmarshal(raw, &altered); err != nil {
				t.Fatal(err)
			}
			tc.edit(altered)
			candidate, err := json.Marshal(altered)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyHostReportV2(signedV2(t, candidate, key, HostPurposeV2), verified, now); err == nil {
				t.Fatal("signed invalid bridge report accepted")
			}
		})
	}
}
