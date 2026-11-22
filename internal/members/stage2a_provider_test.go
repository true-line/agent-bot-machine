package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestStage2aProviderConfigIsExactReviewedBytes(t *testing.T) {
	q := Stage2aBridgeQualification{Model: "pilot-model", RequestSHA256: "sha256:" + strings.Repeat("a", 64), ResponseText: "fixture response"}
	raw, digest, err := stage2aProviderConfig(q)
	if err != nil || digest != fmt.Sprintf("%x", sha256.Sum256(raw)) {
		t.Fatalf("invalid provider digest: %q %v", digest, err)
	}
	var config stage2aProviderConfigBytes
	if json.Unmarshal(raw, &config) != nil || config.Model != q.Model ||
		config.RequestSHA256 != q.RequestSHA256 || config.ResponseText != q.ResponseText {
		t.Fatalf("provider bytes differ from review: %s", raw)
	}
	q.ResponseText = "changed response"
	_, changed, err := stage2aProviderConfig(q)
	if err != nil || changed == digest {
		t.Fatal("response replacement retained the reviewed provider digest")
	}
}
