package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type Stage2aProviderRequest struct {
	Stage2aStopRequest
	BindReceiptSHA256 string `json:"bind_receipt_sha256"`
	Model             string `json:"model"`
	PromptSHA256      string `json:"prompt_sha256"`
}

type Stage2aProviderReply struct {
	Model                string `json:"model"`
	RequestSHA256        string `json:"request_sha256"`
	ResponseText         string `json:"response_text"`
	ProviderConfigSHA256 string `json:"provider_config_sha256"`
	ConfigBase64URL      string `json:"config_base64url"`
	ExpiresAtMS          int64  `json:"expires_at_ms"`
}

// Cooperative provider authority is separate from the protected B bind. HQ
// presents the A-signed attach identity; R receives only the broker response.
type SoulCooperativeProviderRequestV3 struct {
	Stage2aStopRequest
	AttachSHA256 string `json:"attach_sha256"`
	Model        string `json:"model"`
	PromptSHA256 string `json:"prompt_sha256"`
}

func ParseSoulCooperativeProviderRequestV3(raw []byte) (SoulCooperativeProviderRequestV3, error) {
	var q SoulCooperativeProviderRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errors.New("invalid cooperative provider request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.AttachSHA256) ||
		!stage2aBindingID.MatchString(q.Model) ||
		!stage2aPrefixedDigest.MatchString(q.PromptSHA256) {
		return SoulCooperativeProviderRequestV3{}, errors.New("invalid cooperative provider request")
	}
	return q, nil
}

type stage2aProviderConfigBytes struct {
	Model         string `json:"model"`
	RequestSHA256 string `json:"request_sha256"`
	ResponseText  string `json:"response_text"`
}

func stage2aProviderConfig(q Stage2aBridgeQualification) ([]byte, string, error) {
	if !stage2aBindingID.MatchString(q.Model) || !stage2aPrefixedDigest.MatchString(q.RequestSHA256) ||
		len(q.ResponseText) == 0 || len(q.ResponseText) > 4096 {
		return nil, "", errors.New("invalid Stage 2a provider config")
	}
	encoded, err := json.Marshal(stage2aProviderConfigBytes{
		Model: q.Model, RequestSHA256: q.RequestSHA256, ResponseText: q.ResponseText})
	if err != nil {
		return nil, "", err
	}
	raw, err := jsoncanonicalizer.Transform(encoded)
	if err != nil || len(raw) > 8192 {
		return nil, "", errors.New("invalid Stage 2a provider config")
	}
	return raw, fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func ParseStage2aProviderRequest(raw []byte) (Stage2aProviderRequest, error) {
	var q Stage2aProviderRequest
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errors.New("invalid Stage 2a provider request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		!strings.HasPrefix(q.BindReceiptSHA256, "sha256:") ||
		!stage2aLowerHex64(strings.TrimPrefix(q.BindReceiptSHA256, "sha256:")) ||
		!stage2aBindingID.MatchString(q.Model) || !stage2aPrefixedDigest.MatchString(q.PromptSHA256) {
		return Stage2aProviderRequest{}, errors.New("invalid Stage 2a provider request")
	}
	return q, nil
}
