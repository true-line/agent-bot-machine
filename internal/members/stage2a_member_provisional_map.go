package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var stage2aProvisionalChannelBinding = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var stage2aMemberSelectorPattern = regexp.MustCompile(`^mb_[0-9a-f]{64}$`)

// H supplies the exact provisional map over its paired local Machine channel.
// A keeps these bytes for a later signed child observation; accepting the map
// does not finalize Hello or permit ACP input, B relay ingress, or a child.
type Stage2aMemberProvisionalMapRequest struct {
	Stage2aStopRequest
	ProvisionalHQMappingBase64URL string `json:"provisional_hq_mapping_base64url"`
	ProvisionalHQMappingSHA256    string `json:"provisional_hq_mapping_sha256"`
}

type Stage2aProvisionalMemberMap struct {
	Contract                 string `json:"contract"`
	Kind                     string `json:"kind"`
	SchemaVersion            int    `json:"schema_version"`
	ProfileInForce           string `json:"profile_in_force"`
	HostID                   string `json:"host_id"`
	InstallationID           string `json:"installation_id"`
	SoulID                   string `json:"soul_id"`
	StartID                  string `json:"start_id"`
	HQEpoch                  string `json:"hq_epoch"`
	AssignmentEnvelopeSHA256 string `json:"assignment_envelope_sha256"`
	RuntimeState             string `json:"runtime_state"`
	ACPAuthority             string `json:"acp_authority"`
	Members                  []struct {
		MemberID       string `json:"member_id"`
		MemberSelector string `json:"member_selector"`
		RuntimeID      string `json:"runtime_id"`
		ChannelBinding string `json:"channel_binding"`
	} `json:"members"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

type Stage2aMemberProvisionalMapReply struct {
	Accepted bool   `json:"accepted"`
	SHA256   string `json:"sha256"`
}

func ParseStage2aMemberProvisionalMapRequest(raw []byte) (Stage2aMemberProvisionalMapRequest, error) {
	var q Stage2aMemberProvisionalMapRequest
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) {
		return Stage2aMemberProvisionalMapRequest{}, errors.New("invalid Stage 2a provisional member map request")
	}
	if _, _, err := stage2aDecodeProvisionalMap(q); err != nil {
		return Stage2aMemberProvisionalMapRequest{}, err
	}
	return q, nil
}

func stage2aDecodeProvisionalMap(q Stage2aMemberProvisionalMapRequest) ([]byte, Stage2aProvisionalMemberMap, error) {
	var mapping Stage2aProvisionalMemberMap
	if !stage2aPrefixedDigest.MatchString(q.ProvisionalHQMappingSHA256) ||
		len(q.ProvisionalHQMappingBase64URL) == 0 ||
		len(q.ProvisionalHQMappingBase64URL) > base64.RawURLEncoding.EncodedLen(4096) {
		return nil, mapping, errors.New("invalid provisional map encoding")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.ProvisionalHQMappingBase64URL)
	if err != nil || len(raw) == 0 || len(raw) > 4096 ||
		base64.RawURLEncoding.EncodeToString(raw) != q.ProvisionalHQMappingBase64URL ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != q.ProvisionalHQMappingSHA256 ||
		stage2aStrictJSON(raw) != nil || stage2aDecodeExact(raw, &mapping) != nil {
		return nil, Stage2aProvisionalMemberMap{}, errors.New("invalid provisional map bytes")
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) ||
		mapping.Contract != "hq/v1" || mapping.Kind != "stage2a-provisional-member-map" ||
		mapping.SchemaVersion != 1 || mapping.ProfileInForce != "managed-protected" ||
		mapping.RuntimeState != "provisional" || mapping.ACPAuthority != "withheld" ||
		!stage2aPrefixedDigest.MatchString(mapping.AssignmentEnvelopeSHA256) ||
		!stage2aBindingID.MatchString(mapping.HostID) ||
		!soulInstallationID.MatchString(mapping.InstallationID) ||
		!soulIdentity.MatchString(mapping.SoulID) ||
		!soulStartID.MatchString(mapping.StartID) || !soulHQEpoch.MatchString(mapping.HQEpoch) ||
		len(mapping.Members) != 2 ||
		mapping.Members[0].MemberID >= mapping.Members[1].MemberID ||
		mapping.Members[0].RuntimeID == mapping.Members[1].RuntimeID ||
		mapping.Members[0].ChannelBinding == mapping.Members[1].ChannelBinding {
		return nil, Stage2aProvisionalMemberMap{}, errors.New("invalid provisional member map")
	}
	for _, member := range mapping.Members {
		if !stage2aBindingID.MatchString(member.MemberID) ||
			!stage2aBindingID.MatchString(member.RuntimeID) ||
			!stage2aProvisionalChannelBinding.MatchString(member.ChannelBinding) ||
			!stage2aMemberSelectorPattern.MatchString(member.MemberSelector) {
			return nil, Stage2aProvisionalMemberMap{}, errors.New("invalid provisional member")
		}
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, mapping.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
	if issueErr != nil || expiryErr != nil || !expires.After(issued) || expires.Sub(issued) > 20*time.Second {
		return nil, Stage2aProvisionalMemberMap{}, errors.New("invalid provisional map lifetime")
	}
	return raw, mapping, nil
}
